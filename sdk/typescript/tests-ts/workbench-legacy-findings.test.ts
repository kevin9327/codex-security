import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Request, Response } from "./support/workbench-results-fixture";

const scanId = "11111111-1111-4111-8111-111111111111",
  directory = realpathSync(mkdtempSync(join(tmpdir(), "workbench-legacy-"))),
  fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-results-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    format: "cjs",
    platform: "node",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as unknown as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
type Table = Record<string, unknown>;
const load = (root: string, name: string) =>
  parseJson(readFileSync(join(root, name), "utf8")) as Table;
const write = (root: string, name: string, value: unknown) =>
  writeFileSync(join(root, name), stringifyJson(value) + "\n");
const digest = (bytes: Buffer) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
function seed(multiple = false) {
  const root = mkdtempSync(join(directory, "scan-"));
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"])
    copyFileSync(
      join(PLUGIN_ROOT, "examples/completed-scan", name),
      join(root, name),
    );
  const manifest = load(root, "scan-manifest.json"),
    scan = manifest["scan"] as Table,
    target = scan["target"] as Table;
  Object.assign(scan, { id: scanId });
  Object.assign(target, {
    targetId: "target-id",
    displayName: "target",
    revision: "revision",
  });
  delete scan["sealedAt"];
  delete scan["artifacts"];
  write(root, "scan-manifest.json", manifest);
  const findings = load(root, "findings.json"),
    documents = findings["findings"] as Table[];
  findings["scanId"] = scanId;
  if (multiple)
    documents.push({
      ...documents[0],
      ruleId: "synthetic.second-control",
      identity: { anchor: "second-control" },
    });
  for (const finding of documents)
    for (const field of ["findingId", "occurrenceId", "fingerprints"])
      delete finding[field];
  write(root, "findings.json", findings);
  const coverage = load(root, "coverage.json");
  coverage["scanId"] = scanId;
  write(root, "coverage.json", coverage);
  const [prepared] = run({
    scan: { scan_dir: root },
    actions: [{ operation: "finalize" }],
  });
  expect(prepared!.outcomes[0]!.error).toBeUndefined();
  const sealed = load(root, "findings.json")["findings"] as Table[];
  const request: Request = {
    scan: {
      status: "complete",
      scan_dir: root,
      target_path: "/target",
      target_id: "target-id",
      target_snapshot_digest: target["snapshotDigest"] as string,
      target_revision: "revision",
    },
    records: {
      finding_occurrences: sealed.map((finding) => ({
        id: finding["occurrenceId"] as string,
        finding_id: finding["findingId"] as string,
        scan_id: scanId,
        title: finding["title"] as string,
        summary: finding["summary"] as string,
        remediation: finding["remediation"] as string,
        severity: (finding["severity"] as Table)["level"] as string,
        confidence: (finding["confidence"] as Table)["level"] as string,
        details_json: "{}",
        created_at: "created",
      })),
    },
    actions: [{ operation: "backfill" }],
  };
  return {
    root,
    request,
    findings: sealed,
    manifestDigest: digest(readFileSync(join(root, "scan-manifest.json"))),
  };
}
const rows = (response: Response) => response.snapshot["finding_occurrences"]!;
const pin = (response: Response) =>
  response.snapshot["scans"]![0]!["seal_manifest_digest"];
test("legacy backfill restores matching rich details and pins the exact sealed manifest", () => {
  const seeded = seed(true);
  const [response] = run({
    ...seeded.request,
    actions: [{ operation: "backfill" }, { operation: "backfill" }],
  });
  for (const [index, row] of rows(response!).entries())
    expect(parseJson(row["details_json"] as string)).toEqual(
      seeded.findings[index],
    );
  expect(pin(response!)).toBe(seeded.manifestDigest);
  expect(response!.outcomes[0]!).toMatchObject({
    result: null,
    inTransaction: false,
  });
  expect(response!.outcomes[1]!.events).toHaveLength(2);
});
test("backfill skips in-progress scans, caller transactions and populated details", () => {
  const seeded = seed();
  const responses = run(
    {
      ...seeded.request,
      scan: { ...seeded.request.scan, status: "running", scan_dir: "/missing" },
    },
    {
      ...seeded.request,
      actions: [
        { operation: "sql", sql: "UPDATE scans SET updated_at='caller'" },
        { operation: "backfill" },
      ],
    },
    {
      ...seeded.request,
      records: {
        finding_occurrences: seeded.request.records![
          "finding_occurrences"
        ]!.map((row) => ({ ...row, details_json: '{"stored":true}' })),
      },
    },
  );
  expect(responses[0]!.outcomes[0]!.events).toHaveLength(1);
  expect(responses[1]!.outcomes[1]!).toMatchObject({
    result: null,
    inTransaction: true,
  });
  expect(responses[1]!.outcomes[1]!.events).toHaveLength(1);
  expect(rows(responses[2]!)[0]!["details_json"]).toBe('{"stored":true}');
  for (const response of responses) expect(pin(response)).toBeNull();
});
test("backfill requires every legacy summary field to match before replacing details", () => {
  const seeded = seed();
  const responses = run(
    ...[
      "finding_id",
      "title",
      "summary",
      "remediation",
      "severity",
      "confidence",
    ].map(
      (field): Request => ({
        ...seeded.request,
        records: {
          finding_occurrences: seeded.request.records![
            "finding_occurrences"
          ]!.map((row) => ({ ...row, [field]: "changed" })),
        },
      }),
    ),
  );
  for (const response of responses) {
    expect(response.outcomes[0]!.error).toBeUndefined();
    expect(rows(response)[0]!["details_json"]).toBe("{}");
    expect(pin(response)).toBeNull();
  }
});
test("invalid seals and value errors leave legacy details untouched while programming errors propagate", () => {
  const sealed = seed(),
    invalidUrl = seed(),
    oversized = seed(),
    missingRecipe = seed();
  const manifest = load(invalidUrl.root, "scan-manifest.json");
  ((manifest["scan"] as Table)["target"] as Table)["remote"] =
    "https://[127.0.0.1]";
  write(invalidUrl.root, "scan-manifest.json", manifest);
  const responses = run(
    {
      ...sealed.request,
      scan: { ...sealed.request.scan, seal_manifest_digest: "changed" },
    },
    invalidUrl.request,
    {
      ...oversized.request,
      scan: {
        ...oversized.request.scan,
        recipe_json: `{"target":{"kind":"paths","paths":[${"9".repeat(4301)}]}}`,
      },
    },
    {
      ...missingRecipe.request,
      scan: { ...missingRecipe.request.scan, recipe_json: "{}" },
    },
  );
  for (const response of responses) {
    expect(rows(response)[0]!["details_json"]).toBe("{}");
    expect(response.outcomes[0]!.inTransaction).toBe(false);
  }
  for (const response of responses.slice(0, 3))
    expect(response.outcomes[0]!.error).toBeUndefined();
  expect(responses[3]!.outcomes[0]!.error).toBe("'target'");
});
test("backfill rechecks the digest and preserves details written before its transaction", () => {
  const seeded = seed();
  const [changed, updated, existing] = run(
    {
      ...seeded.request,
      actions: [
        {
          operation: "backfill",
          beforeBeginSql: "UPDATE scans SET seal_manifest_digest='changed'",
        },
      ],
    },
    {
      ...seeded.request,
      actions: [
        {
          operation: "backfill",
          beforeBeginSql:
            "UPDATE finding_occurrences SET details_json='{\"newer\":true}'",
        },
      ],
    },
    {
      ...seeded.request,
      actions: [
        {
          operation: "backfill",
          beforeBeginSql: `UPDATE scans SET seal_manifest_digest='${seeded.manifestDigest}'`,
        },
      ],
    },
  );
  expect(changed!.outcomes[0]!).toMatchObject({
    error: "The sealed scan manifest changed after completion.",
    systemExit: true,
    inTransaction: false,
  });
  expect(rows(changed!)[0]!["details_json"]).toBe("{}");
  expect(pin(changed!)).toBe("changed");
  expect(rows(updated!)[0]!["details_json"]).toBe('{"newer":true}');
  expect(pin(updated!)).toBe(seeded.manifestDigest);
  expect(existing!.outcomes[0]!.error).toBeUndefined();
  expect(pin(existing!)).toBe(seeded.manifestDigest);
});
test("write and deferred commit failures roll back details and the newly recorded digest", () => {
  const seeded = seed(true),
    last = seeded.findings[1]!["occurrenceId"] as string;
  const responses = run(
    {
      ...seeded.request,
      setupSql: [
        `CREATE TRIGGER reject_update BEFORE UPDATE OF details_json ON finding_occurrences WHEN NEW.id='${last}' BEGIN SELECT RAISE(ABORT,'update rejected'); END;`,
      ],
    },
    {
      ...seeded.request,
      setupSql: [
        "PRAGMA foreign_keys=ON",
        "CREATE TABLE audit(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER bad_audit AFTER UPDATE OF details_json ON finding_occurrences BEGIN INSERT INTO audit VALUES ('missing'); END;",
      ],
    },
  );
  expect(responses.map((response) => response.outcomes[0]!.error)).toEqual([
    "update rejected",
    "FOREIGN KEY constraint failed",
  ]);
  for (const response of responses) {
    expect(response.outcomes[0]!.events.at(-1)).toEqual([
      "transaction",
      "ROLLBACK",
      true,
    ]);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(rows(response).map((row) => row["details_json"])).toEqual([
      "{}",
      "{}",
    ]);
    expect(pin(response)).toBeNull();
  }
});
