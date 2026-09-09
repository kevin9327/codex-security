import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  symlinkSync,
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
  directory = realpathSync(mkdtempSync(join(tmpdir(), "workbench-export-"))),
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
function seed() {
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
    actions: [{ operation: "export", format: "json" }],
  };
  return {
    root,
    request,
    findings: sealed,
    manifestDigest: digest(readFileSync(join(root, "scan-manifest.json"))),
  };
}
const pin = (response: Response) =>
  response.snapshot["scans"]![0]!["seal_manifest_digest"];
const error = (response: Response, index = 0) =>
  response.outcomes[index]!.error;
const csv = (root: string) =>
  readFileSync(join(root, "exports/findings.csv"), "utf8");

test("completed exports pin the manifest and regenerate sealed SARIF before rendering results", () => {
  const seeded = seed(),
    sarif = readFileSync(join(seeded.root, "exports/results.sarif"));
  writeFileSync(join(seeded.root, "exports/results.sarif"), "{}");
  const [response] = run({
    ...seeded.request,
    actions: [
      { operation: "export", format: "json" },
      { operation: "export", format: "csv" },
      { operation: "export", format: "sarif" },
    ],
  });
  expect(response!.outcomes.every((outcome) => !outcome.error)).toBe(true);
  expect(pin(response!)).toBe(seeded.manifestDigest);
  for (const [index, [format, relative]] of [
    ["json", "findings.json"],
    ["csv", "exports/findings.csv"],
    ["sarif", "exports/results.sarif"],
  ].entries()) {
    expect(response!.outcomes[index]!.result).toMatchObject({
      export: { format, path: join(seeded.root, relative!) },
      scan: {
        scanId,
        sealManifestDigest: index === 0 ? null : seeded.manifestDigest,
      },
    });
    expect(response!.outcomes[index]!.events.slice(-2)).toEqual([
      [
        "export-scan",
        scanId,
        index === 0 ? null : seeded.manifestDigest,
        false,
      ],
      ["export-workspace", "22222222-2222-4222-8222-222222222222", false],
    ]);
  }
  expect(readFileSync(join(seeded.root, "exports/results.sarif"))).toEqual(
    sarif,
  );
  expect(csv(seeded.root)).toStartWith(
    "occurrence_id,finding_id,title,summary,",
  );
});

test("stopped exports require a nonempty seal before inspecting artifacts", () => {
  const seeded = seed();
  const responses = run(
    ...[null, "", seeded.manifestDigest].map((seal) => ({
      ...seeded.request,
      scan: {
        ...seeded.request.scan,
        status: "failed",
        seal_manifest_digest: seal,
      },
    })),
    { ...seeded.request, scan: { ...seeded.request.scan, status: "running" } },
    {
      ...seeded.request,
      scan: { ...seeded.request.scan, status: "failed" },
      setupSql: ["UPDATE scans SET seal_manifest_digest=x''"],
      actions: [
        { operation: "export" },
        { operation: "sql", sql: "UPDATE scans SET seal_manifest_digest=NULL" },
      ],
    },
  );
  expect(error(responses[2]!)).toBeUndefined();
  for (const index of [0, 1, 3, 4]) {
    expect(error(responses[index]!)).toBe(
      "Findings can be exported after the scan completes or preserves stopped results.",
    );
    expect(responses[index]!.outcomes[0]!.events).toHaveLength(1);
  }
});

test("CSV includes triage, the root control location and the existing formula escaping", () => {
  const seeded = seed(),
    occurrence = seeded.request.records!["finding_occurrences"]![0]!;
  Object.assign(occurrence, {
    title: "=value",
    summary: 'a,"quote"\nline',
    remediation: "＠formula",
  });
  const id = occurrence["id"] as string;
  const [response] = run({
    ...seeded.request,
    records: {
      ...seeded.request.records,
      finding_triage: [
        {
          occurrence_id: id,
          status: "closed",
          close_reason: "already_fixed",
          note: "reviewed",
          updated_at: "updated",
        },
      ],
      finding_locations: [
        {
          occurrence_id: id,
          relative_path: "entry.ts",
          start_line: 1n,
          end_line: 2n,
          role: "source",
          sort_order: 0n,
        },
        {
          occurrence_id: id,
          relative_path: "control.ts",
          start_line: 7n,
          end_line: 9n,
          role: "root_control",
          sort_order: 2n,
        },
      ],
    },
    actions: [{ operation: "exportRows" }, { operation: "exportCsv" }],
  });
  expect(error(response!, 1)).toBeUndefined();
  expect(response!.outcomes[0]!.result).toMatchObject([
    {
      relative_path: "control.ts",
      start_line: 7n,
      end_line: 9n,
      status: "closed",
    },
  ]);
  expect(csv(seeded.root)).toContain(
    ',\'=value,"a,""quote""\nline",high,high,closed,already_fixed,reviewed,\'＠formula,control.ts,7,9\r\n',
  );
});

test("deep CSV adds candidate identities with their original precedence", () => {
  const seeded = seed(),
    id = seeded.findings[0]!["occurrenceId"] as string;
  write(seeded.root, "findings.json", {
    findings: [
      { occurrenceId: id, provenance: { candidateId: "earlier" } },
      {
        occurrenceId: id,
        provenance: {},
        extensions: {
          candidateId: " ",
          reportId: "retained-candidate",
          ledgerRowId: "other",
        },
      },
    ],
  });
  const [response] = run({
    ...seeded.request,
    scan: { ...seeded.request.scan, mode: "deep" },
    actions: [{ operation: "exportCsv" }],
  });
  expect(error(response!)).toBeUndefined();
  expect(csv(seeded.root)).toStartWith(
    "occurrence_id,finding_id,candidate_id,title,",
  );
  expect(csv(seeded.root)).toContain(",retained-candidate,");
});

test("CSV preserves SQLite BLOB cells and exact large location integers", () => {
  const seeded = seed(),
    id = seeded.findings[0]!["occurrenceId"] as string;
  const [response] = run({
    ...seeded.request,
    setupSql: ["UPDATE finding_occurrences SET title=x'6162276364ff'"],
    records: {
      ...seeded.request.records,
      finding_locations: [
        {
          occurrence_id: id,
          relative_path: "src.ts",
          start_line: 9007199254740993n,
          end_line: 9007199254740995n,
          role: "root_control",
          sort_order: 0n,
        },
      ],
    },
    actions: [
      { operation: "exportCsv" },
      {
        operation: "sql",
        sql: "UPDATE finding_occurrences SET title='restored'",
      },
    ],
  });
  expect(error(response!)).toBeUndefined();
  expect(csv(seeded.root)).toContain(',"b""ab\'cd\\xff""",');
  expect(csv(seeded.root)).toEndWith(
    ",src.ts,9007199254740993,9007199254740995\r\n",
  );
});

test("manifest failures happen before export writes and unsafe export directories remain rejected", () => {
  const seeded = seed();
  writeFileSync(join(seeded.root, "scan-manifest.json"), "changed");
  const [changed] = run({
    ...seeded.request,
    scan: {
      ...seeded.request.scan,
      seal_manifest_digest: seeded.manifestDigest,
    },
  });
  expect(error(changed!)).toBe(
    "The sealed scan manifest changed after completion.",
  );
  expect(changed!.outcomes[0]!.events).toHaveLength(1);
  if (process.platform !== "win32") {
    const linked = seed(),
      outside = mkdtempSync(join(directory, "outside-"));
    rmSync(join(linked.root, "exports"), { recursive: true });
    symlinkSync(outside, join(linked.root, "exports"));
    const [response] = run({
      ...linked.request,
      actions: [{ operation: "exportCsv" }],
    });
    expect(error(response!)).toBe(
      "exports: expected a regular directory inside the scan directory.",
    );
  }
});

test("pin failures roll back while rendering failures occur after the export is saved", () => {
  const seeded = seed();
  const responses = run(
    {
      ...seeded.request,
      setupSql: [
        "PRAGMA foreign_keys=ON",
        "CREATE TABLE audit(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER invalid_pin AFTER UPDATE OF seal_manifest_digest ON scans BEGIN INSERT INTO audit VALUES ('missing'); END;",
      ],
    },
    {
      ...seeded.request,
      actions: [
        { operation: "sql", sql: "UPDATE scans SET updated_at='caller'" },
        { operation: "export" },
      ],
    },
    {
      ...seeded.request,
      actions: [
        { operation: "export", format: "csv", failExportCallback: "scan" },
      ],
    },
  );
  expect(error(responses[0]!)).toBe("FOREIGN KEY constraint failed");
  expect(pin(responses[0]!)).toBeNull();
  expect(responses[0]!.outcomes[0]!.inTransaction).toBe(false);
  expect(error(responses[1]!, 1)).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(responses[1]!.outcomes[1]!.inTransaction).toBe(true);
  expect(responses[1]!.snapshot["scans"]![0]!["updated_at"]).toBe("caller");
  expect(error(responses[2]!)).toBe("scan projection failed");
  expect(pin(responses[2]!)).toBe(seeded.manifestDigest);
  expect(csv(seeded.root)).toStartWith("occurrence_id,finding_id,");
});

test("CSV retains Python formatting for SQLite REAL location values", () => {
  for (const [number, text] of [
    [1e20, "1e+20"],
    [1.5, "1.5"],
  ] as const) {
    const seeded = seed(),
      id = seeded.findings[0]!["occurrenceId"] as string;
    const [response] = run({
      ...seeded.request,
      records: {
        ...seeded.request.records,
        finding_locations: [
          {
            occurrence_id: id,
            relative_path: "src.ts",
            start_line: 1n,
            end_line: 1n,
            role: "root_control",
            sort_order: 0n,
          },
        ],
      },
      setupSql: [
        `UPDATE finding_locations SET start_line=CAST('${number}' AS REAL), end_line=CAST('${number}' AS REAL)`,
      ],
      actions: [{ operation: "exportCsv" }],
    });
    expect(error(response!)).toBeUndefined();
    expect(csv(seeded.root)).toEndWith(`,src.ts,${text},${text}\r\n`);
  }
});
