import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-results-fixture";

const scanId = "11111111-1111-4111-8111-111111111111";
const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-preserve-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const followUp =
  "Saved scan evidence remains on disk; result publication needs follow-up:";
const outputs = [
  "findings.json",
  "coverage.json",
  "scan-manifest.json",
  "report.md",
  "report.html",
  "exports/results.sarif",
];
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
function root(name: string): string {
  const path = join(directory, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}
function write(scan: string, path: string, value: unknown): void {
  mkdirSync(join(scan, path, ".."), { recursive: true });
  writeFileSync(
    join(scan, path),
    Buffer.isBuffer(value) ? value : stringifyJson(value),
  );
}
function checkpoint(
  scan: string,
  title = "Unchecked destination",
): Record<string, string> {
  const value = {
    scanId,
    findings: [
      {
        ruleId: "unsafe-write",
        identity: { anchor: "destination" },
        title,
        summary: "The destination is unchecked.",
        severity: { level: "medium", rationale: "Source trace" },
        confidence: { level: "high", rationale: "Source trace" },
        taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
        locations: [{ path: "src/a.ts", startLine: 1n, endLine: 1n }],
        remediation: "Check the destination.",
        provenance: { source: "local_plugin" },
      },
    ],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [
        {
          candidateId: "pending",
          reason: "Review pending.",
          paths: ["src/a.ts"],
        },
      ],
    },
  };
  const encoded = stringifyJson(value, {
    compact: true,
    sortKeys: true,
    separators: [",", ":"],
  });
  const digest = createHash("sha256").update(encoded).digest("hex"),
    path = `checkpoints/${digest}.json`;
  write(scan, path, value);
  return { [path]: digest };
}
function request(
  scan: string,
  actions: Action[] = [{ operation: "preserve" }],
): Request {
  return {
    scan: {
      target_path: join(directory, "target"),
      target_revision: "unversioned",
      target_id: "repo:synthetic",
      target_snapshot_digest: `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`,
      scan_dir: scan,
      status: "failed",
      scope: "src",
      phase: "reporting",
      started_at: "2026-01-01T00:00:00Z",
      completed_at: "2026-01-01T01:00:00Z",
      failure_message: "Worker stopped.",
      completion_warnings_json: "[]",
    },
    setupSql: ["PRAGMA foreign_keys=ON"],
    actions,
  };
}
function run(input: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([input]),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child["status"], child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const response = (parseJson(child.stdout) as unknown as Response[])[0]!;
  expect(response.node).toBe(nodeVersion);
  return response;
}
const sql = (query: string): Action => ({ operation: "sql", sql: query });
function published(scan: string): Record<string, string | null> {
  return Object.fromEntries(
    outputs.map((path) => [
      path,
      existsSync(join(scan, path))
        ? readFileSync(join(scan, path)).toString("hex")
        : null,
    ]),
  );
}
function manifest(scan: string): { scan: Record<string, unknown> } {
  return JSON.parse(readFileSync(join(scan, "scan-manifest.json"), "utf8"));
}
function success(response: Response): void {
  for (const outcome of response.outcomes)
    expect(outcome.error).toBeUndefined();
}

test("publishes stopped checkpoints with bound artifacts, findings, and pending coverage", () => {
  for (const canceled of [false, true]) {
    const scan = root(`publish-${canceled}`),
      frozen = checkpoint(scan),
      input = request(scan, [
        { operation: "preserve" },
        { operation: "compareCoverage" },
      ]);
    if (canceled) input.scan!["canceled_at"] = "2026-01-01T01:00:00Z";
    const response = run(input);
    success(response);
    expect(response.outcomes[0]!.result).toBe(true);
    expect(manifest(scan).scan["status"]).toBe(
      canceled ? "canceled" : "failed",
    );
    expect(manifest(scan).scan["preservedSources"]).toEqual(frozen);
    expect(response.snapshot["finding_occurrences"]).toHaveLength(1);
    expect(response.snapshot["scan_artifacts"]).toHaveLength(4);
    expect(
      response.snapshot["scan_progress"]![0]!["reportable_findings_count"],
    ).toBe(1n);
    expect(response.snapshot["scans"]![0]!["seal_manifest_digest"]).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(
      JSON.parse(
        response.snapshot["scans"]![0]![
          "retained_source_digests_json"
        ] as string,
      ),
    ).toEqual(frozen);
    expect(
      (response.outcomes[1]!.result as { deferred: unknown[] }).deferred.length,
    ).toBeGreaterThan(0);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
  }
});

test("replaying a pinned publication preserves triage and remediation while removing stale warnings", () => {
  const scan = root("replay");
  checkpoint(scan);
  const input = request(scan, [
    { operation: "preserve" },
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,updated_at) SELECT id,'open','triaged' FROM finding_occurrences",
    ),
    sql(
      "INSERT INTO finding_remediation_attempts(request_id,occurrence_id,state,version,base_revision,created_at,updated_at) SELECT 'request',id,'failed',2,'unversioned','created','updated' FROM finding_occurrences",
    ),
    sql(
      "INSERT INTO findings(id,fingerprint,rule_id,identity_anchor,created_at,updated_at) VALUES('stale-finding','stale-fingerprint','stale-rule','stale-anchor','created','updated')",
    ),
    sql(
      "INSERT INTO finding_occurrences(id,finding_id,scan_id,title,summary,severity,confidence,remediation,created_at) SELECT 'vanished','stale-finding',scan_id,'stale',summary,severity,confidence,remediation,created_at FROM finding_occurrences",
    ),
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,updated_at) VALUES('vanished','open','stale')",
    ),
    sql(
      "INSERT INTO finding_locations(occurrence_id,relative_path,start_line,end_line,sort_order) VALUES('vanished','src/old.ts',1,1,0)",
    ),
    sql(
      `UPDATE scans SET completion_warnings_json='["kept","kept","${followUp} stale"]'`,
    ),
    { operation: "commit" },
    { operation: "preserve" },
    { operation: "preserve", failNow: true },
  ]);
  const response = run(input);
  success(response);
  expect(response.snapshot["finding_occurrences"]).toHaveLength(1);
  expect(response.snapshot["finding_triage"]).toHaveLength(1);
  expect(response.snapshot["finding_locations"]).toHaveLength(1);
  expect(response.snapshot["finding_triage"]![0]!["updated_at"]).toBe(
    "triaged",
  );
  expect(
    response.snapshot["finding_remediation_attempts"]![0]!["version"],
  ).toBe(2n);
  expect(response.snapshot["scans"]![0]!["completion_warnings_json"]).toBe(
    '["kept"]',
  );
  expect(
    response.outcomes
      .at(-1)!
      .events.some((event) => (event as unknown[])[0] === "now"),
  ).toBe(false);
});

test("publication failure restores all prior outputs and retains the committed source map", () => {
  const scan = root("rollback"),
    frozen = checkpoint(scan);
  write(scan, "report.md", Buffer.from("old markdown"));
  write(scan, "report.html", Buffer.from("old html"));
  write(scan, "exports/results.sarif", Buffer.from("old sarif"));
  const before = published(scan),
    input = request(scan);
  input.setupSql!.push(
    "CREATE TRIGGER reject_pin BEFORE UPDATE OF seal_manifest_digest ON scans BEGIN SELECT RAISE(ABORT,'pin rejected'); END;",
  );
  const response = run(input);
  expect(response.outcomes[0]!.error).toBe("pin rejected");
  expect(published(scan)).toEqual(before);
  expect(
    JSON.parse(
      response.snapshot["scans"]![0]!["retained_source_digests_json"] as string,
    ),
  ).toEqual(frozen);
  expect(response.snapshot["scans"]![0]!["seal_manifest_digest"]).toBeNull();
  expect(response.snapshot["finding_occurrences"]).toEqual([]);
  expect(response.snapshot["scan_artifacts"]).toEqual([]);
  expect(response.outcomes[0]!.inTransaction).toBe(false);
});

test("a failed source freeze leaves published files and the caller transaction rolled back", () => {
  const scan = root("freeze-failure");
  checkpoint(scan);
  const before = published(scan);
  const input = request(scan, [
    sql("UPDATE workspaces SET updated_at='caller'"),
    { operation: "preserve" },
  ]);
  input.setupSql!.push(
    "CREATE TRIGGER reject_freeze BEFORE UPDATE OF retained_source_digests_json ON scans BEGIN SELECT RAISE(ABORT,'freeze rejected'); END;",
  );
  const response = run(input);
  expect(response.outcomes[1]!.error).toBe("freeze rejected");
  expect(response.snapshot["workspaces"]![0]!["updated_at"]).toBe(
    "workspace-updated",
  );
  expect(
    response.snapshot["scans"]![0]!["retained_source_digests_json"],
  ).toBeNull();
  expect(published(scan)).toEqual(before);
});

test("clock failures retain the original caller-transaction boundary", () => {
  for (const alreadyFrozen of [false, true]) {
    const scan = root(`clock-${alreadyFrozen}`),
      frozen = checkpoint(scan),
      input = request(scan, [
        sql("UPDATE workspaces SET updated_at='caller'"),
        { operation: "preserve", failNow: true },
        { operation: "rollback" },
      ]);
    if (alreadyFrozen)
      input.scan!["retained_source_digests_json"] = JSON.stringify(frozen);
    const response = run(input);
    expect(response.outcomes[1]!.error).toBe("clock failed");
    expect(response.outcomes[1]!.inTransaction).toBe(alreadyFrozen);
    expect(response.snapshot["workspaces"]![0]!["updated_at"]).toBe(
      alreadyFrozen ? "workspace-updated" : "caller",
    );
    expect(response.snapshot["scans"]![0]!["seal_manifest_digest"]).toBeNull();
    expect(published(scan)["scan-manifest.json"]).toBeNull();
  }
});

test("nonfailed scans return before parsing saved state or inspecting files", () => {
  const input = request(join(directory, "missing"));
  Object.assign(input.scan!, {
    status: "running",
    retained_source_digests_json: "{",
    completion_warnings_json: "{",
  });
  const response = run(input);
  success(response);
  expect(response.outcomes[0]!.result).toBe(false);
  expect(response.outcomes[0]!.events).toHaveLength(1);
});

test("an empty scan deduplicates warnings without discarding publication follow-up", () => {
  const scan = root("empty"),
    input = request(scan);
  input.scan!["completion_warnings_json"] = JSON.stringify([
    "kept",
    `${followUp} stale`,
    "kept",
  ]);
  const response = run(input);
  success(response);
  expect(response.outcomes[0]!.result).toBe(false);
  expect(
    JSON.parse(
      response.snapshot["scans"]![0]!["completion_warnings_json"] as string,
    ),
  ).toEqual(["kept", `${followUp} stale`]);
  expect(
    response.snapshot["scans"]![0]!["retained_source_digests_json"],
  ).toBeNull();
});

test("stored NaN warnings deduplicate and an unchanged singleton skips the clock", () => {
  for (const repeated of [false, true]) {
    const input = request(root(`nan-${repeated}`));
    input.scan!["completion_warnings_json"] = repeated ? "[NaN,NaN]" : "[NaN]";
    const response = run(input);
    success(response);
    expect(response.outcomes[0]!.result).toBe(false);
    expect(response.snapshot["scans"]![0]!["completion_warnings_json"]).toBe(
      "[NaN]",
    );
    expect(
      response.outcomes[0]!.events.some(
        (event) => (event as unknown[])[0] === "now",
      ),
    ).toBe(repeated);
  }
});

test("binary failure messages preserve empty values and byte diagnostics", () => {
  const textScan = root("empty-text"),
    binaryScan = root("empty-binary");
  for (const scan of [textScan, binaryScan]) {
    checkpoint(scan);
    const input = request(scan);
    input.setupSql!.push(
      `UPDATE scans SET failure_message=${scan === textScan ? "''" : "x''"}`,
    );
    const response = run(input);
    success(response);
    expect(response.outcomes[0]!.result).toBe(true);
  }
  expect(published(binaryScan)).toEqual(published(textScan));
  const bytesScan = root("failure-bytes"),
    input = request(bytesScan);
  checkpoint(bytesScan);
  input.setupSql!.push("UPDATE scans SET failure_message=x'000a7fff'");
  const response = run(input);
  success(response);
  expect(response.outcomes[0]!.result).toBe(true);
  const coverage = JSON.parse(
    readFileSync(join(bytesScan, "coverage.json"), "utf8"),
  ) as { deferred: { id: string; reason: string }[] };
  expect(
    coverage.deferred.find((item) => item.id === "scan-stopped")?.reason,
  ).toEndWith("b'\\x00\\n\\x7f\\xff'");
});

test("explicit recovery bypasses malformed stored source JSON", () => {
  const scan = root("recovery"),
    input = request(scan, [
      { operation: "preserve", preserveOptions: { recoverySourceDigests: {} } },
    ]);
  input.scan!["retained_source_digests_json"] = "{";
  const response = run(input);
  success(response);
  expect(response.outcomes[0]!.result).toBe(false);
});

test("comparison requires a recorded seal and matching scan identity", () => {
  const scan = root("compare");
  checkpoint(scan);
  const first = run(request(scan));
  success(first);
  const pin = first.snapshot["scans"]![0]!["seal_manifest_digest"] as string;
  const input = request(scan, [
    { operation: "compareCoverage" },
    {
      operation: "compareCoverage",
      row: { id: "another", scan_dir: scan, seal_manifest_digest: pin },
    },
  ]);
  const response = run(input);
  expect(response.outcomes.map((outcome) => outcome.error)).toEqual([
    "Only sealed scans can be compared.",
    "Only sealed scans can be compared.",
  ]);
  expect(response.outcomes.every((outcome) => outcome.systemExit)).toBe(true);
});

test("snapshots and restores byte-exact output contents and removes newly created files", () => {
  const scan = root("bytes"),
    bytes = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
  write(scan, "findings.json", bytes);
  write(scan, "coverage.json", Buffer.from("remove"));
  const response = run(
    request(scan, [
      { operation: "snapshotOutputs", directory: scan },
      {
        operation: "restoreOutputs",
        directory: scan,
        snapshots: {
          "findings.json": bytes.toString("hex"),
          "coverage.json": null,
          "report.md": "",
        },
      },
    ]),
  );
  success(response);
  expect(
    (response.outcomes[0]!.result as Record<string, unknown>)["findings.json"],
  ).toBe(bytes.toString("hex"));
  expect(readFileSync(join(scan, "findings.json"))).toEqual(bytes);
  expect(existsSync(join(scan, "coverage.json"))).toBe(false);
  expect(readFileSync(join(scan, "report.md"))).toHaveLength(0);
});

test("snapshots reject directory links and preserve their destination", () => {
  const scan = root("link"),
    outside = root("outside");
  write(outside, "results.sarif", Buffer.from("outside"));
  symlinkSync(
    outside,
    join(scan, "exports"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const response = run(
    request(scan, [{ operation: "snapshotOutputs", directory: scan }]),
  );
  expect(response.outcomes[0]!.error).toBeDefined();
  expect(readFileSync(join(outside, "results.sarif"), "utf8")).toBe("outside");
});
