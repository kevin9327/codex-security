import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { IndexedFinding } from "../../../plugins/codex-security/mcp-app/src/workbench-finding-index";
import type { Operation } from "./support/imported-findings-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = mkdtempSync(join(tmpdir(), "finding-index-"));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/imported-findings-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(root, { recursive: true, force: true }));
type Result = {
  value?: Record<string, unknown>[];
  error?: string;
  inTransaction: boolean;
};
function run(operations: Operation[]): Result[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson({ initialize: true, operations }),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/missing/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return (JSON.parse(child.stdout) as { results: Result[] }).results;
}
const execute = (sql: string, parameters: string[] = []): Operation => ({
  type: "execute",
  sql,
  parameters,
});
const query = (sql: string): Operation => ({ type: "query", sql });
function seed(): Operation[] {
  return [
    ...["first", "second"].flatMap((id) => [
      execute(
        "INSERT INTO security_targets(id,current_path,display_name,created_at,updated_at) VALUES(?,?,?,'before','before')",
        [id, `/${id}`, id],
      ),
      execute(
        "INSERT INTO workspaces(id,target_id,target_path,created_at,updated_at) VALUES(?,?,?,'before','before')",
        [id, id, `/${id}`],
      ),
      execute(
        "INSERT INTO scans(id,workspace_id,target_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES(?,?,?,?,'revision','.','standard',?,'running','discovery','before','before','before')",
        [id, id, id, `/${id}`, `/scans/${id}`],
      ),
    ]),
    execute("COMMIT"),
  ];
}
function finding(extra: Partial<IndexedFinding> = {}): IndexedFinding {
  return {
    findingId: "finding",
    occurrenceId: "occurrence",
    fingerprints: { primary: "fingerprint" },
    ruleId: "rule",
    identity: { anchor: "anchor" },
    title: "Title",
    summary: "Summary",
    severity: { level: "high" },
    confidence: { level: "high" },
    remediation: "Fix",
    locations: [
      { path: "src/main.ts", startLine: 4, endLine: 8, role: "root_control" },
    ],
    ...extra,
  };
}
const index = (
  findings: unknown[],
  scanId = "first",
  timestamp = "after",
): Operation => ({ type: "index", scanId, timestamp, document: { findings } });
const snapshot = () => [
  query("SELECT * FROM findings ORDER BY id"),
  query("SELECT * FROM finding_occurrences ORDER BY id"),
  query(
    "SELECT occurrence_id,relative_path,start_line,end_line,role,sort_order FROM finding_locations ORDER BY id",
  ),
  query("SELECT * FROM finding_repositories ORDER BY repository_id"),
];

test("scan indexing keeps stored JSON bytes, occurrence identity and repository membership across replacement", () => {
  const first = finding({
    extra: parseJson('{"value":1.0,"large":9007199254740993,"unicode":"😀"}'),
  });
  const changed = finding({
    title: "Changed",
    locations: [{ path: "renamed.ts", startLine: 9 }],
  });
  const results = run([
    ...seed(),
    index([first]),
    query("SELECT details_json FROM findings"),
    execute("COMMIT"),
    index([changed], "second", "later"),
    ...snapshot(),
    execute("COMMIT"),
  ]).slice(-9);
  expect(results.every((result) => !result.error)).toBe(true);
  expect(results[0]!.inTransaction).toBe(true);
  expect(results[1]!.value![0]!["details_json"]).toContain(
    '"extra": {"large": 9007199254740993, "unicode": "\\ud83d\\ude00", "value": 1.0}',
  );
  expect(results[2]!.inTransaction).toBe(false);
  expect(results[3]!.inTransaction).toBe(true);
  expect(results[4]!.value![0]).toMatchObject({
    id: "finding",
    created_at: "after",
    updated_at: "later",
  });
  expect(results[4]!.value![0]!["details_json"]).not.toContain('"extra"');
  expect(results[5]!.value![0]).toMatchObject({
    id: "occurrence",
    scan_id: "second",
    created_at: "after",
    title: "Changed",
  });
  expect(results[6]!.value).toEqual([
    {
      occurrence_id: "occurrence",
      relative_path: "renamed.ts",
      start_line: 9,
      end_line: 9,
      role: null,
      sort_order: 0,
    },
  ]);
  expect(results[7]!.value).toEqual([
    { repository_id: "first", finding_id: "finding" },
    { repository_id: "second", finding_id: "finding" },
  ]);
  expect(results[8]!.inTransaction).toBe(false);
});

test("the caller can inspect and roll back partial indexing after a later entry fails", () => {
  const results = run([
    ...seed(),
    index([finding(), null]),
    ...snapshot(),
    execute("ROLLBACK"),
    ...snapshot(),
    { type: "index", scanId: "first", timestamp: "after", document: {} },
  ]).slice(-11);
  expect(results[0]!.error).toBe("findings.json entries must be objects.");
  expect(results[0]!.inTransaction).toBe(true);
  expect(results[1]!.value).toHaveLength(1);
  expect(results[2]!.value).toHaveLength(1);
  expect(results[3]!.value).toHaveLength(1);
  expect(results[4]!.value).toHaveLength(1);
  expect(results[5]!.inTransaction).toBe(false);
  for (const result of results.slice(6, 10)) expect(result.value).toEqual([]);
  expect(results[10]!.error).toBe(
    "findings.json must contain a findings array.",
  );
  expect(results[10]!.inTransaction).toBe(false);
});

test("missing fields fail at the original write boundary and JSON floats retain SQLite affinity", () => {
  const early: Record<string, unknown> = { ...finding() };
  const late: Record<string, unknown> = { ...finding() };
  delete early["severity"];
  delete late["title"];
  const results = run([
    ...seed(),
    index([early]),
    query("SELECT * FROM findings"),
    index([late]),
    query("SELECT * FROM findings"),
    query("SELECT * FROM finding_occurrences"),
    execute("ROLLBACK"),
    index([
      {
        ...finding(),
        locations: parseJson(
          '[{"path":"numeric.ts","startLine":1.0,"endLine":2.0,"role":1.0}]',
        ),
      },
    ]),
    query("SELECT start_line,end_line,role FROM finding_locations"),
  ]).slice(-8);
  expect(results[0]!.error).toBe("'severity'");
  expect(results[0]!.inTransaction).toBe(false);
  expect(results[1]!.value).toEqual([]);
  expect(results[2]!.error).toBe("'title'");
  expect(results[2]!.inTransaction).toBe(true);
  expect(results[3]!.value).toHaveLength(1);
  expect(results[4]!.value).toEqual([]);
  expect(results[6]!.error).toBeUndefined();
  expect(results[7]!.value).toEqual([
    { start_line: 1, end_line: 2, role: "1.0" },
  ]);
});
