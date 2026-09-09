import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Operation, Request } from "./support/navigation-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = mkdtempSync(join(tmpdir(), "workbench-feedback-"));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const workspace = "11111111-1111-4111-8111-111111111111";
const source = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const current = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const environment = { ...process.env, PATH: "", PYTHON: "/missing/python" };
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/navigation-fixture.ts", import.meta.url),
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
  value: Record<string, unknown> | string;
  error?: string;
  inTransaction: boolean;
};
function run(operations: Operation[], database = ":memory:"): Result[] {
  const request: Request = { initialize: true, operations };
  const result = spawnSync(node, [fixture, database], {
    input: stringifyJson(request),
    encoding: "utf8",
    env: environment,
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  const results = JSON.parse(result.stdout) as Result[];
  for (const [index, operation] of operations.entries()) {
    if ("sql" in operation) expect(results[index]!.error).toBeUndefined();
  }
  return results;
}
const sql = (sql: string, ...parameters: string[]): Operation => ({
  sql,
  parameters,
});
function seed(): Operation[] {
  return [
    sql(
      "INSERT INTO security_targets(id,current_path,display_name,created_at,updated_at) VALUES('target','/target','target','before','before')",
    ),
    sql(
      "INSERT INTO workspaces(id,target_id,target_path,created_at,updated_at) VALUES(?,'target','/target','before','before')",
      workspace,
    ),
    ...[source, current].map((id) =>
      sql(
        "INSERT INTO scans(id,workspace_id,target_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,completed_at,created_at,updated_at) VALUES(?,?,'target','/target','revision','.','standard',?,'complete','reporting','before','after','before','after')",
        id,
        workspace,
        `/scan/${id}`,
      ),
    ),
    sql(
      "INSERT INTO findings(id,fingerprint,rule_id,identity_anchor,created_at,updated_at) VALUES('finding','fingerprint','rule','anchor','before','after')",
    ),
    sql(
      "INSERT INTO finding_occurrences(id,finding_id,scan_id,title,summary,severity,confidence,remediation,created_at) VALUES('occurrence','finding',?,'Title','Summary','high','high','Fix','after')",
      source,
    ),
    sql(
      "INSERT INTO finding_locations(occurrence_id,relative_path,start_line,end_line,role,sort_order) VALUES('occurrence','src/main.ts',4,5,'root_control',0)",
    ),
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,close_reason,note,updated_at) VALUES('occurrence','closed','false_positive','Intentional behavior','after')",
    ),
    sql("COMMIT"),
  ];
}
test("shared lookups preserve canonical UUIDs, prefixes and missing-row errors", () => {
  const results = run([
    ...seed(),
    { snapshot: true },
    { lookup: "workspace", id: `urn:uuid:${workspace}` },
    { lookup: "scan", id: "AAAAAAAA" },
    { lookup: "resolve", id: `{${current.toUpperCase()}}` },
    { lookup: "scan", id: "short" },
    { lookup: "scan", id: "cccccccc" },
    { lookup: "workspace", id: current },
    { snapshot: true },
    sql(
      "INSERT INTO scans(id,workspace_id,target_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab',?,'target','/target','revision','.','standard','/scan/ambiguous','complete','reporting','before','before','after')",
      workspace,
    ),
    { lookup: "scan", id: "aaaaaaaa" },
  ]).slice(-10);
  expect(results[1]!.value).toMatchObject({ id: workspace });
  expect(results[2]!.value).toMatchObject({ id: source });
  expect(results[3]!.value).toBe(current);
  expect(results[4]!.error).toBe(
    "Scan ID prefixes must be at least eight characters.",
  );
  expect(results[5]!.error).toBe("Codex Security scan not found.");
  expect(results[6]!.error).toBe(
    "Codex Security workspace not found. Reopen it to continue.",
  );
  expect(results[0]!.value).toEqual(results[7]!.value);
  expect(results[8]!.error).toBeUndefined();
  expect(results[9]!.error).toBe(
    'Scan ID prefix "aaaaaaaa" matches multiple scans; use a longer prefix.',
  );
  expect(results.slice(0, 8).every((result) => !result.inTransaction)).toBe(
    true,
  );
  expect(results[9]!.inTransaction).toBe(true);
});
test("the SDK and helper return feedback without Python and leave scan rows intact", () => {
  const state = join(root, "state");
  mkdirSync(state);
  const results = run(
    [
      ...seed(),
      { snapshot: true },
      {
        sdk: ["get-scan-feedback", "--scan-id", "BBBBBBBB"],
        pluginRoot: PLUGIN_ROOT,
        stateDir: state,
      },
      { snapshot: true },
    ],
    join(state, "workbench.sqlite3"),
  ).slice(-3);
  expect(results[1]!.error).toBeUndefined();
  expect(results[1]!.value).toMatchObject({
    scanId: current,
    targetId: "target",
    falsePositives: [
      {
        findingId: "finding",
        sourceScanId: source,
        reason: "Intentional behavior",
        locations: [{ path: "src/main.ts", startLine: 4, endLine: 5 }],
      },
    ],
  });
  expect(results[0]!.value).toEqual(results[2]!.value);
  const helper = (args: string[]) =>
    spawnSync(
      node,
      [join(PLUGIN_ROOT, "mcp/helpers.mjs"), "get-scan-feedback", ...args],
      {
        encoding: "utf8",
        env: { ...environment, CODEX_SECURITY_STATE_DIR: state },
      },
    );
  const found = helper(["--scan-id", current]);
  expect(found.status, found.stderr).toBe(0);
  expect(found.stderr).toBe("");
  expect(JSON.parse(found.stdout)).toEqual(results[1]!.value);
  const absent = helper(["--scan-id", "cccccccc"]);
  expect(absent.status).toBe(1);
  expect(absent.stdout).toBe("");
  expect(absent.stderr).toBe("Codex Security scan not found.\n");
  expect(helper([]).status).toBe(2);
  expect(helper(["--scan", current]).status).toBe(0);
  expect(helper(["--help"]).status).toBe(0);
});
