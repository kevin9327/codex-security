import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Operation, Request } from "./support/navigation-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-result-commands-")),
);
const target = join(root, "target"),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const workspace = "11111111-1111-4111-8111-111111111111",
  scan = "22222222-2222-4222-8222-222222222222";
const environment = { ...process.env, PATH: "", PYTHON: "/unavailable/python" };
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() => {
  mkdirSync(target);
  writeFileSync(join(target, "source.txt"), "synthetic source\n");
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
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
const sql = (sql: string, ...parameters: string[]): Operation => ({
  sql,
  parameters,
});
function execute(
  operations: Operation[],
  database: string,
): { value?: Record<string, unknown>; error?: string }[] {
  const request: Request = { initialize: true, operations };
  const child = spawnSync(node, [fixture, database], {
    input: stringifyJson(request),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const results = JSON.parse(child.stdout) as {
    value?: Record<string, unknown>;
    error?: string;
  }[];
  for (const [index, operation] of operations.entries())
    if ("sql" in operation) expect(results[index]!.error).toBeUndefined();
  return results;
}
function seed() {
  const state = mkdtempSync(join(root, "state-")),
    database = join(state, "workbench.sqlite3");
  const operations: Operation[] = [
    sql(
      "INSERT INTO security_targets(id,current_path,display_name,created_at,updated_at) VALUES ('target-id',?,'target','created','updated')",
      target,
    ),
    sql(
      "INSERT INTO workspaces(id,thread_id,target_path,target_id,default_scope,default_mode,created_at,updated_at) VALUES (?,'owner',?,'target-id','.','standard','created','workspace-updated')",
      workspace,
      target,
    ),
    sql(
      "INSERT INTO scans(id,workspace_id,target_path,target_id,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES (?,?,?,'target-id','unversioned','.','standard',?,'complete','reporting','started','created','scan-updated')",
      scan,
      workspace,
      target,
      join(state, "absent-scan"),
    ),
    sql(
      "INSERT INTO scan_progress(scan_id,updated_at) VALUES (?,'progress-updated')",
      scan,
    ),
    sql("UPDATE workspaces SET active_scan_id=? WHERE id=?", scan, workspace),
  ];
  for (let index = 0; index < 25; index++) {
    operations.push(
      sql(
        "INSERT INTO findings(id,fingerprint,rule_id,identity_anchor,created_at,updated_at) VALUES (?,?, 'synthetic-rule',?,'created','updated')",
        `finding-${index}`,
        `fingerprint-${index}`,
        `anchor-${index}`,
      ),
      sql(
        "INSERT INTO finding_occurrences(id,finding_id,scan_id,title,summary,severity,confidence,remediation,details_json,created_at) VALUES (?,?,?,?,'summary',?,'high','remediation','{\"ruleId\":\"synthetic-rule\"}','created')",
        `occurrence-${index}`,
        `finding-${index}`,
        scan,
        `Finding ${index}`,
        index % 2 ? "low" : "high",
      ),
    );
  }
  operations.push(
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,close_reason,note,updated_at) VALUES ('occurrence-1','closed','false_positive','reviewed','triage-updated')",
    ),
    sql("COMMIT"),
  );
  execute(operations, database);
  return { state, database };
}
function helper(args: string[], state: string) {
  return spawnSync(node, [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args], {
    encoding: "utf8",
    env: { ...environment, CODEX_SECURITY_STATE_DIR: state },
  });
}
function result(args: string[], state: string): Record<string, unknown> {
  const child = helper(args, state);
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Record<string, unknown>;
}

test("target and setup inspection work without Python or creating a state directory", () => {
  const state = join(root, "unused-state");
  const inspected = result(["inspect-target", "--target-path", target], state);
  expect(inspected).toMatchObject({
    targetPath: target,
    displayName: "target",
    targetMetadata: { isGit: false },
  });
  const setup = result(
    [
      "inspect-setup",
      "--target-path",
      target,
      "--scope",
      ".",
      "--mode",
      "standard",
    ],
    state,
  );
  expect(setup).toMatchObject({
    scope: ".",
    diffTarget: null,
    target: inspected,
  });
  expect(existsSync(state)).toBe(false);
});

test("scan and workspace commands assemble actual finding results and enforce thread ownership", () => {
  const { state } = seed();
  const context = result(["get-scan", "--scan-id", scan], state),
    current = context["scan"] as Record<string, unknown>;
  expect(current).toMatchObject({
    scanId: scan,
    findingCount: 25,
    findingsTruncated: true,
  });
  expect(current["findings"]).toHaveLength(20);
  const workspaceResult = result(
    ["get-workspace", "--workspace-id", workspace, "--thread-id", " owner "],
    state,
  );
  expect(workspaceResult["results"]).toEqual(current);
  const selected = result(
    ["get-scan", "--scan-id", scan, "--occurrence-id", "occurrence-23"],
    state,
  )["scan"] as Record<string, unknown>;
  expect(
    (selected["findings"] as Record<string, unknown>[]).some(
      (finding) => finding["occurrenceId"] === "occurrence-23",
    ),
  ).toBe(true);
  const rejected = helper(
    ["get-workspace", "--workspace-id", workspace, "--thread-id", "other"],
    state,
  );
  expect(rejected.status).toBe(1);
  expect(rejected.stdout).toBe("");
  expect(rejected.stderr).toBe(
    "Codex Security workspace not found in this thread.\n",
  );
});

test("finding pages retain default limits, filtering, offsets and argument validation", () => {
  const { state } = seed();
  const page = result(
    ["list-findings", "--scan-id", scan, "--limit", "100"],
    state,
  )["findingsPage"] as Record<string, unknown>;
  expect(page).toMatchObject({ total: 25, limit: 20, nextOffset: 20 });
  expect(page["findings"]).toHaveLength(20);
  const closed = result(
    ["list-findings", "--scan-id", scan, "--status", "closed"],
    state,
  )["findingsPage"] as Record<string, unknown>;
  expect(closed).toMatchObject({
    total: 1,
    offset: 0,
    limit: 20,
    nextOffset: null,
  });
  expect((closed["findings"] as Record<string, unknown>[])[0]).toMatchObject({
    occurrenceId: "occurrence-1",
    triage: { status: "closed" },
  });
  const empty = result(
    ["list-findings", "--scan-id", scan, "--offset", "999"],
    state,
  )["findingsPage"] as Record<string, unknown>;
  expect(empty).toMatchObject({ findings: [], total: 25, nextOffset: null });
  expect(
    helper(["list-findings", "--scan-id", scan, "--limit", "0"], state).status,
  ).toBe(2);
  expect(helper(["inspect-setup", "--help"], state).stdout).toContain(
    "{working_tree,commit,range}",
  );
});

test.skipIf(Number(nodeVersion.split(".")[0]) < 22)(
  "SDK Workbench dispatch uses the typed runtime for all five commands",
  () => {
    const { state, database } = seed();
    const commands = [
      ["inspect-target", "--target-path", target],
      [
        "inspect-setup",
        "--target-path",
        target,
        "--scope",
        ".",
        "--mode",
        "standard",
      ],
      ["get-workspace", "--workspace-id", workspace],
      ["get-scan", "--scan-id", scan],
      ["list-findings", "--scan-id", scan],
    ];
    const responses = execute(
      commands.map((sdk) => ({
        sdk,
        pluginRoot: PLUGIN_ROOT,
        stateDir: state,
      })),
      database,
    );
    for (const [index, response] of responses.entries()) {
      expect(response.error).toBeUndefined();
      expect(response.value).toEqual(result(commands[index]!, state));
    }
  },
);
