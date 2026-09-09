import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
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
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-deep-start-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const scanId = "11111111-1111-4111-8111-111111111111",
  workspaceId = "22222222-2222-4222-8222-222222222222";
const root = realpathSync(mkdtempSync(join(tmpdir(), "deep-start-"))),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-deep-start-fixture.ts", import.meta.url),
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
function setup(actions: Action[] = [{ operation: "begin" }]): Request {
  const directory = mkdtempSync(join(root, "case-")),
    target = join(directory, "target");
  mkdirSync(target);
  writeFileSync(join(target, "file.ts"), "export const value = 1;\n");
  return {
    environment: {
      CODEX_SECURITY_STATE_DIR: join(directory, "state"),
      CODEX_HOME: join(directory, "codex"),
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: join(directory, "config.toml"),
    },
    target,
    scanRoot: join(directory, "outputs"),
    workspace: null,
    actions,
  };
}
function existing(request: Request): void {
  const scanDir = join(request.target, "..", "saved");
  mkdirSync(scanDir, { mode: 0o700 });
  request.workspace = { thread_id: null, active_scan_id: scanId };
  request.records = {
    scans: [
      {
        id: scanId,
        workspace_id: workspaceId,
        target_path: request.target,
        target_revision: "unversioned",
        scope: ".",
        mode: "deep",
        scan_dir: scanDir,
        status: "running",
        phase: "preflight",
        handoff_status: "delivered",
        recipe_json: '{"mode":"deep"}',
        started_at: "2026-01-01T00:00:00Z",
        created_at: "created",
        updated_at: "scan-updated",
      },
    ],
  };
  for (const action of request.actions)
    action.args = { scanId, ...action.args };
}
function run(request: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return (parseJson(child.stdout) as unknown as Response[])[0]!;
}
const success = (response: Response, index = 0) =>
  expect(response.outcomes[index]!.error).toBeUndefined();
const firstScan = (response: Response) => response.snapshot["scans"]![0]!;

test("Deep startup records one workspace, private artifact directory, snapshot and configuration", () => {
  const request = setup(),
    response = run(request);
  success(response);
  expect(response.outcomes[0]!.result).toMatchObject({
    startDisposition: "created",
    deepScan: {
      status: "running",
      phase: "setup",
      config: { workers: 4n, subagents: 3n },
    },
  });
  expect(response.snapshot["workspaces"]!.length).toBe(1);
  expect(response.snapshot["scans"]!.length).toBe(1);
  expect(response.snapshot["security_targets"]!.length).toBe(1);
  expect(firstScan(response)).toMatchObject({
    target_path: request.target,
    deep_scan_owner_thread_id: "owner",
    handoff_status: "delivered",
    mode: "deep",
    phase: "preflight",
  });
  expect(firstScan(response)["target_snapshot_digest"]).toMatch(
    /^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/u,
  );
  expect(response.snapshot["scan_progress"]![0]!["scope_file_count"]).toBe(1n);
  if (process.platform !== "win32")
    expect(
      statSync(firstScan(response)["scan_dir"] as string).mode & 0o777,
    ).toBe(0o700);
  expect(response.outcomes[0]!.inTransaction).toBe(false);
});

test("a delivered CLI scan is adopted atomically and repeated startup joins its run", () => {
  const request = setup([
    { operation: "begin" },
    { operation: "begin", args: { model: "model-b", reasoningEffort: "high" } },
    { operation: "get" },
  ]);
  existing(request);
  const response = run(request);
  response.outcomes.forEach((_, index) => success(response, index));
  expect(response.outcomes[0]!.result).toMatchObject({
    startDisposition: "created",
  });
  expect(response.outcomes[1]!.result).toMatchObject({
    startDisposition: "joined",
  });
  expect(response.snapshot["workspaces"]![0]!["thread_id"]).toBe("owner");
  expect(firstScan(response)).toMatchObject({
    deep_scan_owner_thread_id: "owner",
    model: "model-b",
    reasoning_effort: "high",
  });
  expect(response.snapshot["deep_scan_runs"]!.length).toBe(1);
});

test("ownership, continuation and setup conflicts fail before creating orchestration state", () => {
  for (const kind of ["thread", "claim", "scope", "context"] as const) {
    const request = setup();
    existing(request);
    if (kind === "thread") request.workspace!["thread_id"] = "another-owner";
    if (kind === "claim")
      request.records!["scans"]![0]!["handoff_claim_token"] = "another-claim";
    if (kind === "scope") request.actions[0]!.args!["scope"] = "src";
    if (kind === "context")
      request.actions[0]!.args!["userContext"] = "context";
    const response = run(request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(response.snapshot["deep_scan_runs"]).toEqual([]);
    expect(firstScan(response)["deep_scan_owner_thread_id"]).toBeNull();
  }
});

test("an ownership race rolls back both sides of CLI adoption", () => {
  const request = setup();
  existing(request);
  request.setupSql = [
    "CREATE TRIGGER ignored BEFORE UPDATE OF deep_scan_owner_thread_id ON scans BEGIN SELECT RAISE(IGNORE); END",
  ];
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe(
    "A scan can only be orchestrated from its owning Codex thread.",
  );
  expect(response.snapshot["workspaces"]![0]!["thread_id"]).toBeNull();
  expect(firstScan(response)["deep_scan_owner_thread_id"]).toBeNull();
  expect(response.outcomes[0]!.inTransaction).toBe(false);
});

test("model updates remain committed if a later workflow validation fails", () => {
  const request = setup([
    { operation: "begin", args: { model: "model-b", workflowVersion: null } },
  ]);
  existing(request);
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe("workflow-version is required.");
  expect(firstScan(response)["model"]).toBe("model-b");
  expect(firstScan(response)["deep_scan_owner_thread_id"]).toBe("owner");
  expect(response.snapshot["deep_scan_runs"]).toEqual([]);
});

test("target replacement during startup is rejected before database inserts", () => {
  const request = setup();
  request.actions[0]!.beforeBeginReplace = request.target;
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe(
    "The selected scan target changed while the scan was starting. Try again.",
  );
  expect(response.snapshot["scans"]).toEqual([]);
  expect(response.snapshot["workspaces"]).toEqual([]);
  expect(response.outcomes[0]!.inTransaction).toBe(false);
  expect(
    readFileSync(join(request.target + ".old", "file.ts"), "utf8"),
  ).toContain("value = 1");
});

test("repeated target startup reuses the same run and saves per-user Deep configuration", () => {
  const request = setup([{ operation: "begin" }, { operation: "begin" }]);
  writeFileSync(
    request.environment["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]!,
    "[deep_scan]\nworkers = 2\nsubagents = 0\nmax_time_hours = 2.5\n",
  );
  const response = run(request);
  success(response);
  success(response, 1);
  expect(response.outcomes[1]!.result).toMatchObject({
    startDisposition: "joined",
  });
  expect(response.snapshot["deep_scan_runs"]!.length).toBe(1);
  expect(response.snapshot["deep_scan_runs"]![0]).toMatchObject({
    workers: 2n,
    subagents: 0n,
  });
  expect(response.snapshot["scans"]!.length).toBe(1);
});

test("target startup keeps artifacts outside the repository and honors stdin context", () => {
  const invalid = setup();
  invalid.scanRoot = invalid.target;
  const rejected = run(invalid);
  expect(rejected.outcomes[0]!.error).toBe(
    "The scan artifact directory must be outside the selected target.",
  );
  expect(rejected.snapshot["scans"]).toEqual([]);
  const request = setup([
      {
        operation: "begin",
        args: { userContextStdin: true },
        stdin: "  inspect the entry point  ",
      },
    ]),
    response = run(request);
  success(response);
  expect(firstScan(response)["user_context"]).toBe("inspect the entry point");
  expect(
    response.outcomes[0]!.events.some((event) => event[0] === "stdin"),
  ).toBe(true);
});

test("invalid Deep configuration retains the command error category before creating rows", () => {
  const request = setup();
  writeFileSync(
    request.environment["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]!,
    "[deep_scan]\nworkers = 0\n",
  );
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe(
    "deep_scan.workers must be a positive integer.",
  );
  expect(response.outcomes[0]!.systemExit).toBe(true);
  expect(response.snapshot["scans"]).toEqual([]);
  expect(response.outcomes[0]!.inTransaction).toBe(false);
});
