import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
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
} from "./support/workbench-scan-kickoff-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "scan-kickoff-"))),
  fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const environment = {
  ...process.env,
  PYTHON: "/unavailable/python",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_AUTHOR_NAME: "Fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.test",
  GIT_COMMITTER_NAME: "Fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.test",
};
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-scan-kickoff-fixture.ts", import.meta.url),
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
function setup(actions: Action[] = [{ operation: "start" }]): Request {
  const root = mkdtempSync(join(directory, "case-")),
    target = join(root, "target"),
    scanRoot = join(root, "outputs");
  mkdirSync(target);
  mkdirSync(join(target, "src"));
  writeFileSync(join(target, "file.txt"), "first\n");
  writeFileSync(join(target, "src", "app.py"), "content\n");
  return { target, scanRoot, actions };
}
function run(input: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([input]),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: {
      ...environment,
      CODEX_SECURITY_STATE_DIR: join(input.scanRoot, "state"),
    },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const response = (parseJson(child.stdout) as unknown as Response[])[0]!;
  expect(response.node).toBe(nodeVersion);
  return response;
}
function git(target: string, ...args: string[]): string {
  const child = spawnSync(
    "git",
    [
      "-c",
      "core.hooksPath=" + (process.platform === "win32" ? "NUL" : "/dev/null"),
      "-C",
      target,
      ...args,
    ],
    { env: environment, encoding: "utf8" },
  );
  expect(child.status, child.stderr).toBe(0);
  return child.stdout.trim();
}
const row = (response: Response, table = "scans") =>
  response.snapshot[table]![0]!;
const sql = (value: string): Action => ({ operation: "sql", sql: value });
const commits = (response: Response, index: number) =>
  response.outcomes[index]!.events.filter(
    (event) => event[0] === "transaction" && event[1] === "COMMIT",
  );

test("workspace starts create bound records and private artifact directories, then join without another clock", () => {
  const input = setup([
    { operation: "start", args: { model: "model", reasoningEffort: "high" } },
    { operation: "start", args: { model: "x".repeat(201) }, failNow: 1 },
  ]);
  const response = run(input);
  expect(
    response.outcomes.every((outcome) => outcome.error === undefined),
  ).toBe(true);
  expect(response.snapshot["scans"]).toHaveLength(1);
  expect(row(response)["status"]).toBe("running");
  expect(row(response)["handoff_status"]).toBe("pending");
  expect(row(response)["target_revision"]).toBe("unversioned");
  expect(row(response)["target_snapshot_digest"]).toStartWith(
    "codex-security-snapshot/v1:sha256:",
  );
  expect(row(response)["model"]).toBe("model");
  expect(row(response, "scan_progress")["scope_file_count"]).toBe(2n);
  expect(row(response, "workspaces")["active_scan_id"]).toBe(
    row(response)["id"],
  );
  const scanDir = row(response)["scan_dir"] as string;
  expect(statSync(scanDir).isDirectory()).toBe(true);
  if (process.platform !== "win32")
    expect(statSync(scanDir).mode & 0o777).toBe(0o700);
  expect(
    response.outcomes[1]!.events.some(
      (event) => event[0] === "now" || event[0] === "uuid",
    ),
  ).toBe(false);
  expect(response.outcomes[0]!.inTransaction).toBe(false);
});

test("prompt and headless starts record the original ownership and join matching scans", () => {
  for (const operation of ["prompt", "headless"] as const) {
    const input = setup([
      { operation },
      { operation, args: { model: "x".repeat(201) } },
    ]);
    const response = run(input);
    expect(
      response.outcomes.every((outcome) => outcome.error === undefined),
    ).toBe(true);
    expect(
      response.outcomes.map(
        (outcome) =>
          (outcome.result as { startDisposition: string }).startDisposition,
      ),
    ).toEqual(["created", "joined"]);
    expect(response.snapshot["scans"]).toHaveLength(1);
    expect(row(response)["handoff_status"]).toBe("delivered");
    expect(row(response)["continuation_thread_id"]).toBe(
      operation === "headless" ? "owner" : null,
    );
    if (operation === "headless")
      expect(row(response)["handoff_claim_token"]).toMatch(/^[0-9a-f-]{36}$/);
    else expect(row(response)["handoff_claim_token"]).toBeNull();
    expect(response.snapshot["security_targets"]).toHaveLength(1);
    expect(commits(response, 1)).toHaveLength(1);
  }
});

test("workspace start respects a caller transaction while prompt starts preserve a failed BEGIN", () => {
  for (const operation of ["start", "prompt", "headless"] as const) {
    const input = setup([
      sql("UPDATE workspaces SET updated_at='caller'"),
      { operation },
      { operation: "rollback" },
    ]);
    const response = run(input);
    expect(response.outcomes[1]!.inTransaction).toBe(true);
    expect(commits(response, 1)).toEqual([]);
    expect(response.outcomes[1]!.error).toBe(
      operation === "start"
        ? undefined
        : "cannot start a transaction within a transaction",
    );
    expect(response.snapshot["scans"]).toEqual([]);
    expect(row(response, "workspaces")["updated_at"]).toBe("workspace-updated");
  }
});

test("workspace versions are rechecked after BEGIN and equal stored BLOB versions remain equal", () => {
  const changed = setup([
    {
      operation: "start",
      beforeBeginSql: "UPDATE workspaces SET updated_at='changed'",
    },
  ]);
  const rejected = run(changed);
  expect(rejected.outcomes[0]!.error).toBe(
    "Codex Security setup changed while the scan was starting. Try again.",
  );
  expect(rejected.snapshot["scans"]).toEqual([]);
  const unchanged = setup();
  unchanged.setupSql = ["UPDATE workspaces SET updated_at=x'76657273696f6e'"];
  const response = run(unchanged);
  expect(response.outcomes[0]!.error).toBeUndefined();
  expect(response.snapshot["scans"]).toHaveLength(1);
});

test("target replacement during startup is rejected before scan insertion", () => {
  for (const operation of ["start", "prompt", "headless"] as const) {
    const input = setup([{ operation }]);
    input.actions[0]!.beforeBeginReplace = input.target;
    const response = run(input);
    expect(response.outcomes[0]!.error).toBe(
      "The selected scan target changed while the scan was starting. Try again.",
    );
    expect(response.snapshot["scans"]).toEqual([]);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(readFileSync(join(input.target + ".old", "file.txt"), "utf8")).toBe(
      "first\n",
    );
  }
});

test("prompt startup rechecks content while workspace startup retains its identity-only check", () => {
  for (const operation of ["start", "prompt"] as const) {
    const input = setup([{ operation }]);
    input.actions[0]!.beforeBeginWrite = {
      path: join(input.target, "file.txt"),
      text: "changed\n",
    };
    const response = run(input);
    expect(response.outcomes[0]!.error).toBe(
      operation === "start"
        ? undefined
        : "The selected scan target changed while the scan was starting. Try again.",
    );
    expect(response.snapshot["scans"]).toHaveLength(
      operation === "start" ? 1 : 0,
    );
  }
});

test("failed insertion rolls back records and leaves the already-created artifact directory", () => {
  for (const operation of ["start", "prompt", "headless"] as const) {
    const input = setup([{ operation }]);
    input.setupSql = [
      "CREATE TRIGGER reject BEFORE INSERT ON scans BEGIN SELECT RAISE(ABORT,'insert rejected'); END",
    ];
    const response = run(input);
    expect(response.outcomes[0]!.error).toBe("insert rejected");
    expect(response.snapshot["scans"]).toEqual([]);
    expect(response.snapshot["scan_progress"]).toEqual([]);
    expect(response.snapshot["workspaces"]).toHaveLength(1);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(readdirSync(join(input.scanRoot, "target"))).toHaveLength(1);
  }
});

test("projection failure after commit retains the created scan and progress", () => {
  const input = setup();
  input.setupSql = [
    "CREATE TRIGGER malformed AFTER INSERT ON scan_progress BEGIN UPDATE scan_progress SET preflight_issues_json='{'; END",
  ];
  const response = run(input);
  expect(response.outcomes[0]!.error).toBeDefined();
  expect(response.snapshot["scans"]).toHaveLength(1);
  expect(response.snapshot["scan_progress"]).toHaveLength(1);
  expect(response.outcomes[0]!.inTransaction).toBe(false);
});

test("a deep workspace refuses an existing scan owned by the same thread", () => {
  for (const owner of ["owner", "another"]) {
    const input = setup([
      { operation: "prompt", args: { mode: "deep" } },
      { operation: "start" },
    ]);
    input.workspace = { default_mode: "deep", thread_id: owner };
    const response = run(input);
    expect(response.outcomes[0]!.error).toBeUndefined();
    if (owner === "owner")
      expect(response.outcomes[1]!.error).toContain(
        "already has an active Deep Scan",
      );
    else expect(response.outcomes[1]!.error).toBeUndefined();
    expect(response.snapshot["scans"]).toHaveLength(owner === "owner" ? 1 : 2);
  }
});

test("prompt join retains the original canceled-running predicate and creates for changed context", () => {
  const input = setup([
    { operation: "prompt" },
    sql("UPDATE scans SET canceled_at='canceled'"),
    { operation: "commit" },
    { operation: "prompt" },
    { operation: "prompt", args: { userContext: "changed" } },
  ]);
  const response = run(input);
  expect(
    response.outcomes.every((outcome) => outcome.error === undefined),
  ).toBe(true);
  expect(
    (response.outcomes[3]!.result as { startDisposition: string })
      .startDisposition,
  ).toBe("joined");
  expect(
    (response.outcomes[4]!.result as { startDisposition: string })
      .startDisposition,
  ).toBe("created");
  expect(response.snapshot["scans"]).toHaveLength(2);
});

test("headless claim failure rolls back the new workspace and scan", () => {
  const input = setup([{ operation: "headless" }]);
  input.setupSql = [
    "CREATE TRIGGER skip BEFORE UPDATE OF handoff_claim_token ON scans BEGIN SELECT RAISE(IGNORE); END",
  ];
  const response = run(input);
  expect(response.outcomes[0]!.error).toBe(
    "Codex Security headless scan ownership could not be recorded.",
  );
  expect(response.snapshot["scans"]).toEqual([]);
  expect(response.snapshot["workspaces"]).toHaveLength(1);
  expect(response.snapshot["security_targets"]).toEqual([]);
});

test("Git diff startup preserves validated revisions and joins the same change set", () => {
  const input = setup();
  git(input.target, "init", "-q", "-b", "main");
  git(input.target, "config", "core.autocrlf", "false");
  git(input.target, "add", ".");
  git(input.target, "commit", "-qm", "Initial fixture");
  const head = git(input.target, "rev-parse", "HEAD");
  writeFileSync(join(input.target, "file.txt"), "changed\n");
  const args = { mode: "diff", diffTargetKind: "working_tree" };
  input.actions = [
    { operation: "headless", args },
    { operation: "headless", args },
  ];
  const response = run(input);
  expect(
    response.outcomes.every((outcome) => outcome.error === undefined),
  ).toBe(true);
  expect(row(response)["target_revision"]).toBe(head);
  expect(row(response)["target_snapshot_digest"]).toBeNull();
  expect(row(response)["diff_target_kind"]).toBe("working_tree");
  expect(row(response)["diff_content_digest"]).toStartWith(
    "codex-security-snapshot/v1:sha256:",
  );
  expect(
    (response.outcomes[1]!.result as { startDisposition: string })
      .startDisposition,
  ).toBe("joined");
});

test("artifact roots use the default segment for targets without a name", () => {
  const input = setup(
    ["", ".", "./"].map((targetPath) => ({
      operation: "root",
      args: { targetPath },
    })),
  );
  const response = run(input);
  expect(response.outcomes.map((outcome) => outcome.result)).toEqual(
    Array(3).fill(join(input.scanRoot, "scan")),
  );
});

test("artifact roots inside the target fail before any scan files are created", () => {
  const input = setup([{ operation: "start" }]);
  input.actions[0]!.args = { scanRoot: input.target };
  const response = run(input);
  expect(response.outcomes[0]!.error).toBe(
    "The scan artifact directory must be outside the selected target.",
  );
  expect(response.snapshot["scans"]).toEqual([]);
  expect(existsSync(join(input.target, "target"))).toBe(false);
});

test("artifact root symlink loops retain the setup owner's diagnostic", () => {
  const input = setup([{ operation: "start" }]);
  const loop = join(input.target, "loop");
  symlinkSync(loop, loop, "file");
  input.actions[0]!.args = { scanRoot: loop };
  const error = run(input).outcomes[0]!.error;
  expect(error).toContain("Symlink loop from ");
  expect(error).toContain(loop);
  if (process.platform !== "win32")
    expect(error).toBe(`Symlink loop from '${loop}'`);
});
