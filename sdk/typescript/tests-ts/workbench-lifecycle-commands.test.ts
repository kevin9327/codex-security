import { randomUUID } from "node:crypto";
import { withWorkbenchDatabase } from "./support/workbench-database";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
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
import { PLUGIN_ROOT } from "./plugin-root";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Operation } from "./support/navigation-fixture";

const root = realpathSync(mkdtempSync(join(tmpdir(), "workbench-lifecycle-")));
const node = Bun.which("node")!,
  fixture = join(root, "fixture.cjs");
const workspace = "11111111-1111-4111-8111-111111111111";
const environment = { ...process.env, PATH: "", PYTHON: "/unavailable/python" };
const nodeMajor = Number(
  spawnSync(node, ["-p", "process.versions.node.split('.')[0]"], {
    encoding: "utf8",
  }).stdout,
);
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
function setup() {
  const directory = mkdtempSync(join(root, "case-")),
    target = join(directory, "target"),
    state = join(directory, "state"),
    scanRoot = join(directory, "outputs");
  mkdirSync(target);
  writeFileSync(join(target, "source.ts"), "synthetic source\n");
  return { directory, target, state, scanRoot };
}
type Setup = ReturnType<typeof setup>;
function helper(args: string[], s: Setup, input?: string | Buffer) {
  return spawnSync(node, [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args], {
    input,
    encoding: "utf8",
    env: {
      ...environment,
      CODEX_SECURITY_STATE_DIR: s.state,
      CODEX_HOME: join(s.directory, "codex"),
      CODEX_SQLITE_HOME: join(s.directory, "sqlite"),
    },
  });
}
function result(
  args: string[],
  s: Setup,
  input?: string,
): Record<string, unknown> {
  const child = helper(args, s, input);
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Record<string, unknown>;
}
function snapshot(s: Setup) {
  const child = spawnSync(node, [fixture, join(s.state, "workbench.sqlite3")], {
    input: stringifyJson({ operations: [{ snapshot: true }] }),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  return (
    JSON.parse(child.stdout) as {
      value: Record<string, Record<string, unknown>[]>;
    }[]
  )[0]!.value;
}
const current = (s: Setup) => snapshot(s)["scans"]![0]!;
const workspaceArgs = (s: Setup) => [
  "--workspace-id",
  workspace,
  "--target-path",
  s.target,
  "--scope",
  ".",
  "--mode",
  "standard",
];
function recipe(s: Setup) {
  return {
    repository: s.target,
    mode: "standard",
    config: {},
    target: { kind: "repository", paths: [] },
  };
}

test("workspace creation, setup and repeated start use the typed helper without Python", () => {
  const s = setup();
  const opened = result(
    ["create-workspace", "--workspace-id", workspace, "--thread-id", "owner"],
    s,
  );
  expect(opened).toMatchObject({
    id: workspace,
    mode: "standard",
    targetPath: null,
    setup: { submitted: false },
  });
  const context = "Review Σ.\r\nKeep this context.";
  expect(
    result(
      ["save-workspace", ...workspaceArgs(s), "--user-context-stdin"],
      s,
      context,
    ),
  ).toMatchObject({
    targetPath: s.target,
    userContext: context,
    setup: { submitted: true },
  });
  const args = [
    "start-scan",
    "--workspace-id",
    workspace,
    "--scan-root",
    s.scanRoot,
    "--model",
    "synthetic-model",
    "--reasoning-effort",
    "high",
  ];
  const started = result(args, s);
  expect(result(args, s)).toEqual(started);
  const scan = current(s);
  expect(scan).toMatchObject({
    status: "running",
    mode: "standard",
    user_context: context,
    model: "synthetic-model",
    reasoning_effort: "high",
    handoff_status: "pending",
  });
  expect(scan["updated_at"]).toMatch(/T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z$/);
  const directory = scan["scan_dir"] as string;
  expect(statSync(directory).isDirectory()).toBe(true);
  if (process.platform !== "win32")
    expect(statSync(directory).mode & 0o777).toBe(0o700);
  const rejected = helper(["save-workspace", ...workspaceArgs(s)], s);
  expect(rejected.status).toBe(1);
  expect(rejected.stderr).toContain("already has a scan");
});

test("prompt and headless starts preserve ownership, context and join behavior", () => {
  for (const command of [
    "start-prompt-only-scan",
    "start-headless-standard-scan",
  ]) {
    const s = setup();
    const args = [
      command,
      "--thread-id",
      "owner",
      "--target-path",
      s.target,
      "--scope",
      ".",
      "--scan-root",
      s.scanRoot,
      "--user-context-stdin",
    ];
    if (command === "start-prompt-only-scan") args.push("--mode", "standard");
    expect(result(args, s, "Review this source.")).toMatchObject({
      startDisposition: "created",
    });
    expect(result(args, s, "Review this source.")).toMatchObject({
      startDisposition: "joined",
    });
    const scan = current(s);
    expect(scan).toMatchObject({
      mode: "standard",
      user_context: "Review this source.",
      handoff_status: "delivered",
      continuation_thread_id:
        command === "start-headless-standard-scan" ? "owner" : null,
    });
  }
});

test("registration accepts each existing recipe transport and persists thread and recipe commands", () => {
  for (const transport of [
    "recipe-json",
    "recipe-json-stdin",
    "registration-json-stdin",
  ]) {
    const s = setup(),
      directory = join(s.directory, "scan");
    mkdirSync(directory, { mode: 0o700 });
    const launch = recipe(s),
      args = [
        "register-cli-scan",
        "--repository",
        s.target,
        "--scan-dir",
        directory,
        `--${transport}`,
      ];
    const json = JSON.stringify(
      transport === "registration-json-stdin"
        ? { recipe: launch, userContext: "context" }
        : launch,
    );
    if (transport === "recipe-json") args.push(json);
    const registered = result(
        args,
        s,
        transport === "recipe-json" ? undefined : json,
      ),
      scanId = registered["scanId"] as string;
    expect(registered).toMatchObject({
      scanDir: directory,
      targetRevision: "unversioned",
      scopeFileCount: 1,
    });
    expect(
      result(
        ["set-scan-thread", "--scan-id", scanId, "--thread-id", "continued"],
        s,
      ),
    ).toEqual({ scanId, threadId: "continued" });
    expect(result(["get-scan-recipe", "--scan-id", scanId], s)).toEqual({
      scanId,
      parentScanId: null,
      recipe: launch,
    });
    expect(current(s)["continuation_thread_id"]).toBe("continued");
    if (transport === "registration-json-stdin")
      expect(current(s)["user_context"]).toBe("context");
  }
});

test("argument validation and help run before database creation", () => {
  const s = setup();
  for (const args of [
    ["create-workspace"],
    ["save-workspace", ...workspaceArgs(s), "--mode", "other"],
    [
      "create-workspace",
      "--workspace-id",
      workspace,
      "--user-context",
      "text",
      "--user-context-stdin",
    ],
    [
      "create-workspace",
      "--workspace-id",
      workspace,
      "--user-context-stdin",
      "--user-context-stdin",
    ],
    ["register-cli-scan", "--scan-dir", s.scanRoot, "--repository", s.target],
    [
      "register-cli-scan",
      "--scan-dir",
      s.scanRoot,
      "--repository",
      s.target,
      "--recipe-json",
      "{}",
      "--recipe-json-stdin",
    ],
    [
      "start-headless-standard-scan",
      "--thread-id",
      "owner",
      "--target-path",
      s.target,
      "--scope",
      ".",
      "--unknown-option",
      "standard",
    ],
  ]) {
    const child = helper(args, s, "context");
    expect(child.status, JSON.stringify(args) + child.stderr).toBe(2);
    expect(child.stdout).toBe("");
  }
  expect(
    helper(
      [
        "register-cli-scan",
        "--scan-dir",
        s.scanRoot,
        "--repository",
        s.target,
        "--unknown",
      ],
      s,
    ).stderr,
  ).toContain(
    "one of the arguments --recipe-json --recipe-json-stdin --registration-json-stdin is required",
  );
  const help = helper(["register-cli-scan", "--help"], s);
  expect(help.status).toBe(0);
  expect(help.stdout).toContain("--registration-json-stdin");
  expect(help.stdout).toContain("--archived-scan-dir");
  expect(existsSync(s.state)).toBe(false);
  const invalid = helper(
    ["create-workspace", "--workspace-id", workspace, "--user-context-stdin"],
    s,
    Buffer.from([0xff]),
  );
  expect(invalid.status).toBe(1);
  expect(invalid.stderr).toContain("invalid start byte");
  expect(existsSync(s.state)).toBe(false);
});

test.skipIf(nodeMajor < 22)(
  "SDK routes all eight lifecycle commands through Node",
  () => {
    const s = setup(),
      directory = join(s.directory, "registered");
    mkdirSync(directory, { mode: 0o700 });
    const commands = [
      ["create-workspace", "--workspace-id", workspace],
      ["save-workspace", ...workspaceArgs(s)],
      ["start-scan", "--workspace-id", workspace, "--scan-root", s.scanRoot],
      [
        "start-prompt-only-scan",
        "--thread-id",
        "prompt-owner",
        "--target-path",
        s.target,
        "--scope",
        ".",
        "--mode",
        "standard",
        "--scan-root",
        s.scanRoot,
      ],
      [
        "start-headless-standard-scan",
        "--thread-id",
        "headless-owner",
        "--target-path",
        s.target,
        "--scope",
        ".",
        "--scan-root",
        s.scanRoot,
      ],
      [
        "register-cli-scan",
        "--repository",
        s.target,
        "--scan-dir",
        directory,
        "--recipe-json",
        JSON.stringify(recipe(s)),
      ],
    ];
    function run(commands: string[][]) {
      const operations: Operation[] = commands.map((sdk) => ({
        sdk,
        pluginRoot: PLUGIN_ROOT,
        stateDir: s.state,
      }));
      const child = spawnSync(node, [fixture], {
        input: stringifyJson({ operations }),
        encoding: "utf8",
        env: environment,
      });
      expect(child.status, child.stderr).toBe(0);
      const results = JSON.parse(child.stdout) as {
        error?: string;
        value: Record<string, unknown>;
      }[];
      for (const response of results) expect(response.error).toBeUndefined();
      return results;
    }
    const scanId = run(commands).at(-1)!.value["scanId"] as string;
    const remaining = run([
      ["set-scan-thread", "--scan-id", scanId, "--thread-id", "sdk-owner"],
      ["get-scan-recipe", "--scan-id", scanId],
    ]);
    expect(remaining[0]!.value).toEqual({ scanId, threadId: "sdk-owner" });
    expect(remaining[1]!.value["recipe"]).toEqual(recipe(s));
  },
);

test("get-scan reports only other running deep scans and removes failed peers", () => {
  const s = setup();
  const scans = new Map<
    string,
    { scanId: string; updatedAt: string; target: string }
  >();
  for (const name of ["current", "other", "standard", "failed", "complete"]) {
    const id = randomUUID(),
      target = join(s.directory, name);
    mkdirSync(target);
    result(
      ["create-workspace", "--workspace-id", id, "--target-path", target],
      s,
    );
    result(
      [
        "save-workspace",
        "--workspace-id",
        id,
        "--target-path",
        target,
        "--scope",
        ".",
        "--mode",
        name === "standard" ? "standard" : "deep",
      ],
      s,
    );
    const started = result(
      ["start-scan", "--workspace-id", id, "--scan-root", s.scanRoot],
      s,
    )["results"] as { scanId: string; updatedAt: string };
    scans.set(name, { ...started, target });
  }
  const other = scans.get("other")!,
    failed = scans.get("failed")!,
    complete = scans.get("complete")!;
  withWorkbenchDatabase(join(s.state, "workbench.sqlite3"), (db) =>
    db.transaction(() => {
      db.prepare(
        "UPDATE scans SET handoff_status = 'delivered' WHERE id IN (?, ?)",
      ).run([failed.scanId, other.scanId]);
      db.prepare(
        "UPDATE scans SET status = 'complete', completed_at = updated_at WHERE id = ?",
      ).run([complete.scanId]);
    }),
  );
  const fail = (scanId: string) =>
    result(
      [
        "fail-scan",
        "--scan-id",
        scanId,
        "--message",
        "Stopped for the fixture.",
      ],
      s,
    );
  fail(failed.scanId);
  const context = () =>
    result(["get-scan", "--scan-id", scans.get("current")!.scanId], s);
  expect(context()["otherRunningDeepScans"]).toEqual([
    {
      phase: "preflight",
      scanId: other.scanId,
      startedAt: other.updatedAt,
      targetPath: other.target,
      updatedAt: other.updatedAt,
    },
  ]);
  fail(other.scanId);
  expect(context()["otherRunningDeepScans"]).toEqual([]);
});
