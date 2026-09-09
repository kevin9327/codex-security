import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type {
  Report,
  Request,
  Snapshot,
} from "./support/connection-state-fixture";

const node = Bun.which("node")!;
const directory = realpathSync(mkdtempSync(join(tmpdir(), "workbench-db-")));
const fixture = join(directory, "fixture.mjs");
const home = join(directory, "home");
let counter = 0;
let scenarios: { name: string; request: Request }[];
let legacyRows: string;
beforeAll(() => {
  mkdirSync(home);
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/connection-state-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp", "helpers.mjs")).href,
      ),
    },
  });
  const described = spawnSync(node, [fixture, "describe"], {
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
  });
  expect(described.status, described.stderr).toBe(0);
  ({ scenarios, legacyRows } = JSON.parse(described.stdout) as {
    scenarios: typeof scenarios;
    legacyRows: string;
  });
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(
  request: Request,
  state = join(directory, `state-${counter++}`),
  environment: NodeJS.ProcessEnv = {},
): Report {
  const child = spawnSync(node, [fixture], {
    cwd: directory,
    input: JSON.stringify(request),
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: "",
      HOME: home,
      USERPROFILE: home,
      CODEX_HOME: undefined,
      CODEX_SECURITY_STATE_DIR: state,
      ...environment,
    },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Report;
}
function scenario(name: string, state?: string) {
  return run(scenarios.find((item) => item.name === name)!.request, state);
}
const targets = (snapshot: Snapshot) => snapshot.tables["security_targets"]!;
const history = (snapshot: Snapshot) => snapshot.tables["schema_migrations"]!;

describe("native workbench connection and target persistence", () => {
  test("selects explicit state and Codex homes with original empty, relative and whitespace handling", () => {
    const base = ["state", "plugins", "codex-security"];
    const defaultPath = join(home, ".codex", ...base);
    for (const value of [undefined, ""]) {
      const result = run({ action: "paths" }, undefined, {
        CODEX_SECURITY_STATE_DIR: value,
      });
      expect(result.error).toBeUndefined();
      expect(result.stateDir).toBe(defaultPath);
      expect(result.databasePath).toBe(join(defaultPath, "workbench.sqlite3"));
    }
    expect(
      run({ action: "paths" }, undefined, {
        CODEX_SECURITY_STATE_DIR: undefined,
        CODEX_HOME: "",
      }).stateDir,
    ).toBe(join(directory, ...base));
    expect(
      run({ action: "paths" }, undefined, {
        CODEX_SECURITY_STATE_DIR: undefined,
        CODEX_HOME: "~/custom",
      }).stateDir,
    ).toBe(join(home, "custom", ...base));
    expect(run({ action: "paths" }, "  ").stateDir).toBe(join(directory, "  "));
    expect(
      run({ action: "paths" }, "relative/./nested/../state").stateDir,
    ).toBe(join(directory, "relative", "state"));
    expect(run({ action: "paths" }, "~/chosen").stateDir).toBe(
      join(home, "chosen"),
    );
    const chosen = join(directory, "chosen");
    mkdirSync(chosen);
    symlinkSync(
      chosen,
      join(directory, "alias"),
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(run({ action: "paths" }, "alias/missing").stateDir).toBe(
      join(chosen, "missing"),
    );
    const file = join(directory, "parent-file");
    writeFileSync(file, "not a directory");
    const blocked = run({ action: "connect" }, join(file, "state"));
    expect(blocked.error).toBeDefined();
    expect(blocked.opens).toBe(0);
    if (process.platform !== "win32")
      expect(blocked.error?.code).toBe("ENOTDIR");
  });

  test.skipIf(process.platform === "win32")(
    "reads raw POSIX state, Codex home and HOME bytes before Node's UTF-8 conversion",
    () => {
      const raw = join(directory, "raw-\udcff");
      const selected = run({
        action: "paths",
        rawEnvironment: { CODEX_SECURITY_STATE_DIR: raw },
      });
      expect(selected.error).toBeUndefined();
      expect(selected.stateDir).toBe(raw);
      const custom = run({
        action: "paths",
        rawEnvironment: { CODEX_SECURITY_STATE_DIR: null, CODEX_HOME: raw },
      });
      expect(custom.stateDir).toBe(
        join(raw, "state", "plugins", "codex-security"),
      );
      const defaultHome = run({
        action: "paths",
        rawEnvironment: {
          CODEX_SECURITY_STATE_DIR: null,
          CODEX_HOME: null,
          HOME: raw,
        },
      });
      expect(defaultHome.stateDir).toBe(
        join(raw, ".codex", "state", "plugins", "codex-security"),
      );
      const opened = run({
        action: "connect",
        repeat: true,
        rawEnvironment: { CODEX_SECURITY_STATE_DIR: raw },
      });
      expect(opened.error).toBeUndefined();
      expect(opened.snapshots![1]).toEqual(opened.snapshots![0]);
      expect(opened.mode).toBe(0o600);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "retains wide Windows environment values through state and home resolution",
    () => {
      const raw = join(directory, "wide-\ud800");
      const selected = run({
        action: "paths",
        rawEnvironment: { CODEX_SECURITY_STATE_DIR: raw },
      });
      expect(selected.error).toBeUndefined();
      expect(selected.stateDir).toBe(raw);
      const custom = run({
        action: "paths",
        rawEnvironment: { CODEX_SECURITY_STATE_DIR: null, CODEX_HOME: raw },
      });
      expect(custom.stateDir).toBe(
        join(raw, "state", "plugins", "codex-security"),
      );
      const defaultHome = run({
        action: "paths",
        rawEnvironment: {
          CODEX_SECURITY_STATE_DIR: null,
          CODEX_HOME: null,
          USERPROFILE: raw,
        },
      });
      expect(defaultHome.stateDir).toBe(
        join(raw, ".codex", "state", "plugins", "codex-security"),
      );
    },
  );

  test("hashes lexical pathlib spellings without resolving targets or replacing Unicode", () => {
    const paths = [
      "/synthetic//alpha/./",
      "/synthetic/alpha",
      "link/../target",
      "target",
      "",
      ".",
      "/",
      "café/🔐",
      "a\0b",
      "bad-\udcff",
      "bad-\ud800\ud800",
    ];
    const result = run({ action: "identities", paths }).identities!;
    expect(result[0]!.id).toBe(result[1]!.id);
    expect(result[2]!.id).not.toBe(result[3]!.id);
    expect(result[4]!.id).toBe(result[5]!.id);
    for (const index of [0, 2, 4, 6, 7, 8])
      expect(result[index]!.id).toMatch(/^target_sha256_[a-f0-9]{64}$/u);
    expect(result[9]!.error).toContain("surrogates not allowed");
    expect(result[10]!.error).toContain("characters in position");
  });

  test("leaves target transactions with the caller and preserves lexical paths and metadata", () => {
    const result = run({
      action: "targets",
      steps: [
        { operation: "ensure", value: "/synthetic//alpha/./" },
        { operation: "ensure", value: "/synthetic/alpha" },
        { operation: "ensure", value: "/synthetic//alpha/./" },
        { operation: "rollback" },
        { operation: "ensure", value: "." },
        { operation: "ensure", value: "/" },
        { operation: "commit" },
        { operation: "ensure", value: "relative/../café/🔐" },
        { operation: "rollback" },
      ],
    });
    const steps = result.steps!;
    expect(steps.every((step) => step.error === null)).toBe(true);
    expect(steps[0]!.result).toBe(steps[1]!.result);
    expect(steps[1]!.result).toBe(steps[2]!.result);
    expect(targets(steps[2]!.snapshot)).toHaveLength(1);
    expect(targets(steps[2]!.snapshot)[0]).toMatchObject({
      current_path: "/synthetic//alpha/./",
      display_name: "alpha",
      created_at: "2026-09-03T01:02:03.000001Z",
      updated_at: "2026-09-03T01:02:03.000001Z",
    });
    expect(steps[0]!.snapshot.inTransaction).toBe(true);
    expect(targets(steps[3]!.snapshot)).toEqual([]);
    expect(steps[6]!.snapshot.inTransaction).toBe(false);
    expect(
      targets(steps[6]!.snapshot).map((row) => row["display_name"]),
    ).toEqual(["", ""]);
    expect(targets(steps[8]!.snapshot)).toEqual(targets(steps[6]!.snapshot));
    expect(result.clock).toHaveLength(5);
    const formatted = run({
      action: "targets",
      clockValues: ["2026-09-03T01:02:03Z", "2026-09-03T01:02:03.123456Z"],
      steps: [
        { operation: "ensure", value: "/zero" },
        { operation: "ensure", value: "/micros" },
      ],
    });
    expect(
      targets(formatted.steps![1]!.snapshot).map((row) => row["created_at"]),
    ).toEqual(formatted.clock!);
  });

  test("backfills each stored path without overwriting non-null IDs, and caller rollback restores rows", () => {
    const result = run({
      action: "targets",
      setup:
        legacyRows +
        `
INSERT INTO security_targets VALUES('kept-id','/synthetic/beta','kept name','old-created','old-updated');
UPDATE scans SET target_id='kept-id' WHERE id='scan-a';`,
      steps: [
        { operation: "backfill" },
        { operation: "backfill" },
        { operation: "rollback" },
      ],
    });
    const first = result.steps![0]!.snapshot;
    expect(result.steps![0]!.error).toBeNull();
    expect(first.inTransaction).toBe(true);
    expect(first.tables["scans"]![0]!["target_id"]).toBe("kept-id");
    expect(first.tables["workspaces"]![0]!["target_id"]).not.toBe("kept-id");
    expect(first.tables["workspaces"]![1]!["target_id"]).toBe("kept-id");
    expect(first.tables["workspaces"]![2]!["target_id"]).toBeNull();
    expect(targets(first).find((row) => row["id"] === "kept-id")).toMatchObject(
      {
        display_name: "kept name",
        created_at: "old-created",
        updated_at: "old-updated",
      },
    );
    expect(result.steps![1]!.snapshot).toEqual(first);
    expect(targets(result.steps![2]!.snapshot)).toHaveLength(1);
    expect(
      result.steps![2]!.snapshot.tables["workspaces"]!.every(
        (row) => row["target_id"] === null,
      ),
    ).toBe(true);
  });

  test("initializes 41 migrations, enables WAL and foreign keys, and discards uncommitted work on close", () => {
    const result = scenario("fresh");
    expect(result.error).toBeUndefined();
    expect(result.pragmas).toEqual({
      foreignKeys: "1",
      busyTimeout: "5000",
      journalMode: "wal",
    });
    expect(history(result.snapshots![0]!)).toHaveLength(41);
    expect(result.snapshots![1]).toEqual(result.snapshots![0]);
    expect(result.snapshots![0]!.inTransaction).toBe(false);
    expect(result.clock).toHaveLength(43);
    expect(result.opens).toBe(2);
    expect(result.closes).toBe(2);
    if (process.platform !== "win32") expect(result.mode).toBe(0o600);
    const state = join(directory, `permissions-${counter++}`);
    mkdirSync(state, { mode: 0o750 });
    const originalMode = statSync(state).mode & 0o777;
    expect(run({ action: "connect" }, state).error).toBeUndefined();
    expect(statSync(state).mode & 0o777).toBe(originalMode);
    chmodSync(join(state, "workbench.sqlite3"), 0o666);
    const reopened = run({ action: "connect" }, state);
    expect(reopened.error).toBeUndefined();
    if (process.platform !== "win32") expect(reopened.mode).toBe(0o600);
  });

  test("migrates populated legacy targets atomically while retaining existing IDs and timestamps", () => {
    for (const name of ["legacy-targets", "existing-targets"]) {
      const result = scenario(name);
      expect(result.error).toBeUndefined();
      expect(result.snapshots![1]).toEqual(result.snapshots![0]);
      expect(history(result.snapshots![0]!)).toHaveLength(41);
      expect(targets(result.snapshots![0]!)).toHaveLength(2);
      expect(result.snapshots![0]!.foreignKeys).toEqual([]);
      if (name === "existing-targets")
        expect(targets(result.snapshots![0]!)[0]).toMatchObject({
          id: "kept-id",
          created_at: "old-created",
          updated_at: "old-updated",
        });
      else
        expect(history(result.snapshots![0]!)[0]!["applied_at"]).toBe(
          "original-1",
        );
    }
    const state = join(directory, `rollback-${counter++}`);
    const failed = scenario("clock-failure", state);
    expect(failed.error?.message).toBe("busy clock failure");
    expect(failed.opens).toBe(1);
    const persisted = run({ action: "inspect" }, state).snapshots![0]!;
    expect(history(persisted)).toHaveLength(15);
    expect(persisted.tables["security_targets"]).toBeUndefined();
    expect(persisted.tables["workspaces"]![0]!["target_path"]).toBe(
      "/synthetic//alpha/./",
    );
  });

  test("retries only busy or locked operational failures, with five attempts and original open-error boundary", () => {
    const success = scenario("busy-then-success");
    expect(success.error).toBeUndefined();
    expect(success.opens).toBe(3);
    expect(success.closes).toBe(3);
    expect(success.activeHandles).toBe(0);
    for (const name of ["busy-exhausted", "busy-named-table"]) {
      const result = scenario(name);
      expect(result.error?.sqliteCode).toBe(name === "busy-exhausted" ? 6 : 1);
      expect(result.opens).toBe(5);
      expect(result.closes).toBe(5);
      expect(result.activeHandles).toBe(0);
      expect(result.clock).toEqual([]);
    }
    const constraint = scenario("constraint-not-retried");
    expect(constraint.error).toMatchObject({
      sqliteCode: 19,
      message: "CHECK constraint failed: busy",
    });
    expect(constraint.opens).toBe(1);
    expect(constraint.activeHandles).toBe(0);
    const missing = scenario("missing-table-not-retried");
    expect(missing.error?.sqliteCode).toBe(1);
    expect(missing.opens).toBe(1);
    expect(missing.closes).toBe(1);
    const unicode = scenario("unicode-name-not-retried");
    expect(unicode.error?.message).toBe("no such table: buſy_fixture");
    expect(unicode.opens).toBe(1);
    const callback = scenario("busy-clock-failure");
    expect(callback.error).toMatchObject({
      message: "busy clock failure",
      sqliteCode: null,
    });
    expect(callback.opens).toBe(1);
    expect(callback.closes).toBe(1);
    expect(callback.activeHandles).toBe(0);
    const open = scenario("database-is-directory");
    expect(open.error?.sqliteCode).toBe(14);
    expect(open.opens).toBe(1);
    expect(open.closes).toBe(0);
  });

  test("serializes concurrent first connections against the same on-disk database", async () => {
    const state = join(directory, `concurrent-${counter++}`);
    const workers = Array.from({ length: 2 }, () => {
      const child = spawn(node, [fixture, "worker"], {
        env: { ...process.env, PATH: "", CODEX_SECURITY_STATE_DIR: state },
      });
      const exit = once(child, "exit");
      let output = "",
        error = "";
      let ready!: () => void;
      const started = new Promise<void>((resolve) => {
        ready = resolve;
      });
      child.stdout.on("data", (chunk: Buffer) => {
        output += chunk.toString();
        if (output.startsWith("ready\n")) ready();
      });
      child.stderr.on("data", (chunk: Buffer) => {
        error += chunk.toString();
      });
      return { child, exit, started, output: () => output, error: () => error };
    });
    await Promise.all(workers.map((worker) => worker.started));
    for (const worker of workers) worker.child.stdin.end("start\n");
    const results: { calls: number; snapshot: Snapshot }[] = [];
    for (const worker of workers) {
      expect(await worker.exit).toEqual([0, null]);
      expect(worker.error()).toBe("");
      results.push(
        JSON.parse(
          worker.output().slice("ready\n".length),
        ) as (typeof results)[number],
      );
    }
    expect(results.map((result) => result.calls).sort((a, b) => a - b)).toEqual(
      [1, 42],
    );
    expect(results[0]!.snapshot).toEqual(results[1]!.snapshot);
    expect(history(results[0]!.snapshot)).toHaveLength(41);
    expect(results[0]!.snapshot.inTransaction).toBe(false);
    expect(run({ action: "paths" }, state).databasePath).toBe(
      resolve(state, "workbench.sqlite3"),
    );
  });
});
