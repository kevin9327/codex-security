import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { constants, tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/completion-lock-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "completion-lock-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const environment = { ...process.env, PATH: "", PYTHON: "/unavailable/python" };
const scanId = "11111111-1111-4111-8111-111111111111";
const children = new Set<ChildProcess>();
beforeAll(() =>
  buildSync({
    absWorkingDir: fileURLToPath(new URL("..", import.meta.url)),
    entryPoints: [
      fileURLToPath(
        new URL("./support/completion-lock-fixture.ts", import.meta.url),
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
afterAll(() => {
  for (const child of children) child.kill();
  rmSync(directory, { recursive: true, force: true });
});
function run(mode: "with" | "model", ...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture, mode], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = JSON.parse(child.stdout) as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}

test("lock files retain contents and private creation modes across successful and failed callbacks", () => {
  const state = join(directory, "state-🧭"),
    path = join(state, "completion-locks", `${scanId}.lock`);
  const [created] = run("with", { state });
  expect(created).toMatchObject({ result: "returned", events: [["callback"]] });
  if (process.platform !== "win32") {
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(readFileSync(path)).toEqual(Buffer.alloc(0));
  } else expect(readFileSync(path)).toEqual(Buffer.from([0]));
  writeFileSync(path, "kept bytes");
  const [failed, next] = run(
    "with",
    { state, operationError: "callback failed" },
    { state },
  );
  expect(failed).toMatchObject({
    error: "callback failed",
    events: [["callback"]],
  });
  expect(next!.result).toBe("returned");
  expect(readFileSync(path, "utf8")).toBe("kept bytes");
});

test("the completion directory is created before scan-id validation and a failed open never invokes the callback", () => {
  const state = join(directory, "invalid-id");
  const [invalid] = run("with", { state, scanId: "invalid" });
  expect(invalid).toMatchObject({ systemExit: true, events: [] });
  expect(invalid!.error).toContain("scan-id");
  expect(readdirSync(join(state, "completion-locks"))).toEqual([]);
  const blockedState = join(directory, "blocked");
  mkdirSync(blockedState);
  writeFileSync(join(blockedState, "completion-locks"), "existing file");
  const [blocked] = run("with", { state: blockedState });
  expect(blocked!.error).toBeDefined();
  expect(blocked!.events).toEqual([]);
  expect(readFileSync(join(blockedState, "completion-locks"), "utf8")).toBe(
    "existing file",
  );
});

test("Windows lock acquisition retries only contention and resets the byte offset before each attempt", () => {
  for (const errno of [
    constants.errno.EACCES,
    constants.errno.EAGAIN,
    constants.errno.EDEADLK,
  ]) {
    const [response] = run("model", {
      writeErrors: [errno],
      lockErrors: [errno],
    });
    expect(response!.error).toBeUndefined();
    expect(response!.size).toBe("1");
    expect(response!.events).toEqual([
      ["size", "0"],
      ["seek", 0],
      ["write", errno],
      ["wait"],
      ["size", "0"],
      ["seek", 0],
      ["write", 0],
      ["size", "1"],
      ["seek", 0],
      ["lock", errno],
      ["wait"],
      ["seek", 0],
      ["lock", 0],
      ["callback"],
      ["seek", 0],
      ["unlock", 0],
    ]);
  }
  const [existing] = run("model", { initialSize: "9007199254740993" });
  expect(existing!.error).toBeUndefined();
  expect(existing!.events).toEqual([
    ["size", "9007199254740993"],
    ["seek", 0],
    ["lock", 0],
    ["callback"],
    ["seek", 0],
    ["unlock", 0],
  ]);
});

test("Windows non-contention and wait failures escape before locking or running the callback", () => {
  const [write, seek, lock, wait] = run(
    "model",
    { writeErrors: [constants.errno.EIO] },
    { seekErrors: [constants.errno.EIO] },
    { initialSize: "1", lockErrors: [constants.errno.EPERM] },
    { lockErrors: [constants.errno.EACCES], waitError: "wait failed" },
  );
  expect(write!.errno).toBe(constants.errno.EIO);
  expect(write!.events).toEqual([
    ["size", "0"],
    ["seek", 0],
    ["write", constants.errno.EIO],
  ]);
  expect(seek!.errno).toBe(constants.errno.EIO);
  expect(seek!.events).toEqual([
    ["size", "0"],
    ["seek", constants.errno.EIO],
  ]);
  expect(lock!.errno).toBe(constants.errno.EPERM);
  expect(lock!.events).toEqual([
    ["size", "1"],
    ["seek", 0],
    ["lock", constants.errno.EPERM],
  ]);
  expect(wait!.error).toBe("wait failed");
  expect(wait!.events.at(-1)).toEqual(["wait"]);
  for (const response of [write, seek, lock, wait])
    expect(response!.events).not.toContainEqual(["callback"]);
});

test("Windows release resets the offset and its error replaces a callback error", () => {
  const [callback, release] = run(
    "model",
    { operationError: "callback failed" },
    { operationError: "callback failed", unlockError: constants.errno.EIO },
  );
  expect(callback!.error).toBe("callback failed");
  expect(callback!.events.slice(-2)).toEqual([
    ["seek", 0],
    ["unlock", 0],
  ]);
  expect(release!.errno).toBe(constants.errno.EIO);
  expect(release!.events.slice(-2)).toEqual([
    ["seek", 0],
    ["unlock", constants.errno.EIO],
  ]);
});

test("separate helpers serialize under one lock and process death releases it", async () => {
  const state = join(directory, "processes");
  function start(mode: "hold" | "visit", label: string) {
    const child = spawn(node, [fixture, mode, state, label], {
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
    });
    children.add(child);
    const lines = createInterface({ input: child.stdout })[
      Symbol.asyncIterator
    ]();
    const exited = once(child, "exit");
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (value: string) => {
      stderr += value;
    });
    return { child, exited, lines, stderr: () => stderr };
  }
  function probe() {
    const result = spawnSync(node, [fixture, "probe", state], {
      env: environment,
      encoding: "utf8",
    });
    expect(result.status, result.stderr).toBe(0);
    return JSON.parse(result.stdout) as { errno: number };
  }
  const first = start("hold", "first");
  expect((await first.lines.next()).value).toBe("waiting");
  expect((await first.lines.next()).value).toBe("acquired");
  expect(probe().errno).not.toBe(0);
  const second = start("visit", "second");
  expect((await second.lines.next()).value).toBe("waiting");
  first.child.stdin.end("release");
  expect((await first.exited)[0], first.stderr()).toBe(0);
  expect((await second.lines.next()).value).toBe("acquired");
  expect((await second.exited)[0], second.stderr()).toBe(0);
  expect(readFileSync(join(state, "events"), "utf8")).toBe(
    "first-enter\nfirst-exit\nsecond-enter\nsecond-exit\n",
  );
  const dying = start("hold", "dying");
  expect((await dying.lines.next()).value).toBe("waiting");
  expect((await dying.lines.next()).value).toBe("acquired");
  dying.child.kill("SIGKILL");
  await dying.exited;
  expect(probe().errno).toBe(0);
  expect(existsSync(join(state, "completion-locks", `${scanId}.lock`))).toBe(
    true,
  );
});
