import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const node = Bun.which("node")!;
const directory = mkdtempSync(join(tmpdir(), "git-transport-"));
const fixture = join(directory, "fixture.mjs");
const repository = join(directory, "repository with spaces ☃");
const environment = { ...process.env };
for (const name of [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
])
  delete environment[name];
Object.assign(environment, {
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "Fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
});
const blob = Buffer.from([0, 10, 13, 255, 128, 32, 0, 65]);
function git(args: string[]): Buffer {
  const result = spawnSync("git", ["-C", repository, ...args], {
    env: environment,
  });
  expect(result.status).toBe(0);
  return result.stdout;
}
beforeAll(() => {
  mkdirSync(repository);
  git(["init", "--quiet"]);
  git(["config", "core.autocrlf", "false"]);
  writeFileSync(join(repository, "binary.dat"), blob);
  writeFileSync(join(repository, "literal[1].txt"), "literal");
  writeFileSync(join(repository, "literal1.txt"), "different");
  git(["add", "."]);
  git(["commit", "--quiet", "-m", "fixture"]);
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/git-transport-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    // Use the installed plugin's actual addon, as the production helper bundle does.
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp", "helpers.mjs")).href,
      ),
    },
  });
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(
  action: "command" | "bytes" | "output" | "blobs" | "decode",
  args: string[],
  options: {
    target?: string;
    input?: Buffer;
    count?: number;
    context?: { gitDir?: string; workTree?: string };
    env?: NodeJS.ProcessEnv;
  } = {},
): { result?: unknown; error?: string; errno?: number; winerror?: number } {
  const result = spawnSync(node, [fixture], {
    encoding: "utf8",
    env: { ...environment, ...options.env },
    input: JSON.stringify({
      action,
      args,
      ...options,
      target: options.target ?? repository,
      input: options.input?.toString("base64"),
    }),
    maxBuffer: Infinity,
  });
  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout);
}

describe("native workbench Git transport", () => {
  test("reads ordered raw blobs, duplicates, and missing objects in one batch", () => {
    expect(
      run("blobs", ["HEAD:binary.dat", "HEAD:missing", "HEAD:binary.dat"])
        .result,
    ).toEqual([blob.toString("base64"), null, blob.toString("base64")]);
    expect(
      run("blobs", [], { target: join(directory, "missing") }).result,
    ).toEqual([]);
    expect(
      run("blobs", ["HEAD:binary.dat"], { target: join(directory, "missing") })
        .result,
    ).toEqual([null]);
  });
  test("preserves binary stdin/output and reports Git failure without treating it as empty success", () => {
    const result = run("command", ["hash-object", "--stdin"], { input: blob })
      .result as {
      returnCode: number;
      stdout: string;
      stderr: string;
      args: string[];
    };
    expect(result.returnCode).toBe(0);
    expect(Buffer.from(result.stdout, "base64").toString().trim()).toBe(
      git(["rev-parse", "HEAD:binary.dat"]).toString().trim(),
    );
    expect(result.stderr).toBe("");
    expect(result.args.slice(0, 7)).toEqual([
      "git",
      "-c",
      "core.fsmonitor=false",
      "-c",
      "i18n.logOutputEncoding=UTF-8",
      "-C",
      repository,
    ]);
    expect(run("bytes", ["cat-file", "blob", "HEAD:binary.dat"]).result).toBe(
      blob.toString("base64"),
    );
    expect(
      run("bytes", ["rev-parse", "--verify", "does-not-exist"]).result,
    ).toBe(null);
    expect(run("output", ["config", "--get", "missing.key"]).result).toBe(null);
  });
  test("clears ambient repository routing and preserves literal pathspecs and explicit worktree context", () => {
    const gitDir = join(repository, ".git");
    const expected = git(["rev-parse", "HEAD"]).toString().trim();
    const env = {
      GIT_DIR: join(directory, "wrong"),
      GIT_WORK_TREE: directory,
      GIT_INDEX_FILE: join(directory, "wrong-index"),
      GIT_OBJECT_DIRECTORY: directory,
      GIT_COMMON_DIR: directory,
      GIT_NAMESPACE: "wrong",
    };
    expect(run("output", ["rev-parse", "HEAD"], { env }).result).toBe(expected);
    expect(run("output", ["ls-files", "--", "literal[1].txt"]).result).toBe(
      "literal[1].txt",
    );
    expect(
      run("output", ["rev-parse", "HEAD"], {
        target: directory,
        context: { gitDir, workTree: repository },
        env,
      }).result,
    ).toBe(expected);
    expect(run("bytes", [], { context: { gitDir } }).error).toBe(
      "git_dir and work_tree must be provided together",
    );
  });
  test("uses Python whitespace trimming without removing a leading UTF-8 BOM", () => {
    git(["config", "fixture.value", "\u001c\u0085  kept \u001f\u2003"]);
    expect(run("output", ["config", "--get", "fixture.value"]).result).toBe(
      "kept",
    );
    git(["config", "fixture.value", "\ufeffkept"]);
    expect(run("output", ["config", "--get", "fixture.value"]).result).toBe(
      "\ufeffkept",
    );
  });
  test("decodes sized binary records and refuses truncated framing", () => {
    const payload = Buffer.concat([
      Buffer.from("oid blob 8\0"),
      blob,
      Buffer.from("\0missing missing\0unused"),
    ]);
    expect(run("decode", [], { input: payload, count: 2 }).result).toEqual([
      blob.toString("base64"),
      null,
    ]);
    for (const input of [
      Buffer.from("oid blob 1"),
      Buffer.from("oid blob -1\0"),
      Buffer.from("oid blob x\0"),
      Buffer.from("oid blob 1\0x"),
    ])
      expect(run("decode", [], { input, count: 1 }).error).toBeDefined();
    expect(
      run("decode", [], { input: Buffer.from("oid blob 0\0\0"), count: 1 })
        .result,
    ).toEqual([""]);
  });
  test.skipIf(process.platform === "win32")(
    "treats unavailable Git as optional status 127",
    () => {
      const result = run("command", ["status"], { env: { PATH: directory } })
        .result as { returnCode: number; stdout: string; stderr: string };
      expect(result.returnCode).toBe(127);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe("");
    },
  );
  test.skipIf(process.platform !== "linux")(
    "preserves raw POSIX directory and tracked filename bytes",
    () => {
      const filename = Buffer.concat([
        Buffer.from(repository + "/"),
        Buffer.from([0xff]),
        Buffer.from(".dat"),
      ]);
      writeFileSync(filename, blob);
      git(["add", "."]);
      git(["commit", "--quiet", "-m", "raw filename"]);
      expect(run("blobs", ["HEAD:\udcff.dat"]).result).toEqual([
        blob.toString("base64"),
      ]);
      const rawDirectory = Buffer.concat([
        Buffer.from(directory + "/"),
        Buffer.from([0xff]),
      ]);
      mkdirSync(rawDirectory);
      expect(
        run("output", ["rev-parse", "HEAD"], {
          target: directory + "/\udcff",
          context: { gitDir: join(repository, ".git"), workTree: repository },
        }).result,
      ).toBe(git(["rev-parse", "HEAD"]).toString().trim());
    },
  );
});
