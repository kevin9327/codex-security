import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const node = Bun.which("node")!;
const directory = realpathSync(mkdtempSync(join(tmpdir(), "git-snapshot-")));
const fixture = join(directory, "fixture.mjs");
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
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/git-snapshot-fixture.ts", import.meta.url),
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
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function git(repository: string, args: string[]) {
  const result = spawnSync("git", ["-C", repository, ...args], {
    env: environment,
  });
  expect(result.status, result.stderr.toString()).toBe(0);
  return result.stdout;
}
function repository() {
  const path = mkdtempSync(join(directory, "repository ☃ "));
  git(path, ["init", "--quiet"]);
  git(path, ["config", "core.autocrlf", "false"]);
  git(path, ["config", "core.ignorecase", "false"]);
  return path;
}
function write(root: string, name: string, contents = "contents") {
  const path = join(root, name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
  return path;
}
function run(
  target: string,
  action: "paths" | "context" = "paths",
  env: NodeJS.ProcessEnv = {},
) {
  const result = spawnSync(node, [fixture], {
    encoding: "utf8",
    env: { ...environment, ...env },
    input: JSON.stringify({ target, action }),
    maxBuffer: Infinity,
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as {
    result?: string[] | null;
    error?: string;
    code?: string;
  };
}
function paths(target: string) {
  const result = run(target);
  expect(result.error).toBeUndefined();
  return result.result!.map((path) =>
    relative(target, path).split(sep).join("/"),
  );
}

describe("workbench Git snapshot inventory", () => {
  test("includes tracked ignored files and untracked files, excluding ignored and deleted entries", () => {
    const root = repository();
    write(root, "scope/tracked.tmp");
    write(root, "scope/staged-then-deleted.txt");
    git(root, ["add", "."]);
    rmSync(join(root, "scope/staged-then-deleted.txt"));
    write(root, ".gitignore", "*.tmp\n");
    write(root, "scope/ignored.tmp");
    write(root, "scope/untracked.txt");
    write(root, "elsewhere.txt");
    expect(paths(join(root, "scope"))).toEqual([
      "tracked.tmp",
      "untracked.txt",
    ]);
    expect(paths(root)).toEqual([
      ".gitignore",
      "elsewhere.txt",
      "scope/tracked.tmp",
      "scope/untracked.txt",
    ]);
  });
  test("keeps literal and Unicode scopes and resolves lexical worktree context", () => {
    const root = repository();
    write(root, "literal[1]/a.txt");
    write(root, "literal1/b.txt");
    write(root, "Σcope/😀.txt");
    write(root, "Σcope/\ue000.txt");
    expect(paths(join(root, "literal[1]"))).toEqual(["a.txt"]);
    expect(paths(join(root, "Σcope"))).toEqual(["\ue000.txt", "😀.txt"]);
    expect(run(join(root, "Σcope", "."), "context").result).toEqual([
      root,
      "Σcope",
    ]);
    expect(run(root, "context").result).toEqual([root, "."]);
    expect(
      run(root, "paths", {
        GIT_DIR: directory,
        GIT_WORK_TREE: directory,
        GIT_INDEX_FILE: join(directory, "missing-index"),
      }),
    ).toEqual(run(root));
  });
  test("uses filesystem identity for index scope spelling after directory renames", () => {
    const root = repository();
    write(root, "Scope/tracked.txt");
    git(root, ["add", "."]);
    renameSync(join(root, "Scope"), join(root, "intermediate"));
    renameSync(join(root, "intermediate"), join(root, "scope"));
    write(root, "scope/new.txt");
    const scope = join(root, "scope");
    let aliases: boolean;
    try {
      aliases =
        statSync(join(root, "Scope"), { bigint: true }).ino ===
        statSync(scope, { bigint: true }).ino;
    } catch {
      aliases = false;
    }
    if (!aliases) {
      symlinkSync(
        scope,
        join(root, "Scope"),
        process.platform === "win32" ? "junction" : "dir",
      );
    }
    expect(paths(scope)).toEqual(["new.txt", "tracked.txt"]);
  });
  test("does not include an icase-matching scope with a different identity", () => {
    const root = repository();
    write(root, "Scope/other.txt");
    write(root, "scope/selected.txt");
    git(root, ["add", "."]);
    const upper = statSync(join(root, "Scope"), { bigint: true });
    const lower = statSync(join(root, "scope"), { bigint: true });
    expect(paths(join(root, "scope"))).toEqual(
      upper.ino === lower.ino && upper.dev === lower.dev
        ? ["other.txt", "selected.txt"]
        : ["selected.txt"],
    );
  });
  test("recurses into nested repositories using their own ignore rules", () => {
    const root = repository();
    const nested = join(root, "nested");
    mkdirSync(nested);
    git(nested, ["init", "--quiet"]);
    write(nested, "tracked.tmp");
    git(nested, ["add", "."]);
    write(nested, ".gitignore", "*.tmp\n");
    write(nested, "ignored.tmp");
    write(nested, "untracked.txt");
    expect(paths(root)).toEqual([
      "nested",
      "nested/.gitignore",
      "nested/tracked.tmp",
      "nested/untracked.txt",
    ]);
  });
  test("expands an indexed file replaced with a directory while filtering .git descendants", () => {
    const root = repository();
    write(root, "replacement");
    git(root, ["add", "."]);
    rmSync(join(root, "replacement"));
    write(root, "replacement/deep/file.txt");
    write(root, "replacement/.git/kept-private");
    expect(paths(root)).toEqual([
      "replacement",
      "replacement/deep",
      "replacement/deep/file.txt",
    ]);
  });
  test.skipIf(process.platform === "win32")(
    "retains symlink leaves without following them in fallback directories",
    () => {
      const root = repository();
      write(root, "replacement");
      git(root, ["add", "."]);
      rmSync(join(root, "replacement"));
      mkdirSync(join(root, "replacement"));
      const external = mkdtempSync(join(directory, "external-"));
      write(external, "outside.txt");
      symlinkSync(external, join(root, "replacement", "link"), "dir");
      symlinkSync("missing", join(root, "replacement", "dangling"));
      expect(paths(root)).toEqual([
        "replacement",
        "replacement/dangling",
        "replacement/link",
      ]);
    },
  );
  test.skipIf(process.platform !== "linux")(
    "preserves undecodable POSIX paths and Python ordering",
    () => {
      const root = repository();
      const raw = Buffer.concat([Buffer.from(root + "/"), Buffer.from([0xff])]);
      mkdirSync(raw);
      writeFileSync(Buffer.concat([raw, Buffer.from("/tracked.txt")]), "raw");
      git(root, ["add", "."]);
      const target = root + "/\udcff";
      expect(paths(target)).toEqual(["tracked.txt"]);
      expect(run(target, "context").result).toEqual([root, "\udcff"]);
    },
  );
  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "suppresses unreadable fallback descendants as pathlib does",
    () => {
      const root = repository();
      write(root, "replacement");
      git(root, ["add", "."]);
      rmSync(join(root, "replacement"));
      const denied = join(root, "replacement", "denied");
      write(denied, "hidden.txt");
      chmodSync(denied, 0);
      try {
        expect(paths(root)).toEqual(["replacement", "replacement/denied"]);
      } finally {
        chmodSync(denied, 0o700);
      }
    },
  );
  test("distinguishes nonrepositories and failed inventories", () => {
    const outside = mkdtempSync(join(directory, "outside-"));
    expect(run(outside).result).toBe(null);
    expect(run(outside, "context").error).toBe(
      "Could not inspect the selected Git working tree.",
    );
    const root = repository();
    write(root, "tracked.txt");
    git(root, ["add", "."]);
    writeFileSync(join(root, ".git", "index"), "corrupt index");
    expect(run(root).error).toBe(
      "Could not inspect files in the selected Git working tree.",
    );
  });
});
