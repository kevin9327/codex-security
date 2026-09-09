import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { PLUGIN_ROOT } from "./plugin-root.js";

const fixtureDirectory = realpathSync(
  mkdtempSync(join(tmpdir(), "target-probe-")),
);
const fixture = join(fixtureDirectory, "fixture.cjs");
const node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(new URL("./support/target-fixture.ts", import.meta.url)),
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
afterAll(() => rmSync(fixtureDirectory, { recursive: true, force: true }));

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function git(directory: string, ...args: string[]): void {
  const result = spawnSync("git", ["-C", directory, ...args], {
    encoding: "utf8",
    windowsHide: true,
  });
  expect(result.status, result.stderr).toBe(0);
}

test("writes nested Git pointers as UTF-8 independently of the locale", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-nested-git-utf8-")),
  );
  temporaryDirectories.push(root);
  const repository = join(root, "repository");
  const nested = join(repository, "nested-漢字");
  const checkout = join(root, "checkout");
  mkdirSync(nested, { recursive: true });
  git(repository, "init", "-q");
  git(nested, "init", "-q");

  const result = spawnSync(node, [fixture], {
    input: JSON.stringify({ operation: "copy", repository, checkout }),
    encoding: "utf8",
    windowsHide: true,
    env: { ...process.env, PYTHON: "/unavailable/python", LC_ALL: "C" },
  });

  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(join(checkout, "nested-漢字", ".git"), "utf8")).toContain(
    "nested-漢字",
  );
});
