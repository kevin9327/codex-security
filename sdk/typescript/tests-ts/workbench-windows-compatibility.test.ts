import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import type { Request } from "./support/path-compatibility-fixture";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const probeDirectory = realpathSync(
  mkdtempSync(join(tmpdir(), "path-compatibility-")),
);
const fixture = join(probeDirectory, "fixture.cjs");
const node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/path-compatibility-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(probeDirectory, { recursive: true, force: true }));
function run<T = Record<string, unknown>>(request: Request): T {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(request),
    encoding: "utf8",
    env: { ...process.env, PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as T;
}

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

test("normalizes absolute scopes without accepting escapes", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-scopes-")),
  );
  directories.push(root);
  expect(
    run<{ accepted: string[]; rejected: boolean[] }>({
      operation: "scopes",
      root,
    }),
  ).toEqual({
    accepted: ["src", "src/nested", "."],
    rejected: [true, true, true, true],
  });
});

test("verifies LF and CRLF patches with Git line-ending conversion enabled", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-line-endings-")),
  );
  directories.push(root);
  expect(
    run<Record<string, boolean>[]>({ operation: "line-endings", root }),
  ).toEqual([
    { applied: true, unchanged: true, unrelatedRejected: true },
    { applied: true, unchanged: true, unrelatedRejected: true },
  ]);
});
