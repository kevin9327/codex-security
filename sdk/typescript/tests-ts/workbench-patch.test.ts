import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import type { Request } from "./support/path-compatibility-fixture";
import { createHash } from "node:crypto";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  test,
} from "bun:test";
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

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("workbench remediation patches", () => {
  test("streams patches larger than 2 MiB without weakening digest checks", async () => {
    const directory = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-large-patch-")),
    );
    temporaryDirectories.push(directory);
    const patch = Buffer.concat([
      Buffer.from("diff --git a/src.ts b/src.ts\n+"),
      Buffer.alloc(2 * 1024 * 1024, 0x78),
      Buffer.from("\n"),
    ]);
    await writeFile(join(directory, "remediation.patch"), patch);
    const digest = `sha256:${createHash("sha256").update(patch).digest("hex")}`;
    const output = run<{
      preview: string;
      stats: Record<string, number | boolean>;
      mismatch: string;
    }>({ operation: "patch", scanDirectory: directory, digest });
    expect(output.preview).toStartWith("diff --git a/src.ts b/src.ts\n+");
    expect(output.preview).toEndWith("... patch preview truncated ...");
    expect(output.stats).toMatchObject({
      additions: 1,
      fileCount: 1,
      previewTruncated: true,
    });
    expect(output.mismatch).toBe(
      "Patch digest does not match the scan-local patch file.",
    );
  });
});
