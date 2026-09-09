import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Action, Request } from "./support/scan-local-files-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "scan-local-files-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
let next = 0;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-local-files-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function request(input: Request, cwd?: string): unknown[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(input),
    encoding: "utf8",
    env: process.env,
    cwd,
    maxBuffer: Infinity,
    timeout: 15000,
  });
  expect(
    child.status,
    JSON.stringify({
      error: child.error?.message,
      signal: child.signal,
      stderr: child.stderr,
    }),
  ).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as unknown[];
}
function run(actions: (root: string, parent: string) => Action[]) {
  const parent = join(directory, String(next++)),
    root = join(parent, "scan");
  return {
    root,
    parent,
    results: request({ mode: "files", root, actions: actions(root, parent) }),
  };
}
const digest = (value: Buffer | string) =>
  createHash("sha256").update(value).digest("hex");
const error = (value: unknown) => (value as { error: string }).error;

test("preserves repository and portable path rules, including Unicode and Windows device aliases", () => {
  const values = [
    "",
    " ",
    "\u0085",
    ".",
    "./",
    "a/./b",
    "a//b/",
    "../x",
    "/a",
    "a\\b",
    "a\0b",
    "A:x",
    "𝒜:x",
    "a/CONIN$.json",
    "a/conın$.json",
    "a/conİn$.json",
    "a/COM¹.txt",
    "a/trailing.",
    "a/normal😀",
    "a/\ud800",
  ];
  const results = request({
    mode: "paths",
    cases: values.map((value) => ({ value, portable: true })),
  });
  expect(results[5]).toBe("a/b");
  expect(results[6]).toBe("a/b");
  expect(results[18]).toBe("a/normal😀");
  for (const index of [
    0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19,
  ])
    expect(error(results[index])).toContain("expected a safe");
  expect(
    request({
      mode: "paths",
      cases: [
        { value: ".", allowDot: true },
        { value: "a/CON", portable: false },
        { value: "\ufeff", portable: false },
      ],
    }),
  ).toEqual([".", "a/CON", "\ufeff"]);
});

test("writes, reads, hashes and replaces large binary files, retaining identity on identical restore", () => {
  const size = 1024 * 1024 + 13;
  const { results } = run((root) => [
    { operation: "identity" },
    { operation: "write", relative: "exports/data", size },
    { operation: "metadata", path: join(root, "exports/data") },
    { operation: "read", relative: "exports/data" },
    { operation: "hash", relative: "exports/data" },
    { operation: "write", relative: "exports/data", size, expected: true },
    { operation: "metadata", path: join(root, "exports/data") },
    { operation: "write", relative: "exports/data", value: "replacement" },
    { operation: "read", relative: "exports/data" },
    { operation: "remove", relative: "exports/data" },
    { operation: "remove", relative: "exports/data" },
  ]);
  expect(results[3]).toEqual({
    length: size,
    digest: digest(Buffer.alloc(size, 0xa5)),
  });
  expect(results[4]).toBe(digest(Buffer.alloc(size, 0xa5)));
  expect(results[6]).toEqual(results[2]);
  expect(results[8]).toEqual({ length: 11, digest: digest("replacement") });
  expect(results.slice(9)).toEqual([null, null]);
  if (process.platform !== "win32")
    expect(results[2]).toMatchObject({ mode: 0o600 });
});

test("rejects noncanonical roots and unsafe output paths while preserving external names", () => {
  const { results } = run((root, parent) => [
    {
      operation: "link",
      path: join(parent, "alias"),
      target: root,
      directory: true,
    },
    { operation: "root", path: join(parent, "alias") },
    { operation: "mkdir", path: join(root, "nested") },
    { operation: "validate", path: join(parent, "outside/file") },
    {
      operation: "link",
      path: join(root, "linked"),
      target: join(parent, "outside"),
      directory: true,
    },
    { operation: "validate", path: join(root, "linked/file") },
    { operation: "write", relative: "../outside/file", value: "blocked" },
    { operation: "write", relative: "x/y", value: "blocked", external: true },
    {
      operation: "write",
      relative: "output.json",
      value: "external",
      external: true,
    },
    { operation: "read", relative: "output.json" },
  ]);
  expect(error(results[1])).toContain("non-symlink directory");
  expect(error(results[3])).toContain("inside the scan directory");
  expect(error(results[5])).toContain("inside the scan directory");
  expect(error(results[6])).toContain("safe repository-relative");
  expect(error(results[7])).toContain("safe file name");
  expect(results[9]).toEqual({ length: 8, digest: digest("external") });
});

test.skipIf(process.platform === "win32")(
  "held parent descriptors keep reads, writes and cleanup on the originally opened directory",
  () => {
    for (const operation of ["read", "write", "remove"] as const) {
      const { root, parent, results } = run((root, parent) => [
        { operation: "mkdir", path: join(root, "nested") },
        {
          operation: "file",
          path: join(root, "nested/data"),
          value: "original",
        },
        {
          operation: "file",
          path: join(parent, "outside/data"),
          value: "outside",
        },
        { operation: "race", value: "parent" },
        operation === "write"
          ? { operation, relative: "nested/data", value: "updated" }
          : { operation, relative: "nested/data" },
        { operation: "metadata", path: join(parent, "outside/data") },
        { operation: "metadata", path: join(parent, "moved/data") },
      ]);
      if (operation === "read")
        expect(results[4]).toEqual({ length: 8, digest: digest("original") });
      else expect(results[4]).toBeNull();
      expect(results[5]).toMatchObject({ size: "7", file: true });
      if (operation === "remove") expect(error(results[6])).toContain("ENOENT");
      else
        expect(results[6]).toMatchObject({
          size: operation === "write" ? "7" : "8",
        });
      expect(root).toContain(parent);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "detects root and existing-file replacement at open, and cleans a failed temporary write",
  () => {
    const rootRace = run(() => [
      { operation: "race", value: "root" },
      { operation: "write", relative: "data", value: "blocked" },
    ]).results;
    expect(error(rootRace[1])).toContain("changed while it was being opened");
    const leafRace = run((root) => [
      { operation: "file", path: join(root, "data"), value: "original" },
      { operation: "race", value: "leaf" },
      { operation: "write", relative: "data", value: "blocked" },
      { operation: "read", relative: "data" },
    ]).results;
    expect(error(leafRace[2])).toContain("changed while it was being opened");
    expect(leafRace[3]).toEqual({ length: 7, digest: digest("swapped") });
    const flush = run((root) => [
      { operation: "write", relative: "data", value: "old" },
      { operation: "race", value: "flush" },
      { operation: "write", relative: "data", value: "new" },
      { operation: "read", relative: "data" },
      { operation: "names", path: root },
    ]);
    expect(error(flush.results[2])).toBe("synthetic flush failure");
    expect(flush.results[3]).toEqual({ length: 3, digest: digest("old") });
    expect(flush.results[4]).toEqual(["data"]);
  },
);

test.skipIf(process.platform === "win32")(
  "rejects FIFOs without blocking and symlink reads while cleanup removes a leaf link",
  () => {
    const { results } = run((root, parent) => [
      { operation: "fifo", path: join(root, "pipe") },
      { operation: "read", relative: "pipe" },
      { operation: "remove", relative: "pipe" },
      { operation: "file", path: join(root, "data"), value: "inside" },
      { operation: "link", path: join(root, "internal"), target: "data" },
      { operation: "read", relative: "internal" },
      {
        operation: "file",
        path: join(parent, "outside/data"),
        value: "outside",
      },
      {
        operation: "link",
        path: join(root, "external"),
        target: join(parent, "outside/data"),
      },
      { operation: "read", relative: "external" },
      { operation: "write", relative: "external", value: "blocked" },
      { operation: "remove", relative: "external" },
      { operation: "metadata", path: join(parent, "outside/data") },
    ]);
    expect(error(results[1])).toContain("regular non-symlink file");
    expect(error(results[2])).toContain("regular file or symlink");
    expect(error(results[5])).toContain("regular non-symlink file");
    expect(error(results[8])).toContain("file inside the scan directory");
    expect(error(results[9])).toContain("regular non-symlink file");
    expect(results[10]).toBeNull();
    expect(results[11]).toMatchObject({ size: "7" });
  },
);

test.skipIf(process.platform === "win32")(
  "retains a verified open file after its pathname is replaced, and allows POSIX external backslashes",
  () => {
    const { results } = run((root) => [
      { operation: "write", relative: "data", value: "original" },
      { operation: "open", relative: "data" },
      {
        operation: "rename",
        path: join(root, "data"),
        destination: join(root, "saved"),
      },
      { operation: "file", path: join(root, "data"), value: "replacement" },
      { operation: "read-held" },
      { operation: "close" },
      {
        operation: "write",
        relative: "result\\v1",
        value: "external",
        external: true,
      },
      { operation: "metadata", path: join(root, "result\\v1") },
    ]);
    expect(results[4]).toEqual({ length: 8, digest: digest("original") });
    expect(results[7]).toMatchObject({ size: "8", mode: 0o600 });
  },
);
