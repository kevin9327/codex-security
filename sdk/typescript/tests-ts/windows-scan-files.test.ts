import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { Request } from "./support/windows-scan-files-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const directory = mkdtempSync(join(tmpdir(), "windows-scan-files-"));
const fixture = join(directory, "fixture.cjs");
const node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/windows-scan-files-fixture.ts", import.meta.url),
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
interface ModelResult {
  results: (
    | { error?: string; length?: number; digest?: string; size?: string }
    | null
    | boolean
  )[];
  entries: { path: string; length: number; digest: string }[];
  openHandles: number;
  temporaryFiles: number;
  blockedMoves: number;
  writes: number;
  flushes: number;
  renames: number;
  maxRead: number;
  maxWrite: number;
}
function run<T>(request: Request): T {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(request),
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as T;
}
const digest = (value: Buffer) =>
  createHash("sha256").update(value).digest("hex");
const error = (result: ModelResult, index: number) =>
  (result.results[index] as { error: string }).error;

test("retains Windows alias rejection and pathlib component normalization", () => {
  const bad = [
    "",
    ".",
    "/root",
    "x/../y",
    "x\\y",
    "x\0y",
    "x/result:stream",
    "x/C:result",
    "x/NUL.json",
    "x/COM1",
    "x/COM¹.txt",
    "x/trailing.",
    "x/trailing ",
  ];
  const result = run<{ parts?: string[]; error?: string }[]>({
    mode: "paths",
    paths: [
      ...bad,
      "./artifacts//02_discovery/./work.jsonl",
      "x/COM10",
      "x/雪-\ud800",
    ],
  });
  expect(
    result
      .slice(0, bad.length)
      .every((item) => item.error?.startsWith("[Errno 22]")),
  ).toBe(true);
  expect(result.slice(bad.length)).toEqual([
    { parts: ["artifacts", "02_discovery", "work.jsonl"] },
    { parts: ["x", "COM10"] },
    { parts: ["x", "雪-\ud800"] },
  ]);
});

test("stream equality handles short reads, empty input, and trailing or changed bytes", () => {
  expect(
    run<boolean[]>({
      mode: "streams",
      cases: [
        { expected: "", actual: "" },
        { expected: "", actual: "extra" },
        {
          expected: "x".repeat(131073),
          actual: "x".repeat(131073),
          shortRead: 17,
        },
        { expected: "same", actual: "same extra" },
        { expected: "longer", actual: "long" },
        { expected: "equal", actual: "differ" },
      ],
    }),
  ).toEqual([true, false, true, false, false, false]);
});

test("models held ancestor and leaf locks, short I/O, replacement and cleanup", () => {
  const size = 1024 * 1024 + 13;
  const result = run<ModelResult>({
    mode: "model",
    options: { shortWrite: 270001, shortRead: 31, raceMoves: true },
    actions: [
      { operation: "write", relative: "exports/data", size },
      { operation: "read", relative: "exports/data", hold: true },
      { operation: "move", path: "C:\\work\\scan\\exports\\data" },
      { operation: "close" },
      { operation: "write", relative: "exports/data", value: "replacement" },
      { operation: "read", relative: "exports/data" },
      { operation: "delete", relative: "exports/data" },
      { operation: "delete", relative: "exports/data" },
    ],
  });
  expect(result.results[1]).toEqual({
    length: size,
    size: String(size),
    digest: digest(Buffer.alloc(size, 0xa5)),
  });
  expect(result.results[2]).toBe(false);
  expect(result.results[5]).toMatchObject({
    length: 11,
    digest: digest(Buffer.from("replacement")),
  });
  expect(result.blockedMoves).toBeGreaterThan(5);
  expect(result.openHandles).toBe(0);
  expect(result.temporaryFiles).toBe(0);
  expect(result.entries.some((entry) => entry.path.endsWith("\\data"))).toBe(
    false,
  );
  expect(result.maxWrite).toBe(1024 * 1024);
});

test("restoration binds root identity, compares the entire existing payload and preserves identical files", () => {
  const result = run<ModelResult>({
    mode: "model",
    actions: [
      { operation: "identity" },
      { operation: "write", relative: "data", size: 131073, expected: true },
      { operation: "write", relative: "data", size: 131073, expected: true },
      {
        operation: "write",
        relative: "data",
        value: "changed",
        expected: true,
      },
      { operation: "replaceRoot" },
      {
        operation: "write",
        relative: "data",
        value: "blocked",
        expected: true,
      },
    ],
  });
  expect(result.renames).toBe(2);
  expect(result.maxRead).toBe(64 * 1024);
  expect(error(result, 5)).toContain(
    "changed after artifact restoration setup",
  );
  expect(result.openHandles).toBe(0);
  expect(
    result.entries.find((entry) => entry.path.endsWith("\\data"))?.digest,
  ).toBe(digest(Buffer.from("changed")));
  const changed = run<ModelResult>({
    mode: "model",
    options: { replaceRootBeforeLock: true },
    actions: [{ operation: "write", relative: "data", value: "blocked" }],
  });
  expect(error(changed, 0)).toContain("changed while it was being opened");
  expect(changed.openHandles).toBe(0);
  expect(changed.writes).toBe(0);
});

test("reparse ancestors and output leaves cannot redirect reads or writes; cleanup removes only the reparse leaf", () => {
  const result = run<ModelResult>({
    mode: "model",
    actions: [
      {
        operation: "add",
        path: "C:\\work\\scan\\link",
        directory: true,
        target: "C:\\outside",
      },
      { operation: "write", relative: "link/new", value: "blocked" },
      { operation: "read", relative: "link/kept" },
      { operation: "write", relative: "link", value: "blocked" },
      { operation: "delete", relative: "link" },
      { operation: "add", path: "C:\\work\\scan\\directory", directory: true },
      { operation: "delete", relative: "directory" },
    ],
  });
  expect(error(result, 1)).toContain("directories must not be reparse");
  expect(error(result, 2)).toContain("test read: scan-local directories");
  expect(error(result, 3)).toContain("files must not be reparse");
  expect(error(result, 6)).toContain("must not be a directory");
  expect(
    result.entries.find((entry) => entry.path === "C:\\outside\\kept")?.digest,
  ).toBe(digest(Buffer.from("outside")));
  expect(result.entries.some((entry) => entry.path.endsWith("\\link"))).toBe(
    false,
  );
  expect(result.openHandles).toBe(0);
});

test("failed writes clean the exact opened object, including after rename, and exhaust only the existing collision budget", () => {
  for (const options of [
    { noWriteProgress: true },
    { writeError: 5 },
    { flushError: 5 },
    { renameError: 5 },
    { finalMismatchAfterRename: true },
    { collide: 16 },
  ]) {
    const result = run<ModelResult>({
      mode: "model",
      options,
      actions: [{ operation: "write", relative: "data", value: "new" }],
    });
    expect(error(result, 0)).toBeDefined();
    expect(result.openHandles).toBe(0);
    expect(result.temporaryFiles).toBe(0);
    expect(result.entries.some((entry) => entry.path.endsWith("\\data"))).toBe(
      false,
    );
  }
  const cleanupFailure = run<ModelResult>({
    mode: "model",
    options: { writeError: 5, dispositionError: 32 },
    actions: [{ operation: "write", relative: "data", value: "new" }],
  });
  expect(error(cleanupFailure, 0)).toContain("WriteFile");
  expect(cleanupFailure.openHandles).toBe(0);
  expect(cleanupFailure.temporaryFiles).toBe(1);
});

test("rename encoding rejects lone surrogates after writing and preserves existing files during cleanup", () => {
  for (const suffix of ["\ud800", "\udfff"]) {
    const leaf = `data-${suffix}`;
    const result = run<ModelResult>({
      mode: "model",
      actions: [
        { operation: "add", path: `C:\\work\\scan\\${leaf}`, value: "old" },
        { operation: "write", relative: leaf, value: "new" },
        { operation: "read", relative: leaf },
        { operation: "delete", relative: leaf },
      ],
    });
    expect(error(result, 1)).toContain(
      "'utf-16-le' codec can't encode character",
    );
    expect(result.writes).toBe(1);
    expect(result.flushes).toBe(1);
    expect(result.renames).toBe(0);
    expect(result.results[2]).toMatchObject({
      length: 3,
      digest: digest(Buffer.from("old")),
    });
    expect(result.results[3]).toBeNull();
    expect(result.openHandles).toBe(0);
    expect(result.temporaryFiles).toBe(0);
  }
  const valid = run<ModelResult>({
    mode: "model",
    actions: [{ operation: "write", relative: "data-😀", value: "new" }],
  });
  expect(valid.results[0]).toBeNull();
  expect(valid.renames).toBe(1);
});

test("busy or unreadable restoration comparisons fall through to replacement", () => {
  for (const options of [
    { comparisonOpenError: 5 },
    { comparisonOpenError: 32 },
    { comparisonOpenError: 33 },
    { readError: 5 },
  ]) {
    const result = run<ModelResult>({
      mode: "model",
      options,
      actions: [
        { operation: "identity" },
        { operation: "add", path: "C:\\work\\scan\\data", value: "old" },
        { operation: "write", relative: "data", value: "new", expected: true },
      ],
    });
    expect(result.results[2]).toBeNull();
    expect(result.renames).toBe(1);
    expect(result.openHandles).toBe(0);
  }
});

test.skipIf(process.platform !== "win32")(
  "native Windows reads, writes, replaces and cleans scan-local files without Python",
  () => {
    expect(
      run<Record<string, boolean>>({ mode: "native", root: directory }),
    ).toEqual({
      readWriteReplaceDelete: true,
      rejectedJunctionAncestor: true,
      deletedJunctionLeaf: true,
    });
  },
);
