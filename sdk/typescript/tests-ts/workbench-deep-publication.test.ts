import { spawnSync } from "node:child_process";
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/deep-publication-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "deep-publication-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/deep-publication-fixture.ts", import.meta.url),
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
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
function paths() {
  const root = realpathSync(mkdtempSync(join(directory, "artifacts Σ ")));
  return {
    root,
    source: join(root, "staged"),
    destination: join(root, "published"),
  };
}
const backup = (destination: string) =>
  join(
    destination,
    "..",
    `.${basename(destination)}.00000000-0000-4000-8000-000000000000.backup`,
  );

test("publication preserves the previous artifact until rollback or finish", () => {
  for (const action of ["rollback", "finish"] as const) {
    const { source, destination } = paths();
    writeFileSync(source, "new bytes");
    writeFileSync(destination, "old bytes");
    const promoted = run({ kind: "promote", source, destination })[0]!;
    expect(promoted.result).toEqual([source, destination, backup(destination)]);
    expect(readFileSync(destination, "utf8")).toBe("new bytes");
    expect(readFileSync(backup(destination), "utf8")).toBe("old bytes");
    expect(existsSync(source)).toBe(false);
    expect(
      run({
        kind: action,
        promotion: promoted.result as [string, string, string],
      }),
    ).toEqual([{ result: null }]);
    expect(readFileSync(destination, "utf8")).toBe(
      action === "rollback" ? "old bytes" : "new bytes",
    );
    expect(existsSync(backup(destination))).toBe(false);
    expect(existsSync(source)).toBe(action === "rollback");
  }
});

test("publication without a previous artifact rolls back and cleanup is repeatable", () => {
  const { source, destination } = paths();
  writeFileSync(source, "bytes");
  expect(
    run(
      { kind: "promote", source, destination },
      { kind: "rollback" },
      { kind: "finish" },
    ),
  ).toEqual([
    { result: [source, destination, null] },
    { result: null },
    { result: null },
  ]);
  expect(readFileSync(source, "utf8")).toBe("bytes");
  expect(existsSync(destination)).toBe(false);
  expect(
    run({
      kind: "finish",
      promotion: [source, destination, backup(destination)],
    }),
  ).toEqual([{ result: null }]);
});

test("failed staged replacement restores the previous output and equal paths fail before writes", () => {
  const { source, destination } = paths();
  writeFileSync(destination, "old bytes");
  expect(run({ kind: "promote", source, destination })[0]!.error).toBeDefined();
  expect(readFileSync(destination, "utf8")).toBe("old bytes");
  expect(existsSync(backup(destination))).toBe(false);
  const equal = run({
    kind: "promote",
    source: destination + "/./",
    destination,
  })[0]!;
  expect(equal.systemExit).toBe(true);
  expect(readFileSync(destination, "utf8")).toBe("old bytes");
});

test("publication copies use hard links and overwrite existing files with metadata", () => {
  const { root, source, destination } = paths();
  writeFileSync(source, Buffer.from([0, 255, 26, 13, 10]));
  utimesSync(
    source,
    new Date("2026-01-01T00:00:00Z"),
    new Date("2026-01-02T00:00:00Z"),
  );
  expect(run({ kind: "copy", source, destination })).toEqual([
    { result: null },
  ]);
  writeFileSync(source, "shared bytes");
  expect(readFileSync(destination, "utf8")).toBe("shared bytes");
  const other = join(root, "existing");
  writeFileSync(other, "old");
  expect(run({ kind: "copy", source, destination: other })).toEqual([
    { result: null },
  ]);
  expect(readFileSync(other, "utf8")).toBe("shared bytes");
  expect(statSync(other).mtimeMs).toBe(statSync(source).mtimeMs);
  const outputDirectory = join(root, "output");
  mkdirSync(outputDirectory);
  expect(run({ kind: "copy", source, destination: outputDirectory })).toEqual([
    { result: null },
  ]);
  expect(readFileSync(join(outputDirectory, basename(source)), "utf8")).toBe(
    "shared bytes",
  );
});

test("copy failures preserve the source and retain platform error semantics", () => {
  const { source, destination } = paths();
  writeFileSync(source, "source");
  linkSync(source, destination);
  const strings = run({ kind: "copy", source, destination })[0]!;
  const pathArguments = run({
    kind: "copy",
    source,
    destination,
    sourceIsPath: true,
    destinationIsPath: true,
  })[0]!;
  if (process.platform === "win32") {
    expect(strings.error).toStartWith("[WinError 32]");
    expect(pathArguments.error).toBe(strings.error);
  } else {
    expect(strings.error).toContain("are the same file");
    expect(strings.error).not.toContain("Path(");
    expect(pathArguments.error).toContain("PosixPath(");
  }
  expect(readFileSync(source, "utf8")).toBe("source");
});

test("copy fallback keeps the existing filesystem error and failing path", () => {
  const { root, source, destination } = paths();
  const missing = run({ kind: "copy", source, destination })[0]!;
  expect(missing.error).toStartWith(
    process.platform === "win32" ? "[WinError 2]" : "[Errno 2]",
  );
  if (process.platform !== "win32") expect(missing.error).toContain(source);
  expect(existsSync(destination)).toBe(false);
  writeFileSync(source, "source");
  const noParent = join(root, "absent", "output");
  const failed = run({ kind: "copy", source, destination: noParent })[0]!;
  expect(failed.error).toStartWith(
    process.platform === "win32" ? "[WinError 3]" : "[Errno 2]",
  );
  if (process.platform !== "win32") expect(failed.error).toContain(noParent);
  expect(readFileSync(source, "utf8")).toBe("source");
});

test("snapshot comparison checks identity, size and binary chunks without changing files", () => {
  const { root, source, destination } = paths();
  const bytes = Buffer.alloc(2 * 1024 * 1024 + 7, 255);
  bytes.set([0, 26, 13, 10]);
  writeFileSync(source, bytes);
  writeFileSync(destination, bytes);
  expect(run({ kind: "matches", source, destination })).toEqual([
    { result: true },
  ]);
  bytes[1024 * 1024 + 1] = 0;
  writeFileSync(destination, bytes);
  expect(run({ kind: "matches", source, destination })).toEqual([
    { result: false },
  ]);
  const alias = join(root, "alias");
  linkSync(source, alias);
  expect(
    run(
      { kind: "matches", source, destination: alias },
      { kind: "matches", source, destination: join(root, "missing") },
      { kind: "matches", source: root, destination: root },
    ),
  ).toEqual([{ result: true }, { result: false }, { result: true }]);
  writeFileSync(destination, "short");
  expect(run({ kind: "matches", source, destination })).toEqual([
    { result: false },
  ]);
  writeFileSync(source, "");
  writeFileSync(destination, "");
  expect(run({ kind: "matches", source, destination })).toEqual([
    { result: true },
  ]);
  const link = join(root, "symlink");
  symlinkSync(source, link, "file");
  expect(run({ kind: "matches", source: link, destination })).toEqual([
    { result: true },
  ]);
});
