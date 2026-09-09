import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Operation } from "./support/deep-files-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(mkdtempSync(join(tmpdir(), "deep-files-")));
const scan = join(root, "scan"),
  file = join(scan, "file"),
  directory = join(scan, "directory"),
  outside = join(root, "outside"),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() => {
  mkdirSync(scan, { mode: 0o700 });
  mkdirSync(directory);
  mkdirSync(outside);
  writeFileSync(file, "original bytes\n");
  writeFileSync(join(outside, "file"), "outside bytes\n");
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/deep-files-fixture.ts", import.meta.url),
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
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
interface Result {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  calls: string[];
}
function run(operations: Operation[]): Result[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(operations),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/missing/python", HOME: scan },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return parseJson(child.stdout) as Result[];
}
const path = (value: string, pathKind = "file"): Operation => ({
  kind: "path",
  scanDir: scan,
  value,
  label: "Artifact",
  pathKind,
});
const output = (value: string): Operation => ({
  kind: "output",
  scanDir: scan,
  value,
  label: "Artifact",
});
const deadline = (created: string, now: string, hours: number): Operation => ({
  kind: "deadline",
  created,
  now,
  hours,
});

test("paths preserve absolute, containment, canonical and file-kind checks in their original order", () => {
  const results = run([
    path(file),
    path(directory, "directory"),
    path(directory),
    path(file, "directory"),
    path("relative"),
    path(join(scan, "missing")),
    path(join(outside, "file")),
    path(`${directory}/../file`),
    path(`${scan}/./file`),
    path(directory, "other"),
  ]);
  expect(results.map((result) => result.value)).toEqual([
    file,
    directory,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    file,
    directory,
  ]);
  expect(results[2]!.error).toBe("Artifact must be a regular file.");
  expect(results[3]!.error).toBe("Artifact must be a directory.");
  expect(results[4]).toMatchObject({
    error: "Artifact must be an absolute path inside the scan directory.",
    calls: [],
    systemExit: true,
  });
  expect(results[5]).toMatchObject({
    error: "Artifact must be an existing path inside the scan directory.",
    calls: [],
  });
  expect(results[6]).toMatchObject({
    error: "Artifact must be an existing path inside the scan directory.",
    calls: [scan],
  });
  expect(results[7]!.error).toBe(
    "Artifact must be a canonical non-symlink path.",
  );
});

test("the canonical scan-directory dependency retains privacy errors and is called before containment", () => {
  const callbackError = [
    "validation",
    "runtime",
    "value",
    "os",
    "type",
  ] as const;
  const results = run(
    callbackError.map((error) => ({
      kind: "path",
      value: join(outside, "file"),
      scanDir: scan,
      label: "Artifact",
      callbackError: error,
    })),
  );
  expect(
    results.every(
      (result) => result.calls.length === 1 && result.calls[0] === scan,
    ),
  ).toBe(true);
  expect(results[0]).toMatchObject({
    error: "Scan directory must be private.",
    systemExit: true,
  });
  for (const result of results.slice(1, 4))
    expect(result).toMatchObject({
      error: "Artifact must be an existing path inside the scan directory.",
      systemExit: true,
    });
  expect(results[4]).toMatchObject({
    error: "canonical type failure",
    systemExit: false,
  });
});

test("output paths allow an absent leaf only after checking its existing parent and never write files", () => {
  const missing = join(directory, "new.json");
  const results = run([
    output(file),
    output(missing),
    output(directory),
    output(join(scan, "missing", "new.json")),
    output(`${directory}/../new.json`),
  ]);
  expect(results[0]!.value).toBe(file);
  expect(results[1]).toEqual({ value: missing, calls: [scan] });
  expect(results[2]!.error).toBe("Artifact must be a regular file.");
  expect(results[3]!.error).toBe(
    "Artifact must be an existing path inside the scan directory.",
  );
  expect(results[4]!.error).toBe(
    "Artifact must be a canonical non-symlink path.",
  );
  expect(existsSync(missing)).toBe(false);
  expect(readFileSync(file, "utf8")).toBe("original bytes\n");
});

test("POSIX links, inaccessible paths and encoded filenames retain the original path behavior", () => {
  if (process.platform === "win32") return;
  const alias = join(scan, "alias"),
    broken = join(scan, "broken"),
    raw = `${scan}/raw-${process.platform === "darwin" ? "λ" : "\udcff"}`;
  symlinkSync(file, alias);
  symlinkSync("missing-target", broken);
  writeFileSync(
    Buffer.concat([
      Buffer.from(`${scan}/raw-`),
      process.platform === "darwin" ? Buffer.from("λ") : Buffer.from([255]),
    ]),
    "raw",
  );
  const nul = `${scan}/nul\0leaf`,
    unpaired = `${scan}/unpaired-\ud800`;
  const results = run([
    path(alias),
    output(alias),
    path(broken),
    output(broken),
    path(raw),
    output(nul),
    output(unpaired),
    path("~/file"),
  ]);
  expect(results[0]!.error).toBe(
    "Artifact must be a canonical non-symlink path.",
  );
  expect(results[1]!.error).toBe(results[0]!.error);
  expect(results[2]!.error).toBe(
    "Artifact must be an existing path inside the scan directory.",
  );
  expect(results.slice(3).map((result) => result.value)).toEqual([
    broken,
    raw,
    nul,
    unpaired,
    file,
  ]);
  expect(readlinkSync(alias)).toBe(file);
  expect(readlinkSync(broken)).toBe("missing-target");
  if (process.getuid?.() !== 0) {
    const denied = join(scan, "denied");
    mkdirSync(denied);
    writeFileSync(join(denied, "file"), "private");
    chmodSync(denied, 0);
    try {
      expect(run([path(join(denied, "file"))])[0]).toMatchObject({
        error: "Artifact must be an existing path inside the scan directory.",
        calls: [],
      });
    } finally {
      chmodSync(denied, 0o700);
    }
  }
});

test("discovery deadlines retain microseconds, fractional hours, future starts and timezone offsets", () => {
  const results = run([
    deadline("2026-01-01T11:00:00Z", "2026-01-01T11:59:59.999999Z", 1),
    deadline("2026-01-01T11:00:00z", "2026-01-01T12:00:00Z", 1),
    deadline("2026-01-01T11:00:00Z", "2026-01-01T12:00:00.000001Z", 1),
    deadline("2026-01-01T11:00:00Z", "2026-01-01T13:29:59.999999Z", 2.5),
    deadline("2026-01-01T11:00:00Z", "2026-01-01T13:30:00Z", 2.5),
    deadline("2026-01-01T11:00:00+02:00", "2026-01-01T10:00:00Z", 1),
    deadline("2026-01-02T11:00:00Z", "2026-01-01T11:00:00Z", 1),
    deadline("2026-01-01T11:00:00", "2026-01-05T11:00:00", 96),
  ]);
  expect(results.map((result) => result.value)).toEqual([
    false,
    true,
    true,
    false,
    true,
    true,
    false,
    true,
  ]);
  expect(results.every((result) => result.calls.length === 0)).toBe(true);
});

test("ISO timestamps preserve basic and week dates, Unicode separators and subsecond offsets", () => {
  const values = [
    "20260101T123456.123456789Z",
    "2026-01-01😀12:34:56.123456+00:00",
    "2026-W01-4T12:34:56.123456Z",
    "2026W014T123456,123456Z",
    "2026-01-01T12:34:56.123456+00:00:01.1",
    "2026-01-01T12:34:56.123456+00:00:00.1",
    "2026-01-01T12.5",
    "0001-01-01T00:00:00Z",
  ];
  const results = run(values.map((value) => ({ kind: "timestamp", value })));
  for (const result of results.slice(0, 4))
    expect(result.value).toEqual({
      microseconds: 1767270896123456n,
      aware: true,
    });
  expect(results[4]!.value).toEqual({
    microseconds: 1767270895023456n,
    aware: true,
  });
  expect(results[5]!.value).toEqual(results[0]!.value);
  expect(results[6]!.value).toEqual({
    microseconds: 1767268800500000n,
    aware: false,
  });
  expect(results[7]!.value).toEqual({
    microseconds: -62135596800000000n,
    aware: true,
  });
});

test("invalid clocks, dates and mixed timezone awareness retain their original diagnostics", () => {
  const results = run([
    { kind: "timestamp", value: "2026-01-01T" },
    { kind: "timestamp", value: "2026-02-29T12:00:00" },
    { kind: "timestamp", value: "2026-01-01T24:00:00" },
    { kind: "timestamp", value: "2026-01-01T12:00:00+24:00" },
    deadline("2026-01-01T11:00:00", "2026-01-01T12:00:00Z", 1),
    {
      kind: "deadline",
      created: parseJson("1.0"),
      now: "2026-01-01T00:00:00Z",
      hours: 1,
    },
  ]);
  expect(results.map((result) => result.error)).toEqual([
    "Invalid isoformat string: '2026-01-01T'",
    "day is out of range for month",
    "hour must be in 0..23",
    "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24), not datetime.timedelta(days=1).",
    "can't subtract offset-naive and offset-aware datetimes",
    "Invalid isoformat string: '1.0'",
  ]);
  expect(results.every((result) => result.systemExit === false)).toBe(true);
});

test("ISO whole-second NUL terminators preserve the original parser distinction from fractional seconds", () => {
  const results = run([
    { kind: "timestamp", value: "2026-01-01T00:00:00\0" },
    { kind: "timestamp", value: "2026-01-01T00:00:00Z\0suffix" },
    { kind: "timestamp", value: "2026-01-01T00:00:00.123\0" },
  ]);
  expect(results[0]!.value).toEqual({
    microseconds: 1767225600000000n,
    aware: false,
  });
  expect(results[1]!.value).toEqual({
    microseconds: 1767225600000000n,
    aware: true,
  });
  expect(results[2]!.error).toBe(
    "Invalid isoformat string: '2026-01-01T00:00:00.123\\x00'",
  );
});
