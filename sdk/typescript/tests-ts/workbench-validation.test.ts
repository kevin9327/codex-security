import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/workbench-validation-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-validation-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-validation-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function request(operation: string, args: unknown): Request {
  return { operation, source: JSON.stringify(args) };
}
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
const decoded = (response: Response) => JSON.parse(response.result!);

test("normalizes UUID forms shared with scan lookup and keeps label-specific failures", () => {
  const values = run(
    request("uuid", {
      value: "urn:uuid:{12345678-1234-5678-90AB-123456789ABC}",
    }),
    request("uuid", { value: "١٢٣٤٥٦٧٨١٢٣٤٥٦٧٨٩٠ab١٢٣٤٥٦٧٨٩abc" }),
    request("uuid", { value: "0x" + "0".repeat(30) }),
    request("uuid", { value: "12345678" }),
  );
  expect(values.slice(0, 2).map(decoded)).toEqual(
    Array(2).fill("12345678-1234-5678-90ab-123456789abc"),
  );
  expect(decoded(values[2]!)).toBe("00000000-0000-0000-0000-000000000000");
  expect(values[3]).toMatchObject({
    kind: "WorkbenchValidationError",
    error: "id must be a UUID.",
  });
});

test("normalizes user text by code points and only reads requested stdin", () => {
  const values = run(
    request("text", { value: "\u001c\u2000😀😀\u2029", maximum: 2 }),
    request("text", { value: "\ufeffx\ufeff" }),
    request("text", { value: "😀😀", maximum: 1 }),
    request("context", { value: " saved ", stdin: false, input: "ignored" }),
    request("context", { value: "ignored", stdin: true, input: "  context\n" }),
    request("busy", { value: "database is LOCKED" }),
    request("busy", { value: "other failure" }),
  );
  expect(values.slice(0, 2).map(decoded)).toEqual(["😀😀", "\ufeffx\ufeff"]);
  expect(values[2]?.error).toBe(
    "Text value must be no longer than 1 characters.",
  );
  expect(values[3]).toEqual({ result: '"saved"', reads: 0 });
  expect(values[4]).toEqual({ result: '"context"', reads: 1 });
  expect(values.slice(5).map(decoded)).toEqual([true, false]);
});

test("uses POSIX scope ancestry and preserves close-note requirements", () => {
  const values = run(
    ...[
      ["a//./b", "a"],
      ["a/../b", "a"],
      ["/a/b", "."],
      ["a\\b", "."],
      ["ab", "a"],
    ].map(([path, scope]) => request("scope", { path, scope })),
    request("note", { reason: "false_positive", note: null }),
    request("note", { reason: "wont_fix", note: null }),
    request("note", { reason: "false_positive", note: "" }),
  );
  expect(values.slice(0, 5).map(decoded)).toEqual([
    true,
    false,
    false,
    true,
    false,
  ]);
  expect(values[5]?.error).toBe(
    "Explain why this finding is a false positive.",
  );
  expect(values[6]?.error).toBe("Explain why this finding will not be fixed.");
  expect(decoded(values[7]!)).toBeNull();
});

const legacy =
  '{"model":"example, : ","inputTokens":9007199254740993,"cachedInputTokens":2,"cacheWriteInputTokens":3,"outputTokens":4,"estimatedUsd":0.0,"10":1,"2":["a, b: c"]}';
test("keeps exact legacy cost integers, float spelling, separators and key order", () => {
  const value = run(request("cost", { value: legacy }))[0]!;
  expect(decoded(value)).toBe(legacy);
  const invalid = run(
    request("cost", {
      value: legacy.replace('"outputTokens":4', '"outputTokens":true'),
    }),
  )[0]!;
  expect(invalid.error).toContain("nonnegative token counts");
});

test("validates measured usage, including complete/partial/unavailable accounting", () => {
  const usage = {
    coverage: "complete",
    source: "codex_rollout",
    threadCount: 1,
    inputTokens: 10,
    cachedInputTokens: 2,
    cacheWriteInputTokens: 3,
    outputTokens: 4,
    reasoningOutputTokens: 1,
    totalTokens: 14,
  };
  const values = run(
    request("measured", { value: usage }),
    request("measured", { value: { ...usage, warnings: ["missing_thread"] } }),
    request("measured", {
      value: { ...usage, coverage: "partial", warnings: ["missing_thread"] },
    }),
    request("measured", {
      value: { ...usage, coverage: "partial", warnings: ["missing_thread\n"] },
    }),
    request("measured", {
      value: {
        coverage: "unavailable",
        source: "codex_rollout",
        threadCount: 0,
      },
    }),
    request("measured", {
      value: { ...usage, coverage: "unavailable", threadCount: 0 },
    }),
    request("cost", {
      value: JSON.stringify({ usage: { ...usage, coverage: [] } }),
    }),
  );
  expect(values.slice(0, 6).map(decoded)).toEqual([
    true,
    false,
    true,
    false,
    true,
    false,
  ]);
  expect(values[6]).toMatchObject({
    kind: "TypeError",
    error: "unhashable type: 'list'",
  });
});

test("retains cost byte limits and numeric failure order", () => {
  const values = run(
    request("cost", { value: "x".repeat(8193) }),
    request("cost", { value: '{"cost":NaN}' }),
    request("cost", { value: '{"x":' + "1".repeat(4301) + "}" }),
    request("cost", { value: "\ud800" }),
    request("cost", {
      value: legacy.replace(
        '"estimatedUsd":0.0',
        '"estimatedUsd":' + "1" + "0".repeat(310),
      ),
    }),
  );
  expect(values[0]?.error).toBe("Scan cost must be no larger than 8 KiB.");
  expect(values.slice(1, 3).map((value) => value.error)).toEqual(
    Array(2).fill("Scan cost must be a valid JSON object."),
  );
  expect(values[3]?.error).toContain("surrogates not allowed");
  expect(values[4]).toMatchObject({
    kind: "RangeError",
    error: "int too large to convert to float",
  });
});

test("truncates encoded output without replacement characters and retains its BOM", () => {
  const values = run(
    request("bounded", { value: "é中😀", maximum: 4 }),
    request("bounded", { value: "é中😀", maximum: -1 }),
    request("bounded", { value: "\ufeffx", maximum: 4 }),
    request("bounded", { value: [true, null, "x"], maximum: 100 }),
  );
  expect(values.map(decoded)).toEqual([
    "é",
    "é中",
    "\ufeffx",
    "[True, None, 'x']",
  ]);
});

test("looks up occurrences only after required text and code-point length checks", () => {
  const values = run(
    ...[" known\n", " ", "missing", "😀".repeat(257)].map((value) =>
      request("occurrence", { value }),
    ),
  );
  expect(decoded(values[0]!)).toEqual({
    id: "known",
    details: "record",
    ordinal: 1,
  });
  expect(values.slice(1).map((value) => value.error)).toEqual([
    "occurrence-id is required.",
    "Codex Security finding occurrence not found.",
    "Text value must be no longer than 256 characters.",
  ]);
});
