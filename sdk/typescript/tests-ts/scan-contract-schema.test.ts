import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/scan-contract-schema-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "scan-contract-schema-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-contract-schema-fixture.ts", import.meta.url),
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
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/missing/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const results = JSON.parse(child.stdout) as Response[];
  for (const result of results) expect(result.unchanged).toBe(true);
  return results;
}
const request = (value: unknown, schema: unknown): Request => ({
  source: JSON.stringify([value, schema]),
});
const errors = (requests: Request[]) =>
  run(requests).map((result) => result.error);

test("validates the canonical completed-scan examples and resolves their schema references", () => {
  const plugin = new URL("../../../plugins/codex-security/", import.meta.url);
  const requests: Request[] = [];
  for (const name of ["scan-manifest", "findings", "coverage"]) {
    const value: unknown = JSON.parse(
      readFileSync(
        new URL(`examples/completed-scan/${name}.json`, plugin),
        "utf8",
      ),
    );
    const schema: unknown = JSON.parse(
      readFileSync(new URL(`schemas/${name}.schema.json`, plugin), "utf8"),
    );
    requests.push(request(value, schema));
  }
  expect(errors(requests)).toEqual([null, null, null]);
});

test("contains counts complete matches before item validation and distinguishes booleans from numbers", () => {
  const schema = {
    type: "array",
    contains: { type: "integer", minimum: 2 },
    minContains: 1,
    maxContains: 2,
    items: { type: ["integer", "boolean", "string"] },
  };
  expect(
    errors([
      request([true, 1, "x"], schema),
      request([true, 2, "x"], schema),
      request([2, 3, 4], schema),
      request([2, null], schema),
      request([], { contains: {}, minContains: 0, maxContains: 0 }),
      request([true, 1], { uniqueItems: true }),
      { source: '[[1,1.0],{"uniqueItems":true}]' },
      { source: '[[1.0],{"contains":{"type":"integer"}}]' },
    ]),
  ).toEqual([
    "artifact: array contains too few matching items",
    null,
    "artifact: array contains too many matching items",
    "artifact[1]: does not match schema type ['integer', 'boolean', 'string']",
    null,
    null,
    "artifact: array items must be unique",
    "artifact: array contains too few matching items",
  ]);
});

test("object allOf and if-then share the root reference and preserve validation order", () => {
  const schema = {
    type: "object",
    $defs: {
      count: { type: "integer", minimum: 1 },
      completed: {
        required: ["count"],
        properties: { count: { $ref: "#/$defs/count" } },
      },
    },
    allOf: [{ required: ["status"] }],
    if: { properties: { status: { const: "complete" } } },
    then: { $ref: "#/$defs/completed" },
  };
  expect(
    errors([
      request({}, schema),
      request({ status: "running" }, schema),
      request({ status: "complete" }, schema),
      request({ status: "complete", count: 0 }, schema),
      request({ status: "complete", count: 1 }, schema),
      request([1], {
        allOf: [{ type: "object" }],
        if: {},
        then: { type: "object" },
      }),
      request(
        { name: 1 },
        {
          properties: { name: { $ref: "#/a~1b/~0value" } },
          "a/b": { "~value": { type: "string" } },
        },
      ),
    ]),
  ).toEqual([
    "artifact.status: missing required schema property",
    null,
    "artifact.count: missing required schema property",
    "artifact.count: value is below schema minimum",
    null,
    null,
    "artifact.name: expected schema type string",
  ]);
});

test("schema properties named like keywords are data and large custom schemas remain accepted", () => {
  const properties = Object.fromEntries(
    Array.from({ length: 4097 }, (_, index) => [`property_${index}`, {}]),
  );
  expect(
    errors([
      request(
        { name: "aaa" },
        {
          type: "object",
          allOf: Array.from({ length: 129 }, () => ({ type: "object" })),
          properties: {
            ...properties,
            name: { type: "string", pattern: "^a+$" },
          },
        },
      ),
      request(
        { $ref: "value", pattern: "^(a+)+$", uniqueItems: true },
        {
          type: "object",
          properties: {
            $ref: { type: "string" },
            pattern: { type: "string" },
            uniqueItems: { type: "boolean" },
          },
        },
      ),
      request("value", { $ref: null, type: "string" }),
    ]),
  ).toEqual([null, null, null]);
});

test("numeric constraints and schema equality preserve integer, float and boolean distinctions", () => {
  expect(
    errors([
      { source: '[9007199254740993,{"const":9007199254740992.0}]' },
      { source: '[1,{"const":1.0}]' },
      { source: '[true,{"enum":[1,1.0]}]' },
      { source: '[2,{"minimum":2.0,"maximum":2.0}]' },
      { source: '[1,{"minimum":2.0}]' },
      { source: '[[1,2],{"minItems":2.0,"maxItems":2.0}]' },
      { source: '[{"a":1},{"minProperties":2.0}]' },
      request([{ x: true }, { x: 1 }], { uniqueItems: true }),
      request([{ x: 1 }, { x: 1 }], { uniqueItems: true }),
    ]),
  ).toEqual([
    "artifact: expected 9007199254740992.0",
    null,
    "artifact: unsupported value True",
    null,
    "artifact: value is below schema minimum",
    null,
    "artifact: object has too few properties",
    null,
    "artifact: array items must be unique",
  ]);
});

test("patterns match complete Unicode strings and retain Python dot behavior at line separators", () => {
  expect(
    errors([
      request("😀", { minLength: 2 }),
      request("😀x", { minLength: 2 }),
      ...["x\rx", "x\u2028x", "x\u2029x"].map((value) =>
        request(value, { pattern: "^.+$" }),
      ),
      request("x\nx", { pattern: "^.+$" }),
      request("a\n", { pattern: "^a$" }),
      request("...", { pattern: "[.]+" }),
      request("a.b", { pattern: "a\\.b" }),
      request("findings/one/one.md", {
        pattern: "^findings/([a-z0-9][a-z0-9._-]*)/\\1\\.md$",
      }),
    ]),
  ).toEqual([
    "artifact: string is too short",
    null,
    null,
    null,
    null,
    "artifact: string does not match schema pattern",
    "artifact: string does not match schema pattern",
    null,
    null,
    null,
  ]);
});

test("date-time validates calendar fields and preserves normalized offset minutes", () => {
  const good = [
    "0001-01-01T00:00:00Z",
    "2000-02-29t23:59:59z",
    "2024-02-29T01:02:03.123456789+00:99",
    "2024-02-29T01:02:03-01:99",
    "9999-12-31T23:59:59+23:59",
  ];
  const bad = [
    "0000-01-01T00:00:00Z",
    "1900-02-29T00:00:00Z",
    "2023-02-29T00:00:00Z",
    "2024-04-31T00:00:00Z",
    "2024-00-01T00:00:00Z",
    "2024-01-00T00:00:00Z",
    "2024-01-01T24:00:00Z",
    "2024-01-01T00:60:00Z",
    "2024-01-01T00:00:60Z",
    "2024-01-01T00:00:00+23:60",
    "2024-01-01T00:00:00+2400",
    "2024-01-01 00:00:00Z",
    "2024-01-01T00:00:00",
    "2024-01-01T00:00:00Z\n",
    "٢٠٢٤-01-01T00:00:00Z",
    "2024-01-01T00:00:00.٩Z",
  ];
  const values = [...good, ...bad];
  for (const timestamp of [true, false]) {
    const results = run(
      values.map((value) => ({
        ...request(value, { type: "string", format: "date-time" }),
        timestamp,
      })),
    );
    expect(results.slice(0, good.length).map((result) => result.error)).toEqual(
      good.map(() => null),
    );
    expect(results.slice(good.length)).toEqual(
      bad.map(() => ({
        error: "artifact: expected an RFC 3339 timestamp",
        kind: "ContractError",
        unchanged: true,
      })),
    );
  }
});

test("unknown type operations escape contains and if while type alternatives stay lazy", () => {
  const results = run([
    request("a", { type: ["string", "unknown"] }),
    request("a", { type: ["unknown", "string"] }),
    request(["a"], { contains: { type: "unknown" }, minContains: 0 }),
    request({}, { if: { type: "unknown" }, then: {} }),
    request("a", { type: [[], "string"] }),
  ]);
  expect(results.map(({ error, kind }) => [error, kind ?? null])).toEqual([
    [null, null],
    ["'unknown'", "KeyError"],
    ["'unknown'", "KeyError"],
    ["'unknown'", "KeyError"],
    ["unhashable type: 'list'", "TypeError"],
  ]);
});

test("enum and required retain string and dictionary iteration without coercing keys", () => {
  const results = run([
    request("a", { enum: "ab" }),
    request("😀", { enum: "😀x" }),
    request("a", { enum: { a: false } }),
    request({ a: 1 }, { required: "a" }),
    request({ a: 1 }, { required: { a: false } }),
    request("a", { enum: null }),
    request("a", { enum: false }),
    request({ "1": true }, { required: [1] }),
    request({ None: true }, { required: [null] }),
    request({ a: true }, { required: [[], "missing"] }),
    request({ a: true }, { required: ["missing", []] }),
  ]);
  expect(results.map(({ error, kind }) => [error, kind ?? null])).toEqual([
    ...Array.from({ length: 5 }, () => [null, null]),
    ["'NoneType' object is not iterable", "TypeError"],
    ["'bool' object is not iterable", "TypeError"],
    ["artifact.1: missing required schema property", "ContractError"],
    ["artifact.None: missing required schema property", "ContractError"],
    ["unhashable type: 'list'", "TypeError"],
    ["artifact.missing: missing required schema property", "ContractError"],
  ]);
});

test("raw schema containers fail only when their original operation is reached", () => {
  const results = run([
    request({}, { properties: null }),
    request({}, { allOf: "", required: {} }),
    request("a", { allOf: null, required: null, properties: null }),
    request({ a: 1 }, { properties: null }),
    request({ a: 1 }, { properties: [] }),
    request({}, { required: null }),
    request({}, { allOf: null }),
    request({}, { allOf: { a: {} } }),
    request({ a: 1 }, { properties: null, required: ["missing"] }),
  ]);
  expect(results.map(({ error, kind }) => [error, kind ?? null])).toEqual([
    [null, null],
    [null, null],
    [null, null],
    ["'NoneType' object has no attribute 'get'", "AttributeError"],
    ["'list' object has no attribute 'get'", "AttributeError"],
    ["'NoneType' object is not iterable", "TypeError"],
    ["'NoneType' object is not iterable", "TypeError"],
    ["'str' object has no attribute 'get'", "AttributeError"],
    ["artifact.missing: missing required schema property", "ContractError"],
  ]);
});

test("numeric bounds preserve bool comparisons and minLength's Python truth test", () => {
  const results = run([
    request(1, { minimum: true, maximum: true }),
    request("a", { minLength: null }),
    request("a", { minLength: {} }),
    request(1, { minimum: null }),
    { source: '[1.0,{"maximum":null}]' },
    request([], { minItems: null }),
    request([], { contains: {}, minContains: null }),
    request("a", { minLength: { x: 1 }, pattern: "[" }),
    request("a", { minLength: {}, pattern: "[" }),
  ]);
  expect(results.map(({ error, kind }) => [error, kind ?? null])).toEqual([
    [null, null],
    [null, null],
    [null, null],
    [
      "'<' not supported between instances of 'int' and 'NoneType'",
      "TypeError",
    ],
    [
      "'>' not supported between instances of 'float' and 'NoneType'",
      "TypeError",
    ],
    [
      "'<' not supported between instances of 'int' and 'NoneType'",
      "TypeError",
    ],
    [
      "'<' not supported between instances of 'int' and 'NoneType'",
      "TypeError",
    ],
    ["'<' not supported between instances of 'int' and 'dict'", "TypeError"],
    ["unterminated character set at position 0", "error"],
  ]);
});

test("pattern argument and syntax errors propagate at the regex operation", () => {
  const results = run([
    request("", { pattern: false }),
    request("a", { pattern: ["a"] }),
    request("a", { pattern: {} }),
    request(["a"], { contains: { pattern: "[" }, minContains: 0 }),
    request({ a: "x" }, { if: { properties: { a: { pattern: "[" } } } }),
    request("a", { enum: "ab", pattern: "[" }),
  ]);
  expect(results.map(({ error, kind }) => [error, kind ?? null])).toEqual([
    ["first argument must be string or compiled pattern", "TypeError"],
    ["unhashable type: 'list'", "TypeError"],
    ["unhashable type: 'dict'", "TypeError"],
    ...Array.from({ length: 3 }, () => [
      "unterminated character set at position 0",
      "error",
    ]),
  ]);
});
