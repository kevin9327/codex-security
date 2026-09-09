import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { TomlResult } from "./support/toml-fixture";
import { PLUGIN_ROOT } from "./plugin-root";
import { parseToml } from "../../../plugins/codex-security/mcp-app/src/helpers/toml";

const node = Bun.which("node")!;
const directory = mkdtempSync(join(tmpdir(), "toml-parser-"));
const fixture = join(directory, "fixture.cjs");
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(new URL("./support/toml-fixture.ts", import.meta.url)),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));

function run(sources: string[]): TomlResult[] {
  const result = spawnSync(node, [fixture], {
    encoding: "utf8",
    input: JSON.stringify(sources),
    env: { ...process.env, PATH: "" },
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as TomlResult[];
}

test("retains config integers, integral floats, negative zero, and nonfinite floats", () => {
  expect(
    run([
      "a = 9007199254740993\nb = 7.0\nc = -0.0\nd = inf\ne = -inf\nf = nan\ng = 0xF_F\nh = 0o7_7\ni = 0b1_0\n",
    ])[0],
  ).toEqual({
    ok: true,
    value: [
      "object",
      [
        ["a", ["int", "9007199254740993"]],
        ["b", ["float", "401c000000000000"]],
        ["c", ["float", "8000000000000000"]],
        ["d", ["float", "7ff0000000000000"]],
        ["e", ["float", "fff0000000000000"]],
        ["f", ["float", "nan"]],
        ["g", ["int", "255"]],
        ["h", ["int", "63"]],
        ["i", ["int", "2"]],
      ],
    ],
  });
});

test("keeps authored profile order and literal keys with dots or prototype names", () => {
  expect(
    run([
      '[profiles."10"]\n"a.b" = true\n[profiles."2"]\n__proto__ = "value"\nconstructor = false',
    ])[0],
  ).toEqual({
    ok: true,
    value: [
      "object",
      [
        [
          "profiles",
          [
            "object",
            [
              ["10", ["object", [["a.b", ["bool", true]]]]],
              [
                "2",
                [
                  "object",
                  [
                    ["__proto__", ["str", "value"]],
                    ["constructor", ["bool", false]],
                  ],
                ],
              ],
            ],
          ],
        ],
      ],
    ],
  });
});

test("supports reopened implicit tables and independent array-table namespaces", () => {
  const result = run([
    '[a.b]\nx = 1\n[a]\ny = 2\n[[routes]]\nname = "first"\n[routes.config]\non = true\n[[routes]]\nname = "second"\n[routes.config]\non = false',
  ])[0]!;
  expect(result.ok).toBe(true);
  expect(result.value).toEqual([
    "object",
    [
      [
        "a",
        [
          "object",
          [
            ["b", ["object", [["x", ["int", "1"]]]]],
            ["y", ["int", "2"]],
          ],
        ],
      ],
      [
        "routes",
        [
          "array",
          [
            [
              "object",
              [
                ["name", ["str", "first"]],
                ["config", ["object", [["on", ["bool", true]]]]],
              ],
            ],
            [
              "object",
              [
                ["name", ["str", "second"]],
                ["config", ["object", [["on", ["bool", false]]]]],
              ],
            ],
          ],
        ],
      ],
    ],
  ]);
});

test("preserves inline-table immutability, dotted declarations, and duplicate diagnostics", () => {
  expect(
    run([
      "a = { b = { c = 1 }, b.d = 2 }",
      "a.b = 1\n[a]\nx = 2",
      "a = { b = 1, b = 2 }",
      "a = 1\na = 2",
      "[[a]\nx = 1",
    ]).map((result) => result.error),
  ).toEqual([
    "Cannot mutate immutable namespace ('b', 'd') (at line 1, column 29)",
    "Cannot declare ('a',) twice (at line 2, column 3)",
    "Duplicate inline table key 'b' (at line 1, column 19)",
    "Cannot overwrite a value (at end of document)",
    "Expected ']]' at the end of an array declaration (at line 1, column 4)",
  ]);
});

test("retains date kinds, timezone offsets, and six-digit microseconds", () => {
  expect(
    run([
      "a = 0001-01-01\nb = 2000-02-29T23:59:59.123456789-00:30\nc = 07:08:09.000001\nd = 2001-01-01 00:00:00Z\ne = 2001-01-01t00:00:00.000000-00:00\nf = 2001-01-01T00:00:00.1",
    ])[0],
  ).toEqual({
    ok: true,
    value: [
      "object",
      [
        ["a", ["date", "0001-01-01"]],
        ["b", ["datetime", "2000-02-29T23:59:59.123456-00:30"]],
        ["c", ["time", "07:08:09.000001"]],
        ["d", ["datetime", "2001-01-01T00:00:00+00:00"]],
        ["e", ["datetime", "2001-01-01T00:00:00+00:00"]],
        ["f", ["datetime", "2001-01-01T00:00:00.100000"]],
      ],
    ],
  });
  expect(
    run(["a = 1900-02-29", "a = 0000-01-01"]).map((result) => result.error),
  ).toEqual([
    "Invalid date or datetime (at line 1, column 5)",
    "Invalid date or datetime (at line 1, column 5)",
  ]);
});

test("normalizes CRLF strings and handles literal strings, escapes, and continuations", () => {
  const source =
    'a = """\r\none\\\r\n  two\r\nthree"""\r\nb = \'\'\'\r\nraw\\text\r\n\'\'\'\r\nc = "\\u00A3\\U0001F600\\t"';
  expect(run([source])[0]).toEqual({
    ok: true,
    value: [
      "object",
      [
        ["a", ["str", "onetwo\nthree"]],
        ["b", ["str", "raw\\text\n"]],
        ["c", ["str", "£😀\t"]],
      ],
    ],
  });
});

test("rejects TOML 1.1 syntax and illegal characters with code-point columns", () => {
  expect(
    run([
      "a = { b = 1, }",
      "a = {\nb = 1\n}",
      'a = "\\e"',
      'a = "\\x41"',
      'a = "\\uD800"',
      '"😀" = "x\\q"',
      "a = 1\v",
    ]).map((result) => result.error),
  ).toEqual([
    "Invalid initial character for a key part (at line 1, column 14)",
    "Invalid initial character for a key part (at line 1, column 6)",
    "Unescaped '\\' in a string (at line 1, column 8)",
    "Unescaped '\\' in a string (at line 1, column 8)",
    "Escaped character is not a Unicode scalar value (at line 1, column 12)",
    "Unescaped '\\' in a string (at line 1, column 11)",
    "Expected newline or end of document after a statement (at line 1, column 6)",
  ]);
});

test("parses long runs of comments and the shipped capability registry without Python", () => {
  const registry = readFileSync(
    join(PLUGIN_ROOT, "preflight/capability-profiles.toml"),
    "utf8",
  );
  const results = run([
    "# comment\n".repeat(20000) + "enabled = true",
    registry,
  ]);
  expect(results[0]).toEqual({
    ok: true,
    value: ["object", [["enabled", ["bool", true]]]],
  });
  expect(results[1]!.ok).toBe(true);
  const fields = (results[1]!.value as [string, [string, unknown][]])[1];
  expect(fields.map(([name]) => name)).toEqual([
    "version",
    "capabilities",
    "profiles",
    "routes",
  ]);
});

test("converts deeply dotted tables without consuming the call stack", () => {
  let row = parseToml("x.".repeat(2999) + "x = 1");
  for (let index = 0; index < 2999; index++)
    row = row["x"] as Record<string, unknown>;
  expect(row["x"]).toBe(1n);
});

test("keeps astral escape positions and the parser's Unicode version in errors", () => {
  expect(
    run([
      'x = "\\😀',
      'x = "\\😀"',
      'x = { "\u1c89" = 1, "\u1c89" = 2 }',
      '["\u{2ebf0}"]\n["\u{2ebf0}"]',
    ]).map((result) => result.error),
  ).toEqual([
    "Unescaped '\\' in a string (at end of document)",
    "Unescaped '\\' in a string (at line 1, column 8)",
    "Duplicate inline table key '\\u1c89' (at line 1, column 23)",
    "Cannot declare ('\\U0002ebf0',) twice (at line 2, column 5)",
  ]);
});
