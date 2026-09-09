import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  MatchCase,
  MatchResult,
} from "./support/python-regex-match-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "pattern-match-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/python-regex-match-fixture.ts", import.meta.url),
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
function run(cases: MatchCase[]): MatchResult[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(cases),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/missing/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as MatchResult[];
}
function matches(cases: [string, string, boolean][]): void {
  expect(run(cases.map(([pattern, value]) => ({ pattern, value })))).toEqual(
    cases.map(([, , matched]) => ({ matched })),
  );
}

test("full match retains Python anchors, line endings and local flags", () => {
  matches([
    ["a", "ba", false],
    ["a$", "a\n", false],
    ["a$\\n", "a\n", true],
    [".", "\r", true],
    [".", "\u2028", true],
    [".", "\n", false],
    ["(?s:.)", "\n", true],
    ["(?m:^a$\\n^b$)", "a\nb", true],
    ["\\Aa\\Z", "a", true],
    ["\\Aa\\Z", "a\n", false],
    ["(?x)a # comment\n b", "ab", true],
    ["(?i:a)(?-i:b)", "Ab", true],
    ["(?i:a)(?-i:b)", "AB", false],
  ]);
});

test("Unicode 15 categories and Python ignore-case pairs survive native matching", () => {
  matches([
    ["\\d", "\u0661", true],
    ["\\d", "²", false],
    ["\\w", "²", true],
    ["\\w", "\u0345", false],
    ["\\s", "\u001c", true],
    ["\\w", "\u{11f04}", true],
    ["\\w", "\u{1c89}", false],
    ["(?ai)[a-z]", "K", false],
    ["(?i)[a-z]", "K", true],
    ["(?i)i", "İ", true],
    ["(?i)i", "ı", true],
    ["(?i)s", "ſ", true],
    ["(?i)σ", "ς", true],
    ["(?i)µ", "Μ", true],
    ["(?i)ß", "ss", false],
    ["(?i)[^a-z]", "K", false],
    ["(?i)[\u0391-\u03c9]", "ς", true],
    ["(?a:\\w+)(?u:\\w+)", "aé", true],
  ]);
});

test("captures, backreferences, lookarounds and conditionals retain engine behavior", () => {
  matches([
    ["(?P<word>ab)(?P=word)", "abab", true],
    ["(?P<word>ab)(?P=word)", "abac", false],
    ["(?i:(σ)\\1)", "σς", false],
    ["(a)?(?(1)b|c)", "ab", true],
    ["(a)?(?(1)b|c)", "c", true],
    ["(a)?(?(1)b|c)", "ac", false],
    ["a(?<=a)b(?<!c)", "ab", true],
    ["a(?=b)b(?!c)", "ab", true],
    ["(?=(a+))\\1", "aaa", true],
    ["(a(b)?)+\\2", "abab", true],
  ]);
});

test("greedy, lazy, atomic and possessive repeats retain backtracking contracts", () => {
  matches([
    ["a+a", "aa", true],
    ["a+?a", "aa", true],
    ["a++a", "aa", false],
    ["(?>a+)a", "aa", false],
    ["(?:a|ab)b", "abb", true],
    ["(?>a|ab)b", "abb", false],
    ["(?:a?)*", "", true],
    ["(?:){2,5}+", "", true],
    ["(?:a?){2,4}+a", "aa", false],
    ["a{100001}", "a".repeat(100001), true],
    ["a{4294967294}", "", false],
  ]);
});

test("nonword boundaries retain Python 3.12 empty-string behavior inside subpatterns", () => {
  matches([
    ["\\B", "", false],
    ["(?:\\B)", "", false],
    ["(?=\\B)", "", false],
    ["(?!\\B)", "", true],
    ["(?<=\\B)", "", false],
    ["(?<!\\B)", "", true],
    ["\\B|", "", true],
    ["(?:\\B)*", "", true],
    ["(?:\\B)+", "", false],
    ["(?>\\B)", "", false],
    ["(?a:\\B)", "", false],
    ["\\B \\B", " ", true],
    ["\\ba\\b", "a", true],
    ["\\Ba\\B", "a", false],
  ]);
});

test("UTF-16 inputs preserve astral characters and lone surrogates", () => {
  matches([
    [".", "😀", true],
    ["..", "😀", false],
    ["[😀-🙏]+", "😀🙏", true],
    ["(?P<x>😀)(?P=x)", "😀😀", true],
    ["😀(?<=😀)a", "😀a", true],
    [".", "\ud800", true],
    ["[\ud800]", "\ud800", true],
    ["[^\ud800]", "\ud800", false],
    ["(\ud800)\\1", "\ud800\ud800", true],
    ["\\w", "\ud800", false],
    ["\\U0001f600", "😀", true],
  ]);
});

test("parser and compiler errors preserve the original error order and positions", () => {
  const results = run(
    ["(?<=a*)", "(?<=a*)a{4294967295}", "(?P<x>a)(?P<x>b)", "[z-a]", "\\q"].map(
      (pattern) => ({ pattern, value: "" }),
    ),
  );
  expect(results).toEqual([
    {
      error: "look-behind requires fixed-width pattern",
      kind: "error",
      position: null,
    },
    { error: "the repetition number is too large", kind: "OverflowError" },
    {
      error:
        "redefinition of group name 'x' as group 2; was group 1 at position 12",
      kind: "error",
      position: 12,
    },
    {
      error: "bad character range z-a at position 1",
      kind: "error",
      position: 1,
    },
    { error: "bad escape \\q at position 0", kind: "error", position: 0 },
  ]);
});
