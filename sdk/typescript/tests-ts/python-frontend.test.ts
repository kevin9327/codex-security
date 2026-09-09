import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";

const root = fileURLToPath(
  new URL("../../../plugins/codex-security/mcp-app/", import.meta.url),
);
const node = Bun.which("node")!;
const program = String.raw`
import { readFileSync } from "node:fs";
import { parse } from "py-ast";
const input = JSON.parse(readFileSync(0, "utf8"));
try {
  const first = parse(input.source, { feature_version: 12 }).body[0];
  console.log(JSON.stringify(first.nodeType === "FunctionDef" ?
    [first.name, first.args.args.map(argument => argument.arg)] :
    first.value.value));
} catch { process.exitCode = 1; }
`;
function run(source: string) {
  return spawnSync(node, ["--input-type=module", "-e", program], {
    cwd: root,
    encoding: "utf8",
    input: JSON.stringify({ source }),
  });
}

test.each([
  ["def 𝒇(K): pass", ["f", ["K"]]],
  ['value = "\\N{SNOWMAN}"', "☃"],
  ['value = "\\N{NULL}"', "\0"],
  ['value = "\\N{HANGUL SYLLABLE GAG}"', "각"],
  ['value = "\\777"', "ǿ"],
  ['value = "\\ud800"', "\ud800"],
] as const)(
  "preserves Python literal and identifier values: %s",
  (source, expected) => {
    const result = run(source);
    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(expected);
  },
);

test.each([
  "def f(/, value): pass",
  "value = lambda /, value: value",
  'value = "\\x1"',
  'value = "\\u123"',
  'value = "\\N{UNKNOWN NAME}"',
  'value = rb"é"',
  'value = b"x" "y"',
  'value = r"unterminated',
  "value = 001",
  "class C:\n\tdef a(self):pass\n        def b(self):pass",
  "def f[T = int](): pass",
  'value = t"hello"',
])("rejects the entire invalid Python 3.12 file: %s", (source) => {
  expect(run("def visible(): pass\n" + source).status).toBe(1);
});
