import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";

const root = fileURLToPath(
  new URL("../../../plugins/codex-security/mcp-app/", import.meta.url),
);
const node = Bun.which("node")!;
const program = String.raw`
import { readFileSync } from "node:fs";
import { parse, unparse } from "py-ast";
const input = JSON.parse(readFileSync(0, "utf8"));
try {
  const first = parse(input.source, { feature_version: 12 }).body[0];
  console.log(input.render ? unparse(first.value, { canonical: true }) :
    JSON.stringify(first.nodeType === "FunctionDef" ?
    [first.name, first.args.args.map(argument => argument.arg)] :
    first.value.literal_kind ? [first.value.value, first.value.literal_kind] : first.value.value));
} catch { process.exitCode = 1; }
`;
function run(source: string, render = false) {
  return spawnSync(node, ["--input-type=module", "-e", program], {
    cwd: root,
    encoding: "utf8",
    input: JSON.stringify({ source, render }),
  });
}

test.each([
  ["value = 1", [1, "int"]],
  ["value = 1.0", [1, "float"]],
  ["value = ...", ["...", "ellipsis"]],
  ['value = "..."', "..."],
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

test.each([
  ["1.0", "1.0"],
  ["-0.0", "-0.0"],
  ["1e-5j", "1e-05j"],
  ["1e1000j", "1e309j"],
  ['"..."', "'...'"],
  ["...", "..."],
  ['b"\\xff\\x00"', "b'\\xff\\x00'"],
  ['"\\x01\\ud800"', "'\\x01\\ud800'"],
  ["(value := left + right)", "(value := (left + right))"],
  ["f\"{item['key']}\"", "f\"{item['key']}\""],
  [
    "{key: value for key, value in rows}",
    "{key: value for key, value in rows}",
  ],
  ["factory(value for value in rows)", "factory((value for value in rows))"],
  ["values[(index,)]", "values[index,]"],
])(
  "normalizes decorator/base expressions as Python does: %s",
  (source, expected) => {
    const result = run("value = " + source, true);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(expected + "\n");
  },
);
