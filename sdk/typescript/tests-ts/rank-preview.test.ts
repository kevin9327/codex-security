import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { previewCases } from "./support/rank-preview-cases";
import type {
  PreviewRequest,
  PreviewResult,
} from "./support/rank-preview-fixture";

const node = Bun.which("node")!;
const directory = mkdtempSync(join(tmpdir(), "rank-preview-"));
const fixture = join(directory, "fixture.cjs");
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/rank-preview-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp", "helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(
  requests: PreviewRequest[],
  env: NodeJS.ProcessEnv = {},
): PreviewResult[] {
  const result = spawnSync(node, [fixture], {
    encoding: "utf8",
    input: JSON.stringify(requests),
    env: { ...process.env, PATH: "", PYTHONINTMAXSTRDIGITS: "", ...env },
    maxBuffer: Infinity,
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as PreviewResult[];
}
function value(request: PreviewRequest): unknown {
  const result = run([request])[0]!;
  expect(result.error).toBeUndefined();
  return result.value;
}

test.each(previewCases)(
  "preserves exact language preview: %s",
  (_, filename, text, expected) => {
    const path = join(directory, filename);
    const results = run([
      { path, text },
      { action: "file", path, text },
    ]);
    for (const result of results)
      expect(result).toEqual({ value: [expected, false] });
  },
);

test("lists only module definitions and direct methods, with canonical decorators and argument order", () => {
  const text = `@route(b"\\xff", 1.0, (x := left + right))
async def handle(a, /, b=2, *args, c=None, **kwargs):
    def nested(): pass
class Service(Base["item"], factory(x for x in xs)):
    @classmethod
    def create(cls): pass
    async def refresh(self): pass
    if enabled:
        def conditional(self): pass
    class Nested:
        def invisible(self): pass
if enabled:
    def conditional(): pass
`;
  expect(value({ text, path: "service.py" })).toEqual([
    "@route(b'\\xff', 1.0, (x := (left + right))) async function handle(a, b, *args, c, **kwargs)\nclass Service(Base['item'], factory((x for x in xs)))\n@classmethod method Service.create\nasync method Service.refresh",
    false,
  ]);
});
test("falls back for the entire malformed file, including definitions after the error", () => {
  const text =
    "@decorate\ndef visible(a): pass\nbroken = (\nclass Later:\n    def member(self): pass";
  expect(value({ action: "python", text })).toEqual([]);
  expect(value({ path: "broken.py", text })).toEqual([
    "function visible\nclass Later\nfunction member",
    false,
  ]);
});
test.each(["le", "be"] as const)(
  "decodes BOM-marked UTF-16 %s and ignores incomplete units",
  (endian) => {
    const encode = (text: string, tail = false) => {
      const bytes = Buffer.from(text, "utf16le");
      if (endian === "be") bytes.swap16();
      return Buffer.concat([
        Buffer.from(endian === "le" ? [255, 254] : [254, 255]),
        bytes,
        ...(tail ? [Buffer.from([0])] : []),
      ]).toString("hex");
    };
    const text = "Write-Output 'café 😀'";
    const path = join(directory, `source-${endian}.ps1`);
    const requests: PreviewRequest[] = [
      { path, hex: encode(text) },
      { action: "file", path, hex: encode(text) },
      { path, hex: encode(text, true) },
      {
        action: "file",
        path,
        hex: encode("a".repeat(2046) + "😀\n" + text),
        budget: 8192,
      },
      {
        action: "file",
        path,
        hex: encode("a".repeat(32766) + "😀\n" + text),
        budget: 128,
        maxRead: 65536,
      },
      { path, hex: encode("a\ud800b\udc00c😀") },
    ];
    expect(run(requests).map((result) => result.value)).toEqual([
      [text, false],
      [text, false],
      [text, false],
      ["a".repeat(2046) + "😀\n" + text, false],
      ["a".repeat(128), false],
      ["abc😀", false],
    ]);
  },
);
test.each([
  "6865616400626f6479",
  "fffe610000006200",
  "feff006100000062",
  "61006200",
])("rejects binary bytes %s", (hex) => {
  const path = join(directory, "binary.ps1");
  expect(run([{ hex }, { action: "file", path, hex }])).toEqual([
    { value: ["", true] },
    { value: ["", true] },
  ]);
});
test("ignores malformed UTF-8 while preserving actual replacement characters and the UTF-8 BOM", () => {
  expect(value({ hex: "efbbbff0288ca061efbfbdf09f988062eda080" })).toEqual([
    "\ufeff(a�😀b",
    false,
  ]);
  expect(value({ path: "source.json", text: '\ufeff{"a":1}' })).toEqual([
    '\ufeff{"a":1}',
    false,
  ]);
});
test("handles continuation-only byte views independently of the preceding allocation byte", () => {
  const results = run([
    { action: "decode", hex: "c2a3", offset: 1 },
    { hex: "c2a3", offset: 1 },
    { action: "decode", hex: "efbbbf66ff" },
    { hex: "efbbbf66ff" },
  ]);
  expect(results.map((result) => result.value)).toEqual([
    "\udca3",
    ["", false],
    "\ufefff\udcff",
    ["\ufefff", false],
  ]);
});
test("reads only the initial sample from a large binary and honors the later read cap", () => {
  const early = run([
    {
      action: "file",
      path: join(directory, "early.bin"),
      text: "head\0body",
      size: 256 * 1024 * 1024,
      countReads: true,
    },
  ])[0]!;
  expect(early.value).toEqual(["", true]);
  if (process.platform !== "win32") expect(early.reads).toEqual([4096]);
  const late = run([
    {
      action: "file",
      path: join(directory, "late.py"),
      text: "a".repeat(6000) + "\0body",
      size: 256 * 1024 * 1024,
      maxRead: 65536,
      countReads: true,
    },
  ])[0]!;
  expect(late.value).toEqual(["", true]);
  if (process.platform !== "win32") expect(late.reads).toEqual([4096, 61440]);
});
test("always reads the first 4096 bytes, and reads past it by default", () => {
  const path = join(directory, "late-declaration.py"),
    text = "# header\n".repeat(600) + "def later(): pass\n";
  expect(
    run([
      { action: "file", path, text },
      { action: "file", path, text, maxRead: 1, budget: 10 },
    ]).map((result) => result.value),
  ).toEqual([
    ["function later()", false],
    ["# header\n#", false],
  ]);
});
test("returns the binary flag for missing files and directories", () => {
  expect(value({ action: "file", path: join(directory, "missing") })).toEqual([
    "",
    true,
  ]);
  expect(value({ action: "file", path: directory })).toEqual(["", true]);
});
test("preserves raw and wide filenames instead of replacing unpaired path surrogates", () => {
  const root = join(directory, "paths with spaces ☃");
  mkdirSync(root);
  for (const filename of ["source😀.py", "source\udcfe.py"]) {
    expect(
      value({
        action: "file",
        path: join(root, filename),
        text: "def visible(): pass",
      }),
    ).toEqual(["function visible()", false]);
  }
  const path = join(root, "normalized.py");
  expect(value({ action: "file", path, text: "def visible(): pass" })).toEqual([
    "function visible()",
    false,
  ]);
  expect(value({ action: "file", path: `${path}/.` })).toEqual([
    "function visible()",
    false,
  ]);
  expect(value({ path: `${path}/.`, text: "def visible(): pass" })).toEqual([
    "function visible()",
    false,
  ]);
});
test("samples head and evenly spaced tail lines, with no marker for 22 lines", () => {
  const lines = Array.from(
    { length: 40 },
    (_, i) => `line_${String(i).padStart(2, "0")} { color: red; }`,
  );
  const expected = [
    ...lines.slice(0, 12),
    "...",
    ...[12, 15, 18, 21, 24, 27, 30, 33, 36, 39].map((i) => lines[i]),
  ].join("\n");
  expect(value({ text: lines.join("\n\n") })).toEqual([expected, false]);
  expect(value({ text: lines.slice(0, 22).join("\n") })).toEqual([
    lines.slice(0, 22).join("\n"),
    false,
  ]);
});
test("fits tiny and Unicode byte budgets while retaining the sampled tail", () => {
  const text = Array.from(
    { length: 40 },
    (_, i) => `line_${String(i).padStart(2, "0")} ${"😀".repeat(20)}`,
  ).join("\n");
  const result = value({ text, budget: 220 }) as [string, boolean];
  expect(Buffer.byteLength(result[0])).toBeLessThanOrEqual(220);
  expect(result[0]).toContain("line_39");
  expect(result[0]).toContain("...");
  expect(value({ text: "...", budget: 2 })).toEqual(["..", false]);
  expect(
    run(
      [-1, 0, 1, 2, 3, 4, 5].map((budget) => ({
        action: "truncate",
        text: "😀x",
        budget,
      })),
    ).map((result) => result.value),
  ).toEqual(["", "", "", "", "", "😀", "😀x"]);
});
test("uses Python line boundaries and whitespace, excluding FEFF and zero-width space", () => {
  const separators = "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029";
  expect(
    value({
      text: Array.from(separators)
        .map((separator) => `a${separator}`)
        .join(""),
    }),
  ).toEqual([Array.from(separators, () => "a").join("\n"), false]);
  expect(
    value({
      action: "compact",
      text: " \x1f a\u0085b\u00a0c\u2007d\ufeff\u200be ",
    }),
  ).toBe("a b c d\ufeff\u200be");
});
test("uses pinned Unicode word characters and boundaries in language heuristics", () => {
  expect(
    value({
      path: "source.ts",
      text: "class Aé²𐐀 {}\nclass A\u0301 {}\nclass A\u{1c89} {}",
    }),
  ).toEqual(["class Aé²𐐀\nclass A", false]);
  expect(
    value({ path: "source.java", text: "éclass Hidden {}\nclass Visible {}" }),
  ).toEqual(["class Visible", false]);
  expect(
    value({
      path: "source.sql",
      text: "CREATE FUNCTİON f();\nCREATE VıEW v();",
    }),
  ).toEqual(["functi̇on f\nvıew v", false]);
});
test("retains JSON insertion order, nested keys, float scalars and lone-surrogate failures", () => {
  expect(
    value({
      path: "source.json",
      text: '{"10":{"2":0,"1":0},"2":1.0,"1":{},"__proto__":{"x":1},"2":NaN}',
    }),
  ).toEqual(["key 10 [2, 1]\nkey 2\nkey 1\nkey __proto__ [x]", false]);
  expect(value({ path: "source.json", text: '[{"a":1}]' })).toEqual([
    '[{"a":1}]',
    false,
  ]);
  const path = join(directory, "surrogate.json");
  const results = run([
    { path, text: '{"\\ud800":1}' },
    { action: "file", path, text: '{"\\ud800":1}' },
  ]);
  for (const result of results)
    expect(result.error).toContain("UTF-8 cannot encode an unpaired surrogate");
});

test("preserves Python's decimal integer limit without applying it to floats", () => {
  const integer = "1".repeat(4301);
  const results = run([
    { path: "source.json", text: `{"key":${integer.slice(1)}}` },
    { path: "source.json", text: `{"key":${integer}}` },
    { path: "source.json", text: `[${integer}]` },
    { path: "source.json", text: `{"key":${integer}.0}` },
  ]);
  expect(results[0]!.value).toEqual(["key key", false]);
  for (const result of results.slice(1, 3))
    expect(result.error).toContain("Exceeds the limit (4300 digits)");
  expect(results[3]!.value).toEqual(["key key", false]);
  for (const setting of ["0", "5000"])
    expect(
      run([{ path: "source.json", text: `{"key":${integer}}` }], {
        PYTHONINTMAXSTRDIGITS: setting,
      })[0]!.value,
    ).toEqual(["key key", false]);
  expect(
    run([{ path: "source.json", text: `{"key":${"1".repeat(641)}}` }], {
      PYTHONINTMAXSTRDIGITS: "640",
    })[0]!.error,
  ).toContain("Exceeds the limit (640 digits)");
});
