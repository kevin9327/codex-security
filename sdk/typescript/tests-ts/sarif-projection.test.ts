import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { Request, Response } from "./support/sarif-projection-fixture";

const root = realpathSync(mkdtempSync(join(tmpdir(), "sarif-projection-")));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/sarif-projection-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(root, { recursive: true, force: true }));
const request = (
  operation: Request["operation"],
  value: unknown,
  options: Omit<Request, "operation" | "source"> = {},
): Request => ({ operation, source: JSON.stringify(value), ...options });
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const results = JSON.parse(child.stdout) as Response[];
  for (const result of results) expect(result.unchanged).toBe(true);
  return results;
}
function values(requests: Request[]): unknown[] {
  return run(requests).map((result) => {
    expect(result.error).toBeUndefined();
    return JSON.parse(result.source!);
  });
}
const plugin = new URL("../../../plugins/codex-security/", import.meta.url);
const manifest = JSON.parse(
  readFileSync(
    new URL("examples/completed-scan/scan-manifest.json", plugin),
    "utf8",
  ),
) as {
  schemaVersion: string;
  scan: {
    id: string;
    producer: { version: string };
    target: Record<string, unknown>;
  };
};
const example = JSON.parse(
  readFileSync(
    new URL("examples/completed-scan/findings.json", plugin),
    "utf8",
  ),
) as { findings: Record<string, unknown>[] };
const finding = (
  fields: Record<string, unknown> = {},
): Record<string, unknown> => ({ ...example.findings[0], ...fields });
function sarif(
  findings: Record<string, unknown>[],
  sourceRoot?: string,
): {
  version: string;
  runs: {
    tool: { driver: { rules: Record<string, unknown>[] } };
    results: Record<string, unknown>[];
    [key: string]: unknown;
  }[];
} {
  return values([
    request(
      "sarif",
      [manifest, { findings }],
      sourceRoot === undefined ? {} : { root: sourceRoot },
    ),
  ])[0] as ReturnType<typeof sarif>;
}

test("SARIF groups rules and results by code-point order and uses the strongest shared rule score", () => {
  const rows = [
    finding({
      occurrenceId: "😀",
      ruleId: "z.sql",
      remediation: "z fix",
      taxonomy: {
        category: "sql_injection",
        cwe: ["CWE-89", "cwe-001", "CWE-0", "custom"],
      },
      severity: { level: "low" },
    }),
    finding({
      occurrenceId: "a",
      ruleId: "z.sql",
      remediation: "a fix",
      taxonomy: { category: "api/authorization", cwe: ["CWE-89"] },
      severity: { level: "critical" },
    }),
    finding({
      occurrenceId: "\ue000",
      ruleId: "a.http",
      severity: { level: "informational" },
    }),
  ];
  const result = sarif(rows),
    run = result.runs[0]!;
  expect(result.version).toBe("2.1.0");
  expect(run.tool.driver.rules.map((rule) => rule["id"])).toEqual([
    "a.http",
    "z.sql",
  ]);
  expect(
    run.results.map(
      (result) =>
        (result["properties"] as Record<string, unknown>)["occurrenceId"],
    ),
  ).toEqual(["a", "\ue000", "😀"]);
  expect(run.results.map((result) => result["ruleIndex"])).toEqual([1, 0, 1]);
  expect(run.results.map((result) => result["level"])).toEqual([
    "error",
    "note",
    "note",
  ]);
  expect(run.tool.driver.rules[0]!["properties"]).not.toHaveProperty(
    "security-severity",
  );
  expect(run.tool.driver.rules[1]!["properties"]).toEqual({
    tags: [
      "api/authorization",
      "external/cwe/cwe-001",
      "external/cwe/cwe-089",
      "security",
      "sql_injection",
    ],
    "security-severity": "9.5",
  });
  expect(run.tool.driver.rules[1]!["name"]).toBe("Z: SQL");
  expect(run.tool.driver.rules[1]!["help"]).toEqual({
    text: "Z: SQL. Categories: API authorization, SQL injection. Weaknesses: CWE-0, CWE-89, custom, cwe-001.\n\nRemediation:\n\na fix\n\nz fix",
    markdown:
      "Z: SQL. Categories: API authorization, SQL injection. Weaknesses: CWE-0, CWE-89, custom, cwe-001.\n\n## Remediation\n\na fix\n\nz fix",
  });
});

test("SARIF messages retain diagnostics and candidate properties use only the legacy extension field", () => {
  const run = sarif([
    finding({
      title: "Title",
      summary: "Summary",
      remediation: "Fix",
      taxonomy: { category: "api_auth", cwe: ["CWE-1"] },
      severity: { level: "high" },
      remediationTests: ["one", "two"],
      preventiveControls: ["guard"],
      provenance: { candidateId: "canonical" },
      extensions: { candidateId: " legacy ", reportId: "other" },
    }),
  ]).runs[0]!;
  expect(run.results[0]!["message"]).toEqual({
    text: "Title\n\nSummary\n\nSeverity: high\n\nCategory: API auth\n\nWeaknesses: CWE-1\n\nRemediation:\nFix\n\nRemediation tests:\n- one\n- two\n\nPreventive controls:\n- guard",
  });
  expect(run.results[0]!["properties"]).toHaveProperty(
    "candidateId",
    " legacy ",
  );
  expect(
    sarif([
      finding({
        provenance: { candidateId: "canonical" },
        extensions: { reportId: "legacy" },
      }),
    ]).runs[0]!.results[0]!["properties"],
  ).not.toHaveProperty("candidateId");
});

test("SARIF puts root-control first, merges canonical evidence first and retains unique locations", () => {
  const row = finding({
    locations: [
      { path: "support.ts", startLine: 4, role: "supporting_evidence" },
      {
        path: "src/a b!()*.ts",
        startLine: 8,
        endLine: 10,
        role: "root_control",
      },
      { path: "support.ts", startLine: 4, role: "duplicate" },
    ],
    codeEvidence: [
      { id: "shared", path: "canonical.ts", startLine: 2, code: "first" },
    ],
    code_evidence: [
      { id: "shared", path: "wrong.ts", startLine: 3, code: "duplicate" },
      { id: "other", path: "./lib//proof.ts", startLine: 5, endLine: 2 },
      { id: "duplicate-location", path: "support.ts", startLine: 4 },
      { id: "invalid", path: "../outside", startLine: 1 },
      { id: "boolean", path: "bool.ts", startLine: true },
      { id: "float", path: "float.ts", startLine: 1.5 },
    ],
  });
  const locations = sarif([row]).runs[0]!.results[0]!["locations"] as Record<
    string,
    unknown
  >[];
  expect(locations).toEqual([
    {
      physicalLocation: {
        artifactLocation: { uri: "src/a%20b%21%28%29%2A.ts" },
        region: { startLine: 8, endLine: 10 },
      },
      message: { text: "root_control" },
    },
    {
      physicalLocation: {
        artifactLocation: { uri: "support.ts" },
        region: { startLine: 4, endLine: 4 },
      },
      message: { text: "supporting_evidence" },
    },
    {
      physicalLocation: {
        artifactLocation: { uri: "canonical.ts" },
        region: { startLine: 2, endLine: 2 },
      },
      message: { text: "evidence:shared" },
    },
    {
      physicalLocation: {
        artifactLocation: { uri: "lib/proof.ts" },
        region: { startLine: 5, endLine: 5 },
      },
      message: { text: "evidence:other" },
    },
  ]);
});

test("evidence strength counts new embedded code once while preserving catalog and alias precedence", () => {
  const catalog = [
    { id: "one", code: "first" },
    { id: "blank", code: "" },
    { id: " ", code: "space-id" },
  ];
  const [result] = values([
    request("evidence", {
      codeEvidence: catalog,
      code_evidence: [
        { id: "one", code: "later" },
        { id: "legacy", code: "legacy" },
        null,
      ],
      rootCause: {
        codeEvidence: [
          { id: "one", code: "ignored" },
          { id: "embedded", code: "new" },
          { code: "new" },
          { code: "\u0085" },
        ],
        code: "root",
      },
      root_cause: {
        code_evidence: [{ code: "root" }, { code: "alias" }],
        code: "alias",
      },
    }),
  ]);
  expect(result).toEqual([[...catalog, { id: "legacy", code: "legacy" }], 7]);
});

test("labels and shared casing preserve Unicode15, contextual sigma and multi-character uppercase", () => {
  expect(
    values(
      [
        "sql_injection",
        "csrf.http-api",
        "ßignal",
        "𐐨name",
        "\ufeffapi",
        "  api\u001cxml  ",
        "\ua7cb",
      ].map((value) => request("label", value)),
    ),
  ).toEqual([
    "SQL injection",
    "CSRF HTTP API",
    "SSignal",
    "𐐀name",
    "\ufeffapi",
    "API XML",
    "\ua7cb",
  ]);
  expect(
    values(
      ["AΣ", "AΣ\u0345", "AΣ\u0345A", "İßﬃ"].map((value) =>
        request("case", value),
      ),
    ),
  ).toEqual([
    ["aς", "AΣ"],
    ["aς\u0345", "AΣΙ"],
    ["aσ\u0345a", "AΣΙA"],
    ["i\u0307ßﬃ", "İSSFFI"],
  ]);
});

test("line hashes retain CRLF, whitespace, UTF16 and duplicate occurrence semantics across byte boundaries", () => {
  const text = "first\r\n\t second \n😀 third\rlast",
    hex = Buffer.from(text).toString("hex");
  const results = run(
    [1, 2, 3, 7, 65536].map((chunk) => ({ operation: "hash", hex, chunk })),
  );
  expect(new Set(results.map((result) => result.source)).size).toBe(1);
  for (const result of results) expect(result.maxRead).toBe(65536);
  const normalized = values([
    {
      operation: "hash",
      hex: Buffer.from("first\nsecond\n😀third\nlast").toString("hex"),
    },
  ])[0];
  expect(JSON.parse(results[0]!.source!)).toEqual(normalized);
  const duplicate = Buffer.from("a\n".repeat(130));
  const [all, selected] = values([
    { operation: "hash", hex: duplicate.toString("hex") },
    {
      operation: "hash",
      hex: duplicate.toString("hex"),
      requested: ["2", "65", "129", "999"],
    },
  ]) as Record<string, string>[];
  expect(selected).toEqual({
    "2": all!["2"]!,
    "65": all!["65"]!,
    "129": all!["129"]!,
  });
  expect(all!["1"]!.split(":")[0]).toBe(all!["2"]!.split(":")[0]);
  expect(all!["1"]!.endsWith(":1")).toBe(true);
  expect(all!["2"]!.endsWith(":2")).toBe(true);
});

test("source hashing reads real files safely and omits unavailable or symlinked sources", () => {
  const source = join(root, "source");
  mkdirSync(source);
  mkdirSync(join(source, "src"));
  const bytes = Buffer.concat([
    Buffer.alloc(65535, 97),
    Buffer.from("😀\r\nsecond\n"),
    Buffer.from([0xed, 0xa0, 0x80]),
  ]);
  writeFileSync(join(source, "src/file.ts"), bytes);
  const requests: Request[] = [
    { operation: "hash", hex: bytes.toString("hex") },
    { operation: "sourceHashes", root: source, path: "src/file.ts" },
    { operation: "sourceHashes", root: source, path: "missing.ts" },
    { operation: "sourceHashes", root: source, path: "../outside.ts" },
    { operation: "sourceHashes", root: source, path: "src" },
  ];
  const results = values(requests);
  expect(results[1]).toEqual(results[0]);
  expect(results.slice(2)).toEqual([null, null, null]);
  if (process.platform !== "win32") {
    symlinkSync(join(source, "src/file.ts"), join(source, "alias.ts"));
    symlinkSync(source, join(source, "loop"));
    expect(
      values([
        { operation: "sourceHashes", root: source, path: "alias.ts" },
        { operation: "sourceHashes", root: source, path: "loop/src/file.ts" },
      ]),
    ).toEqual([null, null]);
  }
  const row = finding({
    locations: [{ path: "src/file.ts", startLine: 2, role: "root_control" }],
  });
  const document = sarif(
    [
      row,
      finding({
        ...row,
        occurrenceId: "second",
        locations: [{ path: "src/file.ts", startLine: 3 }],
      }),
    ],
    source,
  );
  const expected = results[0] as Record<string, string>;
  expect(
    document.runs[0]!.results.map(
      (result) =>
        (result["partialFingerprints"] as Record<string, unknown>)[
          "primaryLocationLineHash"
        ],
    ).sort(),
  ).toEqual([expected["2"], expected["3"]].sort());
  const missing = sarif([row], join(source, "missing"));
  expect(
    missing.runs[0]!.results[0]!["partialFingerprints"],
  ).not.toHaveProperty("primaryLocationLineHash");
});

test("SARIF validation retains the existing version, run, rule and fingerprint errors", () => {
  const good = sarif([finding()]);
  const invalid = [
    {},
    { version: "2.1.0", runs: [] },
    { version: "2.1.0", runs: [null] },
    {
      version: "2.1.0",
      runs: [
        { tool: { driver: { rules: [] } }, results: [{ ruleId: "missing" }] },
      ],
    },
    {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { rules: [{ id: "rule" }] } },
          results: [{ ruleId: "rule", partialFingerprints: {} }],
        },
      ],
    },
  ];
  expect(
    run(invalid.map((value) => request("validate", value))).map(
      (result) => result.error,
    ),
  ).toEqual([
    "SARIF: expected version 2.1.0",
    "SARIF: expected exactly one run",
    "SARIF: expected a run object",
    "SARIF: result references an unknown rule",
    "SARIF: result is missing partialFingerprints",
  ]);
  expect(values([request("validate", good)])).toEqual([null]);
  expect(sarif([]).runs[0]!.results).toEqual([]);
});

test("SARIF retains decimal CWE and strict URI encoding boundaries", () => {
  const result = run([
    request("sarif", [
      manifest,
      {
        findings: [
          finding({
            taxonomy: {
              category: "category",
              cwe: ["CWE-" + "1".repeat(4300)],
            },
          }),
        ],
      },
    ]),
    request("sarif", [
      manifest,
      {
        findings: [
          finding({
            taxonomy: {
              category: "category",
              cwe: ["CWE-" + "1".repeat(4301)],
            },
          }),
        ],
      },
    ]),
    request("sarif", [
      manifest,
      {
        findings: [
          finding({ locations: [{ path: "😀\ud800", startLine: 1 }] }),
        ],
      },
    ]),
  ]);
  expect(result[0]!.error).toBeUndefined();
  expect(result[1]!.error).toBe(
    "Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use sys.set_int_max_str_digits() to increase the limit",
  );
  expect(result[2]!.error).toBe(
    "'utf-8' codec can't encode character '\\ud800' in position 1: surrogates not allowed",
  );
});

test.skipIf(process.platform === "win32")(
  "source hash caching reads a file once and closes it when reading fails",
  () => {
    const source = join(root, "source-lifetime");
    mkdirSync(source);
    const file = join(source, "file.ts");
    writeFileSync(file, "first\nsecond\n");
    const rows = [1, 2].map((line) =>
      finding({
        occurrenceId: String(line),
        locations: [{ path: "file.ts", startLine: line }],
      }),
    );
    const result = run([
      request("sarif", [manifest, { findings: rows }], {
        root: source,
        traceFile: file,
      }),
      request("sarif", [manifest, { findings: rows }], {
        root: source,
        traceFile: file,
        readError: true,
      }),
    ]);
    expect(result[0]!.sourceReads).toBe(2);
    expect(result[0]!.sourceCloses).toBe(1);
    expect(result[1]!.error).toBeUndefined();
    expect(result[1]!.sourceReads).toBe(1);
    expect(result[1]!.sourceCloses).toBe(1);
    const failed = JSON.parse(result[1]!.source!) as {
      runs: { results: { partialFingerprints: unknown }[] }[];
    };
    for (const item of failed.runs[0]!.results)
      expect(item.partialFingerprints).not.toHaveProperty(
        "primaryLocationLineHash",
      );
  },
);

test("source hashes include later lines and every large source file", () => {
  const [late] = values([
    {
      operation: "hash",
      hex: Buffer.from("line\n".repeat(100001)).toString("hex"),
      requested: ["100001"],
    },
  ]) as Record<string, string>[];
  expect(late).toHaveProperty("100001");
  const source = join(root, "large-source");
  mkdirSync(source);
  const rows = [0, 1].map((index) => {
    writeFileSync(
      join(source, `file-${index}.ts`),
      " ".repeat(6 * 1024 * 1024) + "x",
    );
    return finding({
      occurrenceId: String(index),
      locations: [{ path: `file-${index}.ts`, startLine: 1 }],
    });
  });
  const document = sarif(rows, source);
  for (const result of document.runs[0]!.results)
    expect(result["partialFingerprints"]).toHaveProperty(
      "primaryLocationLineHash",
    );
});
