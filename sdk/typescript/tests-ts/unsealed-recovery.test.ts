import { spawnSync } from "node:child_process";
import {
  cpSync,
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
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  Operation,
  Request,
  Response,
} from "./support/unsealed-recovery-fixture";

type Table = Record<string, unknown>;
const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "unsealed-recovery-")),
);
const fixture = join(directory, "fixture.cjs"),
  scanRoot = join(directory, "scan");
const schemaDir = fileURLToPath(
  new URL("../../../plugins/codex-security/schemas", import.meta.url),
);
const node = Bun.which("node")!;
const example = (name: string): Table =>
  JSON.parse(
    readFileSync(
      new URL(
        `../../../plugins/codex-security/examples/completed-scan/${name}`,
        import.meta.url,
      ),
      "utf8",
    ),
  ) as Table;
const manifest = example("scan-manifest.json"),
  findings = example("findings.json"),
  coverage = example("coverage.json");
const finding = (findings["findings"] as Table[])[0]!;
const clone = <T>(value: T): T => structuredClone(value);
const asTable = (value: unknown): Table => value as Table;
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/unsealed-recovery-fixture.ts", import.meta.url),
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
  for (const path of [
    "artifacts/a.json",
    "artifacts/b.json",
    "findings/a/a.md",
    "findings/b/b.md",
    "hardening/hardening.md",
  ]) {
    mkdirSync(join(scanRoot, path, ".."), { recursive: true });
    writeFileSync(join(scanRoot, path), "synthetic");
  }
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function request(
  operation: Operation,
  payload: unknown,
  options: Partial<Request> = {},
): Request {
  return {
    operation,
    source: JSON.stringify(payload),
    root: scanRoot,
    schemaDir,
    ...options,
  };
}
function recover(items: unknown[], options: Partial<Request> = {}): Request {
  return request(
    "findings",
    [manifest, { ...findings, findings: items }, []],
    options,
  );
}
function cover(
  value: Table,
  discarded: string[] = [],
  options: Partial<Request> = {},
): Request {
  return request("coverage", [value, [], discarded], options);
}
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const result = JSON.parse(child.stdout) as Response[];
  if (process.platform === "linux")
    for (const response of result) expect(response.leaked).toBe(0);
  return result;
}
function success(response: Response): unknown[] {
  expect(response.error).toBeUndefined();
  return JSON.parse(response.after) as unknown[];
}
function recovered(response: Response): Table[] {
  return asTable(success(response)[1])["findings"] as Table[];
}
const warnings = (response: Response): string[] =>
  (JSON.parse(response.after) as unknown[])[
    response.value === "null" ? 1 : 2
  ] as string[];
const evidence = (id: string, code = id) => ({
  id,
  code,
  label: id,
  path: "src/a.ts",
  startLine: 1,
  explanation: "synthetic",
});
function row(
  options: {
    title?: string;
    severity?: string;
    confidence?: string;
    anchor?: string;
    writeup?: string;
    evidence?: number;
  } = {},
): Table {
  const value = clone(finding);
  if (options.title) value["title"] = options.title;
  if (options.severity) asTable(value["severity"])["level"] = options.severity;
  if (options.confidence)
    asTable(value["confidence"])["level"] = options.confidence;
  if (options.anchor) asTable(value["identity"])["anchor"] = options.anchor;
  if (options.writeup) value["writeup"] = { reportPath: options.writeup };
  if (options.evidence)
    value["codeEvidence"] = Array.from(
      { length: options.evidence },
      (_, index) => evidence(`e${index}`),
    );
  return value;
}
function surface(id: string, options: Table = {}): Table {
  return {
    id,
    label: "Synthetic surface",
    disposition: "reported",
    receiptRefs: [],
    ...options,
  };
}
function coverageWith(surfaces: unknown[], options: Table = {}): Table {
  return {
    ...clone(coverage),
    surfaces,
    explicitExclusions: [],
    deferred: [],
    ...options,
  };
}
function schemaCopy(
  name: string,
  change: (schemas: { findings: Table; coverage: Table }) => void,
): string {
  const root = join(directory, name);
  cpSync(schemaDir, root, { recursive: true });
  const schemas = Object.fromEntries(
    ["findings", "coverage"].map((key) => [
      key,
      JSON.parse(readFileSync(join(root, `${key}.schema.json`), "utf8")),
    ]),
  ) as { findings: Table; coverage: Table };
  change(schemas);
  for (const [key, value] of Object.entries(schemas))
    writeFileSync(join(root, `${key}.schema.json`), JSON.stringify(value));
  return root;
}

test("normalizes draft identities, legacy details and Python whitespace without mutating input rows", () => {
  const value = row();
  value["ruleId"] = " Archive KEY ";
  value["identity"] = { anchor: "Unsafe Entry İD", instance: " Instance 1 " };
  value["validation"] = { evidence: "legacy evidence" };
  asTable(value["severity"])["changeConditions"] = [
    "\u0085First\u001f",
    "\ufeffSecond\ufeff",
  ];
  value["findingId"] = "draft";
  value["fingerprints"] = null;
  const response = run([recover([value])])[0]!;
  const output = recovered(response)[0]!;
  expect(output["ruleId"]).toBe("archive-key");
  expect(output["identity"]).toEqual({
    anchor: "unsafe-entry-i-d",
    instance: "instance-1",
  });
  expect(asTable(output["severity"])["changeConditions"]).toBe(
    "First \ufeffSecond\ufeff",
  );
  expect(output["validation"]).toEqual({ evidence: ["legacy evidence"] });
  expect(output["findingId"]).toMatch(/^csf_[a-f0-9]{24}$/u);
  expect(warnings(response)).toEqual([
    "Recovered finding 1: normalized legacy finding details, rule identifier, semantic anchor, instance, severity change conditions.",
  ]);
  expect(JSON.parse(response.references)).toEqual([value]);
  expect(JSON.parse(response.value!)).toEqual([]);
  const again = run([recover([output])])[0]!;
  expect(recovered(again)).toEqual([output]);
  expect(warnings(again)).toEqual([]);
});

test("discards malformed findings in order while duplicate warnings stay outside discarded findings", () => {
  const invalid = row();
  asTable(invalid["identity"])["anchor"] = "ΣΣ";
  const optional = row({ anchor: "sibling" });
  asTable(optional["identity"])["instance"] = "";
  const response = run([
    recover([null, invalid, finding, finding, optional]),
  ])[0]!;
  expect(recovered(response)).toHaveLength(1);
  expect(warnings(response)).toEqual([
    "Skipped malformed finding 1: findings.findings[0]: expected an object.",
    "Skipped malformed finding 2: findings.findings[1].identity.anchor: expected a stable lowercase semantic slug.",
    "Skipped malformed finding 4: duplicate logical finding.",
    "Skipped malformed finding 5: findings.findings[4].identity.instance: expected a non-empty string.",
  ]);
  expect(JSON.parse(response.value!)).toEqual(
    warnings(response).filter((_, index) => index !== 2),
  );
  expect(
    asTable(recovered(response)[0]!["provenance"])["previousFindings"],
  ).toBeUndefined();
});

test("removes only malformed optional finding fields before validating the remaining finding", () => {
  const value = row({ writeup: "findings/a/b.md" });
  value["remediationTests"] = [""];
  value["preventiveControls"] = "wrong";
  const malformed = clone(value);
  malformed["rootCause"] = {};
  const responses = run([recover([value]), recover([malformed])]);
  const output = recovered(responses[0]!)[0]!;
  for (const field of ["writeup", "remediationTests", "preventiveControls"])
    expect(output).not.toHaveProperty(field);
  const expected = [
    "Skipped malformed writeup for finding 1: findings.findings[0].writeup.reportPath: string does not match schema pattern.",
    "Skipped malformed remediationTests for finding 1: findings.findings[0].remediationTests[0]: string is too short.",
    "Skipped malformed preventiveControls for finding 1: findings.findings[0].preventiveControls: expected schema type array.",
  ];
  expect(warnings(responses[0]!)).toEqual(expected);
  expect(recovered(responses[1]!)).toEqual([]);
  expect(warnings(responses[1]!)).toEqual([
    ...expected,
    "Skipped malformed finding 1: findings.findings[0].rootCause.summary: missing required schema property.",
  ]);
  expect(JSON.parse(responses[1]!.references)).toEqual([malformed]);
});

test("severity then confidence then independent code evidence choose the strongest duplicate", () => {
  const cases = [
    [
      row({ title: "first", severity: "low", confidence: "high", evidence: 3 }),
      row({ title: "second", severity: "medium", confidence: "low" }),
    ],
    [
      row({ title: "first", confidence: "low", evidence: 3 }),
      row({ title: "second", confidence: "medium" }),
    ],
    [
      row({ title: "first", evidence: 1 }),
      row({ title: "second", evidence: 2 }),
    ],
  ];
  const responses = run(
    cases.flatMap((items) => [recover(items), recover([...items].reverse())]),
  );
  for (const [index, response] of responses.entries()) {
    const output = recovered(response)[0]!;
    expect(output["title"]).toBe("second");
    const history = asTable(output["provenance"])[
      "previousFindings"
    ] as Table[];
    expect(history.map((item) => item["title"])).toEqual(["first"]);
    expect(warnings(response)).toEqual([
      index % 2 === 0
        ? "Recovered finding 2: retained stronger duplicate logical finding."
        : "Skipped malformed finding 2: duplicate logical finding.",
    ]);
    expect(JSON.parse(response.value!)).toEqual([]);
  }
});

test("flattens duplicate histories with Python equality while the first equal-strength finding wins", () => {
  const first = row({ title: "first" }),
    second = row({ title: "second" });
  asTable(first["provenance"])["previousFindings"] = [
    true,
    { retained: "older" },
  ];
  asTable(second["provenance"])["previousFindings"] = [
    1,
    false,
    { retained: "older" },
  ];
  const response = run([recover([first, second, second])])[0]!;
  const output = recovered(response)[0]!;
  expect(output["title"]).toBe("first");
  const history = asTable(output["provenance"])[
    "previousFindings"
  ] as unknown[];
  expect(history.slice(0, 3)).toEqual([true, { retained: "older" }, false]);
  expect(history).toHaveLength(4);
  expect(asTable(history[3])["title"]).toBe("second");
  expect(asTable(asTable(history[3])["provenance"])).not.toHaveProperty(
    "previousFindings",
  );
  expect(JSON.parse(response.references)).toEqual([first, second, second]);
  expect(warnings(response)).toEqual([
    "Skipped malformed finding 2: duplicate logical finding.",
    "Skipped malformed finding 3: duplicate logical finding.",
  ]);
});

test("counts canonical, legacy and embedded evidence consistently when ranking duplicates", () => {
  const canonical = row({ title: "canonical", evidence: 1 });
  const legacy = row({ title: "legacy" });
  legacy["code_evidence"] = [evidence("e0")];
  const embedded = row({ title: "embedded" });
  embedded["rootCause"] = {
    summary: "synthetic",
    code: "one",
    codeEvidence: [{ id: "e0", code: "two" }],
  };
  embedded["root_cause"] = {
    summary: "synthetic",
    code: "one",
    code_evidence: [{ id: "e0", code: "two" }, { code: "three" }],
  };
  const responses = run([
    recover([canonical, legacy]),
    recover([legacy, canonical]),
    recover([canonical, embedded]),
    request("strength", embedded),
  ]);
  expect(recovered(responses[0]!)[0]!["title"]).toBe("canonical");
  expect(recovered(responses[1]!)[0]!["title"]).toBe("legacy");
  expect(recovered(responses[2]!)[0]!["title"]).toBe("embedded");
  expect(JSON.parse(responses[3]!.value!)).toEqual([3, 2, 3]);
});

test("duplicate history copies preserve integer precision, decimal spelling and numeric key order", () => {
  const input = recover([row({ title: "first" }), row({ title: "second" })]);
  input.source = input.source.replaceAll(
    '"extensions":{}',
    '"extensions":{"10":9007199254740993,"2":1.0,"nested":{"8":true,"1":null}}',
  );
  const response = run([input])[0]!;
  const output = recovered(response)[0]!;
  expect(asTable(output["provenance"])["previousFindings"]).toHaveLength(1);
  expect(
    response.after.match(/"10": 9007199254740993,\n\s+"2": 1\.0,/gu),
  ).toHaveLength(2);
  expect(response.after.match(/"8": true,\n\s+"1": null/gu)).toHaveLength(2);
  expect(
    response.references.match(/"10": 9007199254740993,\n\s+"2": 1\.0,/gu),
  ).toHaveLength(2);
});

test("writeup claims follow accepted findings and are released when stronger duplicates replace them", () => {
  const pathA = "findings/a/a.md",
    pathB = "findings/b/b.md";
  const first = row({ title: "first", writeup: pathA, severity: "low" });
  const stronger = row({ title: "second", writeup: pathB });
  const third = row({ anchor: "sibling", writeup: pathA });
  const same = row({ title: "same", writeup: pathA, severity: "low" });
  const responses = run([
    recover([first, same], { trace: true }),
    recover([first, third], { trace: true }),
    recover([first, stronger, third], { trace: true }),
  ]);
  expect(recovered(responses[0]!)[0]!["writeup"]).toEqual({
    reportPath: pathA,
  });
  expect(warnings(responses[0]!)).toEqual([
    "Skipped malformed finding 2: duplicate logical finding.",
  ]);
  expect(recovered(responses[1]!)[1]).not.toHaveProperty("writeup");
  expect(warnings(responses[1]!)).toEqual([
    "Skipped malformed writeup for finding 2: findings.findings[1].writeup.reportPath: duplicate report path.",
  ]);
  expect(recovered(responses[2]!).map((item) => item["writeup"])).toEqual([
    { reportPath: pathB },
    { reportPath: pathA },
  ]);
  expect(warnings(responses[2]!)).toEqual([
    "Recovered finding 2: retained stronger duplicate logical finding.",
  ]);
  if (process.platform !== "win32") {
    expect(responses[0]!.events).toEqual([
      { open: "a.md" },
      { close: "a.md" },
      { open: "a.md" },
      { close: "a.md" },
    ]);
    expect(responses[1]!.events).toEqual([{ open: "a.md" }, { close: "a.md" }]);
    expect(responses[2]!.events).toEqual([
      { open: "a.md" },
      { close: "a.md" },
      { open: "b.md" },
      { close: "b.md" },
      { open: "a.md" },
      { close: "a.md" },
    ]);
  }
});

test("weaker duplicates still validate optional files but do not claim paths or emit normalization warnings", () => {
  const first = row({ severity: "critical", writeup: "findings/a/a.md" });
  const weaker = row({ severity: "low", writeup: "findings/b/b.md" });
  weaker["ruleId"] = String(weaker["ruleId"]).toUpperCase();
  const next = row({ anchor: "other", writeup: "findings/b/b.md" });
  const response = run([recover([first, weaker, next], { trace: true })])[0]!;
  expect(recovered(response).map((item) => item["writeup"])).toEqual([
    { reportPath: "findings/a/a.md" },
    { reportPath: "findings/b/b.md" },
  ]);
  expect(warnings(response)).toEqual([
    "Skipped malformed finding 2: duplicate logical finding.",
  ]);
});

test("recovers coverage rows, checks duplicate IDs only after successful rows, and preserves warning order", () => {
  const bad = surface("repeat", {
    disposition: "invalid",
    receiptRefs: ["./artifacts//a.json", 4],
  });
  delete bad["label"];
  const value = coverageWith(
    [bad, surface("repeat"), surface("repeat"), null],
    {
      completeness: "invalid",
      mode: "deep_repository",
      inventoryStrategy: "directory",
      explicitExclusions: [null, { pattern: "vendor/", reason: "synthetic" }],
      deferred: [{ id: "later", reason: "synthetic" }, {}],
    },
  );
  const response = run([cover(value, [], { trace: true })])[0]!;
  const output = asTable(success(response)[0]);
  expect(output["surfaces"]).toEqual([surface("repeat")]);
  expect(output["completeness"]).toBe("partial");
  expect(output["inventoryStrategy"]).toBe("repository");
  expect(output["explicitExclusions"]).toEqual([
    { pattern: "vendor/", reason: "synthetic" },
  ]);
  expect(output["deferred"]).toEqual([{ id: "later", reason: "synthetic" }]);
  expect(warnings(response)).toEqual([
    "Recovered malformed coverage completeness; marked coverage as partial.",
    "Recovered malformed Deep Scan inventory strategy; marked coverage as partial.",
    "Recovered coverage surface 1: the review disposition could not be verified.",
    "Skipped malformed coverage receipt 1.2: coverage.surfaces[0].receiptRefs[1]: expected a string.",
    "Skipped malformed coverage surface 1: coverage.surfaces[0].label: missing required schema property.",
    "Skipped malformed coverage surface 3: coverage.surfaces[2].id: duplicate surface id.",
    "Skipped malformed coverage surface 4: coverage.surfaces[3]: expected an object.",
    "Skipped malformed coverage exclusion 1: coverage.explicitExclusions[0]: expected an object.",
    "Skipped malformed deferred coverage item 2: coverage.deferred[1].id: missing required schema property.",
    "Coverage has deferred review work; marked coverage as partial.",
  ]);
  const originalSurfaces = (JSON.parse(response.references) as unknown[][])[0]!;
  expect(asTable(originalSurfaces[0])["disposition"]).toBe("needs_follow_up");
  expect(asTable(originalSurfaces[0])["receiptRefs"]).toEqual([
    "artifacts/a.json",
  ]);
});

test("normalizes receipts and keeps duplicate receipts while downgrading only recovered surfaces", () => {
  const value = coverageWith(
    [
      surface("valid", {
        receiptRefs: ["./artifacts//a.json", "artifacts/a.json"],
      }),
      surface("malformed", {
        receiptRefs: [
          "artifacts/b.json",
          "../outside",
          "findings/a/a.md",
          "artifacts/missing",
        ],
      }),
      surface("missing", { receiptRefs: null }),
      surface("no-receipts"),
    ],
    { completeness: "complete" },
  );
  const response = run([cover(value, [], { trace: true })])[0]!;
  const output = asTable(success(response)[0]);
  expect(
    (output["surfaces"] as Table[]).map((item) => [
      item["id"],
      item["disposition"],
      item["receiptRefs"],
    ]),
  ).toEqual([
    ["valid", "reported", ["artifacts/a.json", "artifacts/a.json"]],
    ["malformed", "needs_follow_up", ["artifacts/b.json"]],
    ["missing", "needs_follow_up", []],
    ["no-receipts", "reported", []],
  ]);
  expect(warnings(response).map((warning) => warning.split(":")[0])).toEqual([
    "Skipped malformed coverage receipt 2.2",
    "Skipped malformed coverage receipt 2.3",
    "Skipped malformed coverage receipt 2.4",
    "Skipped malformed receipt references for coverage surface 3",
  ]);
  expect(output["completeness"]).toBe("partial");
});

test("follow-up and deferred warnings use original completeness and discarded findings mark all surfaces", () => {
  const requests = ["complete", "partial", "unknown"].map((completeness) =>
    cover(
      coverageWith([surface("a", { disposition: "needs_follow_up" })], {
        completeness,
        deferred: [{ id: "later", reason: "synthetic" }],
      }),
    ),
  );
  requests.push(
    cover(
      coverageWith(
        [surface("a"), surface("b", { disposition: "no_issue_found" })],
        {
          completeness: "complete",
          deferred: [{ id: "later", reason: "synthetic" }],
        },
      ),
      ["first discarded", "second discarded"],
    ),
  );
  const responses = run(requests);
  for (const [index, response] of responses.entries()) {
    const output = asTable(success(response)[0]);
    expect(output["completeness"]).toBe("partial");
    expect(warnings(response)).toEqual(
      index === 1 || index === 3
        ? []
        : [
            "Coverage surface 1 requires follow-up; marked coverage as partial.",
            "Coverage has deferred review work; marked coverage as partial.",
          ],
    );
  }
  const final = asTable(success(responses[3]!)[0]);
  expect(
    (final["surfaces"] as Table[]).map((item) => item["disposition"]),
  ).toEqual(["needs_follow_up", "needs_follow_up"]);
  expect(final["deferred"]).toEqual([
    { id: "later", reason: "synthetic" },
    { id: "discarded-finding-1", reason: "first discarded" },
    { id: "discarded-finding-2", reason: "second discarded" },
  ]);
});

test("malformed coverage arrays are replaced independently and optional unrelated data is retained", () => {
  const value = coverageWith([], {
    surfaces: null,
    explicitExclusions: "invalid",
    deferred: {},
    openQuestions: [null],
    custom: { retained: true },
  });
  const response = run([cover(value)])[0]!;
  const output = asTable(success(response)[0]);
  expect(output).toEqual({
    ...value,
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
    completeness: "partial",
  });
  expect(warnings(response)).toEqual([
    "Skipped malformed coverage surface records: expected an array.",
    "Skipped malformed coverage exclusion records: expected an array.",
    "Skipped malformed deferred coverage item records: expected an array.",
  ]);
});

test("schema lookup failures preserve earlier coverage mutations and happen before finding validation", () => {
  const malformedSchemas = schemaCopy("missing-nodes", (schemas) => {
    delete asTable(
      asTable(
        asTable(asTable(schemas.findings["properties"])["findings"])["items"],
      )["properties"],
    )["preventiveControls"];
    delete asTable(schemas.coverage["properties"])["explicitExclusions"];
  });
  const value = coverageWith([surface("a", { disposition: "invalid" })], {
    completeness: "invalid",
    mode: "deep_repository",
    inventoryStrategy: "custom",
  });
  const responses = run([
    request("findings", [{}, {}, ["existing"]], {
      schemaDir: malformedSchemas,
    }),
    cover(value, [], { schemaDir: malformedSchemas }),
  ]);
  expect(responses[0]!.error).toBe(
    "findings.schema.properties.findings.items.properties.preventiveControls: expected an object",
  );
  expect(JSON.parse(responses[0]!.after)).toEqual([{}, {}, ["existing"]]);
  expect(responses[1]!.error).toBe(
    "coverage.schema.properties.explicitExclusions: expected an object",
  );
  const [output, messages] = JSON.parse(responses[1]!.after) as [
    Table,
    string[],
  ];
  expect(output["inventoryStrategy"]).toBe("repository");
  expect(output["completeness"]).toBe("invalid");
  expect(output["surfaces"]).toEqual([
    surface("a", { disposition: "needs_follow_up" }),
  ]);
  expect(messages).toEqual([
    "Recovered malformed coverage completeness; marked coverage as partial.",
    "Recovered malformed Deep Scan inventory strategy; marked coverage as partial.",
    "Recovered coverage surface 1: the review disposition could not be verified.",
  ]);
});

test.skipIf(process.platform === "win32")(
  "unexpected close failures propagate after preserving earlier warnings and coverage mutations",
  () => {
    const first = row({ writeup: "findings/a/a.md" });
    first["ruleId"] = String(first["ruleId"]).toUpperCase();
    const second = row({ anchor: "other", writeup: "findings/b/b.md" });
    const value = coverageWith(
      [
        surface("a", { receiptRefs: ["./artifacts//a.json"] }),
        surface("b", {
          disposition: "invalid",
          receiptRefs: ["./artifacts//b.json"],
        }),
      ],
      { completeness: "complete" },
    );
    const responses = run([
      recover([first, second], { trace: true, failCloseAt: 2 }),
      cover(value, [], { trace: true, failCloseAt: 2 }),
    ]);
    for (const response of responses)
      expect(response.error).toBe("synthetic close failure");
    expect(JSON.parse(responses[0]!.after)).toEqual([
      manifest,
      { ...findings, findings: [first, second] },
      ["Recovered finding 1: normalized rule identifier."],
    ]);
    expect(JSON.parse(responses[0]!.references)).toEqual([first, second]);
    const [output, messages] = JSON.parse(responses[1]!.after) as [
      Table,
      string[],
    ];
    expect(output["completeness"]).toBe("complete");
    expect(output["surfaces"]).toEqual([
      surface("a", { receiptRefs: ["artifacts/a.json"] }),
      surface("b", {
        disposition: "needs_follow_up",
        receiptRefs: ["./artifacts//b.json"],
      }),
    ]);
    expect(messages).toEqual([
      "Recovered coverage surface 2: the review disposition could not be verified.",
    ]);
  },
);

test("invalid schema patterns propagate without turning unfinished findings into discarded records", () => {
  const malformedSchemas = schemaCopy("invalid-pattern", (schemas) => {
    const properties = asTable(
      asTable(
        asTable(asTable(schemas.findings["properties"])["findings"])["items"],
      )["properties"],
    );
    asTable(
      asTable(asTable(properties["writeup"])["properties"])["reportPath"],
    )["pattern"] = "[";
  });
  const first = row();
  first["ruleId"] = String(first["ruleId"]).toUpperCase();
  const second = row({ anchor: "other", writeup: "findings/a/a.md" });
  const response = run([
    recover([first, second], { schemaDir: malformedSchemas }),
  ])[0]!;
  expect(response.error).toBe("unterminated character set at position 0");
  expect(JSON.parse(response.after)).toEqual([
    manifest,
    { ...findings, findings: [first, second] },
    ["Recovered finding 1: normalized rule identifier."],
  ]);
  expect(JSON.parse(response.references)).toEqual([first, second]);
});

test("hardening recovery only removes malformed portfolios and preserves unrelated manifest data", () => {
  const choices = [
    undefined,
    null,
    {},
    { portfolioPath: "elsewhere.md" },
    { portfolioPath: "hardening/hardening.md", custom: true },
  ];
  const requests = choices.map((hardening) =>
    request(
      "hardening",
      [
        {
          scan: {
            id: "scan",
            ...(hardening === undefined ? {} : { hardening }),
            custom: true,
          },
        },
        ["existing"],
      ],
      { trace: true },
    ),
  );
  const responses = run(requests);
  for (const [index, response] of responses.entries()) {
    const [output, messages] = success(response) as [Table, string[]];
    expect(output).toEqual({
      scan: {
        id: "scan",
        ...(index === 4 ? { hardening: choices[4] } : {}),
        custom: true,
      },
    });
    expect(messages[0]).toBe("existing");
    expect(messages).toHaveLength(index === 0 || index === 4 ? 1 : 2);
  }
  expect(warnings(responses[1]!)[1]).toBe(
    "Skipped malformed hardening portfolio: manifest.scan.hardening: expected an object.",
  );
  expect(warnings(responses[3]!)[1]).toBe(
    "Skipped malformed hardening portfolio: manifest.scan.hardening.portfolioPath: expected hardening/hardening.md.",
  );
  const invalid = run([request("hardening", [{ scan: null }, []])])[0]!;
  expect(invalid.error).toBe("manifest.scan: expected an object");
  expect(JSON.parse(invalid.after)).toEqual([{ scan: null }, []]);
});

test.skipIf(process.platform === "win32")(
  "writeups, receipts and hardening use the existing regular-file boundary",
  () => {
    const unsafeRoot = join(directory, "unsafe");
    for (const path of ["findings/a", "artifacts", "hardening"])
      mkdirSync(join(unsafeRoot, path), { recursive: true });
    symlinkSync(
      join(scanRoot, "findings/a/a.md"),
      join(unsafeRoot, "findings/a/a.md"),
    );
    symlinkSync(
      join(scanRoot, "artifacts/a.json"),
      join(unsafeRoot, "artifacts/a.json"),
    );
    mkdirSync(join(unsafeRoot, "hardening/hardening.md"));
    const responses = run([
      recover([row({ writeup: "findings/a/a.md" })], {
        root: unsafeRoot,
        trace: true,
      }),
      cover(
        coverageWith([surface("a", { receiptRefs: ["artifacts/a.json"] })]),
        [],
        { root: unsafeRoot, trace: true },
      ),
      request(
        "hardening",
        [
          { scan: { hardening: { portfolioPath: "hardening/hardening.md" } } },
          [],
        ],
        { root: unsafeRoot, trace: true },
      ),
    ]);
    expect(recovered(responses[0]!)[0]).not.toHaveProperty("writeup");
    expect(asTable(success(responses[1]!)[0])["surfaces"]).toEqual([
      surface("a", { disposition: "needs_follow_up" }),
    ]);
    expect(asTable(success(responses[2]!)[0])["scan"]).toEqual({});
    for (const [index, response] of responses.entries()) {
      expect(warnings(response)[0]).toContain(
        index === 2
          ? "expected a regular non-symlink file"
          : "expected a file inside the scan directory",
      );
      expect(response.events).toEqual([]);
    }
  },
);
