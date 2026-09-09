import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { ReportFinding } from "../../../plugins/codex-security/mcp-app/src/helpers/report-projection";
import type {
  Documents,
  Request,
  Response,
} from "./support/report-projection-fixture";

const directory = mkdtempSync(join(tmpdir(), "report-projection-"));
const fixture = join(directory, "fixture.cjs");
const node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/report-projection-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  const responses = JSON.parse(child.stdout) as Response[];
  for (const response of responses) expect(response.unchanged).toBe(true);
  return responses;
}
function documents(): Documents {
  return [
    {
      scan: {
        target: { displayName: "example/repo" },
        scope: {
          includePaths: ["src/"],
          excludePaths: [],
          summary: "## Scope\n- nested item",
        },
        threatModel: { summary: "# Threat heading\nThreat details" },
      },
    },
    {
      findings: [
        {
          occurrenceId: "occ_1",
          title: "Parser | boundary\n## Heading",
          summary: "```\ncode fence\n```",
          severity: { level: "high" },
          confidence: { level: "high", rationale: "Direct trace." },
          taxonomy: { category: "parser | injection", cwe: ["CWE-20"] },
          locations: [{ path: "src/parser.py", startLine: 10 }],
          remediation: "## Remediation\n- normalize input",
        },
      ],
    },
    {
      mode: "repository",
      inventoryStrategy: "repository",
      completeness: "complete",
      includePaths: ["src/"],
      excludePaths: [],
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  ];
}
function render(value: Documents): string {
  const source = JSON.stringify(value);
  const [text, bytes] = run([{ source }, { source, generate: true }]);
  expect(text!.error).toBeUndefined();
  expect(bytes!.error).toBeUndefined();
  expect(Buffer.from(bytes!.result!, "base64").toString("utf8")).toBe(
    text!.result!,
  );
  return text!.result!;
}
function finding(value: Documents): ReportFinding {
  return value[1].findings[0]!;
}
function section(markdown: string, heading: string, next: string): string {
  return markdown.split(`#### ${heading}`)[1]!.split(`#### ${next}`)[0]!;
}

test("normalizes block text while preserving inline code and escaping Markdown link syntax", () => {
  const value = documents();
  finding(value).title = "Parser ](https://example.com) [boundary | field";
  finding(value).summary =
    "The `parse(input)` call uses *data* and <raw> HTML.";
  finding(value).remediation = "[Open report](file:///tmp/report.md)";
  const markdown = render(value);
  expect(markdown).toContain("Text: ## Scope - nested item");
  expect(markdown).toContain("Text: # Threat heading Threat details");
  expect(markdown).toContain(
    "The `parse(input)` call uses \\*data\\* and \\<raw\\> HTML.",
  );
  expect(markdown).toContain(
    "[Parser \\](https://example.com) \\[boundary \\| field](#finding-1)",
  );
  expect(markdown).toContain("\\[Open report\\](file:///tmp/report.md)");
  expect(markdown).not.toContain("\n# Threat heading");
  expect(markdown).toContain('<a id="finding-1"></a>');
  expect(markdown.endsWith("\n")).toBe(true);
  expect(markdown.endsWith("\n\n")).toBe(false);
  const original = render(documents());
  expect(original).toContain("Text: \\`\\`\\` code fence \\`\\`\\`");
  expect(original).not.toContain("\n```");
});

test("renders exact target identity, scope overrides, exclusions and threat-model lists", () => {
  const value = documents();
  value[0].scan.target = {
    displayName: "repo\n## title",
    kind: "git_diff",
    targetId: "repo-1",
    baseRevision: "base",
    headRevision: "head",
    revision: "revision",
    snapshotDigest: "codex-security-snapshot/v1:sha256:" + "a".repeat(64),
  };
  value[0].scan.scope = {
    includePaths: ["fallback/"],
    excludePaths: ["vendor/"],
    context: "Context",
    runtimeStatus: "Static",
    validationMode: "source | trace",
    artifactsReviewed: ["build.json"],
    limitations: ["Runtime unknown"],
  };
  value[0].scan["threatModel"] = {
    assets: ["Files"],
    trustBoundaries: "Uploads",
    attackerCapabilities: ["Send files"],
    securityObjectives: ["Confine writes"],
    assumptions: ["Authentication enabled"],
  };
  value[2]["includePaths"] = ["src\n## path"];
  delete value[2]["excludePaths"];
  value[2]["explicitExclusions"] = [
    null,
    { pattern: "generated/", reason: "Generated files" },
  ];
  const markdown = render(value);
  for (const text of [
    "# Security Review: repo ## title",
    "The scan was configured for the include paths and exclusions listed below.",
    "- Target kind: git_diff",
    "- Target ID: repo-1",
    "- Revision range: base...head",
    "- Revision: revision",
    "- Snapshot digest: codex-security-snapshot/v1:sha256:",
    "- Included paths: src ## path",
    "- Excluded paths: vendor/",
    "- Artifacts reviewed: build.json",
    "- Scan context: Context",
    "- Runtime unknown",
    "Excluded generated/: Generated files",
    "source \\| trace",
    "### Assets",
    "### Trust Boundaries",
    "### Attacker Capabilities",
    "### Security Objectives",
    "### Assumptions",
  ])
    expect(markdown).toContain(text);
  value[2]["includePaths"] = null;
  expect(render(value)).toContain("- Included paths: none");
});

test("uses references and embedded evidence from each diagnostic section without changing source code", () => {
  const value = documents(),
    issue = finding(value);
  issue.summary = "The `write` precedes a check.";
  issue["codeEvidence"] = [
    {
      id: "source",
      label: "Input",
      path: "src/archive.py",
      startLine: 20,
      endLine: 22,
      language: "python",
      code: "path = entry.name",
      explanation: "The entry controls `path`.",
    },
    { id: "sink", code: "destination.write_bytes(payload)" },
    {
      id: "heading",
      language: "markdown",
      code: "### [2] Source heading\n```\nsource fence",
    },
  ];
  issue["code_evidence"] = [{ id: "source", code: "ignored duplicate id" }];
  issue["rootCause"] = { summary: "Broken control", evidence_refs: "source" };
  issue["validation"] = {
    evidenceRefs: ["sink", "missing", 5],
    codeEvidence: [{ id: "sink", code: "destination.write_bytes(payload)" }],
  };
  issue["attackPath"] = {
    evidenceRefs: "source",
    dataflow: { evidence_refs: ["heading"] },
    reachability: { evidence_refs: "sink" },
  };
  const markdown = render(value);
  expect(markdown).toContain("**Input** — `src/archive.py:20-22`");
  expect(markdown).toContain("The entry controls `path`.");
  expect(markdown).toContain("```python\npath = entry.name\n```");
  expect(markdown).toContain(
    "````markdown\n### [2] Source heading\n```\nsource fence\n````",
  );
  expect(markdown).not.toContain("ignored duplicate id");
  expect(
    section(markdown, "Validation", "Dataflow").match(
      /destination\.write_bytes/g,
    ),
  ).toHaveLength(1);
  expect(section(markdown, "Reachability", "Severity")).toContain(
    "destination.write_bytes(payload)",
  );
});

test("merges root-cause aliases, scalar references and embedded evidence while pairing code with its language", () => {
  const cases: [unknown, unknown, string[]][] = [
    ["A string root cause", undefined, ["A string root cause"]],
    [
      { summary: "" },
      { summary: "Legacy summary", code: "legacy()", language: "python" },
      ["Legacy summary", "```python\nlegacy()"],
    ],
    [
      { summary: 42 },
      { summary: "Valid summary", evidence_refs: "legacy" },
      ["Valid summary", "legacy_source()"],
    ],
    [
      { summary: " \t\u001c", code: "\t", language: "text" },
      { summary: "Fallback", code: "legacy()", language: "python" },
      ["Fallback", "```python\nlegacy()"],
    ],
    [
      { summary: "Evidence", evidenceRefs: ["current"] },
      { evidence_refs: "legacy" },
      ["current_source()", "legacy_source()"],
    ],
    [
      { codeEvidence: [{ id: "one", code: "one()" }] },
      { code_evidence: [{ id: "two", code: "two()" }] },
      ["one()", "two()"],
    ],
  ];
  for (const [current, legacy, expected] of cases) {
    const value = documents(),
      issue = finding(value);
    issue["rootCause"] = current;
    if (legacy !== undefined) issue["root_cause"] = legacy;
    issue["codeEvidence"] = [{ id: "current", code: "current_source()" }];
    issue["code_evidence"] = [{ id: "legacy", code: "legacy_source()" }];
    const markdown = render(value);
    for (const text of expected) expect(markdown).toContain(text);
  }
});

test("legacy root-cause code uses the root-control location and avoids duplicating referenced code", () => {
  const value = documents(),
    issue = finding(value);
  issue.locations.push({
    path: "src/control.py",
    startLine: 40,
    role: "root_control",
  });
  issue["rootCause"] = { code: "control()", language: "python" };
  let markdown = render(value);
  expect(markdown).toContain("**Broken control** — `src/control.py:40`");
  issue["codeEvidence"] = [
    { id: "control", code: "control()", language: "rust" },
  ];
  issue["rootCause"] = { code: "control()", evidenceRefs: ["control"] };
  markdown = render(value);
  expect(markdown.match(/control\(\)/g)).toHaveLength(1);
  expect(markdown).not.toContain("**Broken control**");
  expect(markdown).toContain("```rust");
});

test("merges dataflow aliases and transformations, preserving first usable text and evidence", () => {
  const value = documents();
  finding(value)["attackPath"] = {
    dataFlow: {
      summary: ["malformed"],
      transformations: ["decode entry", "parse *input*"],
      source: "request",
    },
    dataflow: {
      summary: "request -> write",
      transformations: ["dispatch", "decode entry"],
      sink: "file",
      outcome: "write",
    },
    data_flow: { transformations: null, summary: "ignored later summary" },
    steps: ["Upload an archive.", "Trigger extraction."],
  };
  const markdown = section(render(value), "Dataflow", "Reachability");
  expect(markdown).toContain("request -\\> write");
  expect(markdown).not.toContain("ignored later summary");
  expect(markdown.match(/- decode entry/g)).toHaveLength(1);
  for (const text of [
    "- dispatch",
    "- parse \\*input\\*",
    "- **Source:** request",
    "- **Sink:** file",
    "- **Outcome:** write",
    "Attack steps:",
    "- Trigger extraction.",
  ])
    expect(markdown).toContain(text);
});

test("renders reachability fallback, combined preconditions and attack-path context", () => {
  const value = documents();
  finding(value)["attackPath"] = {
    summary: "An authenticated uploader can reach extraction.",
    preconditions: ["Uploads enabled", "Authentication enabled"],
    reachability: {
      preconditions: ["Authentication enabled", "Automatic extraction"],
      attacker: "Uploader",
      entrypoint: "Upload handler",
      source: "Archive",
      sink: "File",
      outcome: "Write",
    },
    assumptions: ["Feature enabled"],
    controls: ["Authentication"],
    blindspots: ["Sandbox unknown"],
    limitations: ["Static trace"],
  };
  const markdown = section(render(value), "Reachability", "Severity");
  expect(markdown).toContain("An authenticated uploader can reach extraction.");
  expect(markdown.match(/- Authentication enabled/g)).toHaveLength(1);
  for (const text of [
    "- Uploads enabled",
    "- Automatic extraction",
    "- **Attacker:** Uploader",
    "- **Entry point:** Upload handler",
    "- **Source:** Archive",
    "- **Sink:** File",
    "- **Outcome:** Write",
    "Assumptions:",
    "Existing controls:",
    "Blind spots:",
    "Limitations:",
  ])
    expect(markdown).toContain(text);
});

test("renders validation outcomes and lists, severity assessments and remediation guidance", () => {
  const value = documents(),
    issue = finding(value);
  issue["validation"] = {
    status: "validated",
    disposition: "reported",
    result: "Confirmed write",
    method: "focused test",
    assertions: ["Write escapes root"],
    evidence: "Test output",
    counterEvidence: ["Sandbox unknown"],
    limitations: ["Local reproduction"],
  };
  issue["attackPath"] = {
    impact: {
      level: "high",
      rationale: "Overwrites files",
      why: "Escapes root",
    },
    likelihood: "Likely with uploads",
  };
  issue.severity["rationale"] = "Crosses a boundary";
  issue.severity["changeConditions"] = "A sandbox could reduce severity";
  issue["remediationTests"] = ["Reject traversal"];
  issue["preventiveControls"] = ["Confine extraction"];
  const markdown = render(value);
  for (const text of [
    "- **Status:** validated",
    "- **Disposition:** reported",
    "- **Result:** Confirmed write",
    "Validation method: focused test",
    "Assertions:",
    "Evidence:",
    "Counterevidence and remaining uncertainty:",
    "Limitations:",
    "**High** — Crosses a boundary",
    "A sandbox could reduce severity",
    "Impact assessment:",
    "- **Level:** high",
    "- **Rationale:** Overwrites files",
    "- **Why:** Escapes root",
    "**Likelihood assessment:** Likely with uploads",
    "Tests:",
    "- Reject traversal",
    "Preventive controls:",
    "- Confine extraction",
  ])
    expect(markdown).toContain(text);
  expect(section(markdown, "Validation", "Dataflow")).not.toContain(
    "not recorded separately",
  );
});

test("links detailed writeups without rendering the inline finding narrative", () => {
  const value = documents();
  finding(value)["writeup"] = {
    reportPath: "findings/parser-boundary/parser-boundary.md",
  };
  const markdown = render(value);
  expect(markdown).toContain(
    "[Open report](findings/parser-boundary/parser-boundary.md)",
  );
  expect(markdown).toContain("### [1] Parser");
  expect(markdown).not.toContain("Text: ## Remediation");
  expect(
    markdown.match(/See the \[detailed technical write-up\]/g),
  ).toHaveLength(6);
});

test("rejects malformed or unsafe writeup references and duplicate reportable paths", () => {
  for (const writeup of [
    [],
    "report",
    { reportPath: "../outside.md" },
    { reportPath: "findings/one/two.md" },
    { reportPath: "findings/one/one.md\n" },
    { reportPath: "findings/UPPER/UPPER.md" },
    { reportPath: "findings/one/one.md?query" },
  ]) {
    const value = documents();
    finding(value)["writeup"] = writeup;
    const [response] = run([{ source: JSON.stringify(value) }]);
    expect(response!.errorType).toBe("ReportProjectionError");
    expect(response!.error).toMatch(
      /writeup (must be an object|has an invalid reportPath)/,
    );
  }
  const value = documents(),
    first = finding(value);
  first["writeup"] = { reportPath: "findings/one/one.md" };
  const second = structuredClone(first);
  value[1].findings.push(second);
  expect(run([{ source: JSON.stringify(value) }])[0]!.error).toContain(
    "duplicate writeup reportPath values: findings/one/one.md",
  );
  second["writeup"] = { reportPath: "findings/two/two.md" };
  expect(render(value)).toContain("[Open report](findings/two/two.md)");
  second.severity.level = "informational";
  second["writeup"] = { reportPath: "../ignored.md" };
  expect(render(value)).toContain("| Reportable findings | 1 |");
});

test("groups deep report instances by candidate and orders each severity mix", () => {
  for (const mode of ["deep_repository", "scoped_path"]) {
    const value = documents(),
      first = finding(value);
    value[2].mode = mode;
    first.title = "Archive write [SCAN-001-first]";
    first["extensions"] = {
      candidateId: "SCAN-001",
      reportId: "SCAN-001-first",
      ledgerRowId: "ROW-001",
    };
    first["writeup"] = { reportPath: "findings/first/first.md" };
    const second = structuredClone(first);
    second.title = "Archive write [SCAN-001-second]";
    second.occurrenceId = "occ_2";
    second["extensions"] = {
      candidateId: "SCAN-001",
      reportId: "SCAN-001-second",
    };
    second.severity.level = "medium";
    second.confidence.level = "low";
    second["writeup"] = null;
    value[1].findings.unshift(second);
    const markdown = render(value);
    expect(markdown).toContain("| Reportable DSS findings | 1 |");
    expect(markdown).toContain("| Report instances | 2 |");
    expect(markdown).toContain("| Report severity mix | high: 1, medium: 1 |");
    expect(markdown).toContain(
      "| Archive write | [SCAN-001-first](#finding-1)<br>[SCAN-001-second](#finding-2) | high<br>medium | high<br>low |",
    );
    expect(markdown).toContain(
      "[Open SCAN-001-first](findings/first/first.md)<br>SCAN-001-second: inline below",
    );
  }
});

test("keeps scoped tables ordinary without deep child ids and preserves unrecognized title annotations", () => {
  const value = documents();
  value[2].mode = "scoped_path";
  finding(value).title = "Parser boundary [SCAN-001-parser]";
  finding(value)["extensions"] = { ledgerRowId: "SCAN-001-parser" };
  let markdown = render(value);
  expect(markdown).toContain(
    "| Finding | Severity | Confidence | Detailed write-up |",
  );
  expect(markdown).not.toContain("| Report instances |");
  expect(markdown).toContain(
    "[Parser boundary \\[SCAN-001-parser\\]](#finding-1)",
  );
  value[2].mode = "deep_repository";
  finding(value).title = "Parser boundary [unrelated annotation]";
  markdown = render(value);
  expect(markdown).toContain("| Parser boundary \\[unrelated annotation\\] |");
  finding(value).title = "Parser\ufeff[SCAN-001-parser]";
  expect(render(value)).toContain("| Parser\ufeff\\[SCAN-001-parser\\] |");
});

test("disambiguates deep report labels with recognized annotations then instance identity", () => {
  const value = documents();
  value[2].mode = "deep_repository";
  const first = finding(value);
  first.title = "Archive write [ROW-1; variant-a]";
  first["extensions"] = { candidateId: "SCAN-001", ledgerRowId: "ROW-1" };
  const second = structuredClone(first);
  second.occurrenceId = "occ_2";
  second.title = "Archive write [ROW-1; variant-b]";
  value[1].findings.push(second);
  let markdown = render(value);
  expect(markdown).toContain(
    "[ROW-1; variant-a](#finding-1)<br>[ROW-1; variant-b](#finding-2)",
  );
  second.title = first.title;
  first["identity"] = { instance: "first-instance" };
  second["identity"] = { instance: "second-instance" };
  markdown = render(value);
  expect(markdown).toContain(
    "[first-instance](#finding-1)<br>[second-instance](#finding-2)",
  );
});

test("sorts findings by severity, occurrence id and Unicode code points while omitting informational entries", () => {
  const value = documents(),
    base = finding(value);
  value[1].findings = [
    {
      ...structuredClone(base),
      title: "Supplementary",
      occurrenceId: "\u{10000}",
    },
    { ...structuredClone(base), title: "BMP", occurrenceId: "\ue000" },
    {
      ...structuredClone(base),
      title: "Critical",
      severity: { level: "critical" },
    },
    {
      ...structuredClone(base),
      title: "Omitted",
      severity: { level: "informational" },
    },
  ];
  const markdown = render(value);
  expect(markdown).toContain("[Critical](#finding-1)");
  expect(markdown).toContain("[BMP](#finding-2)");
  expect(markdown).toContain("[Supplementary](#finding-3)");
  expect(markdown).not.toContain("Omitted");
});

test("links only the canonical structural hardening portfolio", () => {
  const value = documents();
  expect(render(value)).not.toContain("## Structural Hardening");
  value[0].scan["hardening"] = { portfolioPath: "hardening/hardening.md" };
  expect(render(value)).toContain(
    "[Open the structural hardening portfolio](hardening/hardening.md)",
  );
  for (const hardening of [
    [],
    "portfolio",
    { portfolioPath: "../hardening.md" },
  ]) {
    value[0].scan["hardening"] = hardening;
    expect(run([{ source: JSON.stringify(value) }])[0]!.errorType).toBe(
      "ReportProjectionError",
    );
  }
});

test("stopped scans and exact timeout or cost-limit reasons retain their distinct no-findings conclusions", () => {
  const timeout =
    "The configured discovery time limit elapsed before any source review completed.";
  const budget =
    "Validation was deferred because the scan reached its cost limit.";
  for (const [status, completeness, reason, expected] of [
    [
      "failed",
      "partial",
      timeout,
      "No findings were retained before the scan stopped.",
    ],
    [
      "canceled",
      "partial",
      budget,
      "No findings were retained before the scan stopped.",
    ],
    [
      "interrupted",
      "complete",
      "",
      "No findings were retained before the scan stopped.",
    ],
    [
      "completed",
      "partial",
      timeout,
      "No source review completed before the configured time limit.",
    ],
    [
      "completed",
      "partial",
      budget,
      "No findings were validated before the scan reached its cost limit.",
    ],
    [
      "completed",
      "partial",
      "Validation was deferred because the scan reached its cost limit: proof remains.",
      "No findings were validated before the scan reached its cost limit.",
    ],
    ...[
      "The parser runtime could not be inspected.",
      "The retry budget was exhausted.",
      "The runtime resource budget prevented the optional check.",
      "An upstream service reached its own cost limit.",
      "Validation was deferred because the scan reached its cost limit unexpectedly.",
      "The configured discovery time limit elapsed during source review.",
      "Validation was deferred because a separate cost limit was reached.",
    ].map((reason) => [
      "completed",
      "partial",
      reason,
      "No reportable findings survived the canonical discovery, validation, and reportability gates.",
    ]),
    [
      "completed",
      "complete",
      timeout,
      "No reportable findings survived the canonical discovery, validation, and reportability gates.",
    ],
  ]) {
    const value = documents();
    value[0].scan["status"] = status;
    value[1].findings = [];
    value[2].completeness = completeness!;
    value[2]["deferred"] = [
      { id: "parser-review", reason, paths: ["src/parser.py"] },
    ];
    const markdown = render(value);
    expect(markdown).toContain("| Reportable findings | 0 |");
    expect(markdown).toContain(expected!);
    expect(markdown).toContain("Review deferred unit parser-review");
  }
});

test("keeps open questions, deferred paths and surface evidence in the final report", () => {
  const value = documents();
  value[2]["openQuestions"] = [
    false,
    {
      question: "Is authentication enabled?",
      followUpPrompt: "Inspect configuration",
    },
  ];
  value[2]["deferred"] = [
    null,
    {
      id: "parser-review",
      reason: "Review incomplete",
      paths: ["src/parser.py"],
      surfaceIds: ["parser-surface"],
    },
  ];
  value[2]["surfaces"] = [
    null,
    {
      id: "parser-surface",
      label: "Parser",
      disposition: "no_issue_found",
      receiptRefs: ["artifacts/receipts/parser.jsonl", 2],
      notes: "Reviewed parser entrypoints.",
    },
  ];
  const markdown = render(value);
  for (const text of [
    "## Reviewed Surfaces",
    "| Parser | not recorded | No issue found |",
    "Reviewed parser entrypoints. Evidence: artifacts/receipts/parser.jsonl",
    "## Open Questions And Follow Up",
    "- Is authentication enabled?",
    "  - Follow-up prompt: Inspect configuration",
    "- Review incomplete",
    "Paths: src/parser.py. Surfaces: parser-surface.",
  ])
    expect(markdown).toContain(text);
});

test("preserves Python whitespace, falsey metadata and the strict UTF-8 generation boundary", () => {
  const value = documents();
  finding(value).summary = "\u001c \u0085# heading\u001f body\ufeff";
  finding(value)["validation"] = { method: [] };
  value[2]["surfaces"] = [
    { label: "Parser", notes: null, receiptRefs: ["receipt"] },
  ];
  let markdown = render(value);
  expect(markdown).toContain("Text: # heading body\ufeff");
  expect(markdown).not.toContain("Validation method:");
  expect(markdown).toContain("None Evidence: receipt");
  finding(value).summary = "Supplementary 😀 text";
  expect(render(value)).toContain("Supplementary 😀 text");
  finding(value).summary = "Unpaired \ud800";
  const source = JSON.stringify(value);
  const [built, generated] = run([{ source }, { source, generate: true }]);
  expect(built!.result).toContain("Unpaired \ud800");
  expect(generated!.error).toContain(
    "'utf-8' codec can't encode character '\\ud800' in position",
  );
  markdown = built!.result!;
  expect(markdown.includes("Unpaired \ufffd")).toBe(false);
  for (const [summary, expected] of [
    ["١. list", "Text: ١. list"],
    ["\u{10d40}. list", "\u{10d40}. list"],
    ["#\ufeffheading", "#\ufeffheading"],
  ]) {
    finding(value).summary = summary;
    expect(section(render(value), "Summary", "Validation")).toBe(
      `\n\n${expected}\n\n`,
    );
  }
});

test("compares JSON line numbers without rounding large integers or printing equal endpoints twice", () => {
  const value = documents(),
    issue = finding(value);
  issue.locations = [{ path: "src/code", startLine: "START", endLine: "END" }];
  issue["rootCause"] = {
    codeEvidence: [
      {
        code: "evidence()",
        path: "src/code",
        startLine: "START",
        endLine: "END",
      },
    ],
  };
  for (const [start, end, expected] of [
    ["true", "1", "src/code:True"],
    ["1", "true", "src/code:1"],
    ["1", "1.0", "src/code:1"],
    [
      "9007199254740993",
      "9007199254740992.0",
      "src/code:9007199254740993-9007199254740992.0",
    ],
  ]) {
    const source = JSON.stringify(value)
      .replaceAll('"START"', start!)
      .replaceAll('"END"', end!);
    const [result] = run([{ source }]);
    expect(result!.error).toBeUndefined();
    expect(result!.result!).toContain(`| Affected lines | ${expected} |`);
    expect(result!.result!).toContain(`**Code evidence 1** — \`${expected}\``);
  }
});
