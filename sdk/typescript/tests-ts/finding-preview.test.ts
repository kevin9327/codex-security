import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { Request, Response } from "./support/finding-preview-fixture";

const root = mkdtempSync(join(tmpdir(), "finding-preview-"));
const fixture = join(root, "fixture.cjs");
const node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/finding-preview-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
  }),
);
afterAll(() => rmSync(root, { recursive: true, force: true }));
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  const responses = JSON.parse(child.stdout) as Response[];
  for (const result of responses) {
    expect(result.error).toBeUndefined();
    expect(result.unchanged).toBe(true);
  }
  return responses;
}
interface Preview {
  rootCause: { summary: string; evidenceRefs: string[] };
  validation: {
    summary: string;
    method: string;
    evidenceRefs: string[];
    counterEvidence: string[];
  };
  attackPath: {
    [key: string]: unknown;
    reachability?: string;
    preconditions?: string[];
    evidenceRefs?: string[];
  };
  writeup: { reportPath: string };
  codeEvidence: { id: string; code: string; role?: string }[];
  code_evidence?: unknown;
  preventiveControls: string[];
  remediationTests: string[];
}
function details(value: unknown): Preview {
  return JSON.parse(
    run([{ source: JSON.stringify(value) }])[0]!.result!,
  ) as Preview;
}

test("reserves diagnostics and evidence when finding fields exceed presentation budgets", () => {
  const bounded = details({
    attackPath: {
      blindspots: ["x".repeat(20_000)],
      summary: "Upload reaches a write. " + "x".repeat(20_000),
      reachability: "Authenticated uploaders",
      preconditions: ["Extraction is enabled"],
      evidenceRefs: ["evidence-0"],
    },
    codeEvidence: Array.from({ length: 10 }, (_, index) => ({
      id: `evidence-${index}`,
      label: "Long source excerpt",
      path: "src/archive.py",
      startLine: 40,
      role: index === 0 ? "user_input" : "propagation",
      code: "\\\\\n😀".repeat(5_000),
      explanation: "Write before check",
    })),
    rootCause: {
      code: "x".repeat(20_000),
      summary: "Check follows write. " + "x".repeat(20_000),
      evidenceRefs: ["evidence-0"],
    },
    validation: {
      evidence: ["x".repeat(20_000)],
      summary: "Reproduced. " + "x".repeat(20_000),
      method: "focused test",
      evidenceRefs: ["evidence-0"],
      futureMetadata: "x".repeat(20_000),
      counterEvidence: ["Mitigations unverified"],
    },
    writeup: {
      reportPath: "findings/example/report.md",
      untrustedExtra: "x".repeat(20_000),
    },
    evidenceExcerpt: "x".repeat(20_000),
  });
  expect(bounded.rootCause.summary.startsWith("Check follows write.")).toBe(
    true,
  );
  expect(bounded.rootCause.evidenceRefs).toEqual(["evidence-0"]);
  expect(bounded.validation.summary.startsWith("Reproduced.")).toBe(true);
  expect(bounded.validation.method).toBe("focused test");
  expect(bounded.validation.evidenceRefs).toEqual(["evidence-0"]);
  expect(bounded.validation.counterEvidence).toEqual([
    "Mitigations unverified",
  ]);
  expect(bounded.attackPath.reachability).toBe("Authenticated uploaders");
  expect(bounded.attackPath.preconditions).toEqual(["Extraction is enabled"]);
  expect(bounded.attackPath.evidenceRefs).toEqual(["evidence-0"]);
  expect(bounded.writeup).toEqual({ reportPath: "findings/example/report.md" });
  expect(bounded.codeEvidence).toHaveLength(4);
  expect(bounded.codeEvidence[0]!.role).toBe("user_input");
  const ascii = (value: unknown) =>
    JSON.stringify(value).replace(
      /[\u007f-\uffff]/g,
      (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
  for (const evidence of bounded.codeEvidence)
    expect(ascii(evidence.code).length).toBeLessThanOrEqual(1_500);
  expect(ascii(bounded).length).toBeLessThanOrEqual(16_000);
});

test("merges legacy root-cause fields while keeping matching code language and evidence order", () => {
  const sources = [
    {
      rootCause: { code: "first()" },
      root_cause: {
        code: "second()",
        evidence_refs: ["legacy"],
        language: "python",
        summary: "A summary",
      },
    },
    {
      rootCause: { summary: 42 },
      root_cause: { summary: "Legacy summary", evidence_refs: ["legacy"] },
    },
    {
      rootCause: "Canonical text",
      root_cause: {
        evidenceRefs: ["b", "a", "b"],
        code: "first()",
        language: "python",
      },
    },
    {
      rootCause: { summary: "\u001c\u0085" },
      root_cause: { summary: "Nonempty", language: "typescript" },
    },
  ];
  const responses = run(
    sources.map((value) => ({ action: "root", source: JSON.stringify(value) })),
  );
  expect(responses.map((row) => JSON.parse(row.result!))).toEqual([
    [
      "rootCause",
      { code: "first()", summary: "A summary", evidenceRefs: ["legacy"] },
    ],
    ["rootCause", { summary: "Legacy summary", evidenceRefs: ["legacy"] }],
    [
      "rootCause",
      {
        summary: "Canonical text",
        code: "first()",
        evidenceRefs: ["b", "a"],
        language: "python",
      },
    ],
    ["rootCause", { summary: "Nonempty", language: "typescript" }],
  ]);
});

test("filters malformed evidence before deduplication and limiting, preserving input objects", () => {
  const bounded = details({
    codeEvidence: [
      null,
      "junk",
      {},
      { id: "empty", code: "" },
      {
        id: "shared",
        code: "canonical()",
        startLine: 0,
        endLine: "12",
        label: 7,
        role: {},
      },
      { id: "shared", code: "duplicate()" },
      { id: "two", code: "two()" },
      { id: "three", code: "three()" },
    ],
    code_evidence: [
      { id: "shared", code: "legacy()" },
      { id: "four", code: "four()" },
      { id: "five", code: "five()" },
    ],
    preventiveControls: ["Validate paths"],
    remediationTests: ["Reject invalid entries"],
    rootCause: { summary: "Summary" },
  });
  expect(bounded.codeEvidence.map((item: { id: string }) => item.id)).toEqual([
    "shared",
    "two",
    "three",
    "four",
  ]);
  expect(bounded.codeEvidence[0]).toEqual({
    id: "shared",
    code: "canonical()",
  });
  expect(bounded.code_evidence).toBeUndefined();
  expect(bounded.preventiveControls).toEqual(["Validate paths"]);
  expect(bounded.remediationTests).toEqual(["Reject invalid entries"]);
  const numeric = JSON.parse(
    run([
      {
        source:
          '{"codeEvidence":[{"id":"x","code":"x()","startLine":1.0,"endLine":null}]}',
      },
    ])[0]!.result!,
  );
  expect(numeric.codeEvidence[0]).toEqual({
    id: "x",
    code: "x()",
    endLine: null,
  });
});

test("normalizes scalar assessments with Python's case matching and preserves structured values", () => {
  for (const level of ["medium", "HIGH", "hıgh", "hİgh", "unKnown"])
    expect(
      details({ attackPath: { impact: "A description", likelihood: level } })
        .attackPath,
    ).toEqual({
      impact: { rationale: "A description" },
      likelihood: { level },
    });
  expect(
    details({
      attackPath: {
        impact: { level: "high", why: "Writable destination" },
        likelihood: null,
      },
    }).attackPath,
  ).toEqual({
    impact: { level: "high", why: "Writable destination" },
    likelihood: null,
  });
  expect(
    details({ attackPath: { summary: "Only summary" } }).attackPath,
  ).toEqual({ summary: "Only summary" });
});

test("counts ASCII JSON bytes and cuts strings at Python code-point boundaries", () => {
  const responses = run(
    [0, 1, 2, 3, 7, 8, 14, 15, 16].map((maximum) => ({
      action: "text",
      source: JSON.stringify("é😀\n"),
      maximum,
    })),
  );
  expect(responses.map((row) => JSON.parse(row.result!))).toEqual([
    ["", 2],
    ["", 2],
    ["", 2],
    ["", 2],
    ["", 2],
    ["é", 8],
    ["é", 8],
    ["é", 8],
    ["é", 8],
  ]);
  const lone = run([{ action: "text", source: '"\\ud800x"', maximum: 8 }])[0]!;
  expect(JSON.parse(lone.result!)).toEqual(["\ud800", 8]);
});

test("retains ordered keys, scalar types, truncated-key collisions, and remaining budgets", () => {
  const responses = run([
    { action: "value", source: '{"2":"a","1":"b","0":"c"}', maximum: 18 },
    { action: "value", source: "[1,1.0,-0.0,true,null]", maximum: 100 },
    { action: "value", source: "[[[1]]]", maximum: 100, maxDepth: 2 },
    { action: "value", source: '"nonempty"', maximum: 1 },
    {
      action: "value",
      source: JSON.stringify({
        ["x".repeat(600) + "a"]: 1,
        ["x".repeat(600) + "b"]: 2,
      }),
      maximum: 2_000,
    },
  ]);
  expect(responses[0]!.result).toBe('{"2": "a", "1": "b"}');
  expect(responses[0]!.remaining).toBe(1);
  expect(responses[1]!.result).toBe("[1, 1.0, -0.0, true, null]");
  expect(JSON.parse(responses[2]!.result!)).toEqual([[null]]);
  expect(responses[3]!.remaining).toBe(0);
  expect(JSON.parse(responses[3]!.result!)).toBe("");
  expect(Object.entries(JSON.parse(responses[4]!.result!))).toEqual([
    ["x".repeat(510), 2],
  ]);
});

test("reserves both guidance lists when diagnostics and guidance are large", () => {
  const bounded = details({
    rootCause: { summary: "r".repeat(10_000) },
    validation: { summary: "v".repeat(10_000) },
    attackPath: { narrative: "a".repeat(10_000) },
    evidenceExcerpt: "e".repeat(20_000),
    remediationTests: ["😀".repeat(20_000)],
    preventiveControls: ["é".repeat(20_000)],
  });
  expect(bounded.rootCause).toBeDefined();
  expect(bounded.validation).toBeDefined();
  expect(bounded.attackPath).toBeDefined();
  expect(bounded.remediationTests[0]!.length).toBeGreaterThan(0);
  expect(bounded.preventiveControls[0]!.length).toBeGreaterThan(0);
});
