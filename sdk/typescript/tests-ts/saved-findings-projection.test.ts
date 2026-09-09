import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import type {
  Request,
  Response,
} from "./support/saved-findings-projection-fixture";

const directory = mkdtempSync(join(tmpdir(), "saved-findings-projection-"));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL(
          "./support/saved-findings-projection-fixture.ts",
          import.meta.url,
        ),
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
const request = (operation: Request["operation"], value: unknown): Request => ({
  operation,
  source: JSON.stringify(value),
});
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
const example = JSON.parse(
  readFileSync(
    new URL(
      "../../../plugins/codex-security/examples/completed-scan/findings.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as { findings: Record<string, unknown>[] };
function finding(
  fields: Record<string, unknown> = {},
): Record<string, unknown> {
  return { ...example.findings[0], ...fields };
}
function csv(findings: Record<string, unknown>[], mode: string): string {
  const result = run([request("csv", [{ findings }, { mode }])])[0]!;
  expect(result.error).toBeUndefined();
  return Buffer.from(result.hex!, "hex").toString("utf8");
}

test("legacy projection deduplicates evidence and keeps only known references on a detached copy", () => {
  const input = {
    findings: [
      finding({
        codeEvidence: [{ id: "canonical", code: "canonical code" }],
        code_evidence: [
          null,
          { id: "canonical", code: "duplicate" },
          { id: "legacy", code: "first", extra: { keep: true } },
          { id: "legacy", code: "second" },
          { id: " \u001c", code: "discard" },
          { id: "empty", code: "\u0085" },
        ],
        rootCause: {
          evidenceRefs: ["legacy", "missing", "canonical", "legacy"],
        },
        root_cause: {
          summary: "  ",
          code: false,
          language: "",
          evidence_refs: "legacy",
        },
        validation: {
          evidence: " proof ",
          evidenceRefs: ["missing"],
          limitations: ["", false, "limit"],
        },
      }),
    ],
  };
  const [output] = values([request("legacy", input)]) as (typeof input)[];
  expect(output!.findings[0]!["code_evidence"]).toEqual([
    { id: "legacy", code: "first", extra: { keep: true } },
  ]);
  expect(output!.findings[0]!["rootCause"]).toEqual({
    evidenceRefs: ["legacy", "canonical", "legacy"],
  });
  expect(output!.findings[0]!["root_cause"]).toEqual({
    summary: "  ",
    evidence_refs: ["legacy"],
  });
  expect(output!.findings[0]!["validation"]).toEqual({
    evidence: [" proof "],
    evidenceRefs: [],
    limitations: ["limit"],
  });
  expect(input.findings[0]!["code_evidence"]).toHaveLength(6);
});

test("legacy projection preserves scalar whitespace and normalizes all attack-path detail variants", () => {
  const attack: Record<string, unknown> = {
    summary: "",
    impact: { level: 1, rationale: null, why: " " },
    likelihood: false,
  };
  for (const field of ["dataFlow", "data_flow", "dataflow", "reachability"])
    attack[field] = {
      summary: null,
      source: " source ",
      sink: 1,
      outcome: "",
      attacker: "",
      entrypoint: false,
      transformations: " transform ",
      preconditions: ["", "needed", false],
      evidence_refs: ["unknown"],
    };
  const [output] = values([
    request("legacy", {
      findings: [
        {
          code_evidence: null,
          root_cause: null,
          attackPath: attack,
          validation: {
            status: null,
            disposition: 1,
            result: "",
            method: " ",
            evidence: [],
            assertions: false,
          },
        },
      ],
    }),
  ]) as { findings: Record<string, unknown>[] }[];
  const value = output!.findings[0]!;
  expect(value["code_evidence"]).toBeUndefined();
  expect(value["root_cause"]).toBeNull();
  expect(value["validation"]).toEqual({ method: " " });
  const projected = value["attackPath"] as Record<string, unknown>;
  expect(projected["impact"]).toEqual({ why: " " });
  expect(projected["likelihood"]).toBeUndefined();
  expect(projected["summary"]).toBeUndefined();
  expect(projected["reachability"]).toEqual({
    source: " source ",
    transformations: [" transform "],
    preconditions: ["needed"],
    evidence_refs: [],
  });
  for (const field of ["dataFlow", "data_flow", "dataflow"])
    expect(projected[field]).toEqual({
      source: " source ",
      attacker: "",
      entrypoint: false,
      transformations: [" transform "],
      preconditions: ["", "needed", false],
      evidence_refs: [],
    });
  expect(
    values([
      request("legacy", {
        findings: [
          false,
          null,
          {
            root_cause: "",
            attackPath: {
              dataFlow: "",
              data_flow: null,
              dataflow: 1,
              reachability: " ",
              impact: null,
            },
          },
        ],
      }),
    ]),
  ).toEqual([
    {
      findings: [
        false,
        null,
        { attackPath: { reachability: " ", impact: null } },
      ],
    },
  ]);
});

test("legacy projection preserves numeric tokens and dictionary order after removing fields", () => {
  const results = run([
    {
      operation: "legacy",
      source:
        '{"findings":[{"root_cause":{"code":null,"2":1.0,"1":9007199254740993,"unknown":{"keep":true}}}]}',
    },
    { operation: "entries", source: '{"2":1,"remove":null,"1":2}' },
  ]);
  expect(results[0]!.source).toBe(
    '{\n  "findings": [\n    {\n      "root_cause": {\n        "2": 1.0,\n        "1": 9007199254740993,\n        "unknown": {\n          "keep": true\n        }\n      }\n    }\n  ]\n}',
  );
  expect(JSON.parse(results[1]!.source!)).toEqual([
    ["2", 1],
    ["1", 2],
  ]);
});

test("candidate IDs preserve precedence and Python whitespace behavior", () => {
  expect(
    values([
      request("candidate", {
        provenance: { candidateId: " canonical " },
        extensions: { candidateId: "legacy" },
      }),
      request("candidate", {
        provenance: { candidateId: "\u001c" },
        extensions: {
          candidateId: "\u0085",
          reportId: "report",
          ledgerRowId: "ledger",
        },
      }),
      request("candidate", { extensions: { ledgerRowId: "ledger" } }),
      request("candidate", { extensions: { candidateId: "\ufeff" } }),
      request("candidate", { extensions: [] }),
    ]),
  ).toEqual([" canonical ", "report", "ledger", "\ufeff", null]);
});

test("CSV projection keeps the complete byte format, root-control location and deep candidate rules", () => {
  const row = finding({
    occurrenceId: "occurrence",
    findingId: "finding",
    title: "title",
    summary: "summary",
    severity: { level: "high" },
    confidence: { level: "medium" },
    remediation: "fix",
    provenance: { candidateId: "canonical" },
    extensions: { reportId: "legacy" },
    locations: [
      { path: "first.ts", startLine: 1 },
      { path: "root.ts", startLine: 9, role: "root_control" },
    ],
  });
  const header =
    "occurrence_id,finding_id,title,summary,severity,confidence,status,close_reason,note,remediation,path,start_line,end_line\r\n";
  expect(csv([row], "repository")).toBe(
    header +
      "occurrence,finding,title,summary,high,medium,open,,,fix,root.ts,9,9\r\n",
  );
  for (const mode of ["deep_repository", "scoped_path"])
    expect(csv([row], mode)).toBe(
      header.replace("finding_id,title", "finding_id,candidate_id,title") +
        "occurrence,finding,canonical,title,summary,high,medium,open,,,fix,root.ts,9,9\r\n",
    );
  expect(
    csv(
      [finding({ ...row, extensions: { ledgerRowId: "ledger" } })],
      "scoped_path",
    ),
  ).toBe(
    header +
      "occurrence,finding,title,summary,high,medium,open,,,fix,root.ts,9,9\r\n",
  );
  expect(csv([], "repository")).toBe(header);
  expect(
    csv(
      [
        finding({
          ...row,
          provenance: null,
          extensions: {},
          locations: [{ path: "one.ts", startLine: 2, endLine: null }],
        }),
      ],
      "deep_repository",
    ),
  ).toContain(
    "occurrence,finding,,title,summary,high,medium,open,,,fix,one.ts,2,\r\n",
  );
});

test("CSV quotes delimiters and protects the existing formula prefixes without changing other cells", () => {
  const inputs = [
    "=1",
    " +2",
    "\u001c-3",
    "@x",
    "＝1",
    "＋1",
    "－1",
    "＠x",
    "\tplain",
    "\rplain",
    "\nplain",
    " plain",
    "\ufeff=1",
    "\u200b=1",
    "'already",
    -1,
    true,
    null,
  ];
  expect(values(inputs.map((value) => request("cell", value)))).toEqual(
    inputs.map((value, index) => (index < 11 ? `'${value}` : value)),
  );
  const text = csv(
    [
      finding({
        title: 'a,"b"',
        summary: "\n=SUM(1)",
        remediation: "\u0085＠x",
        locations: [{ path: "one.ts", startLine: 1, endLine: 3 }],
      }),
    ],
    "repository",
  );
  expect(text).toContain('"a,""b""","\'\n=SUM(1)"');
  expect(text).toContain(",open,,,\u0027\u0085＠x,one.ts,1,3\r\n");
});

test("CSV and report encoding share strict Unicode error positions measured in code points", () => {
  expect(
    run([
      request("encode", "😀\ud800"),
      request("encode", "😀\ud800\udfff"),
      request("encode", "😀\ud800\ud800x"),
      request("encode", "valid😀"),
    ]),
  ).toEqual([
    {
      error:
        "'utf-8' codec can't encode character '\\ud800' in position 1: surrogates not allowed",
      unchanged: true,
    },
    { hex: Buffer.from("😀\ud800\udfff").toString("hex"), unchanged: true },
    {
      error:
        "'utf-8' codec can't encode characters in position 1-2: surrogates not allowed",
      unchanged: true,
    },
    { hex: Buffer.from("valid😀").toString("hex"), unchanged: true },
  ]);
  const result = run([
    request("csv", [
      { findings: [finding({ title: "\ud800" })] },
      { mode: "repository" },
    ]),
  ])[0]!;
  expect(result.error).toMatch(
    /codec can't encode character '\\ud800' in position \d+: surrogates not allowed/u,
  );
});
