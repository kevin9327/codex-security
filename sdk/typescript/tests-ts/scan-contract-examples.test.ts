import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { validateDateTime } from "../../../plugins/codex-security/mcp-app/src/helpers/contract-date-time";

type Table = Record<string, unknown>;
const object = (value: unknown) => value as Table;
const read = (path: string): Table =>
  JSON.parse(readFileSync(join(PLUGIN_ROOT, path), "utf8")) as Table;
const schema = (name: string) => read(`schemas/${name}.schema.json`);
const ajv = new Ajv2020({ strict: false });
ajv.addFormat("date-time", (value: string) => {
  try {
    validateDateTime(value, "date-time");
    return true;
  } catch {
    return false;
  }
});
ajv.addFormat(
  "uuid",
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu,
);
ajv.addSchema(schema("definitions/artifact-common"));
ajv.addSchema(schema("tools/scan-draft"));
const validators = {
  manifest: ajv.compile(schema("scan-manifest")),
  findings: ajv.compile(schema("findings")),
  coverage: ajv.compile(schema("coverage")),
  draft: ajv.getSchema(object(schema("tools/scan-draft"))["$id"] as string)!,
  reducer: ajv.compile(schema("tools/deep-reducer")),
};
function example() {
  const manifest = read("examples/completed-scan/scan-manifest.json"),
    findings = read("examples/completed-scan/findings.json"),
    coverage = read("examples/completed-scan/coverage.json");
  const scan = object(manifest["scan"]),
    target = object(scan["target"]),
    finding = (findings["findings"] as Table[])[0]!,
    surface = (coverage["surfaces"] as Table[])[0]!;
  return { manifest, findings, coverage, scan, target, finding, surface };
}

test("the packaged schemas are Draft 2020-12 schemas and accept their completed example", () => {
  for (const file of readdirSync(join(PLUGIN_ROOT, "schemas")).filter((name) =>
    name.endsWith(".schema.json"),
  )) {
    expect(ajv.validateSchema(read(`schemas/${file}`)), file).toBe(true);
  }
  const data = example();
  for (const name of ["manifest", "findings", "coverage"] as const)
    expect(
      validators[name](data[name]),
      JSON.stringify(validators[name].errors),
    ).toBe(true);
  expect(data.scan["id"]).toBe(data.findings["scanId"]);
  expect(data.scan["id"]).toBe(data.coverage["scanId"]);
  expect(data.scan["findingsRef"]).toBe("findings.json");
  expect(data.scan["coverageRef"]).toBe("coverage.json");
  const artifacts = data.scan["artifacts"] as {
    path: string;
    sha256: string;
  }[];
  expect(artifacts.map((item) => item.path).sort()).toEqual([
    "coverage.json",
    "findings.json",
  ]);
  for (const item of artifacts)
    expect(
      createHash("sha256")
        .update(
          readFileSync(join(PLUGIN_ROOT, "examples/completed-scan", item.path)),
        )
        .digest("hex"),
    ).toBe(item.sha256);
});

test("the manifest schema requires target snapshots, safe remotes and canonical artifact records", () => {
  for (const [kind, missing] of [
    ["git_revision", "revision"],
    ["git_worktree", "snapshotDigest"],
    ["git_diff", "snapshotDigest"],
    ["directory_snapshot", "snapshotDigest"],
  ]) {
    const d = example();
    d.target["kind"] = kind;
    delete d.target[missing!];
    expect(validators.manifest(d.manifest), `${kind}: ${missing}`).toBe(false);
  }
  for (const [field, value] of [
    ["snapshotDigest", "sha256:worktree-example"],
    ["remote", "https://token@example.com/repo"],
    ["remote", "https://example.com/repo?token=secret"],
    ["remote", "https://example.com/repo#token"],
  ]) {
    const d = example();
    d.target[field!] = value;
    expect(validators.manifest(d.manifest), `${field}: ${value}`).toBe(false);
  }
  const invalidTime = example();
  invalidTime.scan["startedAt"] = "2026-99-99T00:00:00Z";
  expect(validators.manifest(invalidTime.manifest)).toBe(false);
  for (const path of [
    "../../secret.json",
    "/tmp/secret.json",
    "exports\\results.sarif",
  ]) {
    const d = example();
    (d.scan["artifacts"] as Table[]).push({
      path,
      sha256: "0".repeat(64),
      mediaType: "application/json",
    });
    expect(validators.manifest(d.manifest), path).toBe(false);
  }
  for (const path of ["findings.json", "coverage.json"]) {
    const d = example(),
      artifacts = d.scan["artifacts"] as Table[];
    d.scan["artifacts"] = artifacts.filter((item) => item["path"] !== path);
    expect(validators.manifest(d.manifest), `missing ${path}`).toBe(false);
    d.scan["artifacts"] = [...artifacts, { ...artifacts[0], path }];
    expect(validators.manifest(d.manifest), `duplicate ${path}`).toBe(false);
  }
});

test("schemas constrain report links, coverage receipts, and unfinished work", () => {
  const d = example();
  d.scan["hardening"] = { portfolioPath: "hardening/hardening.md" };
  expect(validators.manifest(d.manifest)).toBe(true);
  d.scan["hardening"] = { portfolioPath: "../hardening.md" };
  expect(validators.manifest(d.manifest)).toBe(false);
  d.finding["writeup"] = {
    reportPath: "findings/unsafe-archive/unsafe-archive.md",
  };
  expect(validators.findings(d.findings)).toBe(true);
  d.finding["writeup"] = { reportPath: "../outside.md" };
  expect(validators.findings(d.findings)).toBe(false);
  for (const ref of [
    "report.md",
    "artifacts/../report.md",
    "artifacts\\receipt.jsonl",
  ]) {
    const copy = example();
    copy.surface["receiptRefs"] = [ref];
    expect(validators.coverage(copy.coverage), ref).toBe(false);
  }
  d.coverage["completeness"] = "probably-complete";
  expect(validators.coverage(d.coverage)).toBe(false);
  d.coverage["completeness"] = "complete";
  d.surface["disposition"] = "needs_follow_up";
  expect(validators.coverage(d.coverage)).toBe(false);
  d.surface["disposition"] = "reported";
  d.coverage["deferred"] = [
    {
      id: "deferred_archive_review",
      reason: "Archive extraction review was not completed.",
    },
  ];
  expect(validators.coverage(d.coverage)).toBe(false);
  d.surface["disposition"] = "needs_follow_up";
  d.coverage["completeness"] = "partial";
  expect(validators.coverage(d.coverage)).toBe(true);
});

function draft() {
  const finding = example().finding;
  for (const field of ["findingId", "occurrenceId", "fingerprints"])
    delete finding[field];
  return {
    scanId: "7fc17317-9594-49e0-b06a-d72fd7e14bba",
    findings: [finding],
    coverage: {
      completeness: "complete",
      surfaces: [{ label: "HTTP responses", disposition: "reported" }],
      explicitExclusions: [{ pattern: "docs/", reason: "Documentation only." }],
      deferred: [],
    },
  };
}
test("Standard submissions require coverage while Deep reducer submissions omit it", () => {
  const standard = draft(),
    { coverage, ...request } = standard;
  const reduction = object(
    object(schema("tools/deep-reducer")["$defs"])["reductionInput"],
  );
  expect(object(reduction["properties"])).not.toHaveProperty("coverage");
  expect((reduction["required"] as string[]).toSorted()).toEqual([
    "findings",
    "scanId",
  ]);
  expect(reduction["additionalProperties"]).toBe(false);
  expect(validators.reducer(request)).toBe(true);
  expect(validators.reducer({ ...request, findings: [] })).toBe(true);
  expect(
    validators.reducer({
      ...request,
      complete: true,
      handoffClaimToken: "2ea75b4f-f9b2-49b4-a5a9-2a8de8ca9047",
      scope: { summary: "HTTP responses" },
      threatModel: { summary: "Untrusted requests reach responses." },
    }),
  ).toBe(true);
  expect(validators.reducer(standard)).toBe(false);
  expect(validators.draft(request)).toBe(false);
  expect(validators.draft(standard)).toBe(true);
  for (const completeness of ["complete", "partial", "unknown", "invalid"]) {
    const value = { ...standard, coverage: { ...coverage, completeness } };
    expect(validators.draft(value), completeness).toBe(
      completeness !== "invalid",
    );
    expect(validators.reducer(value), completeness).toBe(false);
  }
  for (const field of [
    "completeness",
    "surfaces",
    "explicitExclusions",
    "deferred",
  ]) {
    const value = { ...coverage } as Table;
    delete value[field];
    expect(validators.draft({ ...standard, coverage: value }), field).toBe(
      false,
    );
  }
  for (const field of [
    "source_worker_id",
    "unknown_field",
    "resultPath",
    "consumedWorkerIds",
    "schemaVersion",
  ])
    expect(
      validators.reducer({ ...request, [field]: "not allowed" }),
      field,
    ).toBe(false);
  for (const field of [
    "ruleId",
    "title",
    "summary",
    "severity",
    "confidence",
    "taxonomy",
    "locations",
    "remediation",
    "provenance",
  ]) {
    const finding = { ...request.findings[0] };
    delete finding[field];
    expect(validators.reducer({ ...request, findings: [finding] }), field).toBe(
      false,
    );
    expect(validators.draft({ ...standard, findings: [finding] }), field).toBe(
      false,
    );
  }
  for (const field of ["scanId", "findings"]) {
    const value = { ...request } as Table;
    delete value[field];
    expect(validators.reducer(value), field).toBe(false);
  }
  expect(validators.reducer({ candidates: [], merges: [] })).toBe(false);
});

test("canonical and draft evidence accept call-stack roles and require code and explanations", () => {
  const data = example(),
    request = draft();
  const evidence: Table = {
    id: "request-input",
    label: "Request field enters the handler",
    path: "src/handler.py",
    startLine: 12,
    role: "user_input",
    code: "value = request.json['value']",
    explanation: "The request controls value before the handler forwards it.",
  };
  data.finding["codeEvidence"] = [evidence];
  request.findings[0]!["codeEvidence"] = [evidence];
  expect(validators.findings(data.findings)).toBe(true);
  expect(validators.draft(request)).toBe(true);
  for (const field of ["code", "explanation"]) {
    const invalid = { ...evidence };
    delete invalid[field];
    if (field === "code") invalid["snippet"] = evidence["code"];
    data.finding["codeEvidence"] = [invalid];
    request.findings[0]!["codeEvidence"] = [invalid];
    expect(validators.findings(data.findings), field).toBe(false);
    expect(validators.draft(request), field).toBe(false);
  }
  data.finding["codeEvidence"] = [{ ...evidence, role: "" }];
  expect(validators.findings(data.findings)).toBe(false);
});
