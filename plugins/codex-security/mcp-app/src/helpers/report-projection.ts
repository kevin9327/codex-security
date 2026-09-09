import decimalDigit from "@unicode/unicode-15.0.0/General_Category/Decimal_Number/regex.js";
import { hasText, mergedRootCause } from "./finding-root-cause";
import { JsonFloat, object, pythonRepr } from "./python-json";

type Table = Record<string, unknown>;
export interface ReportFinding extends Table {
  title: string;
  summary: unknown;
  occurrenceId?: string;
  severity: Table & { level: string };
  confidence: Table & { level: string; rationale: unknown };
  taxonomy: { category: unknown; cwe: string[] };
  locations: Table[];
  remediation: unknown;
}
export interface ReportManifest {
  scan: Table & { target: Table; scope: Table };
}
export interface ReportCoverage extends Table {
  mode: string;
  inventoryStrategy: string;
  completeness: string;
}
type Group = { number: number; finding: ReportFinding; path: string | null }[];
const severities = ["critical", "high", "medium", "low", "informational"];
const confidences = ["high", "medium", "low"];
const dispositions = new Map([
  ["reported", "Reported"],
  ["no_issue_found", "No issue found"],
  ["rejected", "Rejected"],
  ["not_applicable", "Not applicable"],
  ["needs_follow_up", "Needs follow-up"],
]);

export class ReportProjectionError extends Error {}

const get = (value: Table, key: string, fallback: unknown = null): unknown =>
  Object.hasOwn(value, key) ? value[key] : fallback;
const row = (value: unknown): Table => (object(value) ? value : {});
const str = (value: unknown): string =>
  typeof value === "string" ? value : pythonRepr(value);
function truth(value: unknown): boolean {
  if (value instanceof JsonFloat) return Number(value.source) !== 0;
  if (Array.isArray(value)) return value.length !== 0;
  if (object(value)) return Object.keys(value).length !== 0;
  return Boolean(value);
}
function compare(left: string, right: string): number {
  const a = Array.from(left, (c) => c.codePointAt(0)!);
  const b = Array.from(right, (c) => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}
const normalize = (value: string) =>
  value
    .split(/[\p{White_Space}\u001c-\u001f]+/u)
    .filter(Boolean)
    .join(" ");
const escapeText = (value: string) => value.replace(/([\\`*\[\]<>])/gu, "\\$1");
function text(value: unknown, fallback: string): string {
  let normalized = normalize(hasText(value) ? value : fallback);
  if (!normalized) return "";
  const numbered = /^(.+?)\. /u.exec(normalized);
  if (
    /^(?:#{1,6} |[-*+] |> |```|\|)/u.test(normalized) ||
    (numbered &&
      Array.from(numbered[1]!).every((digit) => decimalDigit.test(digit)))
  )
    normalized = `Text: ${normalized}`;
  const rendered: string[] = [];
  let cursor = 0;
  for (const match of normalized.matchAll(/(?<!`)`([^`\n]+)`(?!`)/gu)) {
    rendered.push(
      escapeText(normalized.slice(cursor, match.index)),
      `\`${match[1]}\``,
    );
    cursor = match.index + match[0].length;
  }
  rendered.push(escapeText(normalized.slice(cursor)));
  return rendered.join("");
}
function strings(value: unknown): string[] {
  const items = typeof value === "string" ? [value] : value;
  return Array.isArray(items)
    ? items.map((item) => text(item, "")).filter(Boolean)
    : [];
}
const cell = (value: unknown) =>
  text(value, "none").replaceAll("|", "\\|").replaceAll("\n", "<br>");
const linkLabel = (value: unknown, fallback: string) =>
  cell(value) || cell(fallback);
const bullets = (items: string[], fallback: string) =>
  (items.length ? items : [fallback]).map((item) => `- ${item}`);
function counts(values: string[]): Map<string, number> {
  const result = new Map<string, number>();
  for (const value of values) result.set(value, (result.get(value) ?? 0) + 1);
  return result;
}
function deepReportId(finding: ReportFinding): string {
  const extensions = row(finding["extensions"]);
  for (const value of [
    extensions["reportId"],
    extensions["ledgerRowId"],
    row(finding["identity"])["instance"],
    finding.occurrenceId,
  ])
    if (hasText(value)) return value;
  return "Unidentified report";
}
function deepCandidateId(finding: ReportFinding): string {
  const candidate = row(finding["extensions"])["candidateId"];
  return hasText(candidate) ? candidate : deepReportId(finding);
}
function usesDeepPresentation(
  coverage: ReportCoverage,
  findings: ReportFinding[],
): boolean {
  if (coverage.mode === "deep_repository") return true;
  // Child ids distinguish scoped deep scans from ordinary scoped scans.
  return (
    coverage.mode === "scoped_path" &&
    findings.some((finding) => {
      const extensions = row(finding["extensions"]);
      return (
        hasText(extensions["candidateId"]) || hasText(extensions["reportId"])
      );
    })
  );
}
function deepTitleParts(finding: ReportFinding): [string, string | null] {
  if (typeof finding.title !== "string") return ["Untitled finding", null];
  const normalized = normalize(finding.title);
  const match = /^(.+?) +\[([^\[\]\n]+)\]$/u.exec(normalized);
  if (!match) return [normalized, null];
  const annotation = match[2]!;
  const ids = [deepReportId(finding)];
  const ledger = row(finding["extensions"])["ledgerRowId"];
  if (hasText(ledger)) ids.push(ledger);
  return ids.some((id) => annotation === id || annotation.startsWith(`${id};`))
    ? [match[1]!, annotation]
    : [normalized, null];
}
function deepGroups(
  findings: ReportFinding[],
  paths: (string | null)[],
): Group[] {
  const groups = new Map<string, Group>();
  findings.forEach((finding, index) => {
    const id = deepCandidateId(finding);
    const group = groups.get(id) ?? [];
    group.push({ number: index + 1, finding, path: paths[index]! });
    groups.set(id, group);
  });
  return [...groups.values()];
}
const groupTitles = (group: Group) =>
  [
    ...new Set(group.map(({ finding }) => cell(deepTitleParts(finding)[0]))),
  ].join("<br>");
function groupLevels(
  group: Group,
  field: "severity" | "confidence",
  order: string[],
): string {
  const rank = (value: string) =>
    order.includes(value) ? order.indexOf(value) : order.length;
  return [...new Set(group.map(({ finding }) => finding[field].level))]
    .sort((a, b) => rank(a) - rank(b))
    .join("<br>");
}
function groupLabels(group: Group): unknown[] {
  const ids = group.map(({ finding }) => deepReportId(finding));
  const idCounts = counts(ids);
  const labels = group.map(({ finding }, index) => {
    const id = ids[index]!;
    return (idCounts.get(id)! > 1 ? deepTitleParts(finding)[1] : id) || id;
  });
  const labelCounts = counts(labels);
  return group.map(({ finding }, index) => {
    const label = labels[index]!;
    const identity = finding["identity"];
    const value =
      labelCounts.get(label)! > 1 && object(identity)
        ? get(identity, "instance")
        : label;
    return truth(value) ? value : deepReportId(finding);
  });
}
function groupLinks(group: Group, writeups: boolean): string {
  const labels = groupLabels(group);
  return group
    .map(({ number, path }, index) => {
      const label = linkLabel(labels[index], "Unidentified report");
      return writeups
        ? path
          ? `[Open ${label}](${path})`
          : `${label}: inline below`
        : `[${label}](#finding-${number})`;
    })
    .join("<br>");
}
function writeupPath(finding: ReportFinding): string | null {
  const writeup = get(finding, "writeup");
  if (writeup === null) return null;
  if (!object(writeup))
    throw new ReportProjectionError("finding writeup must be an object");
  const path = writeup["reportPath"];
  if (
    typeof path !== "string" ||
    !/^findings\/([a-z0-9][a-z0-9._-]*)\/\1\.md$/u.test(path) ||
    path.endsWith("\n")
  )
    throw new ReportProjectionError(
      "finding writeup has an invalid reportPath",
    );
  return path;
}
function hardeningPath(scan: Table): string | null {
  const hardening = get(scan, "hardening");
  if (hardening === null) return null;
  if (!object(hardening))
    throw new ReportProjectionError("scan hardening must be an object");
  if (hardening["portfolioPath"] !== "hardening/hardening.md")
    throw new ReportProjectionError(
      "scan hardening has an invalid portfolioPath",
    );
  return hardening["portfolioPath"];
}
function sectionEvidence(
  finding: ReportFinding,
  ...sections: Table[]
): Table[] {
  const catalog = new Map<string, Table>();
  for (const key of ["codeEvidence", "code_evidence"]) {
    const raw = finding[key];
    if (Array.isArray(raw))
      for (const item of raw)
        if (
          object(item) &&
          typeof item["id"] === "string" &&
          hasText(item["code"]) &&
          !catalog.has(item["id"])
        )
          catalog.set(item["id"], item);
  }
  const resolved: Table[] = [];
  for (const section of sections) {
    for (const key of ["evidenceRefs", "evidence_refs"]) {
      const raw = section[key];
      const refs = typeof raw === "string" ? [raw] : raw;
      if (Array.isArray(refs))
        for (const ref of refs)
          if (typeof ref === "string" && catalog.has(ref))
            resolved.push(catalog.get(ref)!);
    }
    for (const key of ["codeEvidence", "code_evidence"]) {
      const embedded = section[key];
      if (Array.isArray(embedded))
        for (const item of embedded)
          if (object(item) && hasText(item["code"])) resolved.push(item);
    }
  }
  const seen = new Map<string, Set<string>>();
  return resolved.filter((item) => {
    const id = str(get(item, "id", ""));
    const code = item["code"] as string;
    const codes = seen.get(id) ?? new Set<string>();
    if (codes.has(code)) return false;
    codes.add(code);
    seen.set(id, codes);
    return true;
  });
}
function rootCauseEvidence(finding: ReportFinding, rootCause: Table): Table[] {
  const evidence = sectionEvidence(finding, rootCause);
  const code = rootCause["code"];
  if (!hasText(code) || evidence.some((item) => item["code"] === code))
    return evidence;
  return [
    ...evidence,
    {
      code,
      label: "Broken control",
      language: get(rootCause, "language", ""),
      location:
        finding.locations.find(
          (location) => object(location) && location["role"] === "root_control",
        ) ?? {},
    },
  ];
}
function sameLine(left: unknown, right: unknown): boolean {
  const numeric = (value: unknown) =>
    typeof value === "boolean"
      ? BigInt(value)
      : value instanceof JsonFloat
        ? Number(value.source)
        : value;
  const a = numeric(left),
    b = numeric(right);
  if (typeof a === "bigint" && typeof b === "number")
    return Number.isInteger(b) && a === BigInt(b);
  if (typeof b === "bigint" && typeof a === "number")
    return Number.isInteger(a) && b === BigInt(a);
  return a === b;
}
function evidenceLocation(item: Table): string {
  const location = item["location"];
  if (typeof location === "string") return location;
  if (object(location)) item = location;
  const path = item["path"],
    start = get(item, "startLine"),
    end = get(item, "endLine", start);
  if (typeof path !== "string" || !path) return "";
  if (
    typeof start !== "bigint" &&
    typeof start !== "boolean" &&
    !(typeof start === "number" && Number.isInteger(start))
  )
    return path;
  return sameLine(start, end)
    ? `${path}:${str(start)}`
    : `${path}:${str(start)}-${str(end)}`;
}
function evidenceLines(evidence: Table[]): string[] {
  const lines: string[] = [];
  evidence.forEach((item, index) => {
    const label = text(item["label"], `Code evidence ${index + 1}`);
    const location = text(evidenceLocation(item), "");
    const explanation = text(item["explanation"], "");
    const language =
      typeof item["language"] === "string" &&
      /^[A-Za-z0-9_+.-]*$/u.test(item["language"]) &&
      !item["language"].endsWith("\n")
        ? item["language"]
        : "";
    const code = item["code"] as string;
    let fenceLength = 3;
    for (const match of code.matchAll(/`+/gu))
      fenceLength = Math.max(fenceLength, match[0].length + 1);
    const fence = "`".repeat(fenceLength);
    lines.push("", `**${label}**${location ? ` — \`${location}\`` : ""}`);
    if (explanation) lines.push("", explanation);
    lines.push("", `${fence}${language}`, code, fence);
  });
  return lines;
}
function mix(
  findings: ReportFinding[],
  field: "severity" | "confidence",
  order: string[],
): string {
  const levels = counts(findings.map((finding) => finding[field].level));
  return (
    order
      .filter((level) => levels.has(level))
      .map((level) => `${level}: ${levels.get(level)}`)
      .join(", ") || "none"
  );
}
function locations(finding: ReportFinding): string {
  return finding.locations
    .map((location) => {
      const start = location["startLine"],
        end = get(location, "endLine", start);
      return `${str(location["path"])}:${str(start)}${sameLine(start, end) ? "" : `-${str(end)}`}`;
    })
    .join(", ");
}
function targetScopeLines(target: Table): string[] {
  const lines = [
    `- Target kind: ${text(target["kind"], "not recorded")}`,
    `- Target ID: ${text(target["targetId"], "not recorded")}`,
  ];
  const base = text(target["baseRevision"], ""),
    head = text(target["headRevision"], "");
  if (base || head)
    lines.push(`- Revision range: ${base || "unknown"}...${head || "unknown"}`);
  const revision = text(target["revision"], ""),
    digest = text(target["snapshotDigest"], "");
  if (revision) lines.push(`- Revision: ${revision}`);
  if (digest) lines.push(`- Snapshot digest: ${digest}`);
  return lines;
}
function surfaceNotes(surface: Table): string {
  const notes = get(
    surface,
    "notes",
    "No additional canonical notes were recorded.",
  );
  const refs = surface["receiptRefs"];
  if (!Array.isArray(refs) || !refs.length) return cell(notes);
  const evidence = refs.filter((item) => typeof item === "string").join(", ");
  return evidence ? cell(`${str(notes)} Evidence: ${evidence}`) : cell(notes);
}
function findingHeader(number: number, finding: ReportFinding): string[] {
  return [
    `<a id="finding-${number}"></a>`,
    "",
    `### [${number}] ${text(finding.title, "Untitled finding")}`,
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| Severity | ${cell(finding.severity.level)} |`,
    `| Confidence | ${cell(finding.confidence.level)} |`,
    `| Confidence rationale | ${cell(finding.confidence.rationale)} |`,
    `| Category | ${cell(finding.taxonomy.category)} |`,
    `| CWE | ${cell(finding.taxonomy.cwe.join(", ") || "none")} |`,
    `| Affected lines | ${cell(locations(finding))} |`,
  ];
}

function findingSection(number: number, finding: ReportFinding): string[] {
  const validation = row(finding["validation"]);
  const [, rawRootCause] = mergedRootCause(finding);
  const rootCause = row(rawRootCause);
  const attackPath = row(finding["attackPath"]);
  const dataflowSections = ["dataFlow", "dataflow", "data_flow"].flatMap(
    (key): Table[] => {
      const value = attackPath[key];
      return typeof value === "string"
        ? [{ summary: value }]
        : object(value)
          ? [value]
          : [];
    },
  );
  const dataflow: Table = {};
  for (const key of ["summary", "source", "sink", "outcome"]) {
    const value = dataflowSections.map((section) => section[key]).find(hasText);
    if (value !== undefined) dataflow[key] = value;
  }
  const transformations = [
    ...new Set(
      dataflowSections.flatMap((section): string[] => {
        const raw = section["transformations"];
        return (
          typeof raw === "string" ? [raw] : Array.isArray(raw) ? raw : []
        ).filter(hasText);
      }),
    ),
  ];
  if (transformations.length) dataflow["transformations"] = transformations;
  const rawReachability = attackPath["reachability"];
  const reachability =
    typeof rawReachability === "string"
      ? { summary: rawReachability }
      : row(rawReachability);
  const severity = finding.severity;
  const outcomes = [
    ["Status", "status"],
    ["Disposition", "disposition"],
    ["Result", "result"],
  ].flatMap(([label, key]) => {
    const value = text(validation[key!], "");
    return value ? [`- **${label}:** ${value}`] : [];
  });
  const validationSummary = text(
    validation["summary"],
    outcomes.length
      ? "Validation outcomes are recorded below."
      : `${str(finding.confidence.rationale)} Validation details were not recorded separately.`,
  );
  const rootSummary = text(
    typeof rawRootCause === "string" ? rawRootCause : rootCause["summary"],
    "",
  );
  const rootEvidence = rootCauseEvidence(finding, rootCause);
  const dataflowSummary = text(
    dataflow["summary"],
    `The canonical finding records the affected path at ${locations(finding)}, but no expanded source-to-sink narrative was recorded.`,
  );
  const reachabilitySummary = text(
    reachability["summary"],
    text(
      attackPath["summary"],
      "Reachability was not recorded beyond the canonical finding summary and affected locations.",
    ),
  );
  const severityRationale = text(
    severity["rationale"],
    `The scan assigned ${severity.level} severity; no separate canonical severity rationale was recorded.`,
  );
  const severityChange = text(
    severity["changeConditions"],
    "Additional runtime or deployment evidence could raise or lower this severity.",
  );
  const lines = [
    ...findingHeader(number, finding),
    "",
    "#### Summary",
    "",
    text(finding.summary, "No canonical finding summary was recorded."),
  ];
  if (rootSummary || rootEvidence.length) {
    lines.push("", "#### Root Cause", "");
    if (rootSummary) lines.push(rootSummary);
    lines.push(...evidenceLines(rootEvidence));
  }
  lines.push("", "#### Validation", "", validationSummary);
  if (truth(validation["method"]))
    lines.push(
      "",
      `Validation method: ${text(validation["method"], "not recorded")}`,
    );
  if (outcomes.length) lines.push("", ...outcomes);
  lines.push(...evidenceLines(sectionEvidence(finding, validation)));
  for (const [heading, key, fallback] of [
    ["Assertions:", "assertions", "None recorded."],
    ["Evidence:", "evidence", "No evidence recorded."],
    [
      "Counterevidence and remaining uncertainty:",
      "counterEvidence",
      "None recorded.",
    ],
    ["Limitations:", "limitations", "None recorded."],
  ]) {
    const values = strings(validation[key!]);
    if (values.length) lines.push("", heading!, ...bullets(values, fallback!));
  }
  lines.push("", "#### Dataflow", "", dataflowSummary);
  const steps = strings(attackPath["steps"]);
  if (steps.length)
    lines.push("", "Attack steps:", ...bullets(steps, "None recorded."));
  for (const [label, key] of [
    ["Source", "source"],
    ["Sink", "sink"],
    ["Outcome", "outcome"],
  ])
    if (truth(dataflow[key!]))
      lines.push("", `- **${label}:** ${text(dataflow[key!], "not recorded")}`);
  const renderedTransformations = strings(dataflow["transformations"]);
  if (renderedTransformations.length)
    lines.push(
      "",
      "Transformations:",
      ...bullets(renderedTransformations, "None recorded."),
    );
  lines.push(
    ...evidenceLines(sectionEvidence(finding, attackPath, ...dataflowSections)),
  );
  lines.push("", "#### Reachability", "", reachabilitySummary);
  for (const [label, key] of [
    ["Attacker", "attacker"],
    ["Entry point", "entrypoint"],
    ["Source", "source"],
    ["Sink", "sink"],
    ["Outcome", "outcome"],
  ])
    if (truth(reachability[key!]))
      lines.push(
        "",
        `- **${label}:** ${text(reachability[key!], "not recorded")}`,
      );
  const preconditions = [
    ...new Set([
      ...strings(attackPath["preconditions"]),
      ...strings(reachability["preconditions"]),
    ]),
  ];
  if (preconditions.length)
    lines.push(
      "",
      "Preconditions:",
      ...bullets(preconditions, "None recorded."),
    );
  for (const [label, key] of [
    ["Assumptions", "assumptions"],
    ["Existing controls", "controls"],
    ["Blind spots", "blindspots"],
    ["Limitations", "limitations"],
  ]) {
    const values = strings(attackPath[key!]);
    if (values.length)
      lines.push("", `${label}:`, ...bullets(values, "None recorded."));
  }
  lines.push(...evidenceLines(sectionEvidence(finding, reachability)));
  lines.push(
    "",
    "#### Severity",
    "",
    `**${severity.level[0]!.toUpperCase()}${severity.level.slice(1).toLowerCase()}** — ${severityRationale}`,
    "",
    severityChange,
  );
  for (const [label, key] of [
    ["Impact", "impact"],
    ["Likelihood", "likelihood"],
  ]) {
    const assessment = attackPath[key!];
    if (typeof assessment === "string") {
      const rendered = text(assessment, "");
      if (rendered) lines.push("", `**${label} assessment:** ${rendered}`);
      continue;
    }
    if (!object(assessment)) continue;
    const details = [
      ["Level", "level"],
      ["Rationale", "rationale"],
      ["Why", "why"],
    ].flatMap(([name, field]) => {
      const value = text(assessment[field!], "");
      return value ? [`- **${name}:** ${value}`] : [];
    });
    if (details.length) lines.push("", `${label} assessment:`, ...details);
  }
  lines.push(
    "",
    "#### Remediation",
    "",
    text(finding.remediation, "No canonical remediation was recorded."),
  );
  const tests = strings(finding["remediationTests"]),
    controls = strings(finding["preventiveControls"]);
  if (tests.length)
    lines.push("", "Tests:", ...bullets(tests, "No tests recorded."));
  if (controls.length)
    lines.push(
      "",
      "Preventive controls:",
      ...bullets(controls, "None recorded."),
    );
  return lines;
}

function linkedFindingSection(
  number: number,
  finding: ReportFinding,
  path: string,
): string[] {
  const lines = findingHeader(number, finding);
  for (const heading of [
    "Summary",
    "Validation",
    "Dataflow",
    "Reachability",
    "Severity",
    "Remediation",
  ])
    lines.push(
      "",
      `#### ${heading}`,
      "",
      `See the [detailed technical write-up](${path}).`,
    );
  return lines;
}

/** Project canonical documents without reading files or changing the input objects. */
export function buildReportMarkdown(
  manifest: ReportManifest,
  findingsDocument: { findings: ReportFinding[] },
  coverage: ReportCoverage,
): string {
  const scan = manifest.scan,
    target = scan.target,
    scope = scan.scope;
  const threatModel = row(scan["threatModel"]);
  const findings = findingsDocument.findings
    .filter((finding) =>
      severities.slice(0, 4).includes(finding.severity.level),
    )
    .sort(
      (a, b) =>
        severities.indexOf(a.severity.level) -
          severities.indexOf(b.severity.level) ||
        compare(a.occurrenceId ?? "", b.occurrenceId ?? "") ||
        compare(a.title, b.title),
    );
  const paths = findings.map(writeupPath);
  const duplicates = [
    ...counts(paths.filter((path): path is string => path !== null)),
  ]
    .filter(([, count]) => count > 1)
    .map(([path]) => path)
    .sort(compare);
  if (duplicates.length)
    throw new ReportProjectionError(
      `reportable findings have duplicate writeup reportPath values: ${duplicates.join(", ")}`,
    );
  const deep = usesDeepPresentation(coverage, findings);
  const groups = deep ? deepGroups(findings, paths) : [];
  const portfolio = hardeningPath(scan);
  const includePaths = strings(
    get(coverage, "includePaths", get(scope, "includePaths", [])),
  );
  const excludePaths = strings(
    get(coverage, "excludePaths", get(scope, "excludePaths", [])),
  );
  const limitations = strings(scope["limitations"]);
  const lines = [
    `# Security Review: ${text(target["displayName"], "Unknown target")}`,
    "",
    "## Scope",
    "",
    text(
      scope["summary"],
      "The scan was configured for the include paths and exclusions listed below.",
    ),
    "",
    `- Scan mode: ${coverage.mode}`,
    ...targetScopeLines(target),
    `- Inventory strategy: ${coverage.inventoryStrategy}`,
    `- Included paths: ${includePaths.join(", ") || "none"}`,
    `- Excluded paths: ${excludePaths.join(", ") || "none"}`,
    `- Runtime or test status: ${text(scope["runtimeStatus"], "not recorded")}`,
  ];
  const artifacts = strings(scope["artifactsReviewed"]);
  if (artifacts.length)
    lines.push(`- Artifacts reviewed: ${artifacts.join(", ")}`);
  const context = text(scope["context"], "");
  if (context) lines.push(`- Scan context: ${context}`);
  for (const exclusion of get(coverage, "explicitExclusions", []) as unknown[])
    if (object(exclusion))
      limitations.push(
        `Excluded ${text(exclusion["pattern"], "unspecified")}: ${text(exclusion["reason"], "reason not recorded")}`,
      );
  if (limitations.length)
    lines.push(
      "",
      "Limitations and exclusions:",
      ...bullets(limitations, "None recorded."),
    );
  const countLines = deep
    ? [
        `| Reportable DSS findings | ${groups.length} |`,
        `| Report instances | ${findings.length} |`,
        `| Report severity mix | ${mix(findings, "severity", severities)} |`,
        `| Report confidence mix | ${mix(findings, "confidence", confidences)} |`,
      ]
    : [
        `| Reportable findings | ${findings.length} |`,
        `| Severity mix | ${mix(findings, "severity", severities)} |`,
        `| Confidence mix | ${mix(findings, "confidence", confidences)} |`,
      ];
  lines.push(
    "",
    "### Scan Summary",
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| Scan outcome | ${str(get(scan, "status", "completed"))} |`,
    ...countLines,
    `| Coverage | ${coverage.completeness} |`,
    `| Validation mode | ${cell(get(scope, "validationMode", "not recorded"))} |`,
    "",
    "Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.",
    "",
    "## Threat Model",
    "",
    text(
      threatModel["summary"],
      "No explicit canonical threat-model summary was recorded.",
    ),
  );
  for (const [heading, key, fallback] of [
    ["Assets", "assets", "No assets were recorded."],
    [
      "Trust Boundaries",
      "trustBoundaries",
      "No trust boundaries were recorded.",
    ],
    [
      "Attacker Capabilities",
      "attackerCapabilities",
      "No attacker capabilities were recorded.",
    ],
    [
      "Security Objectives",
      "securityObjectives",
      "No security objectives were recorded.",
    ],
    ["Assumptions", "assumptions", "No assumptions were recorded."],
  ]) {
    const values = strings(threatModel[key!]);
    if (values.length)
      lines.push("", `### ${heading}`, "", ...bullets(values, fallback!));
  }
  lines.push("", "## Findings", "");
  if (findings.length) {
    if (deep) {
      lines.push(
        "| Findings | Reports | Severity | Confidence | Detailed write-up |",
        "| --- | --- | --- | --- | --- |",
      );
      for (const group of groups)
        lines.push(
          `| ${groupTitles(group)} | ${groupLinks(group, false)} | ${groupLevels(group, "severity", severities)} | ${groupLevels(group, "confidence", confidences)} | ${groupLinks(group, true)} |`,
        );
    } else {
      lines.push(
        "| Finding | Severity | Confidence | Detailed write-up |",
        "| --- | --- | --- | --- |",
      );
      findings.forEach((finding, index) => {
        const link = `[${linkLabel(finding.title, "Untitled finding")}](#finding-${index + 1})`;
        const writeup = paths[index]
          ? `[Open report](${paths[index]})`
          : "inline below";
        lines.push(
          `| ${link} | ${finding.severity.level} | ${finding.confidence.level} | ${writeup} |`,
        );
      });
    }
    lines.push(
      "",
      "### Confidence Scale",
      "",
      "| Label | Meaning |",
      "| --- | --- |",
      "| high | Direct evidence supports the finding with no material unresolved blocker. |",
      "| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |",
      "| low | Evidence is incomplete and the item is retained only for explicit follow-up. |",
    );
    findings.forEach((finding, index) =>
      lines.push(
        "",
        ...(paths[index] !== null
          ? linkedFindingSection(index + 1, finding, paths[index]!)
          : findingSection(index + 1, finding)),
      ),
    );
  } else {
    const deferred = coverage["deferred"];
    const partial =
      coverage.completeness === "partial" && Array.isArray(deferred)
        ? deferred
        : [];
    const noSource = partial.some(
      (item) =>
        object(item) &&
        item["reason"] ===
          "The configured discovery time limit elapsed before any source review completed.",
    );
    const exhausted = partial.some(
      (item) =>
        object(item) &&
        typeof item["reason"] === "string" &&
        (item["reason"] ===
          "Validation was deferred because the scan reached its cost limit." ||
          item["reason"].startsWith(
            "Validation was deferred because the scan reached its cost limit: ",
          )),
    );
    const stopped = ["failed", "canceled", "interrupted"].includes(
      scan["status"] as string,
    );
    lines.push(
      "### No findings",
      "",
      stopped
        ? "No findings were retained before the scan stopped. The scan did not complete. No vulnerability conclusion can be drawn."
        : noSource
          ? "No source review completed before the configured time limit. No vulnerability conclusion can be drawn."
          : exhausted
            ? "No findings were validated before the scan reached its cost limit. Review the deferred candidates in Open Questions And Follow Up."
            : "No reportable findings survived the canonical discovery, validation, and reportability gates.",
    );
  }
  if (portfolio !== null)
    lines.push(
      "",
      "## Structural Hardening",
      "",
      "The scan also produced derived, unsealed design guidance based on the complete finding collection. These proposals describe options and tradeoffs; they do not indicate that any finding has been remediated.",
      "",
      `[Open the structural hardening portfolio](${portfolio})`,
    );
  const surfaces = get(coverage, "surfaces", []);
  if (truth(surfaces)) {
    lines.push(
      "",
      "## Reviewed Surfaces",
      "",
      "| Surface | Risk Area | Outcome | Notes |",
      "| --- | --- | --- | --- |",
    );
    for (const surface of surfaces as unknown[]) {
      if (!object(surface)) continue;
      const disposition = get(surface, "disposition");
      lines.push(
        `| ${[
          cell(get(surface, "label", get(surface, "id"))),
          cell(get(surface, "riskArea", "not recorded")),
          cell(
            typeof disposition === "string"
              ? dispositions.get(disposition) ?? disposition
              : disposition,
          ),
          surfaceNotes(surface),
        ].join(" | ")} |`,
      );
    }
  }
  const openQuestions = coverage["openQuestions"];
  const questions: unknown[] = Array.isArray(openQuestions)
    ? [...openQuestions]
    : [];
  const deferred = coverage["deferred"];
  if (Array.isArray(deferred))
    for (const item of deferred) {
      if (!object(item)) continue;
      questions.push({
        question: get(item, "reason", "Deferred review requires follow-up."),
        followUpPrompt: [
          `Review deferred unit ${str(get(item, "id", "unknown"))} and close its stated proof gap.`,
          truth(item["paths"])
            ? `Paths: ${(item["paths"] as string[]).join(", ")}.`
            : "",
          truth(item["surfaceIds"])
            ? `Surfaces: ${(item["surfaceIds"] as string[]).join(", ")}.`
            : "",
        ]
          .join(" ")
          .replace(
            /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
            "",
          ),
      });
    }
  if (questions.length) {
    lines.push("", "## Open Questions And Follow Up", "");
    for (const question of questions) {
      if (!object(question)) continue;
      lines.push(
        `- ${text(question["question"], "Unspecified open question.")}`,
      );
      const prompt = text(question["followUpPrompt"], "");
      if (prompt) lines.push(`  - Follow-up prompt: ${prompt}`);
    }
  }
  return (
    lines.join("\n").replace(/[\p{White_Space}\u001c-\u001f]+$/u, "") + "\n"
  );
}

export function generateReportMarkdown(
  manifest: ReportManifest,
  findings: { findings: ReportFinding[] },
  coverage: ReportCoverage,
): Buffer {
  const markdown = buildReportMarkdown(manifest, findings, coverage);
  const surrogate = /[\ud800-\udfff]/u;
  if (surrogate.test(markdown)) {
    const characters = Array.from(markdown);
    const start = characters.findIndex((character) =>
      surrogate.test(character),
    );
    let end = start + 1;
    while (end < characters.length && surrogate.test(characters[end]!)) end++;
    const detail =
      end === start + 1
        ? `character ${pythonRepr(characters[start])} in position ${start}`
        : `characters in position ${start}-${end - 1}`;
    throw new Error(
      `'utf-8' codec can't encode ${detail}: surrogates not allowed`,
    );
  }
  return Buffer.from(markdown);
}
