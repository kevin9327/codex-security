import { hasText } from "./finding-root-cause";
import { primaryFindingLocation } from "./finding-evidence";
import { copyJson, object, pythonRepr } from "./python-json";
import { encodeUtf8 } from "./utf8";

type Table = Record<string, unknown>;

function normalizeLists(section: Table, fields: readonly string[]): void {
  for (const field of fields) {
    if (!Object.hasOwn(section, field)) continue;
    const value = section[field];
    const normalized =
      typeof value === "string"
        ? hasText(value)
          ? [value]
          : []
        : Array.isArray(value)
          ? value.filter(hasText)
          : [];
    if (normalized.length) section[field] = normalized;
    else delete section[field];
  }
}

function removeUnsupportedStrings(
  section: Table,
  fields: readonly string[],
): void {
  for (const field of fields)
    if (
      Object.hasOwn(section, field) &&
      (typeof section[field] !== "string" || section[field] === "")
    )
      delete section[field];
}

function filterEvidenceRefs(section: Table, ids: Set<string>): void {
  for (const field of ["evidenceRefs", "evidence_refs"]) {
    const refs = section[field];
    if (Array.isArray(refs))
      section[field] = refs.filter((ref) => hasText(ref) && ids.has(ref));
  }
}

/** Preserve the finalizer's compatibility projection without changing sealed input. */
export function legacySealedFindingsForValidation(findings: Table): Table {
  const compatible = copyJson(findings) as Table;
  const items = compatible["findings"];
  if (!Array.isArray(items)) return compatible;
  for (const finding of items) {
    if (!object(finding)) continue;
    const canonical = finding["codeEvidence"];
    const ids = new Set<string>();
    for (const evidence of Array.isArray(canonical) ? canonical : [])
      if (
        object(evidence) &&
        typeof evidence["id"] === "string" &&
        evidence["id"] !== ""
      )
        ids.add(evidence["id"]);
    const legacy = finding["code_evidence"];
    if (Array.isArray(legacy)) {
      finding["code_evidence"] = legacy.filter((evidence) => {
        if (
          !object(evidence) ||
          !hasText(evidence["id"]) ||
          !hasText(evidence["code"]) ||
          ids.has(evidence["id"])
        )
          return false;
        ids.add(evidence["id"]);
        return true;
      });
    } else if (Object.hasOwn(finding, "code_evidence"))
      delete finding["code_evidence"];
    const refs = ["evidenceRefs", "evidence_refs"];
    for (const [name, fields] of [
      ["rootCause", refs],
      ["root_cause", refs],
      [
        "validation",
        ["assertions", "counterEvidence", "evidence", ...refs, "limitations"],
      ],
      [
        "attackPath",
        [
          "assumptions",
          "blindspots",
          "controls",
          ...refs,
          "limitations",
          "preconditions",
          "steps",
        ],
      ],
    ] satisfies [string, string[]][]) {
      const section = finding[name];
      if (!object(section)) continue;
      normalizeLists(section, fields);
      filterEvidenceRefs(section, ids);
    }
    const rootCause = finding["root_cause"];
    if (object(rootCause))
      removeUnsupportedStrings(rootCause, ["summary", "code", "language"]);
    else if (
      Object.hasOwn(finding, "root_cause") &&
      rootCause !== null &&
      (typeof rootCause !== "string" || rootCause === "")
    )
      delete finding["root_cause"];
    const validation = finding["validation"];
    if (object(validation))
      removeUnsupportedStrings(validation, [
        "method",
        "status",
        "summary",
        "disposition",
        "result",
      ]);
    const attack = finding["attackPath"];
    if (!object(attack)) continue;
    removeUnsupportedStrings(attack, ["summary"]);
    for (const field of ["dataFlow", "data_flow", "dataflow", "reachability"]) {
      if (!Object.hasOwn(attack, field)) continue;
      const detail = attack[field];
      if (typeof detail === "string") {
        if (detail === "") delete attack[field];
        continue;
      }
      if (!object(detail)) {
        delete attack[field];
        continue;
      }
      removeUnsupportedStrings(detail, [
        "summary",
        "source",
        "sink",
        "outcome",
        ...(field === "reachability" ? ["attacker", "entrypoint"] : []),
      ]);
      normalizeLists(detail, [...refs, "transformations"]);
      filterEvidenceRefs(detail, ids);
      if (field === "reachability") normalizeLists(detail, ["preconditions"]);
    }
    for (const field of ["impact", "likelihood"]) {
      const detail = attack[field];
      if (object(detail))
        removeUnsupportedStrings(detail, ["level", "rationale", "why"]);
      else if (
        Object.hasOwn(attack, field) &&
        detail !== null &&
        (typeof detail !== "string" || detail === "")
      )
        delete attack[field];
    }
  }
  return compatible;
}

export function findingCandidateId(finding: Table): string | null {
  const provenance = finding["provenance"];
  if (object(provenance) && hasText(provenance["candidateId"]))
    return provenance["candidateId"];
  const extensions = finding["extensions"];
  if (object(extensions))
    for (const field of ["candidateId", "reportId", "ledgerRowId"])
      if (hasText(extensions[field])) return extensions[field];
  return null;
}

export function csvCell(value: unknown): unknown {
  return typeof value === "string" &&
    (/^[\t\r\n]/u.test(value) ||
      /^[\p{White_Space}\u001c-\u001f]*[=+\-@＝＋－＠]/u.test(value))
    ? `'${value}`
    : value;
}

export interface CsvFinding extends Table {
  occurrenceId: unknown;
  findingId: unknown;
  title: unknown;
  summary: unknown;
  severity: { level: unknown };
  confidence: { level: unknown };
  remediation: unknown;
  locations: {
    path: unknown;
    startLine: unknown;
    endLine?: unknown;
    role?: unknown;
  }[];
}

export function buildCsvProjection(
  findings: { findings: CsvFinding[] },
  coverage: Table,
): Buffer {
  const deep =
    coverage["mode"] === "deep_repository" ||
    (coverage["mode"] === "scoped_path" &&
      findings.findings.some((finding) => {
        const extensions = finding["extensions"];
        return (
          object(extensions) &&
          ["candidateId", "reportId"].some((field) =>
            hasText(extensions[field]),
          )
        );
      }));
  const rows: unknown[][] = [
    [
      "occurrence_id",
      "finding_id",
      ...(deep ? ["candidate_id"] : []),
      "title",
      "summary",
      "severity",
      "confidence",
      "status",
      "close_reason",
      "note",
      "remediation",
      "path",
      "start_line",
      "end_line",
    ],
  ];
  for (const finding of findings.findings) {
    const location = primaryFindingLocation(finding);
    rows.push([
      csvCell(finding.occurrenceId),
      csvCell(finding.findingId),
      ...(deep ? [csvCell(findingCandidateId(finding))] : []),
      csvCell(finding.title),
      csvCell(finding.summary),
      csvCell(finding.severity.level),
      csvCell(finding.confidence.level),
      "open",
      "",
      "",
      csvCell(finding.remediation),
      csvCell(location.path),
      location.startLine,
      Object.hasOwn(location, "endLine")
        ? location.endLine
        : location.startLine,
    ]);
  }
  return encodeUtf8(
    rows
      .map(
        (row) =>
          row
            .map((value) => {
              const cell =
                value === null || value === undefined
                  ? ""
                  : typeof value === "string"
                    ? value
                    : pythonRepr(value);
              return /[,"\r\n]/u.test(cell)
                ? `"${cell.replaceAll('"', '""')}"`
                : cell;
            })
            .join(",") + "\r\n",
      )
      .join(""),
  );
}
