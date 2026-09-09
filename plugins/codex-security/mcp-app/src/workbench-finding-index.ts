import type { Connection, Parameter } from "../../native/sqlite.mjs";
import {
  JsonFloat,
  jsonGet,
  jsonItem,
  jsonTypeName,
  object,
  objectEntries,
  stringifyJson,
} from "./helpers/python-json";
import { upsertFinding, type ImportedFinding } from "./workbench-findings";
import { WorkbenchValidationError } from "./workbench-validation";

export interface IndexedFinding extends ImportedFinding {
  occurrenceId: string;
  title: string;
  summary: string;
  severity: { level: string };
  confidence: { level: string };
  remediation: string;
  locations: {
    path: string;
    startLine: bigint | number;
    endLine?: bigint | number | null;
    role?: string | null;
  }[];
}

const parameters = (values: unknown[]): Parameter[] =>
  values.map((value) =>
    value instanceof JsonFloat ? Number(value.source) : value,
  ) as Parameter[];
function locations(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return Array.from(value);
  if (object(value)) return objectEntries(value).map(([key]) => key);
  throw new TypeError(`'${jsonTypeName(value)}' object is not iterable`);
}

// The caller owns the transaction, including partial writes before a failure.
export function indexFindings(
  connection: Connection,
  scanId: string,
  document: { findings?: unknown },
  timestamp: string,
): void {
  const findings = document.findings;
  if (!Array.isArray(findings))
    throw new WorkbenchValidationError(
      "findings.json must contain a findings array.",
    );
  const scan = connection
    .prepare("SELECT target_id FROM scans WHERE id = ?")
    .get([scanId]);
  if (scan === undefined)
    throw new TypeError("'NoneType' object is not subscriptable");
  const repositoryId = scan.get("target_id") as string | null;
  for (const value of findings) {
    if (!object(value))
      throw new WorkbenchValidationError(
        "findings.json entries must be objects.",
      );
    const finding = value as IndexedFinding;
    const severity = jsonItem(finding, "severity"),
      confidence = jsonItem(finding, "confidence");
    upsertFinding(connection, finding, timestamp, repositoryId);
    connection
      .prepare(
        `
      INSERT INTO finding_occurrences (
        id, finding_id, scan_id, title, summary, severity, confidence, remediation,
        details_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        finding_id = excluded.finding_id,
        scan_id = excluded.scan_id,
        title = excluded.title,
        summary = excluded.summary,
        severity = excluded.severity,
        confidence = excluded.confidence,
        remediation = excluded.remediation,
        details_json = excluded.details_json
    `,
      )
      .run(
        parameters([
          jsonItem(finding, "occurrenceId"),
          jsonItem(finding, "findingId"),
          scanId,
          jsonItem(finding, "title"),
          jsonItem(finding, "summary"),
          jsonItem(severity, "level"),
          jsonItem(confidence, "level"),
          jsonItem(finding, "remediation"),
          stringifyJson(finding, {
            compact: true,
            allowNan: false,
            sortKeys: true,
          }),
          timestamp,
        ]),
      );
    connection
      .prepare("DELETE FROM finding_locations WHERE occurrence_id = ?")
      .run(parameters([jsonItem(finding, "occurrenceId")]));
    for (const [index, location] of locations(
      jsonItem(finding, "locations"),
    ).entries()) {
      connection
        .prepare(
          `
        INSERT INTO finding_locations (
          occurrence_id, relative_path, start_line, end_line, role, sort_order
        ) VALUES (?, ?, ?, ?, ?, ?)
      `,
        )
        .run(
          parameters([
            jsonItem(finding, "occurrenceId"),
            jsonItem(location, "path"),
            jsonItem(location, "startLine"),
            jsonGet(location, "endLine", jsonItem(location, "startLine")),
            jsonGet(location, "role"),
            BigInt(index),
          ]),
        );
    }
  }
}
