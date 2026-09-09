import { Connection, type Parameter } from "../../native/sqlite.mjs";
import { sqliteBinding } from "./native";
import { preflightInteger } from "./helpers/preflight-config";
import {
  JsonFloat,
  jsonItem,
  jsonTypeName,
  object,
  objectEntries,
  objectFromEntries,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { encodeUtf8 } from "./helpers/utf8";
import { upsertFinding, type ImportedFinding } from "./workbench-findings";
import { WorkbenchValidationError } from "./workbench-validation";

const fields = {
  findingId: "finding_id",
  occurrenceId: "occurrence_id",
  inputSha256: "input_sha256",
  rubricSha256: "rubric_sha256",
  knowledgeBaseSha256: "knowledge_base_sha256",
  assessedAt: "assessed_at",
  source: "source",
  decision: "decision",
  level: "level",
  rubricLabel: "rubric_label",
  rationale: "rationale",
  confidence: "confidence",
  reviewTrigger: "review_trigger",
} as const;
const parameters = (values: unknown[]): Parameter[] =>
  values.map((value) =>
    value instanceof JsonFloat ? Number(value.source) : value,
  ) as Parameter[];
export function severityAssessments(
  connection: Connection,
  findingIds: unknown,
): Record<string, unknown>[] {
  return connection
    .prepare(
      `SELECT assessment.* FROM json_each(?) AS selected
    JOIN finding_severity_assessments AS assessment ON assessment.finding_id = selected.value
    ORDER BY selected.key`,
    )
    .all([stringifyJson(findingIds, { compact: true })])
    .map((row) =>
      Object.fromEntries(
        Object.entries(fields).map(([key, column]) => [key, row.get(column)]),
      ),
    );
}
export function severityCheckpoint(
  connection: Connection,
  payload: unknown,
  timestamp: string,
): Record<string, unknown> {
  if (jsonItem(payload, "action") === "begin") {
    return connection.transaction(() => {
      connection
        .prepare(
          `INSERT INTO scan_severity_classifications (
        scan_id, finding_ids_json, assessed_at, rubric_sha256, knowledge_base_sha256
      ) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(scan_id) DO UPDATE SET
        finding_ids_json = excluded.finding_ids_json,
        assessed_at = excluded.assessed_at,
        rubric_sha256 = excluded.rubric_sha256,
        knowledge_base_sha256 = excluded.knowledge_base_sha256`,
        )
        .run(
          parameters([
            jsonItem(payload, "scanId"),
            stringifyJson(jsonItem(payload, "findingIds"), { compact: true }),
            jsonItem(payload, "assessedAt"),
            jsonItem(payload, "rubricSha256"),
            jsonItem(payload, "knowledgeBaseSha256"),
          ]),
        );
      return {
        assessments: severityAssessments(
          connection,
          jsonItem(payload, "findingIds"),
        ),
      };
    });
  }
  if (jsonItem(payload, "action") !== "save")
    throw new WorkbenchValidationError("Unknown severity checkpoint action.");
  const finding = jsonItem(payload, "finding") as ImportedFinding;
  const source = jsonItem(payload, "assessment");
  if (!object(source))
    throw new TypeError(`'${jsonTypeName(source)}' object is not a mapping`);
  const assessment = objectFromEntries([
    ...objectEntries(source),
    ["assessedAt", timestamp],
  ]);
  connection.transaction(() => {
    if (
      connection
        .prepare("SELECT 1 FROM findings WHERE id = ?")
        .get(parameters([jsonItem(finding, "findingId")])) === undefined
    )
      upsertFinding(connection, finding, timestamp);
    const columns = Object.values(fields).join(", "),
      placeholders = Object.keys(fields)
        .map(() => "?")
        .join(", "),
      updates = Object.values(fields)
        .map((column) => `${column} = excluded.${column}`)
        .join(", ");
    connection
      .prepare(
        `INSERT INTO finding_severity_assessments (${columns}) VALUES (${placeholders}) ON CONFLICT(finding_id) DO UPDATE SET ${updates}`,
      )
      .run(
        parameters(Object.keys(fields).map((key) => jsonItem(assessment, key))),
      );
  });
  return {};
}
export function readSeverityClassification(
  database: string,
  scanId: string,
): Record<string, unknown> {
  const path = Array.from(encodeUtf8(database), (byte) =>
    /[A-Za-z0-9_.~-]/u.test(String.fromCharCode(byte))
      ? String.fromCharCode(byte)
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`,
  ).join("");
  const connection = new Connection(sqliteBinding(), `file:${path}?mode=ro`, {
    uri: true,
  });
  try {
    connection.prepare("BEGIN").run();
    if (
      connection
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scan_severity_classifications'",
        )
        .get() === undefined
    )
      return {};
    const row = connection
      .prepare("SELECT * FROM scan_severity_classifications WHERE scan_id = ?")
      .get([scanId]);
    if (row === undefined) return {};
    const findingIds = parseJson(
      row.get("finding_ids_json") as string | Buffer,
      false,
      preflightInteger,
    );
    return {
      scanId,
      findingIds,
      assessedAt: row.get("assessed_at"),
      rubricSha256: row.get("rubric_sha256"),
      knowledgeBaseSha256: row.get("knowledge_base_sha256"),
      assessments: severityAssessments(connection, findingIds),
    };
  } finally {
    connection.close();
  }
}
