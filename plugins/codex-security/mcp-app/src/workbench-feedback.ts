import type { Connection, Row } from "../../native/sqlite.mjs";
import { boundedOutputText } from "./workbench-validation";

export function getScanFeedback(connection: Connection, scan: Row) {
  const rows = connection
    .prepare(
      `
    WITH ranked_decisions AS (
      SELECT findings.id AS finding_id, findings.fingerprint, findings.rule_id,
        findings.identity_anchor, findings.identity_instance, occurrences.title,
        occurrences.summary, COALESCE(triage.status, 'open') AS triage_status,
        triage.close_reason, triage.note,
        COALESCE(triage.updated_at, source_scans.completed_at) AS updated_at,
        source_scans.id AS source_scan_id,
        source_scans.completed_at AS source_completed_at,
        locations.relative_path, locations.start_line, locations.end_line, locations.role,
        ROW_NUMBER() OVER (
          PARTITION BY findings.id
          ORDER BY COALESCE(triage.updated_at, source_scans.completed_at) DESC,
            source_scans.completed_at DESC,
            source_scans.id DESC, occurrences.id DESC
        ) AS decision_rank
      FROM finding_occurrences AS occurrences
      JOIN findings ON findings.id = occurrences.finding_id
      JOIN scans AS source_scans ON source_scans.id = occurrences.scan_id
      LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
      JOIN finding_locations AS locations ON locations.id = (
        SELECT candidate.id
        FROM finding_locations AS candidate
        WHERE candidate.occurrence_id = occurrences.id
        ORDER BY CASE WHEN candidate.role = 'root_control' THEN 0 ELSE 1 END,
          candidate.sort_order
        LIMIT 1
      )
      WHERE source_scans.target_id = ?
        AND source_scans.id != ?
        AND source_scans.status = 'complete'
    )
    SELECT * FROM ranked_decisions
    WHERE decision_rank = 1
      AND triage_status = 'closed'
      AND close_reason = 'false_positive'
      AND note IS NOT NULL
      AND trim(note) != ''
    ORDER BY updated_at DESC, source_completed_at DESC, source_scan_id DESC, finding_id DESC
    LIMIT 50
  `,
    )
    .all([scan.get("target_id"), scan.get("id")]);
  const falsePositives = rows.map((row) => ({
    findingId: row.get("finding_id"),
    fingerprint: row.get("fingerprint"),
    ruleId: row.get("rule_id"),
    identity: {
      anchor: row.get("identity_anchor"),
      ...(row.get("identity_instance") === null
        ? {}
        : { instance: row.get("identity_instance") }),
    },
    title: boundedOutputText(row.get("title"), 512),
    summary: boundedOutputText(row.get("summary"), 2000),
    reason: row.get("note"),
    locations: [
      {
        path: boundedOutputText(row.get("relative_path"), 2048),
        startLine: row.get("start_line"),
        endLine: row.get("end_line"),
        ...(row.get("role") === null ? {} : { role: row.get("role") }),
      },
    ],
    sourceScanId: row.get("source_scan_id"),
    updatedAt: row.get("updated_at"),
  }));
  return {
    scanId: scan.get("id"),
    targetId: scan.get("target_id"),
    falsePositives,
  };
}
