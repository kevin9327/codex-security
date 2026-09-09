import type { Connection, Row } from "../../native/sqlite.mjs";
import { contractValuesEqual } from "./helpers/contract-validation";
import { JsonSyntaxError, object, stringifyJson } from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { ContractError } from "./helpers/scan-contract-errors";
import { JsonValueError } from "./helpers/scan-contract-json";
import { finalizeScan } from "./helpers/scan-finalization";
import { UnicodeDecodeError } from "./helpers/utf8";
import {
  publishedManifestDigest,
  requireRecordedManifestDigest,
  verifyManifestBinding,
} from "./workbench-binding";
import {
  readJsonObject,
  requireCanonicalScanDirectory,
} from "./workbench-files";
import { requireScan } from "./workbench-records";
import { expectedCoverageMode } from "./workbench-results";
import { WorkbenchValidationError } from "./workbench-validation";

export function legacyFindingMatches(row: Row, finding: unknown): boolean {
  if (!object(finding)) return false;
  const severity = finding["severity"],
    confidence = finding["confidence"];
  return (
    contractValuesEqual(finding["findingId"] ?? null, row.get("finding_id")) &&
    contractValuesEqual(finding["title"] ?? null, row.get("title")) &&
    contractValuesEqual(finding["summary"] ?? null, row.get("summary")) &&
    contractValuesEqual(
      finding["remediation"] ?? null,
      row.get("remediation"),
    ) &&
    object(severity) &&
    contractValuesEqual(severity["level"] ?? null, row.get("severity")) &&
    object(confidence) &&
    contractValuesEqual(confidence["level"] ?? null, row.get("confidence"))
  );
}

export function backfillLegacyFindingDetails(
  connection: Connection,
  scan: Row,
): void {
  if (scan.get("status") !== "complete" || connection.inTransaction) return;
  const legacyRows = connection
    .prepare(
      `
    SELECT id, finding_id, title, summary, severity, confidence, remediation
    FROM finding_occurrences
    WHERE scan_id = ? AND details_json = '{}'
  `,
    )
    .all([scan.get("id")]);
  if (!legacyRows.length) return;
  let findingsDocument: Record<string, unknown>, manifestDigest: string;
  try {
    const scanDir = requireCanonicalScanDirectory(
      parsedPath(scan.get("scan_dir") as string),
    );
    requireRecordedManifestDigest(scan, scanDir);
    verifyManifestBinding(
      scan,
      readJsonObject(appendPath(scanDir, "scan-manifest.json")),
    );
    const [manifest, findings] = finalizeScan(scanDir, undefined, undefined, {
      expectedCoverageMode: expectedCoverageMode(scan),
    });
    verifyManifestBinding(scan, manifest);
    manifestDigest = publishedManifestDigest(scanDir, manifest);
    findingsDocument = findings;
  } catch (error) {
    const system = error as { errno?: number; winerror?: number };
    if (
      error instanceof ContractError ||
      error instanceof WorkbenchValidationError ||
      error instanceof JsonSyntaxError ||
      error instanceof JsonValueError ||
      error instanceof UnicodeDecodeError ||
      (error instanceof Error && error.name === "ValueError") ||
      system.errno !== undefined ||
      system.winerror !== undefined
    )
      return;
    throw error;
  }
  const findings = findingsDocument["findings"];
  if (!Array.isArray(findings)) return;
  const byOccurrence = new Map(
    findings
      .filter(
        (finding): finding is Record<string, unknown> =>
          object(finding) && typeof finding["occurrenceId"] === "string",
      )
      .map((finding) => [finding["occurrenceId"] as string, finding]),
  );
  const updates: [string, string, string][] = [];
  for (const row of legacyRows) {
    const finding = byOccurrence.get(row.get("id") as string);
    if (!legacyFindingMatches(row, finding)) continue;
    updates.push([
      stringifyJson(finding, {
        compact: true,
        allowNan: false,
        sortKeys: true,
      }),
      scan.get("id") as string,
      row.get("id") as string,
    ]);
  }
  if (!updates.length) return;
  connection.prepare("BEGIN IMMEDIATE").run();
  connection.transaction(() => {
    const current = requireScan(connection, scan.get("id") as string),
      recordedDigest = current.get("seal_manifest_digest");
    if (recordedDigest !== null && recordedDigest !== manifestDigest)
      throw new WorkbenchValidationError(
        "The sealed scan manifest changed after completion.",
      );
    const update = connection.prepare(`
      UPDATE finding_occurrences
      SET details_json = ?
      WHERE scan_id = ? AND id = ? AND details_json = '{}'
    `);
    for (const parameters of updates) update.run(parameters);
    if (recordedDigest === null)
      connection
        .prepare("UPDATE scans SET seal_manifest_digest = ? WHERE id = ?")
        .run([manifestDigest, scan.get("id")]);
  });
}
