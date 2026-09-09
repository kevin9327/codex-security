import type { Connection, Row } from "../../native/sqlite.mjs";
import { JsonFloat, object } from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import {
  csvCell,
  encodeCsvRows,
  findingCandidateId,
} from "./helpers/saved-findings-projection";
import { ContractError } from "./helpers/scan-contract-errors";
import { finalizeScan } from "./helpers/scan-finalization";
import { writeScanLocalBytes } from "./helpers/scan-local-files";
import { writeSarifProjection } from "./helpers/sealed-scan";
import { uppercase } from "./helpers/unicode-case";
import {
  pinLegacyManifestDigest,
  publishedManifestDigest,
  requireRecordedManifestDigest,
  verifyManifestBinding,
} from "./workbench-binding";
import {
  artifactPath,
  availableArtifactPath,
  readJsonObject,
  requireCanonicalScanDirectory,
} from "./workbench-files";
import { requireScan } from "./workbench-records";
import { expectedCoverageMode } from "./workbench-results";
import { WorkbenchValidationError } from "./workbench-validation";

export interface ExportContext {
  scanResult(connection: Connection, scan: Row): Record<string, unknown>;
  workspaceState(
    connection: Connection,
    workspaceId: string,
  ): Record<string, unknown>;
}

export function exportFindings(
  context: ExportContext,
  connection: Connection,
  args: { scanId: string; format: string },
): Record<string, unknown> {
  const scan = requireScan(connection, args.scanId);
  const seal = scan.get("seal_manifest_digest");
  if (
    scan.get("status") !== "complete" &&
    !(
      scan.get("status") === "failed" &&
      (Buffer.isBuffer(seal) ? seal.length : seal)
    )
  )
    throw new WorkbenchValidationError(
      "Findings can be exported after the scan completes or preserves stopped results.",
    );
  const scanDir = requireCanonicalScanDirectory(
    parsedPath(scan.get("scan_dir") as string),
  );
  requireRecordedManifestDigest(scan, scanDir);
  verifyManifestBinding(
    scan,
    readJsonObject(appendPath(scanDir, "scan-manifest.json")),
  );
  let manifest: Record<string, unknown>;
  try {
    [manifest] = finalizeScan(scanDir, undefined, undefined, {
      expectedCoverageMode: expectedCoverageMode(scan),
    });
  } catch (error) {
    if (!(error instanceof ContractError)) throw error;
    throw new WorkbenchValidationError(error.message);
  }
  verifyManifestBinding(scan, manifest);
  const manifestDigest = publishedManifestDigest(scanDir, manifest);
  pinLegacyManifestDigest(connection, scan.get("id") as string, manifestDigest);
  let path: string | null;
  if (args.format === "json")
    path = artifactPath(scanDir, "findings.json", true);
  else if (args.format === "sarif") {
    try {
      writeSarifProjection(scanDir);
    } catch (error) {
      if (!(error instanceof ContractError)) throw error;
      throw new WorkbenchValidationError(error.message);
    }
    path = artifactPath(scanDir, "exports/results.sarif", true);
  } else path = writeCsvExport(connection, scan);
  if (path === null)
    throw new WorkbenchValidationError(
      `Could not export Codex Security findings as ${uppercase(args.format)}.`,
    );
  return {
    export: { format: args.format, path },
    scan: context.scanResult(connection, scan),
    workspace: context.workspaceState(
      connection,
      scan.get("workspace_id") as string,
    ),
  };
}

export function writeCsvExport(connection: Connection, scan: Row): string {
  const scanDir = requireCanonicalScanDirectory(
    parsedPath(scan.get("scan_dir") as string),
  );
  const deep = scan.get("mode") === "deep";
  const candidates = new Map<string, string>();
  if (deep) {
    const findings = readJsonObject(appendPath(scanDir, "findings.json"))[
      "findings"
    ];
    if (!Array.isArray(findings))
      throw new WorkbenchValidationError(
        "findings.json must contain a findings array.",
      );
    for (const finding of findings) {
      if (!object(finding))
        throw new WorkbenchValidationError(
          "findings.json entries must be objects.",
        );
      const occurrenceId = finding["occurrenceId"],
        candidateId = findingCandidateId(finding);
      if (typeof occurrenceId === "string" && typeof candidateId === "string")
        candidates.set(occurrenceId, candidateId);
    }
  }
  const columns = [
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
  ];
  const rows: unknown[][] = [columns];
  for (const row of findingExportRows(connection, scan.get("id") as string)) {
    rows.push([
      csvCell(row.get("occurrence_id")),
      csvCell(row.get("finding_id")),
      ...(deep
        ? [csvCell(candidates.get(row.get("occurrence_id") as string) ?? null)]
        : []),
      ...[
        "title",
        "summary",
        "severity",
        "confidence",
        "status",
        "close_reason",
        "note",
        "remediation",
        "relative_path",
      ].map((column) => csvCell(row.get(column))),
      ...["start_line", "end_line"].map((column) => {
        const value = row.get(column);
        return typeof value === "number" ? new JsonFloat(String(value)) : value;
      }),
    ]);
  }
  try {
    writeScanLocalBytes(scanDir, "exports/findings.csv", encodeCsvRows(rows));
  } catch (error) {
    if (!(error instanceof ContractError)) throw error;
    throw new WorkbenchValidationError(
      "exports: expected a regular directory inside the scan directory.",
    );
  }
  const path = availableArtifactPath(
    scanDir,
    appendPath(scanDir, "exports/findings.csv"),
  );
  if (path === null)
    throw new WorkbenchValidationError(
      "findings.csv: expected a regular file inside the scan directory.",
    );
  return path;
}

export function findingExportRows(
  connection: Connection,
  scanId: string,
): Row[] {
  return connection
    .prepare(
      `
    SELECT
      occurrences.id AS occurrence_id,
      occurrences.finding_id,
      occurrences.title,
      occurrences.summary,
      occurrences.severity,
      occurrences.confidence,
      occurrences.remediation,
      COALESCE(triage.status, 'open') AS status,
      triage.close_reason,
      triage.note,
      locations.relative_path,
      locations.start_line,
      locations.end_line
    FROM finding_occurrences AS occurrences
    LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
    LEFT JOIN finding_locations AS locations
      ON locations.occurrence_id = occurrences.id
      AND locations.sort_order = (
        SELECT primary_location.sort_order
        FROM finding_locations AS primary_location
        WHERE primary_location.occurrence_id = occurrences.id
        ORDER BY
          CASE WHEN primary_location.role = 'root_control' THEN 0 ELSE 1 END,
          primary_location.sort_order
        LIMIT 1
      )
    WHERE occurrences.scan_id = ?
    ORDER BY occurrences.created_at, occurrences.id
  `,
    )
    .all([scanId]);
}
