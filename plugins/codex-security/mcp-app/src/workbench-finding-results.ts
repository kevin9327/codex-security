import type { Connection, Row } from "../../native/sqlite.mjs";
import { boundedFindingDetails } from "./helpers/finding-preview";
import { preflightInteger } from "./helpers/preflight-config";
import {
  JsonSyntaxError,
  object,
  parseJson,
  parseJsonBytes,
} from "./helpers/python-json";
import { parsedPath } from "./helpers/resolve-security-md";
import { UnicodeDecodeError } from "./helpers/utf8";
import {
  findingSourceExcerpt,
  safeSourcePath,
} from "./helpers/workbench-source-excerpt";
import { findingArtifactPaths, patchArtifactPreview } from "./workbench-files";
import { TargetInspectionError } from "./workbench-git-snapshot";
import { findingTriageResult } from "./workbench-results";
import { findingMatches } from "./workbench-scan-comparison";
import {
  gitRevision,
  requireScanTargetIdentity,
  type TargetIdentityScan,
} from "./workbench-target";
import {
  boundedOutputText,
  WorkbenchValidationError,
} from "./workbench-validation";

type Result = Record<string, unknown>;
const validationError = (error: unknown) =>
  error instanceof TargetInspectionError ||
  error instanceof WorkbenchValidationError;
const targetIdentity = (scan: Row): TargetIdentityScan => ({
  target_path: scan.get("target_path") as string,
  target_inode: scan.get("target_inode"),
});

export function remediationAvailability(scan: Row): [boolean, string | null] {
  if (scan.get("status") !== "complete")
    return [
      false,
      "Remediation is available only for successfully completed scans.",
    ];
  let revision: string;
  try {
    revision = gitRevision(requireScanTargetIdentity(targetIdentity(scan)));
  } catch (error) {
    if (!validationError(error)) throw error;
    return [false, (error as Error).message];
  }
  return revision === scan.get("target_revision")
    ? [true, null]
    : [
        false,
        "Remediation is unavailable because the selected checkout is not at the revision that was scanned. Check out the scanned revision or start a new scan.",
      ];
}

class FindingDetailsValueError extends Error {}
export function readFindingDetails(value: unknown): Result {
  if (typeof value !== "string" && !Buffer.isBuffer(value)) return {};
  const integer = (source: string) => {
    try {
      return preflightInteger(source);
    } catch {
      throw new FindingDetailsValueError();
    }
  };
  const constant = (): never => {
    throw new FindingDetailsValueError();
  };
  try {
    const details =
      typeof value === "string"
        ? parseJson(value, false, integer, constant)
        : parseJsonBytes(value, false, integer, constant);
    return object(details) ? details : {};
  } catch (error) {
    if (
      error instanceof JsonSyntaxError ||
      error instanceof UnicodeDecodeError ||
      error instanceof TypeError ||
      error instanceof FindingDetailsValueError
    )
      return {};
    throw error;
  }
}

export function findingRemediationResult(
  connection: Connection,
  occurrenceId: string,
): Result {
  const row = connection
    .prepare(
      `
    SELECT remediation.request_id, remediation.state, remediation.version,
      remediation.base_revision, remediation.base_content_digest,
      remediation.applied_content_digest, remediation.pending_action,
      remediation.pending_action_claimed_at, remediation.pending_action_claim_token,
      remediation.pending_action_delivered_at,
      remediation.patch_path, remediation.patch_digest, remediation.summary,
      remediation.verification_summary, remediation.updated_at, scans.scan_dir
    FROM finding_remediation_attempts AS remediation
    JOIN finding_occurrences AS occurrences ON occurrences.id = remediation.occurrence_id
    JOIN scans ON scans.id = occurrences.scan_id
    WHERE remediation.occurrence_id = ?
    ORDER BY remediation.created_at DESC, remediation.rowid DESC
    LIMIT 1
  `,
    )
    .get([occurrenceId]);
  if (row === undefined) return { state: "idle" };
  const [patch, patchStats] = patchArtifactPreview(
    parsedPath(row.get("scan_dir") as string),
    row.get("patch_path") as string | null,
    row.get("patch_digest") as string | null,
  );
  return {
    baseRevision: row.get("base_revision"),
    actionClaimedAt: row.get("pending_action_claimed_at"),
    actionClaimToken: row.get("pending_action_claim_token"),
    actionDeliveredAt: row.get("pending_action_delivered_at"),
    pendingAction: row.get("pending_action"),
    patchDigest: row.get("patch_digest"),
    patchPath: row.get("patch_path"),
    patch,
    patchStats,
    requestId: row.get("request_id"),
    state: row.get("state"),
    summary: row.get("summary"),
    updatedAt: row.get("updated_at"),
    verificationSummary: row.get("verification_summary"),
    version: row.get("version"),
  };
}

export function findingResult(
  connection: Connection,
  scan: Row,
  occurrence: Row,
  related: Result[],
): Result {
  const details = boundedFindingDetails(
    readFindingDetails(occurrence.get("details_json")),
  );
  const confidence = object(details["confidence"]) ? details["confidence"] : {};
  const severity = object(details["severity"]) ? details["severity"] : {};
  const locations: Result[] = [];
  let target: string | null;
  try {
    target = requireScanTargetIdentity(targetIdentity(scan));
  } catch (error) {
    if (!validationError(error)) throw error;
    target = null;
  }
  const rows = connection
    .prepare(
      `
    SELECT relative_path, start_line, end_line, role
    FROM finding_locations WHERE occurrence_id = ?
    ORDER BY CASE WHEN role = 'root_control' THEN 0 ELSE 1 END, sort_order
    LIMIT ?
  `,
    )
    .iterate([occurrence.get("id"), 8n]);
  try {
    for (let current = rows.next(); !current.done; ) {
      const row = current.value;
      current = rows.next();
      const absolutePath = target
        ? safeSourcePath(target, row.get("relative_path") as string)
        : null;
      const location: Result = {
        endLine: row.get("end_line"),
        path: boundedOutputText(row.get("relative_path"), 2048),
        role:
          row.get("role") !== null
            ? boundedOutputText(row.get("role"), 128)
            : null,
        startLine: row.get("start_line"),
      };
      if (absolutePath !== null)
        location["absolutePath"] = boundedOutputText(absolutePath, 4096);
      locations.push(location);
    }
  } finally {
    rows.return(undefined);
  }
  const result: Result = {
    ...details,
    confidence: {
      ...confidence,
      level: boundedOutputText(occurrence.get("confidence"), 128),
    },
    createdAt: occurrence.get("created_at"),
    findingId: occurrence.get("finding_id"),
    locations,
    occurrenceId: occurrence.get("id"),
    remediationState: findingRemediationResult(
      connection,
      occurrence.get("id") as string,
    ),
    remediation: boundedOutputText(occurrence.get("remediation"), 2000),
    severity: {
      ...severity,
      level: boundedOutputText(occurrence.get("severity"), 128),
    },
    summary: boundedOutputText(occurrence.get("summary"), 2000),
    title: boundedOutputText(occurrence.get("title"), 512),
    triage: findingTriageResult(connection, occurrence.get("id") as string),
  };
  const [matches, knownSince, knownScanIds] = findingMatches(
    connection,
    occurrence.get("id") as string,
    scan.get("id") as string,
    scan.get("started_at") as string,
  );
  if (matches.length)
    Object.assign(result, { matches, knownSince, knownScanIds });
  if (related.length) result["related"] = related;
  delete result["artifactPaths"];
  const sourceExcerpt = findingSourceExcerpt(
    {
      target_revision: scan.get("target_revision"),
      target_snapshot_digest: scan.get("target_snapshot_digest"),
    },
    target,
    locations,
  );
  if (sourceExcerpt) result["sourceExcerpt"] = sourceExcerpt;
  result["artifactPaths"] = findingArtifactPaths(
    parsedPath(scan.get("scan_dir") as string),
    details,
  );
  return result;
}
