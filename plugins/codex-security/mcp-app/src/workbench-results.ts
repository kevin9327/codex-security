import { parse } from "node:path";
import type { Connection, Row, SqlValue } from "../../native/sqlite.mjs";
import { compare } from "./helpers/rank-worklists";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { jsonItem, parseJson } from "./helpers/python-json";
import { preflightInteger } from "./helpers/preflight-config";
import {
  cleanWorktreeContentDigest,
  TargetInspectionError,
} from "./workbench-git-snapshot";
import { requireScan, requireWorkspace } from "./workbench-records";
import { findingRelations } from "./workbench-finding-links";
import { backfillLegacyFindingDetails } from "./workbench-legacy-findings";
import { availableArtifactPath } from "./workbench-files";
import {
  findingResult,
  remediationAvailability,
} from "./workbench-finding-results";
import { scanResultsRecoveryNeeded } from "./workbench-saved-result-sources";
import { storedDiffTarget } from "./workbench-scan-start";
import {
  findingOccurrenceConditions,
  findingOccurrenceRows,
  storedScanCostFields,
  type FindingOccurrenceQuery,
} from "./workbench-scan-history";
import { inspectSetupValues, requireTarget } from "./workbench-setup";
import { gitTargetMetadata } from "./workbench-target";
import {
  independentReviewProgress,
  otherRunningDeepScans,
} from "./workbench-deep-state";
import {
  optionalText,
  requireOccurrence,
  WorkbenchValidationError,
} from "./workbench-validation";

type Result = Record<string, unknown>;
export interface ResultCallbacks {
  backfillFindingDetails(connection: Connection, scan: Row): void;
  availableArtifactPath(scanDir: string, candidate: string): string | null;
  findingResult(
    connection: Connection,
    scan: Row,
    occurrence: Row,
    related: Record<string, unknown>[],
  ): Result;
  remediationAvailability(scan: Row): [boolean, string | null];
  scanResultsRecoveryNeeded(connection: Connection, scan: Row): boolean;
}
export const resultCallbacks: ResultCallbacks = {
  backfillFindingDetails: backfillLegacyFindingDetails,
  availableArtifactPath,
  findingResult,
  remediationAvailability,
  scanResultsRecoveryNeeded,
};
const validationError = (error: unknown) =>
  error instanceof WorkbenchValidationError ||
  error instanceof TargetInspectionError;
const recipe = (value: string | Buffer) =>
  parseJson(value, false, preflightInteger, (constant) => {
    throw new Error(`non-finite JSON number '${constant}' is not supported`);
  });
function column(row: Row | undefined, name: string): SqlValue {
  if (row === undefined)
    throw new TypeError("'NoneType' object is not subscriptable");
  return row.get(name);
}

export function expectedTargetKinds(scan: Row): string[] {
  if (scan.get("mode") === "diff") return ["git_diff"];
  if (scan.get("target_revision") === "unversioned")
    return ["directory_snapshot"];
  if (scan.get("target_snapshot_digest") === null)
    return ["git_worktree", "git_revision"];
  return scan.get("target_snapshot_digest") === cleanWorktreeContentDigest()
    ? ["git_revision"]
    : ["git_worktree"];
}
export function requestedScanPaths(scan: Row): unknown {
  if (
    scan.columns.includes("recipe_json") &&
    scan.get("recipe_json") !== null
  ) {
    const target = jsonItem(
      recipe(scan.get("recipe_json") as string | Buffer),
      "target",
    );
    if (jsonItem(target, "kind") === "paths") return jsonItem(target, "paths");
  }
  return [scan.get("scope")];
}
export function scanContract(scan: Row): Result {
  const path = parsedPath(scan.get("target_path") as string);
  const target: Result = {
    allowedKinds: expectedTargetKinds(scan),
    displayName: path === "." ? "" : parse(path).base,
    targetId: scan.get("target_id"),
  };
  if (
    scan.get("mode") !== "diff" &&
    scan.get("target_snapshot_digest") &&
    (scan.get("target_revision") === "unversioned" ||
      scan.get("target_snapshot_digest") !== cleanWorktreeContentDigest())
  )
    target["requiredSnapshotDigest"] = scan.get("target_snapshot_digest");
  return {
    diffTarget: storedDiffTarget(scan),
    scope: {
      requiredExcludePaths: [],
      requestedPath: scan.get("scope"),
      ...(scan.get("mode") !== "diff"
        ? { requiredIncludePaths: requestedScanPaths(scan) }
        : {}),
    },
    target,
  };
}
export function expectedCoverageMode(scan: Row): string {
  if (scan.get("mode") === "diff") {
    const kind = scan.get("diff_target_kind");
    const mode =
      kind === "commit"
        ? "commit"
        : kind === "range"
          ? "branch_diff"
          : kind === "working_tree"
            ? "working_tree"
            : null;
    if (mode === null)
      throw new WorkbenchValidationError(
        "This migrated diff scan does not have a validated change set.",
      );
    return mode;
  }
  if (
    scan.get("scope") !== "." ||
    (scan.columns.includes("recipe_json") &&
      scan.get("recipe_json") !== null &&
      jsonItem(
        jsonItem(
          parseJson(
            scan.get("recipe_json") as string | Buffer,
            false,
            preflightInteger,
          ),
          "target",
        ),
        "kind",
      ) === "paths")
  )
    return "scoped_path";
  return scan.get("mode") === "deep" ? "deep_repository" : "repository";
}

export function findingManagementUpdatedAt(
  connection: Connection,
  scanId: string,
): string | null {
  return connection
    .prepare(
      `
    SELECT MAX(updated_at) FROM (
      SELECT triage.updated_at FROM finding_triage AS triage
      JOIN finding_occurrences AS occurrences ON occurrences.id = triage.occurrence_id
      WHERE occurrences.scan_id = ?
      UNION ALL
      SELECT remediation.updated_at FROM finding_remediation_attempts AS remediation
      JOIN finding_occurrences AS occurrences ON occurrences.id = remediation.occurrence_id
      WHERE occurrences.scan_id = ?
    )
  `,
    )
    .get([scanId, scanId])!
    .get(0) as string | null;
}
export function findingTriageResult(
  connection: Connection,
  occurrenceId: string,
): Result {
  const row = connection
    .prepare(
      "SELECT status, close_reason, note, updated_at FROM finding_triage WHERE occurrence_id = ?",
    )
    .get([occurrenceId]);
  return row === undefined
    ? { status: "open" }
    : {
        closeReason: row.get("close_reason"),
        note: row.get("note"),
        status: row.get("status"),
        updatedAt: row.get("updated_at"),
      };
}

export function workspaceState(
  connection: Connection,
  workspaceId: string,
  callbacks: ResultCallbacks,
  options: {
    resultScanId?: string | null;
    resultScan?: Result | null;
    threadId?: string | null;
  } = {},
): Result {
  const workspace = requireWorkspace(connection, workspaceId);
  if (
    options.threadId != null &&
    workspace.get("thread_id") !== optionalText(options.threadId, 512)
  )
    throw new WorkbenchValidationError(
      "Codex Security workspace not found in this thread.",
    );
  const persistedDiffTarget = storedDiffTarget(workspace);
  const result: Result = {
    id: workspace.get("id"),
    diffTarget: persistedDiffTarget,
    mode: workspace.get("default_mode"),
    scope: workspace.get("default_scope"),
    setup: { submitted: Boolean(workspace.get("submitted")) },
    setupValidation: {
      error: null,
      valid: Boolean(workspace.get("submitted")),
    },
    targetPath: workspace.get("target_path"),
    targetSummary: workspace.get("target_summary"),
    targetTitle: workspace.get("target_title"),
    updatedAt: workspace.get("updated_at"),
    userContext: workspace.get("user_context"),
  };
  const selectedId = options.resultScanId || workspace.get("active_scan_id");
  if (selectedId) {
    const selectedScan = requireScan(connection, selectedId as string);
    result["userContext"] = selectedScan.get("user_context");
    result["results"] =
      options.resultScan ?? scanResult(connection, selectedScan, callbacks);
    return result;
  }
  let targetMetadata: ReturnType<typeof gitTargetMetadata> | null = null,
    setupError: string | null = null,
    validatedDiffTarget: ReturnType<typeof inspectSetupValues>["diffTarget"] =
      null;
  if (workspace.get("target_path")) {
    try {
      const inspected = inspectSetupValues(
        workspace.get("target_path") as string,
        workspace.get("default_scope") as string,
        workspace.get("default_mode") as string,
        workspace.get("diff_target_kind") as string | null,
        workspace.get("diff_base_revision") as string | null,
        workspace.get("diff_head_revision") as string | null,
        workspace.get("diff_content_digest") as string | null,
      );
      targetMetadata = inspected.target.targetMetadata;
      validatedDiffTarget = inspected.diffTarget;
    } catch (error) {
      if (!validationError(error)) throw error;
      setupError = (error as Error).message;
      try {
        targetMetadata = gitTargetMetadata(
          requireTarget(workspace.get("target_path") as string),
        );
      } catch (error) {
        if (!validationError(error)) throw error;
      }
    }
  }
  result["diffTarget"] = validatedDiffTarget || persistedDiffTarget;
  result["setupValidation"] = {
    error: setupError,
    valid: setupError === null && Boolean(targetMetadata),
  };
  if (targetMetadata) result["targetMetadata"] = targetMetadata;
  return result;
}

export function scanContext(
  connection: Connection,
  scanId: string,
  callbacks: ResultCallbacks,
  occurrenceId: string | null = null,
): Result {
  const scan = requireScan(connection, scanId);
  const result = scanResult(connection, scan, callbacks, occurrenceId);
  const workspaceResult =
    occurrenceId === null ? result : scanResult(connection, scan, callbacks);
  const workspace = workspaceState(
    connection,
    scan.get("workspace_id") as string,
    callbacks,
    { resultScanId: scan.get("id") as string, resultScan: workspaceResult },
  );
  const context: Result = {
    otherRunningDeepScans: otherRunningDeepScans(
      connection,
      scan.get("id") as string,
    ),
    scan: result,
    workspace,
  };
  if (scan.get("recipe_json") !== null) {
    context["parentScanId"] = scan.get("parent_scan_id");
    context["recipe"] = recipe(scan.get("recipe_json") as string);
  }
  return context;
}

export function listFindings(
  connection: Connection,
  args: FindingOccurrenceQuery & {
    scanId: string;
    limit: bigint;
    offset: bigint;
  },
  callbacks: ResultCallbacks,
): Result {
  const scan = requireScan(connection, args.scanId);
  callbacks.backfillFindingDetails(connection, scan);
  const limit = args.limit < 20n ? args.limit : 20n;
  const rows = findingOccurrenceRows(connection, scan.get("id") as string, {
    ...args,
    limit,
  });
  const [conditions, values] = findingOccurrenceConditions(
    scan.get("id") as string,
    args,
  );
  const total = connection
    .prepare(
      `SELECT COUNT(*) FROM finding_occurrences AS occurrences LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id WHERE ${conditions}`,
    )
    .get(values)!
    .get(0) as bigint;
  const nextOffset = args.offset + BigInt(rows.length);
  const relations = findingRelations(
    connection,
    scan.get("id") as string,
    rows.map((row) => row.get("id") as string),
  );
  return {
    findingsPage: {
      findings: rows.map((row) =>
        callbacks.findingResult(
          connection,
          scan,
          row,
          (relations[row.get("id") as string] as
            | Record<string, unknown>[]
            | undefined) ?? [],
        ),
      ),
      limit,
      nextOffset: nextOffset < total ? nextOffset : null,
      offset: args.offset,
      scanId: scan.get("id"),
      total,
    },
  };
}

export function scanResult(
  connection: Connection,
  scan: Row,
  callbacks: ResultCallbacks,
  occurrenceId: string | null = null,
): Result {
  callbacks.backfillFindingDetails(connection, scan);
  const scanId = scan.get("id") as string,
    scanDir = scan.get("scan_dir") as string,
    directory = parsedPath(scanDir);
  const progress = connection
    .prepare("SELECT * FROM scan_progress WHERE scan_id = ?")
    .get([scanId]);
  const artifacts: Record<string, string> = {};
  const artifactRows = connection
    .prepare("SELECT kind, path FROM scan_artifacts WHERE scan_id = ?")
    .iterate([scanId]);
  try {
    for (let current = artifactRows.next(); !current.done; ) {
      const row = current.value;
      // sqlite3 advances its cursor before returning the current row.
      current = artifactRows.next();
      const kind = row.get("kind") as string;
      if (
        !["coverage", "findings", "manifest", "markdownReport"].includes(kind)
      )
        continue;
      const path = callbacks.availableArtifactPath(
        directory,
        parsedPath(row.get("path") as string),
      );
      if (path !== null) artifacts[kind] = path;
    }
  } finally {
    artifactRows.return(undefined);
  }
  const sarif = callbacks.availableArtifactPath(
    directory,
    appendPath(directory, "exports/results.sarif"),
  );
  if (sarif !== null) artifacts["sarifReport"] = sarif;
  const occurrences = findingOccurrenceRows(connection, scanId, {
    offset: 0n,
    limit: 20n,
  });
  if (
    occurrenceId !== null &&
    occurrences.every((row) => row.get("id") !== occurrenceId)
  ) {
    const occurrence = requireOccurrence(connection, occurrenceId);
    if (occurrence.get("scan_id") !== scan.get("id"))
      throw new WorkbenchValidationError(
        "This finding does not belong to the selected scan.",
      );
    occurrences.push(occurrence);
  }
  const findingCount = connection
    .prepare("SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?")
    .get([scanId])!
    .get(0) as bigint;
  const severityCounts = Object.fromEntries(
    connection
      .prepare(
        "SELECT severity, COUNT(*) AS count FROM finding_occurrences WHERE scan_id = ? GROUP BY severity",
      )
      .all([scanId])
      .map((row) => [row.get("severity"), row.get("count")]),
  );
  const [remediationAvailable, remediationUnavailableReason] =
    callbacks.remediationAvailability(scan);
  const reviews =
    scan.get("mode") === "deep"
      ? independentReviewProgress(connection, scanId)
      : null;
  const progressResult: Result = {
    candidates: { reportable: column(progress, "reportable_findings_count") },
    coverage: {
      closedRows: column(progress, "review_items_completed"),
      filesTotal: column(progress, "scope_file_count"),
      worklistRows: column(progress, "review_items_total"),
    },
    phase: scan.get("phase"),
    phaseProgress: {
      completed: column(progress, "phase_items_completed"),
      total: column(progress, "phase_items_total"),
      unit: column(progress, "phase_progress_unit"),
    },
    preflightProgress: {
      completed: column(progress, "preflight_checks_completed"),
      total: column(progress, "preflight_checks_total"),
    },
    preflightIssues: parseJson(
      column(progress, "preflight_issues_json") as string | Buffer,
      false,
      preflightInteger,
    ),
    reviewPass: column(progress, "deep_review_pass"),
    status: scan.get("canceled_at") ? "canceled" : scan.get("status"),
    updatedAt: column(progress, "updated_at"),
  };
  if (reviews !== null)
    progressResult["independentReviews"] = {
      active: reviews.active,
      completed: reviews.completed,
      maximum: reviews.maximum,
      consolidating: reviews.consolidating,
    };
  const relations = findingRelations(
    connection,
    scanId,
    occurrences.map((row) => row.get("id") as string),
  );
  return {
    artifacts,
    canceledAt: scan.get("canceled_at"),
    ...storedScanCostFields(scan.get("cost_json") as string | Buffer | null),
    contract: scanContract(scan),
    continuationThreadId: scan.get("continuation_thread_id"),
    failureMessage: scan.get("failure_message"),
    findings: occurrences.map((row) =>
      callbacks.findingResult(
        connection,
        scan,
        row,
        (relations[row.get("id") as string] as
          | Record<string, unknown>[]
          | undefined) ?? [],
      ),
    ),
    findingCount,
    findingsTruncated: findingCount > BigInt(occurrences.length),
    severityCounts,
    handoffClaimedAt: scan.get("handoff_claimed_at"),
    handoffClaimToken: scan.get("handoff_claim_token"),
    handoffStatus: scan.get("handoff_status"),
    mode: scan.get("mode"),
    model: scan.get("model"),
    diffTarget: storedDiffTarget(scan),
    progress: progressResult,
    reasoningEffort: scan.get("reasoning_effort"),
    remediationAvailable,
    remediationUnavailableReason,
    reportAvailable: Object.hasOwn(artifacts, "markdownReport"),
    resultsRecoveryNeeded: callbacks.scanResultsRecoveryNeeded(
      connection,
      scan,
    ),
    scanDir,
    scanId,
    scope: scan.get("scope"),
    targetPath: scan.get("target_path"),
    targetRevision: scan.get("target_revision"),
    targetSummary: scan.get("target_summary"),
    updatedAt: [
      scan.get("updated_at") as string,
      column(progress, "updated_at") as string,
      reviews?.updatedAt ?? "",
      findingManagementUpdatedAt(connection, scanId) || "",
    ]
      .sort(compare)
      .at(-1),
    userContext: scan.get("user_context"),
    warnings: parseJson(
      scan.get("completion_warnings_json") as string | Buffer,
      false,
      preflightInteger,
    ),
  };
}
