import type { Connection, Row } from "../../native/sqlite.mjs";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { preflightInteger } from "./helpers/preflight-config";
import {
  JsonSyntaxError,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { ContractError } from "./helpers/scan-contract-errors";
import { JsonValueError } from "./helpers/scan-contract-json";
import { UnicodeDecodeError } from "./helpers/utf8";
import { withScanCompletionLock } from "./workbench-completion-lock";
import {
  cancelFromParentScan,
  clearDeepScanPublicationFailure,
  failFromParentScan,
} from "./workbench-deep-terminal";
import { requireCurrentContinuation } from "./workbench-handoff";
import {
  preserveScanResultsLocked,
  storedWarningValues,
  uniqueWarnings,
  type PreservedResultsContext,
} from "./workbench-preserve-saved-results";
import { requireScan, requireWorkspace } from "./workbench-records";
import {
  resultCallbacks,
  scanContext,
  workspaceState,
} from "./workbench-results";
import {
  optionalText,
  parseScanCost,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

interface FailScanArgs {
  scanId: string;
  costJson: string | null;
  claimToken: string | null;
  message: string | null;
}
interface CancelScanArgs {
  scanId: string;
  threadId: string | null;
}

export function failScan(
  db: PreservedResultsContext,
  connection: Connection,
  args: FailScanArgs,
): Record<string, unknown> {
  return withScanCompletionLock(requireUuid(args.scanId, "scan-id"), () =>
    failScanLocked(db, connection, args),
  );
}

export function failScanLocked(
  db: PreservedResultsContext,
  connection: Connection,
  args: FailScanArgs,
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id"),
    costJson = parseScanCost(args.costJson);
  connection.prepare("BEGIN IMMEDIATE").run();
  let scan: Row;
  try {
    const timestamp = db.now();
    scan = requireScan(connection, scanId);
    if (scan.get("status") === "failed") {
      connection.commit();
      return scanContext(connection, scan.get("id") as string, resultCallbacks);
    }
    if (scan.get("status") === "complete")
      throw new WorkbenchValidationError(
        "A completed scan cannot be marked failed.",
      );
    requireCurrentContinuation(scan, args.claimToken, {
      errorMessage: "Scan failure is owned by another continuation.",
    });
    const message = optionalText(args.message, 2400);
    const updated = connection
      .prepare(
        `UPDATE scans
         SET status = 'failed', failure_message = ?, completed_at = ?, updated_at = ?,
             cost_json = ?
         WHERE id = ? AND status = 'running'`,
      )
      .run([message, timestamp, timestamp, costJson, scan.get("id")]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Only a running scan can be marked failed.",
      );
    failFromParentScan(
      connection,
      scan.get("id") as string,
      message,
      timestamp,
    );
    const progress = connection
      .prepare("UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?")
      .run([timestamp, scan.get("id")]);
    if (progress.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Codex Security scan progress not found.",
      );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  preserveStoppedResultsAfterTransition(
    db,
    connection,
    scan.get("id") as string,
  );
  return scanContext(connection, scan.get("id") as string, resultCallbacks);
}

export function cancelScan(
  db: PreservedResultsContext,
  connection: Connection,
  args: CancelScanArgs,
): Record<string, unknown> {
  return withScanCompletionLock(requireUuid(args.scanId, "scan-id"), () =>
    cancelScanLocked(db, connection, args),
  );
}

export function cancelScanLocked(
  db: PreservedResultsContext,
  connection: Connection,
  args: CancelScanArgs,
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id"),
    threadId = optionalText(args.threadId, 512);
  connection.prepare("BEGIN IMMEDIATE").run();
  let scan: Row;
  try {
    const timestamp = db.now();
    scan = requireScan(connection, scanId);
    const workspace = requireWorkspace(
        connection,
        scan.get("workspace_id") as string,
      ),
      continuation = scan.get("continuation_thread_id"),
      owner = (
        Buffer.isBuffer(continuation)
          ? continuation.length !== 0
          : Boolean(continuation)
      )
        ? continuation
        : workspace.get("thread_id");
    if (threadId !== null && owner !== threadId)
      throw new WorkbenchValidationError(
        "A scan can only be canceled from its owning Codex thread.",
      );
    if (scan.get("canceled_at") !== null) {
      connection.commit();
      return workspaceState(
        connection,
        scan.get("workspace_id") as string,
        resultCallbacks,
      );
    }
    if (scan.get("status") !== "running")
      throw new WorkbenchValidationError(
        "Only a running scan can be canceled.",
      );
    const updated = connection
      .prepare(
        `UPDATE scans
         SET status = 'failed', canceled_at = ?, completed_at = ?, updated_at = ?
         WHERE id = ? AND status = 'running'`,
      )
      .run([timestamp, timestamp, timestamp, scan.get("id")]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Only a running scan can be canceled.",
      );
    cancelFromParentScan(connection, scan.get("id") as string, timestamp);
    const progress = connection
      .prepare("UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?")
      .run([timestamp, scan.get("id")]);
    if (progress.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Codex Security scan progress not found.",
      );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  preserveStoppedResultsAfterTransition(
    db,
    connection,
    scan.get("id") as string,
  );
  return workspaceState(
    connection,
    scan.get("workspace_id") as string,
    resultCallbacks,
  );
}

export function preserveStoppedResultsAfterTransition(
  db: PreservedResultsContext,
  connection: Connection,
  scanId: string,
): void {
  let published: boolean;
  try {
    published = preserveScanResultsLocked(db, connection, scanId);
  } catch (error) {
    const system = error as { errno?: number; winerror?: number };
    if (
      !(
        error instanceof ContractError ||
        error instanceof WorkbenchValidationError ||
        error instanceof JsonSyntaxError ||
        error instanceof JsonValueError ||
        error instanceof UnicodeDecodeError ||
        (error instanceof Error && error.name === "ValueError") ||
        system.errno !== undefined ||
        system.winerror !== undefined
      )
    )
      throw error;
    const scan = requireScan(connection, scanId),
      warnings = parseJson(
        scan.get("completion_warnings_json") as string | Buffer,
        false,
        preflightInteger,
      ),
      warning = `Saved scan evidence remains on disk; result publication needs follow-up: ${filesystemErrorMessage(error)}`;
    connection.transaction(() => {
      connection
        .prepare("UPDATE scans SET completion_warnings_json = ? WHERE id = ?")
        .run([
          stringifyJson(
            uniqueWarnings([...storedWarningValues(warnings, true), warning]),
            { compact: true },
          ),
          scanId,
        ]);
    });
    return;
  }
  if (published)
    clearDeepScanPublicationFailure(connection, scanId, () => db.now());
}
