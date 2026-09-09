import { randomUUID } from "node:crypto";
import type { Connection } from "../../native/sqlite.mjs";
import { withScanCompletionLock } from "./workbench-completion-lock";
import {
  canonicalDiscoveryArtifacts,
  deepScanDeadlineReached,
  deepScanOutputPath,
  deepScanPath,
} from "./workbench-deep-files";
import { requireCurrentCoordinator } from "./workbench-deep-lease";
import {
  finishStagedFile,
  promoteStagedFile,
  rollbackStagedFile,
  type StagedFilePromotion,
} from "./workbench-deep-publication";
import { deepScanResult, requireDeepScanRun } from "./workbench-deep-state";
import { cancelActiveWorkers } from "./workbench-deep-terminal";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { requireScan } from "./workbench-records";
import { preserveStoppedResultsAfterTransition } from "./workbench-scan-stop";
import {
  optionalText,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export interface DeepFailureContext {
  now(): string;
  uuid?(): string;
}
export interface FailDeepScanArguments {
  scanId: string;
  coordinatorGeneration: bigint | null;
  message: string | null;
  deepStatus: string;
  manifestPath: string | null;
  stagedManifestPath: string | null;
}
export interface DeepPublicationFailureArguments {
  scanId: string;
  coordinatorGeneration: bigint | null;
  message: string | null;
}
function fail(message: string): never {
  throw new WorkbenchValidationError(message);
}

export function failDeepScan(
  context: DeepFailureContext,
  connection: Connection,
  args: FailDeepScanArguments,
) {
  const scanId = requireUuid(args.scanId, "scan-id");
  return withScanCompletionLock(scanId, () =>
    failDeepScanLocked(context, connection, args, scanId),
  );
}
export function failDeepScanLocked(
  context: DeepFailureContext,
  connection: Connection,
  args: FailDeepScanArguments,
  scanId: string,
) {
  const message = optionalText(args.message, 2400);
  if (message === null) fail("message is required.");
  const result = () =>
    deepScanResult(connection, scanId, {
      canonicalDiscoveryArtifacts,
      deepScanDeadlineReached: (run) =>
        deepScanDeadlineReached(run, context.now),
    });
  let promotion: StagedFilePromotion | null = null;
  connection.exec("BEGIN IMMEDIATE");
  try {
    const run = requireDeepScanRun(connection, scanId);
    requireCurrentCoordinator(run, args);
    const scan = requireScan(connection, scanId);
    let manifestPath: string | null = null;
    if (args.manifestPath)
      manifestPath = args.stagedManifestPath
        ? deepScanOutputPath(
            scan,
            args.manifestPath,
            "Deep Scan failure manifest path",
            requireCanonicalScanDirectory,
          )
        : deepScanPath(
            scan,
            args.manifestPath,
            "Deep Scan failure manifest path",
            "file",
            requireCanonicalScanDirectory,
          );
    if (
      ["failed", "interrupted"].includes(run.get("status") as string) ||
      scan.get("status") === "failed"
    ) {
      if (
        run.get("status") === args.deepStatus &&
        scan.get("status") === "failed" &&
        run.get("error_message") === message &&
        run.get("manifest_path") === manifestPath &&
        scan.get("failure_message") === message
      ) {
        connection.commit();
        return result();
      }
      fail(
        "Deep Scan terminal failure state is immutable; failure status, message, manifest path, and parent failure must exactly match.",
      );
    }
    const terminalBeforeManifest =
      ["failed", "interrupted"].includes(args.deepStatus) &&
      run.get("status") === "succeeded" &&
      ["saturated", "capped"].includes(run.get("terminal_reason") as string) &&
      run.get("manifest_path") === null;
    if (
      (run.get("status") !== "running" && !terminalBeforeManifest) ||
      scan.get("status") !== "running"
    )
      fail("Only a running Deep Scan can be failed or interrupted.");
    if (
      ![null, manifestPath].includes(run.get("manifest_path") as string | null)
    )
      fail("Deep Scan coordinator manifest path is immutable.");
    if (args.stagedManifestPath && manifestPath) {
      const staged = deepScanPath(
        scan,
        args.stagedManifestPath,
        "Staged Deep Scan failure manifest path",
        "file",
        requireCanonicalScanDirectory,
      );
      promotion = promoteStagedFile(
        staged,
        manifestPath,
        context.uuid ?? randomUUID,
      );
    }
    const timestamp = context.now();
    connection
      .prepare(
        `
            UPDATE deep_scan_runs
            SET status = ?, phase = 'terminal', cancel_requested = 1,
                error_message = ?, manifest_path = ?, completed_at = ?, updated_at = ?
            WHERE scan_id = ?
            `,
      )
      .run([
        args.deepStatus,
        message,
        manifestPath,
        timestamp,
        timestamp,
        scanId,
      ]);
    cancelActiveWorkers(connection, scanId, timestamp);
    const parentUpdate = connection
      .prepare(
        `
            UPDATE scans
            SET status = 'failed', failure_message = ?, completed_at = ?, updated_at = ?
            WHERE id = ? AND status = 'running'
            `,
      )
      .run([message, timestamp, timestamp, scanId]);
    if (parentUpdate.rowcount !== 1n)
      fail("Deep Scan failure could not be persisted to its parent scan.");
    connection
      .prepare("UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?")
      .run([timestamp, scanId]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    if (promotion !== null) rollbackStagedFile(promotion);
    throw error;
  }
  if (promotion !== null) finishStagedFile(promotion);
  preserveStoppedResultsAfterTransition(context, connection, scanId);
  return result();
}

export function recordDeepScanPublicationFailure(
  context: DeepFailureContext,
  connection: Connection,
  args: DeepPublicationFailureArguments,
) {
  const scanId = requireUuid(args.scanId, "scan-id"),
    message = optionalText(args.message, 2400);
  if (message === null) fail("message is required.");
  const result = () =>
    deepScanResult(connection, scanId, {
      canonicalDiscoveryArtifacts,
      deepScanDeadlineReached: (run) =>
        deepScanDeadlineReached(run, context.now),
    });
  const early = withScanCompletionLock(scanId, () => {
    connection.exec("BEGIN IMMEDIATE");
    try {
      const run = requireDeepScanRun(connection, scanId);
      requireCurrentCoordinator(run, args);
      const scan = requireScan(connection, scanId);
      if (
        !["failed", "canceled", "interrupted"].includes(
          run.get("status") as string,
        ) ||
        scan.get("status") !== "failed"
      )
        fail(
          "Saved result publication failures can only update a stopped Deep Scan.",
        );
      if (scan.get("seal_manifest_digest") !== null) {
        connection.commit();
        return result();
      }
      if (run.get("publication_error_message") !== message) {
        const timestamp = context.now();
        connection
          .prepare(
            `
                    UPDATE deep_scan_runs
                    SET publication_error_message = ?, updated_at = ?
                    WHERE scan_id = ?
                    `,
          )
          .run([message, timestamp, scanId]);
      }
      connection.commit();
    } catch (error) {
      connection.rollback();
      throw error;
    }
    return undefined;
  });
  return early ?? result();
}
