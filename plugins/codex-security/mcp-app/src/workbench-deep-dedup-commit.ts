import { randomUUID } from "node:crypto";
import { basename, dirname } from "node:path";
import type { Connection } from "../../native/sqlite.mjs";
import { appendPath } from "./helpers/rank-selection";
import { withScanCompletionLock } from "./workbench-completion-lock";
import {
  canonicalDiscoveryArtifacts,
  deepScanDeadlineReached,
  deepScanOutputPath,
  deepScanPath,
} from "./workbench-deep-files";
import { requireCurrentCoordinator } from "./workbench-deep-lease";
import {
  createPublicationCopy,
  finishStagedFile,
  promoteStagedFile,
  rollbackStagedFile,
  unlinkPublicationFile,
  type StagedFilePromotion,
} from "./workbench-deep-publication";
import {
  deepScanResult,
  requireDeepScanRun,
  requireDeepScanWorker,
  requireRunningDeepScan,
} from "./workbench-deep-state";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { requireScan } from "./workbench-records";
import { requireUuid, WorkbenchValidationError } from "./workbench-validation";

export interface DeepDedupCommitContext {
  now(): string;
  uuid?(): string;
}
export interface CommitDeepDedupArguments {
  scanId: string;
  workerId: string;
  coordinatorGeneration: bigint | null;
  candidateLedgerPath: string | null;
  resultManifestPath: string;
  newFindingsCount: bigint;
}
function fail(message: string): never {
  throw new WorkbenchValidationError(message);
}

export function commitDeepScanDedup(
  context: DeepDedupCommitContext,
  connection: Connection,
  args: CommitDeepDedupArguments,
) {
  const scanId = requireUuid(args.scanId, "scan-id");
  return withScanCompletionLock(scanId, () =>
    commitDeepScanDedupLocked(context, connection, args, scanId),
  );
}

export function commitDeepScanDedupLocked(
  context: DeepDedupCommitContext,
  connection: Connection,
  args: CommitDeepDedupArguments,
  scanId: string,
) {
  const workerId = requireUuid(args.workerId, "worker-id"),
    uuid = context.uuid ?? randomUUID;
  const result = () =>
    deepScanResult(connection, scanId, {
      canonicalDiscoveryArtifacts,
      deepScanDeadlineReached: (run) =>
        deepScanDeadlineReached(run, context.now),
    });
  let promotion: StagedFilePromotion | null = null,
    publicationCopy: string | null = null;
  connection.exec("BEGIN IMMEDIATE");
  try {
    const run = requireDeepScanRun(connection, scanId);
    requireCurrentCoordinator(run, args);
    const scan = requireScan(connection, scanId),
      worker = requireDeepScanWorker(connection, workerId);
    if (worker.get("scan_id") !== scanId || worker.get("kind") !== "dedup")
      fail("Dedup worker does not belong to this Deep Scan.");
    if (worker.get("status") === "succeeded") {
      connection.commit();
      return result();
    }
    requireRunningDeepScan(connection, scanId);
    if (!["queued", "running"].includes(worker.get("status") as string))
      fail("Only an active dedup worker can commit a result.");
    let candidateLedgerPath: string | null = null,
      canonicalCandidateLedgerPath: string | null = null;
    if (args.candidateLedgerPath) {
      candidateLedgerPath = deepScanPath(
        scan,
        args.candidateLedgerPath,
        "Staged candidate ledger path",
        "file",
        requireCanonicalScanDirectory,
      );
      const discoveryDirectory = appendPath(
        scan.get("scan_dir") as string,
        "artifacts/02_discovery",
      );
      deepScanPath(
        scan,
        appendPath(discoveryDirectory, "in_scope_files.txt"),
        "Canonical in-scope inventory path",
        "file",
        requireCanonicalScanDirectory,
      );
      canonicalCandidateLedgerPath = deepScanOutputPath(
        scan,
        appendPath(discoveryDirectory, "candidate_ledger.jsonl"),
        "Canonical candidate ledger path",
        requireCanonicalScanDirectory,
      );
    }
    const resultManifestPath = deepScanPath(
      scan,
      args.resultManifestPath,
      "Dedup result manifest path",
      "file",
      requireCanonicalScanDirectory,
    );
    const inputs = connection
      .prepare(
        `
                SELECT workers.*
                FROM deep_scan_dedup_inputs AS inputs
                JOIN deep_scan_workers AS workers ON workers.id = inputs.discovery_worker_id
                WHERE inputs.dedup_worker_id = ?
                ORDER BY inputs.input_order
                `,
      )
      .all([workerId]);
    if (
      !inputs.length ||
      inputs.some((row) => row.get("merge_state") !== "merging")
    )
      fail("Dedup inputs are not in the claimed merging state.");
    if (candidateLedgerPath && canonicalCandidateLedgerPath) {
      publicationCopy = appendPath(
        dirname(canonicalCandidateLedgerPath),
        `.${basename(canonicalCandidateLedgerPath)}.${uuid()}.publish`,
      );
      createPublicationCopy(candidateLedgerPath, publicationCopy, false, true);
      promotion = promoteStagedFile(
        publicationCopy,
        canonicalCandidateLedgerPath,
        uuid,
      );
    }
    const timestamp = context.now();
    connection
      .prepare(
        `
            UPDATE deep_scan_workers
            SET merge_state = 'merged', updated_at = ?
            WHERE id IN (
                SELECT discovery_worker_id FROM deep_scan_dedup_inputs
                WHERE dedup_worker_id = ?
            )
            `,
      )
      .run([timestamp, workerId]);
    connection
      .prepare(
        `
            UPDATE deep_scan_workers
            SET status = 'succeeded', result_manifest_path = ?,
                error_message = NULL, started_at = COALESCE(started_at, ?),
                completed_at = ?, updated_at = ?
            WHERE id = ?
            `,
      )
      .run([resultManifestPath, timestamp, timestamp, timestamp, workerId]);
    const previous = run.get("consecutive_no_new") as bigint | number;
    const noNewStreak =
      args.newFindingsCount > 0n
        ? 0n
        : typeof previous === "bigint"
          ? previous + BigInt(inputs.length)
          : previous + inputs.length;
    connection
      .prepare(
        `
            UPDATE deep_scan_runs
            SET phase = 'discovery', consecutive_no_new = ?, updated_at = ?
            WHERE scan_id = ?
            `,
      )
      .run([noNewStreak, timestamp, scanId]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    if (promotion !== null) rollbackStagedFile(promotion);
    if (publicationCopy !== null) unlinkPublicationFile(publicationCopy);
    throw error;
  }
  if (promotion !== null) finishStagedFile(promotion);
  if (publicationCopy !== null) unlinkPublicationFile(publicationCopy);
  return result();
}
