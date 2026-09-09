import { randomUUID } from "node:crypto";
import { statSync } from "node:fs";
import type { Connection, Row } from "../../native/sqlite.mjs";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { encodePosixPath } from "./helpers/posix-path";
import { jsonGet, object } from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { readScanLocalJson } from "./helpers/scan-contract-json";
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
import {
  deepScanResult,
  requireDeepScanRun,
  requireRunningDeepScan,
} from "./workbench-deep-state";
import { cancelActiveWorkers } from "./workbench-deep-terminal";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { requireScan } from "./workbench-records";
import { requireUuid, WorkbenchValidationError } from "./workbench-validation";

export interface DeepFinishContext {
  now(): string;
  uuid?(): string;
}
export interface FinishDeepScanArguments {
  scanId: string;
  coordinatorGeneration: bigint | null;
  manifestPath: string;
  stagedManifestPath: string | null;
  terminalReason: string;
  omittedWorkerId: string[];
}
function fail(message: string): never {
  throw new WorkbenchValidationError(message);
}
const number = (row: Row, field: string) => row.get(field) as bigint | number;

export function finishDeepScan(
  context: DeepFinishContext,
  connection: Connection,
  args: FinishDeepScanArguments,
) {
  const scanId = requireUuid(args.scanId, "scan-id");
  return withScanCompletionLock(scanId, () =>
    finishDeepScanLocked(context, connection, args, scanId),
  );
}
export function finishDeepScanLocked(
  context: DeepFinishContext,
  connection: Connection,
  args: FinishDeepScanArguments,
  scanId: string,
) {
  const omittedWorkerIds = args.omittedWorkerId.map((value) =>
    requireUuid(value, "omitted-worker-id"),
  );
  if (new Set(omittedWorkerIds).size !== omittedWorkerIds.length)
    fail("Omitted Deep Scan worker IDs must be unique.");
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
    const scan = requireScan(connection, scanId),
      scanDirectory = parsedPath(scan.get("scan_dir") as string);
    const manifestPath = args.stagedManifestPath
      ? deepScanOutputPath(
          scan,
          args.manifestPath,
          "Deep Scan coordinator manifest path",
          requireCanonicalScanDirectory,
        )
      : deepScanPath(
          scan,
          args.manifestPath,
          "Deep Scan coordinator manifest path",
          "file",
          requireCanonicalScanDirectory,
        );
    const standardScanManifest =
      manifestPath === appendPath(scanDirectory, "scan-manifest.json");
    let failureCapped = false;
    if (
      standardScanManifest &&
      args.terminalReason === "capped" &&
      (run.get("status") === "running" || omittedWorkerIds.length > 0)
    ) {
      for (const artifactName of [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
      ])
        deepScanPath(
          scan,
          appendPath(scanDirectory, artifactName),
          `Canonical parent ${artifactName}`,
          "file",
          requireCanonicalScanDirectory,
        );
      const coverage = readScanLocalJson(
          scanDirectory,
          "coverage.json",
          "Canonical parent coverage.json",
        ),
        deferred = jsonGet(coverage, "deferred");
      failureCapped =
        jsonGet(coverage, "completeness") === "partial" &&
        Array.isArray(deferred) &&
        deferred.some((item) => {
          if (!object(item)) return false;
          const reason = jsonGet(item, "reason");
          return (
            typeof reason === "string" &&
            reason.startsWith("Deep Scan stopped before completion: ")
          );
        }) &&
        connection
          .prepare(
            `
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'dedup' AND status = 'succeeded'
            LIMIT 1
            `,
          )
          .get([scanId]) !== undefined;
      if (failureCapped && run.get("status") === "running") {
        requireRunningDeepScan(connection, scanId);
        connection
          .prepare(
            `
                    UPDATE deep_scan_workers
                    SET merge_state = 'buffered', updated_at = ?
                    WHERE scan_id = ? AND kind = 'discovery' AND status = 'succeeded'
                        AND merge_state = 'merging'
                        AND id IN (
                            SELECT inputs.discovery_worker_id
                            FROM deep_scan_dedup_inputs AS inputs
                            JOIN deep_scan_workers AS reducers
                                ON reducers.id = inputs.dedup_worker_id
                                AND reducers.scan_id = inputs.scan_id
                            WHERE inputs.scan_id = ?
                                AND reducers.kind = 'dedup'
                                AND reducers.status IN ('failed', 'canceled')
                        )
                    `,
          )
          .run([context.now(), scanId, scanId]);
      }
    }
    const bufferedWorkerIds = connection
      .prepare(
        `
                SELECT id
                FROM deep_scan_workers
                WHERE scan_id = ? AND kind = 'discovery' AND merge_state = 'buffered'
                ORDER BY completion_sequence, id
                `,
      )
      .all([scanId])
      .map((row) => row.get("id") as string);
    const omitted = new Set(omittedWorkerIds),
      buffered = new Set(bufferedWorkerIds);
    const omissionsMatch =
      args.terminalReason === "saturated" || failureCapped
        ? omitted.size === buffered.size &&
          [...omitted].every((id) => buffered.has(id))
        : omittedWorkerIds.length === 0 && bufferedWorkerIds.length === 0;
    if (run.get("status") === "succeeded") {
      if (
        run.get("terminal_reason") !== args.terminalReason ||
        ![null, manifestPath].includes(
          run.get("manifest_path") as string | null,
        ) ||
        !omissionsMatch
      )
        fail(
          "Deep Scan terminal state is immutable; finish must exactly replay its terminal reason, manifest path, and omitted worker IDs.",
        );
      if (run.get("manifest_path") === null)
        connection
          .prepare(
            "UPDATE deep_scan_runs SET manifest_path = ?, updated_at = ? WHERE scan_id = ?",
          )
          .run([manifestPath, context.now(), scanId]);
      connection.commit();
      return result();
    }
    requireRunningDeepScan(connection, scanId);
    if (
      args.terminalReason === "saturated" &&
      number(run, "consecutive_no_new") < number(run, "stop_after_no_new")
    )
      fail(
        "Deep Scan cannot finish saturated before reaching its no-new-findings threshold.",
      );
    if (
      args.terminalReason === "capped" &&
      number(run, "discovery_runs_dispatched") <
        number(run, "max_discovery_runs") &&
      !deepScanDeadlineReached(run, context.now) &&
      !failureCapped
    )
      fail(
        "Deep Scan cannot finish capped before reaching its configured maximum.",
      );
    let canonicalArtifacts: Record<string, string> | null = null;
    if (standardScanManifest) {
      for (const artifactName of [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
      ])
        deepScanPath(
          scan,
          appendPath(scanDirectory, artifactName),
          `Canonical parent ${artifactName}`,
          "file",
          requireCanonicalScanDirectory,
        );
    } else {
      try {
        canonicalArtifacts = canonicalDiscoveryArtifacts(scan);
      } catch (error) {
        if (!(error instanceof WorkbenchValidationError)) throw error;
        fail(
          `Deep Scan cannot finish without canonical discovery artifacts: ${error.message}`,
        );
      }
    }
    const successfulReducer = connection
      .prepare(
        `
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'dedup' AND status = 'succeeded'
            LIMIT 1
            `,
      )
      .get([scanId]);
    const ledgerSize = () => {
      const path = canonicalArtifacts!["candidateLedgerPath"]!;
      return process.platform === "win32"
        ? windowsFileSystem(windowsBinding()).stat(widePath(path)).size
        : statSync(encodePosixPath(path), { bigint: true }).size;
    };
    const zeroDiscoveryDeadline =
      args.terminalReason === "capped" &&
      deepScanDeadlineReached(run, context.now) &&
      number(run, "completion_sequence") == 0n &&
      (standardScanManifest ||
        (canonicalArtifacts !== null && ledgerSize() == 0n));
    if (successfulReducer === undefined && !zeroDiscoveryDeadline)
      fail("Deep Scan cannot finish without a successful dedup worker.");
    const failedWorker = connection
      .prepare(
        `
            SELECT 1 FROM deep_scan_workers AS failed
            WHERE failed.scan_id = ? AND failed.status = 'failed'
                AND (? != 'saturated' OR failed.kind != 'discovery')
                AND (
                    failed.kind != 'dedup'
                    OR NOT EXISTS (
                        SELECT 1 FROM deep_scan_dedup_inputs AS failed_inputs
                        WHERE failed_inputs.dedup_worker_id = failed.id
                    )
                    OR EXISTS (
                        SELECT 1 FROM deep_scan_dedup_inputs AS failed_inputs
                        WHERE failed_inputs.dedup_worker_id = failed.id
                            AND NOT EXISTS (
                                SELECT 1
                                FROM deep_scan_dedup_inputs AS replacement_inputs
                                JOIN deep_scan_workers AS replacement
                                    ON replacement.scan_id = replacement_inputs.scan_id
                                    AND replacement.id = replacement_inputs.dedup_worker_id
                                WHERE replacement_inputs.scan_id = failed.scan_id
                                    AND replacement_inputs.discovery_worker_id =
                                        failed_inputs.discovery_worker_id
                                    AND replacement.kind = 'dedup'
                                    AND replacement.status = 'succeeded'
                            )
                    )
                )
            LIMIT 1
            `,
      )
      .get([scanId, args.terminalReason]);
    if (failedWorker !== undefined && !failureCapped)
      fail("Deep Scan cannot finish after a worker has failed.");
    if (args.terminalReason === "saturated")
      cancelActiveWorkers(connection, scanId, context.now());
    if (
      connection
        .prepare(
          `
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND status IN ('queued', 'running')
            LIMIT 1
            `,
        )
        .get([scanId]) !== undefined
    )
      fail("Deep Scan cannot finish while workers are active.");
    if (
      connection
        .prepare(
          `
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND merge_state = 'merging'
            LIMIT 1
            `,
        )
        .get([scanId]) !== undefined
    )
      fail("Deep Scan cannot finish while discovery output is merging.");
    if (
      args.terminalReason === "capped" &&
      omittedWorkerIds.length &&
      !failureCapped
    )
      fail(
        "Deep Scan capped completion cannot declare omitted buffered workers.",
      );
    if (
      args.terminalReason === "capped" &&
      bufferedWorkerIds.length &&
      !failureCapped
    )
      fail(
        "Deep Scan cannot finish capped while discovery output remains buffered.",
      );
    if (
      (args.terminalReason === "saturated" || failureCapped) &&
      !omissionsMatch
    )
      fail(
        `Deep Scan ${args.terminalReason} completion must exactly identify all buffered discovery workers with --omitted-worker-id.`,
      );
    if (args.stagedManifestPath) {
      const staged = deepScanPath(
        scan,
        args.stagedManifestPath,
        "Staged Deep Scan coordinator manifest path",
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
            SET status = 'succeeded', phase = 'terminal', terminal_reason = ?,
                manifest_path = ?, completed_at = ?, updated_at = ?
            WHERE scan_id = ?
            `,
      )
      .run([args.terminalReason, manifestPath, timestamp, timestamp, scanId]);
    cancelActiveWorkers(connection, scanId, timestamp);
    connection.commit();
  } catch (error) {
    connection.rollback();
    if (promotion !== null) rollbackStagedFile(promotion);
    throw error;
  }
  if (promotion !== null) finishStagedFile(promotion);
  return result();
}
