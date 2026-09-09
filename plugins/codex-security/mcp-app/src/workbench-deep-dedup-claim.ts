import type { Connection } from "../../native/sqlite.mjs";
import { contractValuesEqual } from "./helpers/contract-validation";
import {
  canonicalDiscoveryArtifacts,
  deepScanDeadlineReached,
  deepScanPath,
} from "./workbench-deep-files";
import { requireCurrentCoordinator } from "./workbench-deep-lease";
import { deepScanResult, requireRunningDeepScan } from "./workbench-deep-state";
import type { DeepWorkerContext } from "./workbench-deep-worker";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { requireUuid, WorkbenchValidationError } from "./workbench-validation";

export interface ClaimDeepDedupArguments {
  scanId: string;
  workerId: string;
  coordinatorGeneration: bigint | null;
  inputWorkerId: string[];
  promptPath: string;
  artifactDir: string;
}
function fail(message: string): never {
  throw new WorkbenchValidationError(message);
}

export function claimDeepScanDedup(
  context: DeepWorkerContext,
  connection: Connection,
  args: ClaimDeepDedupArguments,
) {
  const scanId = requireUuid(args.scanId, "scan-id"),
    workerId = requireUuid(args.workerId, "worker-id");
  const inputIds = args.inputWorkerId.map((value) =>
    requireUuid(value, "input-worker-id"),
  );
  if (new Set(inputIds).size !== inputIds.length)
    fail("Dedup input worker IDs must be unique.");
  const result = () =>
    deepScanResult(connection, scanId, {
      canonicalDiscoveryArtifacts,
      deepScanDeadlineReached: (run) =>
        deepScanDeadlineReached(run, context.now),
    });
  connection.exec("BEGIN IMMEDIATE");
  try {
    const [run, scan] = requireRunningDeepScan(connection, scanId);
    requireCurrentCoordinator(run, args);
    const promptPath = deepScanPath(
      scan,
      args.promptPath,
      "Dedup prompt path",
      "file",
      requireCanonicalScanDirectory,
    );
    const artifactDir = deepScanPath(
      scan,
      args.artifactDir,
      "Dedup artifact directory",
      "directory",
      requireCanonicalScanDirectory,
    );
    const existing = connection
      .prepare("SELECT * FROM deep_scan_workers WHERE id = ?")
      .get([workerId]);
    if (existing !== undefined) {
      const persistedInputs = connection
        .prepare(
          `
                    SELECT discovery_worker_id
                    FROM deep_scan_dedup_inputs
                    WHERE dedup_worker_id = ?
                    ORDER BY input_order
                    `,
        )
        .all([workerId])
        .map((row) => row.get("discovery_worker_id"));
      if (
        existing.get("scan_id") === scanId &&
        existing.get("kind") === "dedup" &&
        existing.get("prompt_path") === promptPath &&
        existing.get("artifact_dir") === artifactDir &&
        contractValuesEqual(persistedInputs, inputIds)
      ) {
        connection.commit();
        return result();
      }
      fail("Dedup worker ID is already used by a different reducer claim.");
    }
    const activeReducer = connection
      .prepare(
        `
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'dedup' AND status IN ('queued', 'running')
            `,
      )
      .get([scanId]);
    if (activeReducer !== undefined)
      fail("Only one Deep Scan dedup worker can run at a time.");
    const bufferedIds = connection
      .prepare(
        `
                SELECT id FROM deep_scan_workers
                WHERE scan_id = ? AND kind = 'discovery'
                    AND status = 'succeeded' AND merge_state = 'buffered'
                ORDER BY completion_sequence
                `,
      )
      .all([scanId])
      .map((row) => row.get("id"));
    if (!contractValuesEqual(inputIds, bufferedIds.slice(0, inputIds.length)))
      fail(
        "A Deep Scan dedup worker must claim an ordered prefix of buffered discovery results in completion order.",
      );
    const cappedSingleton =
      inputIds.length === 1 &&
      ((run.get("discovery_runs_dispatched") as bigint | number) >=
        (run.get("max_discovery_runs") as bigint | number) ||
        deepScanDeadlineReached(run, context.now)) &&
      connection
        .prepare(
          `
                SELECT 1 FROM deep_scan_workers
                WHERE scan_id = ? AND kind = 'discovery' AND status IN ('queued', 'running')
                LIMIT 1
                `,
        )
        .get([scanId]) === undefined;
    const successfulReducer = connection
      .prepare(
        `
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'dedup' AND status = 'succeeded'
            LIMIT 1
            `,
      )
      .get([scanId]);
    const minimumInputs =
      successfulReducer !== undefined || cappedSingleton ? 1 : 2;
    if (inputIds.length < minimumInputs)
      fail(
        minimumInputs === 2
          ? "The first Deep Scan dedup requires two buffered discovery results."
          : "A Deep Scan dedup requires at least one buffered discovery result.",
      );
    const timestamp = context.now();
    connection
      .prepare(
        `
            INSERT INTO deep_scan_workers (
                id, scan_id, kind, status, prompt_path, artifact_dir,
                created_at, updated_at
            ) VALUES (?, ?, 'dedup', 'queued', ?, ?, ?, ?)
            `,
      )
      .run([workerId, scanId, promptPath, artifactDir, timestamp, timestamp]);
    for (const [order, id] of inputIds.entries())
      connection
        .prepare(
          `
                INSERT INTO deep_scan_dedup_inputs (
                    scan_id, dedup_worker_id, discovery_worker_id, input_order
                ) VALUES (?, ?, ?, ?)
                `,
        )
        .run([scanId, workerId, id, BigInt(order)]);
    connection
      .prepare(
        `
            UPDATE deep_scan_workers
            SET merge_state = 'merging', updated_at = ?
            WHERE scan_id = ? AND id IN (${inputIds.map(() => "?").join(",")})
            `,
      )
      .run([timestamp, scanId, ...inputIds]);
    connection
      .prepare(
        "UPDATE deep_scan_runs SET phase = 'reducing', updated_at = ? WHERE scan_id = ?",
      )
      .run([timestamp, scanId]);
    connection
      .prepare(
        `
            UPDATE scan_progress
            SET deep_review_pass = COALESCE(deep_review_pass, 0) + 1, updated_at = ?
            WHERE scan_id = ?
            `,
      )
      .run([timestamp, scanId]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return result();
}
