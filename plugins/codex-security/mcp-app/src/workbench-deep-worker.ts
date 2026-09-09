import type { Connection, Row } from "../../native/sqlite.mjs";
import {
  canonicalDiscoveryArtifacts,
  deepScanDeadlineReached,
  deepScanPath,
} from "./workbench-deep-files";
import { requireCurrentCoordinator } from "./workbench-deep-lease";
import {
  deepScanResult,
  requireDeepScanRun,
  requireRunningDeepScan,
  requireWorkerTransition,
} from "./workbench-deep-state";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { requireScan } from "./workbench-records";
import {
  optionalText,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export interface DeepWorkerContext {
  now(): string;
}
export interface UpsertDeepWorkerArguments {
  scanId: string;
  workerId: string;
  coordinatorGeneration: bigint | null;
  kind: string;
  status: string;
  promptPath: string;
  artifactDir: string;
  resultManifestPath: string | null;
  attempt: bigint | null;
  sdkThreadId: string | null;
  errorMessage: string | null;
  replaceableFailureKind: string | null;
}
function fail(message: string): never {
  throw new WorkbenchValidationError(message);
}
const number = (row: Row, field: string) => row.get(field) as bigint | number;
const increment = (value: bigint | number) =>
  typeof value === "bigint" ? value + 1n : value + 1;

export function upsertDeepScanWorker(
  context: DeepWorkerContext,
  connection: Connection,
  args: UpsertDeepWorkerArguments,
) {
  const scanId = requireUuid(args.scanId, "scan-id"),
    workerId = requireUuid(args.workerId, "worker-id");
  const result = () =>
    deepScanResult(connection, scanId, {
      canonicalDiscoveryArtifacts,
      deepScanDeadlineReached: (run) =>
        deepScanDeadlineReached(run, context.now),
    });
  connection.exec("BEGIN IMMEDIATE");
  try {
    const run = requireDeepScanRun(connection, scanId);
    requireCurrentCoordinator(run, args);
    const scan = requireScan(connection, scanId);
    const existing = connection
      .prepare("SELECT * FROM deep_scan_workers WHERE id = ?")
      .get([workerId]);
    const replaceableFailureKind = args.replaceableFailureKind;
    if (
      replaceableFailureKind !== null &&
      (args.kind !== "discovery" ||
        args.status !== "canceled" ||
        existing === undefined ||
        !["running", "canceled"].includes(existing.get("status") as string) ||
        optionalText(args.errorMessage, 2400) === null)
    )
      fail(
        "A replaceable Deep Scan failure requires a running discovery worker, canceled status, and an error message.",
      );
    const cleanupUpdate =
      existing !== undefined &&
      args.status === "canceled" &&
      ["queued", "running", "canceled"].includes(
        existing.get("status") as string,
      ) &&
      ["succeeded", "failed", "canceled", "interrupted"].includes(
        run.get("status") as string,
      );
    const terminalRepeat =
      existing !== undefined &&
      existing.get("status") === args.status &&
      ["succeeded", "failed", "canceled"].includes(args.status);
    if (!cleanupUpdate && !terminalRepeat)
      requireRunningDeepScan(connection, scanId);
    const promptPath = deepScanPath(
      scan,
      args.promptPath,
      "Worker prompt path",
      "file",
      requireCanonicalScanDirectory,
    );
    const artifactDir = deepScanPath(
      scan,
      args.artifactDir,
      "Worker artifact directory",
      "directory",
      requireCanonicalScanDirectory,
    );
    let resultManifestPath = args.resultManifestPath
      ? deepScanPath(
          scan,
          args.resultManifestPath,
          "Worker result manifest path",
          "file",
          requireCanonicalScanDirectory,
        )
      : null;
    const timestamp = context.now();
    if (existing === undefined) {
      if (args.kind === "dedup")
        fail("Create dedup workers with claim-deep-scan-dedup.");
      if (!["queued", "running"].includes(args.status))
        fail("A new Deep Scan worker must be queued or running.");
      if (
        args.kind === "setup" &&
        connection
          .prepare(
            "SELECT 1 FROM deep_scan_workers WHERE scan_id = ? AND kind = 'setup'",
          )
          .get([scanId]) !== undefined
      )
        fail("A Deep Scan can have only one setup worker.");
      const attempt = args.attempt ?? (args.status === "running" ? 1n : 0n);
      if (args.status === "running" && attempt < 1n)
        fail("A running Deep Scan worker attempt must be at least one.");
      if (args.kind === "discovery") {
        if (
          number(run, "discovery_runs_dispatched") >=
          number(run, "max_discovery_runs")
        )
          fail("Deep Scan maximum discovery runs has been reached.");
        connection
          .prepare(
            `
                    UPDATE deep_scan_runs
                    SET discovery_runs_dispatched = discovery_runs_dispatched + 1,
                        phase = 'discovery', updated_at = ?
                    WHERE scan_id = ?
                    `,
          )
          .run([timestamp, scanId]);
      }
      connection
        .prepare(
          `
                INSERT INTO deep_scan_workers (
                    id, scan_id, kind, status, prompt_path, artifact_dir, attempt,
                    sdk_thread_id, error_message, created_at, started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
        )
        .run([
          workerId,
          scanId,
          args.kind,
          args.status,
          promptPath,
          artifactDir,
          attempt,
          optionalText(args.sdkThreadId, 512),
          optionalText(args.errorMessage, 2400),
          timestamp,
          args.status === "running" ? timestamp : null,
          timestamp,
        ]);
      connection.commit();
      return result();
    }
    if (
      existing.get("scan_id") !== scanId ||
      existing.get("kind") !== args.kind
    )
      fail(
        "Deep Scan worker identity does not match its persisted run and kind.",
      );
    if (
      existing.get("prompt_path") !== promptPath ||
      existing.get("artifact_dir") !== artifactDir
    )
      fail("Deep Scan worker prompt and artifact paths are immutable.");
    requireWorkerTransition(existing.get("status") as string, args.status);
    if (terminalRepeat) {
      const repeatedAttempt = args.attempt ?? existing.get("attempt"),
        repeatedThread = optionalText(args.sdkThreadId, 512),
        repeatedError = optionalText(args.errorMessage, 2400);
      const repeatedResult =
        resultManifestPath || existing.get("result_manifest_path");
      if (
        repeatedAttempt !== existing.get("attempt") ||
        repeatedResult !== existing.get("result_manifest_path") ||
        (repeatedThread !== null &&
          repeatedThread !== existing.get("sdk_thread_id")) ||
        (repeatedError !== null &&
          repeatedError !== existing.get("error_message"))
      )
        fail("Deep Scan worker terminal state is immutable.");
      connection.commit();
      return result();
    }
    const attempt = args.attempt ?? number(existing, "attempt");
    if (attempt < number(existing, "attempt"))
      fail("Deep Scan worker attempt cannot decrease.");
    if (args.status === "running" && attempt < 1n)
      fail("A running Deep Scan worker attempt must be at least one.");
    if (args.kind === "dedup" && args.status === "succeeded")
      fail("Commit a successful dedup worker with commit-deep-scan-dedup.");
    if (
      args.kind === "discovery" &&
      args.status === "succeeded" &&
      resultManifestPath === null
    ) {
      resultManifestPath = existing.get("result_manifest_path") as
        | string
        | null;
      if (resultManifestPath === null)
        fail("A successful Deep Scan worker requires a result manifest.");
    }
    let completionSequence = existing.get("completion_sequence"),
      mergeState = existing.get("merge_state");
    if (
      args.kind === "discovery" &&
      args.status === "succeeded" &&
      completionSequence === null
    ) {
      completionSequence = increment(number(run, "completion_sequence"));
      mergeState = "buffered";
      connection
        .prepare(
          `
                UPDATE deep_scan_runs
                SET completion_sequence = ?, phase = 'discovery',
                    consecutive_errors = 0, updated_at = ?
                WHERE scan_id = ?
                `,
        )
        .run([completionSequence, timestamp, scanId]);
    } else if (
      args.kind === "discovery" &&
      args.status === "canceled" &&
      replaceableFailureKind !== null &&
      existing.get("status") === "running"
    ) {
      connection
        .prepare(
          `
                UPDATE deep_scan_runs
                SET consecutive_errors = consecutive_errors + 1, updated_at = ?
                WHERE scan_id = ?
                `,
        )
        .run([timestamp, scanId]);
    } else if (
      args.kind === "dedup" &&
      args.status === "failed" &&
      existing.get("status") === "running"
    ) {
      connection
        .prepare(
          `
                UPDATE deep_scan_workers
                SET merge_state = 'buffered', updated_at = ?
                WHERE scan_id = ? AND kind = 'discovery' AND status = 'succeeded'
                    AND merge_state = 'merging'
                    AND id IN (
                        SELECT discovery_worker_id FROM deep_scan_dedup_inputs
                        WHERE scan_id = ? AND dedup_worker_id = ?
                    )
                `,
        )
        .run([timestamp, scanId, scanId, workerId]);
      connection
        .prepare(
          `
                UPDATE deep_scan_runs
                SET phase = 'discovery', updated_at = ?
                WHERE scan_id = ?
                `,
        )
        .run([timestamp, scanId]);
    }
    const completedAt = ["succeeded", "failed", "canceled"].includes(
      args.status,
    )
      ? timestamp
      : existing.get("completed_at");
    let errorMessage = optionalText(args.errorMessage, 2400);
    if (errorMessage === null && args.status !== "succeeded")
      errorMessage = existing.get("error_message") as string | null;
    const startedAt =
      existing.get("started_at") ||
      (args.status === "running" ? timestamp : null);
    connection
      .prepare(
        `
            UPDATE deep_scan_workers
            SET status = ?, result_manifest_path = ?, attempt = ?,
                sdk_thread_id = COALESCE(?, sdk_thread_id),
                completion_sequence = ?, merge_state = ?,
                error_message = ?,
                started_at = ?, completed_at = ?, updated_at = ?
            WHERE id = ?
            `,
      )
      .run([
        args.status,
        resultManifestPath || existing.get("result_manifest_path"),
        attempt,
        optionalText(args.sdkThreadId, 512),
        completionSequence,
        mergeState,
        errorMessage,
        startedAt,
        completedAt,
        timestamp,
        workerId,
      ]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return result();
}
