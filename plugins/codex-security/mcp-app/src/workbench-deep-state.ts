import { createHash } from "node:crypto";
import { statSync } from "node:fs";
import type { Connection, Row } from "../../native/sqlite.mjs";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { exists } from "./helpers/helper-files";
import { encodePosixPath } from "./helpers/posix-path";
import { pythonRepr } from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { encodeUtf8 } from "./helpers/utf8";
import { requireScan, requireWorkspace } from "./workbench-records";
import {
  optionalText,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

const MAX_ERROR_LENGTH = 2400;
const PUBLICATION_ERROR_SEPARATOR = "\nOriginal Deep Scan failure:\n";

export function boundedErrorText(message: string, maximum: number): string {
  const characters = Array.from(message);
  if (characters.length <= maximum) return message;
  const digest = createHash("sha256").update(encodeUtf8(message)).digest("hex");
  const suffix = `\n...[truncated; sha256:${digest}]`;
  if (suffix.length >= maximum) return characters.slice(0, maximum).join("");
  return characters.slice(0, maximum - suffix.length).join("") + suffix;
}

export function deepScanError(run: Row): string | null {
  const original = run.get("error_message"),
    publication = run.get("publication_error_message");
  if (typeof publication !== "string")
    return typeof original === "string" ? original : null;
  if (typeof original !== "string") return publication;
  const available = MAX_ERROR_LENGTH - PUBLICATION_ERROR_SEPARATOR.length;
  const publicationLength = Array.from(publication).length,
    originalLength = Array.from(original).length;
  let publicationBudget = Math.min(
    publicationLength,
    Math.floor(available / 2),
  );
  const originalBudget = Math.min(
    originalLength,
    available - publicationBudget,
  );
  publicationBudget = Math.min(publicationLength, available - originalBudget);
  return (
    boundedErrorText(publication, publicationBudget) +
    PUBLICATION_ERROR_SEPARATOR +
    boundedErrorText(original, originalBudget)
  );
}

export function requireDeepScanRun(
  connection: Connection,
  scanId: string,
): Row {
  scanId = requireUuid(scanId, "scan-id");
  const row = connection
    .prepare("SELECT * FROM deep_scan_runs WHERE scan_id = ?")
    .get([scanId]);
  if (row === undefined)
    throw new WorkbenchValidationError(
      "Codex Security Deep Scan orchestration state not found.",
    );
  return row;
}

export function requireDeepScanReadyForParentCompletion(
  connection: Connection,
  scan: Row,
): void {
  if (scan.get("mode") !== "deep") return;
  const run = connection
    .prepare(
      "SELECT status, manifest_path FROM deep_scan_runs WHERE scan_id = ?",
    )
    .get([scan.get("id")]);
  if (
    run === undefined ||
    run.get("status") !== "succeeded" ||
    run.get("manifest_path") === null
  )
    throw new WorkbenchValidationError(
      "Deep Scan discovery orchestration must finish and persist its manifest before the parent scan can be completed.",
    );
}

export function requireOwnedScan(
  connection: Connection,
  scanId: string,
  threadId: string,
): [Row, Row] {
  const scan = requireScan(connection, scanId);
  const workspace = requireWorkspace(
    connection,
    scan.get("workspace_id") as string,
  );
  const owner = optionalText(threadId, 512);
  if (owner === null)
    throw new WorkbenchValidationError("thread-id is required.");
  const persistedOwner =
    scan.get("deep_scan_owner_thread_id") || workspace.get("thread_id");
  if (persistedOwner !== owner)
    throw new WorkbenchValidationError(
      "A scan can only be orchestrated from its owning Codex thread.",
    );
  return [scan, workspace];
}

export interface DeepScanStateCallbacks {
  canonicalDiscoveryArtifacts(scan: Row): Record<string, string>;
  deepScanDeadlineReached(run: Row): boolean;
}

function collectRows<T>(
  rows: Generator<Row>,
  current: IteratorResult<Row>,
  project: (row: Row) => T,
): T[] {
  const result: T[] = [];
  while (!current.done) {
    const row = current.value;
    current = rows.next();
    result.push(project(row));
  }
  return result;
}

export function deepScanState(
  connection: Connection,
  scanId: string,
  callbacks: DeepScanStateCallbacks,
) {
  const run = requireDeepScanRun(connection, scanId);
  const scan = requireScan(connection, run.get("scan_id") as string);
  const workerRows = connection
    .prepare(
      `
    SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id
  `,
    )
    .iterate([run.get("scan_id")]);
  let inputRows: Generator<Row> | undefined;
  try {
    // sqlite3.execute steps once before returning its cursor; keep both reads open.
    const firstWorker = workerRows.next();
    inputRows = connection
      .prepare(
        `
      SELECT dedup_worker_id, discovery_worker_id, input_order
      FROM deep_scan_dedup_inputs WHERE scan_id = ? ORDER BY dedup_worker_id, input_order
    `,
      )
      .iterate([run.get("scan_id")]);
    const firstInput = inputRows.next();
    let canonicalArtifacts: Record<string, string> | null = null;
    if (
      run.get("canonical_inventory_path") === null &&
      run.get("status") === "succeeded" &&
      run.get("manifest_path") !== null &&
      run.get("manifest_path") !==
        appendPath(
          parsedPath(scan.get("scan_dir") as string),
          "scan-manifest.json",
        ) &&
      exists(
        appendPath(
          parsedPath(scan.get("scan_dir") as string),
          "artifacts/02_discovery/in_scope_files.txt",
        ),
      )
    ) {
      canonicalArtifacts = callbacks.canonicalDiscoveryArtifacts(scan);
      if (
        run.get("terminal_reason") === "capped" &&
        run.get("completion_sequence") === 0n &&
        callbacks.deepScanDeadlineReached(run)
      ) {
        const path = parsedPath(canonicalArtifacts["candidateLedgerPath"]!);
        const size =
          process.platform === "win32"
            ? windowsFileSystem(windowsBinding()).stat(widePath(path)).size
            : statSync(encodePosixPath(path), { bigint: true }).size;
        if (size != 0n)
          throw new WorkbenchValidationError(
            "A capped Deep Scan without completed discoveries requires an empty candidate ledger.",
          );
      }
    }
    return {
      scanId: run.get("scan_id"),
      targetPath: scan.get("target_path"),
      scope: scan.get("scope"),
      userContext: scan.get("user_context"),
      scanDir: scan.get("scan_dir"),
      schemaVersion: run.get("schema_version"),
      workflowVersion: run.get("workflow_version"),
      coordinatorGeneration: run.get("coordinator_generation"),
      status: run.get("status"),
      phase: run.get("phase"),
      config: {
        workers: run.get("workers"),
        subagents: run.get("subagents"),
        stopAfterNoNew: run.get("stop_after_no_new"),
        stopAfterConsecutiveErrors: run.get("stop_after_consecutive_errors"),
        maxDiscoveryRuns: run.get("max_discovery_runs"),
        maxTimeHours: run.get("max_time_hours"),
      },
      dispatchedCount: run.get("discovery_runs_dispatched"),
      completionSequence: run.get("completion_sequence"),
      noNewStreak: run.get("consecutive_no_new"),
      consecutiveErrors: run.get("consecutive_errors"),
      cancelRequested: Boolean(run.get("cancel_requested")),
      canonicalArtifacts,
      manifestPath: run.get("manifest_path"),
      terminalReason: run.get("terminal_reason"),
      error: deepScanError(run),
      createdAt: run.get("created_at"),
      updatedAt: run.get("updated_at"),
      completedAt: run.get("completed_at"),
      workers: collectRows(workerRows, firstWorker, deepScanWorkerState),
      dedupInputs: collectRows(inputRows, firstInput, (row) => ({
        dedupWorkerId: row.get("dedup_worker_id"),
        discoveryWorkerId: row.get("discovery_worker_id"),
        inputOrder: row.get("input_order"),
      })),
    };
  } finally {
    workerRows.return(undefined);
    inputRows?.return(undefined);
  }
}

export function independentReviewProgress(
  connection: Connection,
  scanId: string,
) {
  const run = connection
    .prepare(
      `
    SELECT completion_sequence, phase, updated_at, max_discovery_runs FROM deep_scan_runs WHERE scan_id = ?
  `,
    )
    .get([scanId]);
  if (run === undefined) return null;
  const active = connection
    .prepare(
      `
    SELECT COUNT(*) FROM deep_scan_workers
    WHERE scan_id = ? AND kind = 'discovery' AND status IN ('queued', 'running')
  `,
    )
    .get([scanId])!
    .get(0) as bigint;
  const integer = (value: bigint | number) =>
    typeof value === "number" ? BigInt(Math.trunc(value)) : value;
  return {
    active,
    completed: integer(run.get("completion_sequence") as bigint | number),
    maximum: integer(run.get("max_discovery_runs") as bigint | number),
    consolidating: run.get("phase") === "reducing",
    updatedAt: String(run.get("updated_at")),
  };
}

export function deepScanWorkerState(row: Row) {
  return {
    id: row.get("id"),
    kind: row.get("kind"),
    status: row.get("status"),
    mergeState: row.get("merge_state"),
    promptPath: row.get("prompt_path"),
    artifactDir: row.get("artifact_dir"),
    resultManifestPath: row.get("result_manifest_path"),
    attempt: row.get("attempt"),
    sdkThreadId: row.get("sdk_thread_id"),
    completionSequence: row.get("completion_sequence"),
    error: row.get("error_message"),
    createdAt: row.get("created_at"),
    startedAt: row.get("started_at"),
    completedAt: row.get("completed_at"),
    updatedAt: row.get("updated_at"),
  };
}

export function deepScanResult(
  connection: Connection,
  scanId: string,
  callbacks: DeepScanStateCallbacks,
  startDisposition: string | null = null,
) {
  const result: {
    deepScan: ReturnType<typeof deepScanState>;
    startDisposition?: string;
  } = { deepScan: deepScanState(connection, scanId, callbacks) };
  if (startDisposition !== null) result.startDisposition = startDisposition;
  return result;
}

export interface DeepScanRunConfig {
  workers: bigint;
  subagents: bigint;
  stopAfterNoNew: bigint;
  stopAfterConsecutiveErrors: bigint;
  maxDiscoveryRuns: bigint;
  maxTimeHours: bigint | number;
}

export function ensureDeepScanRun(
  connection: Connection,
  scan: Row,
  config: DeepScanRunConfig,
  workflowVersion: string,
  timestamp: string,
): Row {
  const existing = connection
    .prepare("SELECT * FROM deep_scan_runs WHERE scan_id = ?")
    .get([scan.get("id")]);
  if (existing !== undefined) return existing;
  if (scan.get("mode") !== "deep")
    throw new WorkbenchValidationError(
      "Deep Scan orchestration requires a scan in deep mode.",
    );
  if (scan.get("status") !== "running")
    throw new WorkbenchValidationError(
      "Only a running Deep Scan can start orchestration.",
    );
  connection
    .prepare(
      `
    INSERT INTO deep_scan_runs (
      scan_id, schema_version, workflow_version, status, phase,
      workers, subagents, stop_after_no_new, stop_after_consecutive_errors,
      max_discovery_runs, max_time_hours, created_at, updated_at
    ) VALUES (?, 1, ?, 'running', 'setup', ?, ?, ?, ?, ?, ?, ?, ?)
  `,
    )
    .run([
      scan.get("id"),
      workflowVersion,
      config.workers,
      config.subagents,
      config.stopAfterNoNew,
      config.stopAfterConsecutiveErrors,
      config.maxDiscoveryRuns,
      config.maxTimeHours,
      timestamp,
      timestamp,
    ]);
  return requireDeepScanRun(connection, scan.get("id") as string);
}

export function existingDeepScanForTarget(
  connection: Connection,
  threadId: string,
  targetPath: string,
  scope: string,
): Row | undefined {
  return connection
    .prepare(
      `
    SELECT scans.* FROM scans JOIN workspaces ON workspaces.id = scans.workspace_id
    WHERE workspaces.thread_id = ?
      AND COALESCE(scans.deep_scan_owner_thread_id, workspaces.thread_id) = ?
      AND scans.target_path = ? AND scans.scope = ? AND scans.mode = 'deep' AND scans.status = 'running'
    ORDER BY scans.updated_at DESC, scans.started_at DESC, scans.id LIMIT 1
  `,
    )
    .get([threadId, threadId, targetPath, scope]);
}

export function terminalDeepScanForTargetSnapshot(
  connection: Connection,
  threadId: string,
  targetPath: string,
  scope: string,
  revision: string,
  snapshotDigest: string,
  targetDevice: bigint | string,
  targetInode: bigint | string,
): Row | undefined {
  return connection
    .prepare(
      `
    SELECT scans.* FROM scans JOIN deep_scan_runs ON deep_scan_runs.scan_id = scans.id
    JOIN workspaces ON workspaces.id = scans.workspace_id
    WHERE scans.target_path = ? AND scans.scope = ? AND scans.mode = 'deep' AND scans.status = 'running'
      AND scans.canceled_at IS NULL AND scans.target_revision = ? AND scans.target_snapshot_digest = ?
      AND scans.target_device = ? AND scans.target_inode = ? AND scans.handoff_status = 'delivered'
      AND scans.handoff_claim_token IS NULL
      AND COALESCE(scans.deep_scan_owner_thread_id, workspaces.thread_id) <> ?
      AND workspaces.active_scan_id = scans.id AND deep_scan_runs.status = 'succeeded'
      AND deep_scan_runs.phase = 'terminal' AND deep_scan_runs.cancel_requested = 0
      AND deep_scan_runs.terminal_reason IN ('saturated', 'capped')
      AND deep_scan_runs.manifest_path IS NOT NULL AND deep_scan_runs.completed_at IS NOT NULL
    ORDER BY deep_scan_runs.completed_at DESC, scans.updated_at DESC, scans.id LIMIT 1
  `,
    )
    .get([
      targetPath,
      scope,
      revision,
      snapshotDigest,
      targetDevice,
      targetInode,
      threadId,
    ]);
}

export function requireDeepScanWorker(
  connection: Connection,
  workerId: string,
): Row {
  workerId = requireUuid(workerId, "worker-id");
  const row = connection
    .prepare("SELECT * FROM deep_scan_workers WHERE id = ?")
    .get([workerId]);
  if (row === undefined)
    throw new WorkbenchValidationError(
      "Codex Security Deep Scan worker not found.",
    );
  return row;
}

export function requireRunningDeepScan(
  connection: Connection,
  scanId: string,
): [Row, Row] {
  const run = requireDeepScanRun(connection, scanId),
    scan = requireScan(connection, run.get("scan_id") as string);
  if (run.get("status") !== "running" || run.get("cancel_requested"))
    throw new WorkbenchValidationError(
      "Only a running Deep Scan can update orchestration state.",
    );
  if (scan.get("status") !== "running" || scan.get("canceled_at") !== null)
    throw new WorkbenchValidationError(
      "Only a running scan can update Deep Scan orchestration state.",
    );
  return [run, scan];
}

export function requireWorkerTransition(
  current: string,
  requested: string,
): void {
  const allowed: Record<string, readonly string[]> = {
    queued: ["queued", "running", "failed", "canceled"],
    running: ["running", "succeeded", "failed", "canceled"],
    succeeded: ["succeeded"],
    failed: ["failed"],
    canceled: ["canceled"],
  };
  if (!Object.hasOwn(allowed, current)) throw new Error(pythonRepr(current));
  if (!allowed[current]!.includes(requested))
    throw new WorkbenchValidationError(
      `Deep Scan worker cannot transition from ${current} to ${requested}.`,
    );
}

export function otherRunningDeepScans(
  connection: Connection,
  currentScanId: string,
) {
  return Array.from(
    connection
      .prepare(
        `
    SELECT id, target_path, phase, started_at, updated_at FROM scans
    WHERE mode = 'deep' AND status = 'running' AND id != ?
    ORDER BY updated_at DESC, started_at DESC, id
  `,
      )
      .iterate([currentScanId]),
    (row) => ({
      phase: row.get("phase"),
      scanId: row.get("id"),
      startedAt: row.get("started_at"),
      targetPath: row.get("target_path"),
      updatedAt: row.get("updated_at"),
    }),
  );
}
