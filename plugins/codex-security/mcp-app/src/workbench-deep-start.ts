import { cpus } from "node:os";
import { basename } from "node:path";
import type { Connection } from "../../native/sqlite.mjs";
import { resolveDeepScanConfig } from "./helpers/deep-scan-config";
import { mkdir } from "./helpers/helper-files";
import { appendPath } from "./helpers/rank-selection";
import { ensureSecurityTarget } from "./workbench-db";
import {
  canonicalDiscoveryArtifacts,
  deepScanDeadlineReached,
} from "./workbench-deep-files";
import {
  deepScanResult,
  ensureDeepScanRun,
  existingDeepScanForTarget,
  requireOwnedScan,
  terminalDeepScanForTargetSnapshot,
  type DeepScanStateCallbacks,
} from "./workbench-deep-state";
import { requireCurrentContinuation } from "./workbench-handoff";
import { requireScan, requireWorkspace } from "./workbench-records";
import type { ScanKickoffContext } from "./workbench-scan-kickoff";
import {
  compactTimestamp,
  safeSegment,
  temporaryDirectory,
} from "./workbench-scan-start";
import {
  requireScannableTarget,
  requireScope,
  requireTarget,
  scanTargetRoot,
} from "./workbench-setup";
import {
  directorySnapshotRegularFileCount,
  filesystemIdentity,
  requireRemediationTarget,
  scanTargetIdentity,
} from "./workbench-target";
import {
  optionalText,
  requireUuid,
  userContextArgument,
  WorkbenchValidationError,
} from "./workbench-validation";

export interface BeginDeepScanArguments {
  threadId: string | null;
  scanId: string | null;
  targetPath: string | null;
  scope: string;
  userContext: string | null;
  userContextStdin?: boolean;
  scanRoot: string | null;
  claimToken: string | null;
  model: string | null;
  reasoningEffort: string | null;
  availableParallelism: bigint | number | null;
  workflowVersion: string | null;
}
const config = (args: BeginDeepScanArguments) =>
  resolveDeepScanConfig(args.availableParallelism || cpus().length || 1);
const callbacks = (
  context: Pick<ScanKickoffContext, "now">,
): DeepScanStateCallbacks => ({
  canonicalDiscoveryArtifacts,
  deepScanDeadlineReached: (run) => deepScanDeadlineReached(run, context.now),
});
const continuationOptions = {
  errorMessage: "Deep Scan orchestration is owned by another continuation.",
};
const workflow = (args: BeginDeepScanArguments) => {
  const version = optionalText(args.workflowVersion, 256);
  if (version === null)
    throw new WorkbenchValidationError("workflow-version is required.");
  return version;
};

export function beginDeepScanForScan(
  context: ScanKickoffContext,
  connection: Connection,
  scanId: string,
  threadId: string,
  args: BeginDeepScanArguments,
) {
  scanId = requireUuid(scanId, "scan-id");
  const candidate = requireScan(connection, scanId),
    workspace = requireWorkspace(
      connection,
      candidate.get("workspace_id") as string,
    );
  if (
    candidate.get("mode") === "deep" &&
    candidate.get("status") === "running" &&
    candidate.get("recipe_json") !== null &&
    candidate.get("handoff_status") === "delivered" &&
    candidate.get("deep_scan_owner_thread_id") === null &&
    workspace.get("thread_id") === null
  ) {
    requireCurrentContinuation(candidate, args.claimToken, continuationOptions);
    const timestamp = context.now();
    connection.transaction(() => {
      const claimedWorkspace = connection
          .prepare(
            "UPDATE workspaces SET thread_id = ?, updated_at = ? WHERE id = ? AND thread_id IS NULL",
          )
          .run([threadId, timestamp, workspace.get("id")]),
        claimedScan = connection
          .prepare(
            "UPDATE scans SET deep_scan_owner_thread_id = ?, updated_at = ? WHERE id = ? AND deep_scan_owner_thread_id IS NULL AND handoff_status = 'delivered' AND handoff_claim_token IS ?",
          )
          .run([
            threadId,
            timestamp,
            scanId,
            candidate.get("handoff_claim_token"),
          ]);
      if (claimedWorkspace.rowcount !== 1n || claimedScan.rowcount !== 1n)
        throw new WorkbenchValidationError(
          "A scan can only be orchestrated from its owning Codex thread.",
        );
    });
  }
  let [scan] = requireOwnedScan(connection, scanId, threadId);
  requireCurrentContinuation(scan, args.claimToken, continuationOptions);
  if (scan.get("mode") !== "deep")
    throw new WorkbenchValidationError(
      "Deep Scan orchestration requires a scan in deep mode.",
    );
  const model = optionalText(args.model, 200),
    reasoningEffort = optionalText(args.reasoningEffort, 32);
  if (model !== null || reasoningEffort !== null) {
    connection
      .prepare(
        `UPDATE scans SET model = COALESCE(?, model), reasoning_effort = COALESCE(?, reasoning_effort) WHERE id = ?`,
      )
      .run([model, reasoningEffort, scanId]);
    connection.commit();
  }
  const existing = connection
    .prepare("SELECT scan_id FROM deep_scan_runs WHERE scan_id = ?")
    .get([scanId]);
  if (existing !== undefined)
    return deepScanResult(connection, scanId, callbacks(context), "joined");
  const resolved = config(args),
    workflowVersion = workflow(args);
  connection.prepare("BEGIN IMMEDIATE").run();
  try {
    [scan] = requireOwnedScan(connection, scanId, threadId);
    requireCurrentContinuation(scan, args.claimToken, continuationOptions);
    ensureDeepScanRun(
      connection,
      scan,
      resolved,
      workflowVersion,
      context.now(),
    );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return deepScanResult(connection, scanId, callbacks(context), "created");
}

export function beginDeepScanForTarget(
  context: ScanKickoffContext,
  connection: Connection,
  args: BeginDeepScanArguments,
  threadId: string,
) {
  const target = requireTarget(args.targetPath!);
  requireScannableTarget(target);
  const scope = requireScope(args.scope, "deep", target);
  let existing = existingDeepScanForTarget(connection, threadId, target, scope);
  if (existing !== undefined)
    return beginDeepScanForScan(
      context,
      connection,
      existing.get("id") as string,
      threadId,
      args,
    );
  const metadata = filesystemIdentity(target),
    [revision, snapshot, device, inode] = scanTargetIdentity(
      target,
      null,
      metadata,
    ),
    scopeFileCount = directorySnapshotRegularFileCount(
      scope === "." ? target : appendPath(target, scope),
    );
  let scanId: string;
  connection.prepare("BEGIN IMMEDIATE").run();
  try {
    existing = existingDeepScanForTarget(connection, threadId, target, scope);
    if (existing !== undefined) {
      const existingRun = connection
        .prepare("SELECT 1 FROM deep_scan_runs WHERE scan_id = ?")
        .get([existing.get("id")]);
      if (existingRun === undefined) {
        const resolved = config(args),
          workflowVersion = workflow(args);
        ensureDeepScanRun(
          connection,
          existing,
          resolved,
          workflowVersion,
          context.now(),
        );
      }
      connection.commit();
      return deepScanResult(
        connection,
        existing.get("id") as string,
        callbacks(context),
        existingRun !== undefined ? "joined" : "created",
      );
    }
    const current = filesystemIdentity(requireRemediationTarget(target));
    if (current.dev !== metadata.dev || current.ino !== metadata.ino)
      throw new WorkbenchValidationError(
        "The selected scan target changed while the scan was starting. Try again.",
      );
    const terminal = terminalDeepScanForTargetSnapshot(
      connection,
      threadId,
      target,
      scope,
      revision,
      snapshot!,
      device,
      inode,
    );
    if (terminal !== undefined) {
      connection.commit();
      return deepScanResult(
        connection,
        terminal.get("id") as string,
        callbacks(context),
        "joined",
      );
    }
    const resolved = config(args),
      workflowVersion = workflow(args),
      targetRoot = scanTargetRoot(args.scanRoot, target);
    mkdir(targetRoot);
    const userContext = userContextArgument(args, context.stdin),
      model = optionalText(args.model, 200),
      reasoningEffort = optionalText(args.reasoningEffort, 32),
      workspaceId = context.uuid();
    scanId = context.uuid();
    const timestamp = context.now(),
      targetId = ensureSecurityTarget(connection, target, context.now),
      scanDir = temporaryDirectory(
        targetRoot,
        `${safeSegment(revision)}_${compactTimestamp()}_`,
      );
    connection
      .prepare(
        `INSERT INTO workspaces (
      id, thread_id, target_id, target_path, target_title, default_scope, default_mode,
      user_context, submitted, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'deep', ?, 1, ?, ?)`,
      )
      .run([
        workspaceId,
        threadId,
        targetId,
        target,
        basename(target),
        scope,
        userContext,
        timestamp,
        timestamp,
      ]);
    connection
      .prepare(
        `INSERT INTO scans (
      id, workspace_id, target_id, target_path, target_revision, target_snapshot_digest,
      target_device, target_inode, scope, mode, user_context,
      deep_scan_owner_thread_id, scan_dir, model, reasoning_effort, status, phase,
      handoff_status, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'deep', ?, ?, ?, ?, ?,
      'running', 'preflight', 'delivered', ?, ?, ?)`,
      )
      .run([
        scanId,
        workspaceId,
        targetId,
        target,
        revision,
        snapshot,
        device,
        inode,
        scope,
        userContext,
        threadId,
        scanDir,
        model,
        reasoningEffort,
        timestamp,
        timestamp,
        timestamp,
      ]);
    connection
      .prepare(
        `INSERT INTO scan_progress (
      scan_id, scope_file_count, review_items_total, review_items_completed,
      reportable_findings_count, updated_at
    ) VALUES (?, ?, 0, 0, 0, ?)`,
      )
      .run([scanId, scopeFileCount, timestamp]);
    connection
      .prepare(
        "UPDATE workspaces SET active_scan_id = ?, updated_at = ? WHERE id = ?",
      )
      .run([scanId, timestamp, workspaceId]);
    const scan = requireScan(connection, scanId);
    ensureDeepScanRun(connection, scan, resolved, workflowVersion, timestamp);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return deepScanResult(connection, scanId, callbacks(context), "created");
}

export function beginDeepScan(
  context: ScanKickoffContext,
  connection: Connection,
  args: BeginDeepScanArguments,
) {
  const threadId = optionalText(args.threadId, 512);
  if (threadId === null)
    throw new WorkbenchValidationError("thread-id is required.");
  if (args.scanId) {
    if (
      args.userContext !== null ||
      args.userContextStdin ||
      args.scope !== "."
    )
      throw new WorkbenchValidationError(
        "scan-id cannot be combined with target setup fields.",
      );
    return beginDeepScanForScan(
      context,
      connection,
      args.scanId,
      threadId,
      args,
    );
  }
  if (args.claimToken !== null)
    throw new WorkbenchValidationError(
      "claim-token is only valid with scan-id.",
    );
  return beginDeepScanForTarget(context, connection, args, threadId);
}

export function getDeepScan(
  context: Pick<ScanKickoffContext, "now">,
  connection: Connection,
  args: { scanId: string; threadId: string },
) {
  const [scan] = requireOwnedScan(connection, args.scanId, args.threadId);
  return deepScanResult(
    connection,
    scan.get("id") as string,
    callbacks(context),
  );
}
