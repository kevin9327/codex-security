import { basename } from "node:path";
import type { Connection, Row, SqlValue } from "../../native/sqlite.mjs";
import { mkdir } from "./helpers/helper-files";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { ensureSecurityTarget } from "./workbench-db";
import { existingDeepScanForTarget } from "./workbench-deep-state";
import { requireWorkspace } from "./workbench-records";
import {
  resultCallbacks,
  scanContext,
  workspaceState,
} from "./workbench-results";
import { insertRunningScan, scanDiffIdentity } from "./workbench-scan-start";
import {
  diffTargetSummary,
  inspectSetupValues,
  requireDiffTarget,
  requireScannableTarget,
  requireScope,
  requireTarget,
  scanTargetRoot,
  type SetupArguments,
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

export interface ScanKickoffContext {
  now(): string;
  uuid(): string;
  stdin(): string;
}
export interface StartScanArguments {
  workspaceId: string;
  scanRoot: string | null;
  model: string | null;
  reasoningEffort: string | null;
}
export interface PromptScanArguments extends SetupArguments {
  threadId: string | null;
  userContext: string | null;
  userContextStdin?: boolean;
  targetSummary: string | null;
  scanRoot: string | null;
  model: string | null;
  reasoningEffort: string | null;
}
const truth = (value: SqlValue) =>
  Buffer.isBuffer(value) ? value.length !== 0 : Boolean(value);
const targetChanged = () =>
  new WorkbenchValidationError(
    "The selected scan target changed while the scan was starting. Try again.",
  );

export function startScan(
  context: ScanKickoffContext,
  connection: Connection,
  args: StartScanArguments,
): Record<string, unknown> {
  const workspaceId = requireUuid(args.workspaceId, "workspace-id"),
    managesTransaction = !connection.inTransaction;
  let workspace: Row;
  const active = (id: SqlValue) =>
    connection
      .prepare(
        `SELECT * FROM scans WHERE workspace_id = ? AND status = 'running' AND canceled_at IS NULL`,
      )
      .get([id]);
  try {
    workspace = requireWorkspace(connection, workspaceId);
    if (
      !truth(workspace.get("submitted")) ||
      !truth(workspace.get("target_path"))
    )
      throw new WorkbenchValidationError(
        "Save the Codex Security setup before starting the scan.",
      );
    if (active(workspace.get("id")) !== undefined)
      return workspaceState(
        connection,
        workspace.get("id") as string,
        resultCallbacks,
      );
    const workspaceVersion = workspace.get("updated_at"),
      scanId = context.uuid(),
      timestamp = context.now(),
      target = requireTarget(workspace.get("target_path") as string);
    requireScannableTarget(target);
    const metadata = filesystemIdentity(target),
      scope = requireScope(
        workspace.get("default_scope") as string,
        workspace.get("default_mode") as string,
        target,
      ),
      diffTarget =
        workspace.get("default_mode") === "diff"
          ? requireDiffTarget(
              target,
              workspace.get("diff_target_kind") as string | null,
              workspace.get("diff_base_revision") as string | null,
              workspace.get("diff_head_revision") as string | null,
              workspace.get("diff_content_digest") as string | null,
            )
          : null;
    let targetSummary =
      workspace.get("default_mode") === "diff"
        ? workspace.get("target_summary")
        : null;
    if (diffTarget !== null && !truth(targetSummary))
      targetSummary = diffTargetSummary(diffTarget);
    const scopeFileCount = directorySnapshotRegularFileCount(
        scope === "." ? target : appendPath(target, scope),
      ),
      identity = scanTargetIdentity(target, diffTarget, metadata),
      targetRoot = scanTargetRoot(args.scanRoot, target);
    mkdir(targetRoot);
    if (managesTransaction) connection.prepare("BEGIN IMMEDIATE").run();
    workspace = requireWorkspace(connection, workspaceId);
    if (active(workspace.get("id")) !== undefined) {
      if (managesTransaction) connection.commit();
      return workspaceState(
        connection,
        workspace.get("id") as string,
        resultCallbacks,
      );
    }
    const currentVersion = workspace.get("updated_at");
    if (
      Buffer.isBuffer(currentVersion) && Buffer.isBuffer(workspaceVersion)
        ? !currentVersion.equals(workspaceVersion)
        : currentVersion !== workspaceVersion
    )
      throw new WorkbenchValidationError(
        "Codex Security setup changed while the scan was starting. Try again.",
      );
    const current = requireRemediationTarget(target),
      currentMetadata = filesystemIdentity(current);
    if (
      currentMetadata.dev !== metadata.dev ||
      currentMetadata.ino !== metadata.ino
    )
      throw targetChanged();
    if (
      workspace.get("default_mode") === "deep" &&
      workspace.get("thread_id") !== null &&
      existingDeepScanForTarget(
        connection,
        workspace.get("thread_id") as string,
        target,
        scope,
      ) !== undefined
    )
      throw new WorkbenchValidationError(
        "This Codex thread already has an active Deep Scan for the selected target and scope. Rejoin that scan instead of starting another one.",
      );
    insertRunningScan(connection, {
      scanId,
      workspace,
      target,
      scope,
      diffTarget,
      targetIdentity: identity,
      targetRoot,
      targetSummary: targetSummary as string | null,
      scopeFileCount,
      timestamp,
      model: args.model,
      reasoningEffort: args.reasoningEffort,
    });
    if (managesTransaction) connection.commit();
  } catch (error) {
    if (managesTransaction) connection.rollback();
    throw error;
  }
  return workspaceState(
    connection,
    workspace.get("id") as string,
    resultCallbacks,
  );
}

export function startPromptOnlyScan(
  context: ScanKickoffContext,
  connection: Connection,
  args: PromptScanArguments,
): Record<string, unknown> {
  return startPromptDrivenScan(context, connection, args, false);
}
export function startHeadlessStandardScan(
  context: ScanKickoffContext,
  connection: Connection,
  args: PromptScanArguments,
): Record<string, unknown> {
  return startPromptDrivenScan(context, connection, args, true);
}
function startPromptDrivenScan(
  context: ScanKickoffContext,
  connection: Connection,
  args: PromptScanArguments,
  headlessStandard: boolean,
): Record<string, unknown> {
  const threadId = optionalText(args.threadId, 512);
  if (threadId === null)
    throw new WorkbenchValidationError("thread-id is required.");
  const inspected = inspectSetupValues(
      args.targetPath,
      args.scope,
      args.mode,
      args.diffTargetKind,
      args.diffBaseRevision,
      args.diffHeadRevision,
      args.diffContentDigest,
    ),
    target = parsedPath(inspected.target.targetPath),
    scope = inspected.scope,
    diffTarget = inspected.diffTarget,
    userContext = userContextArgument(args, () => context.stdin());
  let targetSummary = optionalText(args.targetSummary, 2400);
  if (diffTarget !== null && !targetSummary)
    targetSummary = diffTargetSummary(diffTarget);
  const scopeFileCount = directorySnapshotRegularFileCount(
      scope === "." ? target : appendPath(target, scope),
    ),
    diffIdentity = scanDiffIdentity(diffTarget),
    identity = scanTargetIdentity(target, diffTarget),
    targetRoot = scanTargetRoot(args.scanRoot, target);
  connection.prepare("BEGIN IMMEDIATE").run();
  let scanId: string;
  try {
    const current = requireRemediationTarget(target),
      currentDiff =
        args.mode === "diff"
          ? requireDiffTarget(
              current,
              args.diffTargetKind,
              args.diffBaseRevision,
              args.diffHeadRevision,
              args.diffContentDigest,
            )
          : null;
    if (
      scanTargetIdentity(current, currentDiff).some(
        (value, index) => value !== identity[index],
      ) ||
      scanDiffIdentity(currentDiff).some(
        (value, index) => value !== diffIdentity[index],
      )
    )
      throw targetChanged();
    const existing = connection
      .prepare(
        `
      SELECT scans.* FROM scans
      JOIN workspaces ON workspaces.active_scan_id = scans.id
      WHERE workspaces.thread_id = ? AND workspaces.target_path = ?
          AND workspaces.default_scope = ? AND workspaces.default_mode = ?
          AND workspaces.user_context IS ? AND workspaces.target_summary IS ?
          AND workspaces.diff_target_kind IS ? AND workspaces.diff_base_revision IS ?
          AND workspaces.diff_head_revision IS ? AND workspaces.diff_content_digest IS ?
          AND workspaces.submitted = 1 AND scans.target_revision = ?
          AND scans.target_snapshot_digest IS ? AND scans.target_device = ?
          AND scans.target_inode = ? AND scans.status = 'running'
          AND scans.handoff_status = 'delivered'
          AND ((? = 0 AND scans.handoff_claim_token IS NULL) OR (
              ? = 1 AND scans.handoff_claim_token IS NOT NULL
              AND scans.continuation_thread_id = ?))
      ORDER BY scans.updated_at DESC, scans.started_at DESC, scans.id LIMIT 1
    `,
      )
      .get([
        threadId,
        target,
        scope,
        args.mode,
        userContext,
        targetSummary,
        ...diffIdentity,
        ...identity,
        BigInt(headlessStandard),
        BigInt(headlessStandard),
        threadId,
      ]);
    if (existing !== undefined) {
      connection.commit();
      return {
        ...scanContext(
          connection,
          existing.get("id") as string,
          resultCallbacks,
        ),
        startDisposition: "joined",
      };
    }
    mkdir(targetRoot);
    const workspaceId = context.uuid();
    scanId = context.uuid();
    const timestamp = context.now(),
      targetId = ensureSecurityTarget(connection, target, () => context.now());
    connection
      .prepare(
        `
      INSERT INTO workspaces (
        id, thread_id, target_id, target_path, target_title, target_summary, default_scope,
        default_mode, user_context, diff_target_kind, diff_base_revision,
        diff_head_revision, diff_content_digest, submitted, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `,
      )
      .run([
        workspaceId,
        threadId,
        targetId,
        target,
        basename(target),
        targetSummary,
        scope,
        args.mode,
        userContext,
        ...diffIdentity,
        timestamp,
        timestamp,
      ]);
    const workspace = requireWorkspace(connection, workspaceId);
    insertRunningScan(connection, {
      scanId,
      workspace,
      target,
      scope,
      diffTarget,
      targetIdentity: identity,
      targetRoot,
      targetSummary,
      scopeFileCount,
      timestamp,
      handoffStatus: "delivered",
      model: args.model,
      reasoningEffort: args.reasoningEffort,
    });
    if (headlessStandard) {
      const claimed = connection
        .prepare(
          `
        UPDATE scans
        SET handoff_claim_token = ?, continuation_thread_id = ?
        WHERE id = ? AND status = 'running' AND handoff_status = 'delivered'
          AND handoff_claim_token IS NULL AND continuation_thread_id IS NULL
      `,
        )
        .run([context.uuid(), threadId, scanId]);
      if (claimed.rowcount !== 1n)
        throw new WorkbenchValidationError(
          "Codex Security headless scan ownership could not be recorded.",
        );
    }
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return {
    ...scanContext(connection, scanId, resultCallbacks),
    startDisposition: "created",
  };
}
