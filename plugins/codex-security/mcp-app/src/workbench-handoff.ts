import type { Connection, Row } from "../../native/sqlite.mjs";
import {
  optionalText,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export const RECOVERY_HANDOFF_TOKEN_PREFIX = "recovery_";

export interface HandoffArguments {
  scanId: string;
  claimToken: string;
}
export interface HandoffCallbacks {
  now(): string;
  requireScan(connection: Connection, scanId: string): Row;
  workspaceState(
    connection: Connection,
    workspaceId: string,
  ): Record<string, unknown>;
}

export function requireHandoffClaimToken(value: string): string {
  const recovery = value.startsWith(RECOVERY_HANDOFF_TOKEN_PREFIX);
  const token = recovery
    ? value.slice(RECOVERY_HANDOFF_TOKEN_PREFIX.length)
    : value;
  const normalized = requireUuid(token, "claim-token");
  return recovery
    ? `${RECOVERY_HANDOFF_TOKEN_PREFIX}${normalized}`
    : normalized;
}

export function requireCurrentContinuation(
  scan: Row,
  claimToken: string | null,
  { errorMessage }: { errorMessage: string },
): void {
  if (
    scan.get("handoff_status") === "delivered" &&
    scan.get("handoff_claim_token") === null &&
    claimToken === null
  )
    return;
  if (claimToken === null) throw new WorkbenchValidationError(errorMessage);
  if (scan.get("handoff_claim_token") !== requireHandoffClaimToken(claimToken))
    throw new WorkbenchValidationError(errorMessage);
}

export function validateHandoffDeliveryThread(
  owningThreadId: string | null,
  requestingThreadId: string,
  claimToken: string,
): void {
  if (
    owningThreadId !== requestingThreadId &&
    !claimToken.startsWith(RECOVERY_HANDOFF_TOKEN_PREFIX)
  )
    throw new WorkbenchValidationError(
      "A scan handoff can only be marked delivered from its owning Codex thread.",
    );
}

export function claimHandoffDelivery(
  connection: Connection,
  args: HandoffArguments & { takeOverStale: boolean },
  callbacks: HandoffCallbacks & { staleClaimBefore(): string },
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id");
  const claimToken = requireHandoffClaimToken(args.claimToken);
  const timestamp = callbacks.now();
  let scan!: Row;
  const unchanged = connection.transaction(() => {
    scan = callbacks.requireScan(connection, scanId);
    if (
      scan.get("handoff_status") !== "pending" ||
      scan.get("handoff_claim_token") === claimToken
    )
      return callbacks.workspaceState(
        connection,
        scan.get("workspace_id") as string,
      );
    const updated = connection
      .prepare(
        `
      UPDATE scans
      SET handoff_claimed_at = ?, handoff_claim_token = ?,
          continuation_thread_id = CASE
              WHEN handoff_claim_token IS NULL THEN continuation_thread_id
              ELSE NULL
          END,
          deep_scan_owner_thread_id = CASE
              WHEN handoff_claim_token IS NULL THEN deep_scan_owner_thread_id
              ELSE NULL
          END,
          updated_at = ?
      WHERE id = ? AND handoff_status = 'pending'
          AND (
              handoff_claim_token IS NULL
              OR (
                  ? = 1
                  AND (handoff_claimed_at IS NULL OR handoff_claimed_at <= ?)
              )
          )
    `,
      )
      .run([
        timestamp,
        claimToken,
        timestamp,
        scan.get("id"),
        args.takeOverStale,
        callbacks.staleClaimBefore(),
      ]);
    if (updated.rowcount !== 1n)
      return callbacks.workspaceState(
        connection,
        scan.get("workspace_id") as string,
      );
    return undefined;
  });
  return unchanged === undefined
    ? callbacks.workspaceState(connection, scan.get("workspace_id") as string)
    : unchanged;
}

export function releaseHandoffDelivery(
  connection: Connection,
  args: HandoffArguments,
  callbacks: HandoffCallbacks,
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id");
  const claimToken = requireHandoffClaimToken(args.claimToken);
  const timestamp = callbacks.now();
  let scan!: Row;
  connection.transaction(() => {
    scan = callbacks.requireScan(connection, scanId);
    connection
      .prepare(
        `
      UPDATE scans
      SET handoff_claimed_at = NULL, handoff_claim_token = NULL,
          continuation_thread_id = NULL, deep_scan_owner_thread_id = NULL,
          updated_at = ?
      WHERE id = ? AND handoff_status = 'pending'
          AND handoff_claim_token = ?
    `,
      )
      .run([timestamp, scan.get("id"), claimToken]);
  });
  return callbacks.workspaceState(
    connection,
    scan.get("workspace_id") as string,
  );
}

export function attachScanContinuationThread(
  connection: Connection,
  args: HandoffArguments & { threadId: string | null },
  callbacks: HandoffCallbacks,
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id");
  const claimToken = requireHandoffClaimToken(args.claimToken);
  const threadId = optionalText(args.threadId, 512);
  if (threadId === null)
    throw new WorkbenchValidationError(
      "Codex Security continuation thread ID is required.",
    );
  connection.exec("BEGIN IMMEDIATE");
  let scan: Row;
  try {
    const timestamp = callbacks.now();
    scan = callbacks.requireScan(connection, scanId);
    if (scan.get("handoff_claim_token") !== claimToken)
      throw new WorkbenchValidationError(
        "Codex Security continuation thread claim token does not match.",
      );
    if (scan.get("continuation_thread_id") !== null) {
      if (scan.get("continuation_thread_id") !== threadId)
        throw new WorkbenchValidationError(
          "Codex Security scan continuation is owned by another continuation.",
        );
      connection.commit();
      return callbacks.workspaceState(
        connection,
        scan.get("workspace_id") as string,
      );
    }
    const updated = connection
      .prepare(
        `
      UPDATE scans
      SET continuation_thread_id = ?,
          deep_scan_owner_thread_id = CASE
              WHEN mode = 'deep' THEN ? ELSE deep_scan_owner_thread_id
          END,
          updated_at = ?
      WHERE id = ? AND continuation_thread_id IS NULL
          AND handoff_claim_token = ?
    `,
      )
      .run([threadId, threadId, timestamp, scan.get("id"), claimToken]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Codex Security continuation thread could not be attached.",
      );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return callbacks.workspaceState(
    connection,
    scan.get("workspace_id") as string,
  );
}

export function markHandoffDelivered(
  connection: Connection,
  args: HandoffArguments & { threadId: string | null },
  callbacks: HandoffCallbacks & {
    requireWorkspace(connection: Connection, workspaceId: string): Row;
  },
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id");
  const claimToken = requireHandoffClaimToken(args.claimToken);
  const threadId = optionalText(args.threadId, 512);
  connection.exec("BEGIN IMMEDIATE");
  let scan: Row;
  try {
    const timestamp = callbacks.now();
    scan = callbacks.requireScan(connection, scanId);
    if (threadId !== null) {
      const workspace = callbacks.requireWorkspace(
        connection,
        scan.get("workspace_id") as string,
      );
      validateHandoffDeliveryThread(
        (scan.get("continuation_thread_id") || workspace.get("thread_id")) as
          | string
          | null,
        threadId,
        claimToken,
      );
    }
    if (scan.get("handoff_status") === "delivered") {
      if (scan.get("handoff_claim_token") !== claimToken)
        throw new WorkbenchValidationError(
          "Codex Security handoff delivery is owned by another continuation.",
        );
      connection.commit();
      return callbacks.workspaceState(
        connection,
        scan.get("workspace_id") as string,
      );
    }
    const updated = connection
      .prepare(
        `
      UPDATE scans
      SET handoff_status = 'delivered', handoff_claimed_at = NULL,
          updated_at = ?
      WHERE id = ? AND handoff_status = 'pending'
          AND handoff_claim_token = ?
    `,
      )
      .run([timestamp, scan.get("id"), claimToken]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Codex Security handoff delivery could not be recorded.",
      );
    if (scan.get("mode") !== "deep")
      connection
        .prepare(
          `
        UPDATE scan_progress
        SET phase_items_total = 0, phase_items_completed = 0,
            phase_progress_unit = 'checks',
            preflight_checks_total = 0, preflight_checks_completed = 0,
            updated_at = ?
        WHERE scan_id = ?
      `,
        )
        .run([timestamp, scan.get("id")]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return callbacks.workspaceState(
    connection,
    scan.get("workspace_id") as string,
  );
}
