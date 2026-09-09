import type { Connection, Row } from "../../native/sqlite.mjs";
import { jsonItem } from "./helpers/python-json";
import { requireScan } from "./workbench-records";
import { remediationClaimIsActive } from "./workbench-remediation";
import { remediationCheckoutSnapshot } from "./workbench-target";
import {
  requireOccurrence,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export interface RemediationRequestArguments {
  occurrenceId: string | null;
  requestId: string;
  actionToken: string;
}
export interface RemediationActionArguments
  extends RemediationRequestArguments {
  action: string;
  expectedVersion: bigint;
}
export interface WorkbenchRemediationRequestContext {
  now(): string;
  nowMicroseconds(): bigint;
  staleClaimBefore(seconds?: bigint): string;
  scanContext(connection: Connection, scanId: string): Record<string, unknown>;
  requireMatchingPatchDigest(scan: Row, path: string, digest: string): void;
  requireRemediationCheckoutUnchanged(
    scan: Row,
    remediation: Row,
    options: { requireBaseContent: boolean; requireAppliedContent: boolean },
  ): void;
}
type RenderingContext = Pick<
  WorkbenchRemediationRequestContext,
  "now" | "scanContext"
>;

export function requireFindingOpen(
  connection: Connection,
  occurrenceId: string,
): void {
  const triage = connection
    .prepare("SELECT status FROM finding_triage WHERE occurrence_id = ?")
    .get([occurrenceId]);
  if (triage?.get("status") === "closed")
    throw new WorkbenchValidationError(
      "Reopen this finding before requesting remediation.",
    );
}

export function requestFindingRemediation(
  context: RenderingContext &
    Pick<WorkbenchRemediationRequestContext, "nowMicroseconds">,
  connection: Connection,
  args: RemediationRequestArguments,
): Record<string, unknown> {
  const requestId = requireUuid(args.requestId, "request-id"),
    actionToken = requireUuid(args.actionToken, "action-token");
  let occurrence: Row;
  try {
    occurrence = requireOccurrence(connection, args.occurrenceId);
    requireFindingOpen(connection, occurrence.get("id") as string);
    const scan = requireScan(connection, occurrence.get("scan_id") as string);
    let existing = connection
      .prepare(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
      )
      .get([requestId]);
    if (existing !== undefined) {
      if (existing.get("occurrence_id") !== occurrence.get("id"))
        throw new WorkbenchValidationError(
          "This remediation request belongs to a different finding.",
        );
      return context.scanContext(
        connection,
        occurrence.get("scan_id") as string,
      );
    }
    const [baseRevision, baseContentDigest] = remediationCheckoutSnapshot({
      target_path: scan.get("target_path") as string,
      target_inode: scan.get("target_inode"),
      target_revision: scan.get("target_revision") as string,
      scan_dir: scan.get("scan_dir") as string,
    });
    connection.prepare("BEGIN IMMEDIATE").run();
    const timestamp = context.now();
    occurrence = requireOccurrence(connection, args.occurrenceId);
    requireFindingOpen(connection, occurrence.get("id") as string);
    existing = connection
      .prepare(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
      )
      .get([requestId]);
    if (existing !== undefined) {
      if (existing.get("occurrence_id") !== occurrence.get("id"))
        throw new WorkbenchValidationError(
          "This remediation request belongs to a different finding.",
        );
      connection.commit();
      return context.scanContext(
        connection,
        occurrence.get("scan_id") as string,
      );
    }
    const latest = connection
      .prepare(
        `
        SELECT *
        FROM finding_remediation_attempts
        WHERE occurrence_id = ?
        ORDER BY created_at DESC, rowid DESC
        LIMIT 1
      `,
      )
      .get([occurrence.get("id")]);
    if (latest !== undefined) {
      const state = latest.get("state"),
        activeOperation =
          latest.get("pending_action") !== null ||
          state === "requested" ||
          state === "verifying";
      if (
        activeOperation &&
        (state !== "failed" ||
          remediationClaimIsActive(latest, () => context.nowMicroseconds()))
      )
        throw new WorkbenchValidationError(
          "Finish or retry the active remediation operation before regenerating.",
        );
      if (state === "failed" && latest.get("pending_action") !== null)
        connection
          .prepare(
            `
            UPDATE finding_remediation_attempts
            SET pending_action = NULL, pending_action_claimed_at = NULL,
                pending_action_claim_token = NULL,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ?
          `,
          )
          .run([timestamp, latest.get("request_id")]);
      if (state === "generated" || state === "applied")
        connection
          .prepare(
            `
            UPDATE finding_remediation_attempts
            SET state = 'superseded', version = version + 1,
                pending_action = NULL, pending_action_claimed_at = NULL,
                pending_action_claim_token = NULL,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ?
          `,
          )
          .run([timestamp, latest.get("request_id")]);
    }
    connection
      .prepare(
        `
        INSERT INTO finding_remediation_attempts (
            request_id, occurrence_id, state, version, base_revision,
            base_content_digest, pending_action, pending_action_claimed_at,
            pending_action_claim_token, created_at, updated_at
        ) VALUES (?, ?, 'requested', 1, ?, ?, 'generate', ?, ?, ?, ?)
      `,
      )
      .run([
        requestId,
        occurrence.get("id"),
        baseRevision,
        baseContentDigest,
        timestamp,
        actionToken,
        timestamp,
        timestamp,
      ]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return context.scanContext(connection, occurrence.get("scan_id") as string);
}

export function requestFindingRemediationAction(
  context: RenderingContext &
    Pick<
      WorkbenchRemediationRequestContext,
      "requireMatchingPatchDigest" | "requireRemediationCheckoutUnchanged"
    >,
  connection: Connection,
  args: RemediationActionArguments,
): Record<string, unknown> {
  const requestId = requireUuid(args.requestId, "request-id"),
    actionToken = requireUuid(args.actionToken, "action-token");
  let occurrence: Row;
  try {
    occurrence = requireOccurrence(connection, args.occurrenceId);
    requireFindingOpen(connection, occurrence.get("id") as string);
    const scan = requireScan(connection, occurrence.get("scan_id") as string),
      current = connection
        .prepare(
          "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
        )
        .get([requestId]);
    if (
      current === undefined ||
      current.get("occurrence_id") !== occurrence.get("id")
    )
      throw new WorkbenchValidationError(
        "Codex Security finding remediation request not found.",
      );
    if (current.get("pending_action") !== null) {
      if (
        current.get("pending_action") === args.action &&
        current.get("pending_action_claim_token") === actionToken
      ) {
        connection.commit();
        return context.scanContext(
          connection,
          occurrence.get("scan_id") as string,
        );
      }
      throw new WorkbenchValidationError(
        "Another remediation operation is already pending.",
      );
    }
    if (current.get("version") !== args.expectedVersion)
      throw new WorkbenchValidationError(
        "This remediation request changed. Refresh it before recording an update.",
      );
    const requiredState = jsonItem(
      { apply: "generated", verify: "applied" },
      args.action,
    );
    if (current.get("state") !== requiredState)
      throw new WorkbenchValidationError(
        `Finding remediation cannot request ${args.action} from ${current.get("state")}.`,
      );
    if (
      current.get("patch_path") === null ||
      current.get("patch_digest") === null
    )
      throw new WorkbenchValidationError(
        "Generated remediation states require a scan-local patch path and digest.",
      );
    context.requireMatchingPatchDigest(
      scan,
      current.get("patch_path") as string,
      current.get("patch_digest") as string,
    );
    context.requireRemediationCheckoutUnchanged(scan, current, {
      requireBaseContent: args.action === "apply",
      requireAppliedContent: args.action === "verify",
    });
    connection.prepare("BEGIN IMMEDIATE").run();
    const timestamp = context.now();
    occurrence = requireOccurrence(connection, args.occurrenceId);
    requireFindingOpen(connection, occurrence.get("id") as string);
    const updated = connection
      .prepare(
        `
        UPDATE finding_remediation_attempts
        SET pending_action = ?, pending_action_claimed_at = ?,
            pending_action_claim_token = ?, pending_action_delivered_at = NULL,
            version = version + 1, updated_at = ?
        WHERE request_id = ? AND occurrence_id = ? AND version = ? AND pending_action IS NULL
      `,
      )
      .run([
        args.action,
        timestamp,
        actionToken,
        timestamp,
        requestId,
        occurrence.get("id"),
        args.expectedVersion,
      ]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "This remediation request changed. Refresh it before recording an update.",
      );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return context.scanContext(connection, occurrence.get("scan_id") as string);
}

export function claimFindingRemediationResend(
  context: RenderingContext &
    Pick<WorkbenchRemediationRequestContext, "staleClaimBefore">,
  connection: Connection,
  args: RemediationRequestArguments,
): Record<string, unknown> {
  const requestId = requireUuid(args.requestId, "request-id"),
    actionToken = requireUuid(args.actionToken, "action-token");
  connection.prepare("BEGIN IMMEDIATE").run();
  let occurrence: Row;
  try {
    const timestamp = context.now();
    occurrence = requireOccurrence(connection, args.occurrenceId);
    requireFindingOpen(connection, occurrence.get("id") as string);
    const current = connection
      .prepare(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
      )
      .get([requestId]);
    if (
      current === undefined ||
      current.get("occurrence_id") !== occurrence.get("id")
    )
      throw new WorkbenchValidationError(
        "Codex Security finding remediation request not found.",
      );
    if (current.get("pending_action") === null)
      throw new WorkbenchValidationError(
        "This remediation attempt does not have a pending host request.",
      );
    if (current.get("pending_action_claim_token") === actionToken) {
      connection.commit();
      const result = context.scanContext(
        connection,
        occurrence.get("scan_id") as string,
      );
      result["actionToken"] = actionToken;
      return result;
    }
    const delivered = current.get("pending_action_delivered_at") !== null;
    const staleBefore = delivered
      ? context.staleClaimBefore(900n)
      : context.staleClaimBefore();
    const updated = delivered
      ? connection
          .prepare(
            `
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?, pending_action_claim_token = ?,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                AND pending_action_claim_token = ? AND pending_action_delivered_at <= ?
          `,
          )
          .run([
            timestamp,
            actionToken,
            timestamp,
            requestId,
            occurrence.get("id"),
            current.get("pending_action_claim_token"),
            staleBefore,
          ])
      : connection
          .prepare(
            `
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?, pending_action_claim_token = ?,
                pending_action_delivered_at = NULL, updated_at = ?
            WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
                AND (
                    pending_action_claim_token IS NULL
                    OR pending_action_claimed_at IS NULL
                    OR pending_action_claimed_at <= ?
                )
          `,
          )
          .run([
            timestamp,
            actionToken,
            timestamp,
            requestId,
            occurrence.get("id"),
            staleBefore,
          ]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        delivered
          ? "This remediation worker is still within its execution lease. Retry later."
          : "This remediation host request is still owned by another panel. Retry after its lease expires.",
      );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  const result = context.scanContext(
    connection,
    occurrence.get("scan_id") as string,
  );
  result["actionToken"] = actionToken;
  return result;
}

export function markFindingRemediationDelivered(
  context: RenderingContext,
  connection: Connection,
  args: RemediationRequestArguments,
): Record<string, unknown> {
  const requestId = requireUuid(args.requestId, "request-id"),
    actionToken = requireUuid(args.actionToken, "action-token"),
    timestamp = context.now();
  const occurrence = connection.transaction(() => {
    const current = requireOccurrence(connection, args.occurrenceId);
    const updated = connection
      .prepare(
        `
        UPDATE finding_remediation_attempts
        SET pending_action_delivered_at = ?, updated_at = ?
        WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
            AND pending_action_claim_token = ?
      `,
      )
      .run([timestamp, timestamp, requestId, current.get("id"), actionToken]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "This remediation host request is no longer owned by this action token.",
      );
    return current;
  });
  return context.scanContext(connection, occurrence.get("scan_id") as string);
}

export function releaseFindingRemediationClaim(
  context: RenderingContext,
  connection: Connection,
  args: RemediationRequestArguments,
): Record<string, unknown> {
  const requestId = requireUuid(args.requestId, "request-id"),
    actionToken = requireUuid(args.actionToken, "action-token"),
    timestamp = context.now();
  const occurrence = connection.transaction(() => {
    const current = requireOccurrence(connection, args.occurrenceId);
    connection
      .prepare(
        `
        UPDATE finding_remediation_attempts
        SET pending_action_claimed_at = NULL, pending_action_claim_token = NULL,
            pending_action_delivered_at = NULL, updated_at = ?
        WHERE request_id = ? AND occurrence_id = ? AND pending_action IS NOT NULL
            AND pending_action_claim_token = ?
      `,
      )
      .run([timestamp, requestId, current.get("id"), actionToken]);
    return current;
  });
  return context.scanContext(connection, occurrence.get("scan_id") as string);
}
