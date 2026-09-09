import type { Connection, Row } from "../../native/sqlite.mjs";
import { requireScan } from "./workbench-records";
import {
  requireRemediationPendingAction,
  requireRemediationTransition,
} from "./workbench-remediation";
import {
  requireMatchingPatchDigest,
  requireRemediationCheckoutUnchanged,
  requireScanRelativeFile,
  requireSha256Digest,
} from "./workbench-remediation-guards";
import {
  requireFindingOpen,
  type RemediationRequestArguments,
} from "./workbench-remediation-requests";
import {
  optionalText,
  requireOccurrence,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export interface RemediationUpdateArguments
  extends RemediationRequestArguments {
  expectedVersion: bigint;
  state: string;
  summary: string | null;
  verificationSummary: string | null;
  patchPath: string | null;
  patchDigest: string | null;
  baseRevision: string | null;
}
export interface WorkbenchRemediationUpdateContext {
  now(): string;
  scanContext(connection: Connection, scanId: string): Record<string, unknown>;
  requireReviewedPatchApplied(
    scan: Row,
    remediation: Row,
    patchPath: string,
  ): string;
}

export function setFindingRemediation(
  context: WorkbenchRemediationUpdateContext,
  connection: Connection,
  args: RemediationUpdateArguments,
): Record<string, unknown> {
  const requestId = requireUuid(args.requestId, "request-id"),
    actionToken = requireUuid(args.actionToken, "action-token"),
    summary = optionalText(args.summary, 2400),
    verificationSummary = optionalText(args.verificationSummary, 2400);
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
    if (current.get("version") !== args.expectedVersion)
      throw new WorkbenchValidationError(
        "This remediation request changed. Refresh it before recording an update.",
      );
    if (current.get("pending_action_claim_token") === null)
      throw new WorkbenchValidationError(
        "This remediation attempt does not have an owned pending host request.",
      );
    if (current.get("pending_action_claim_token") !== actionToken)
      throw new WorkbenchValidationError(
        "This remediation host request is owned by a different action token.",
      );
    requireRemediationTransition(current.get("state") as string, args.state);
    requireRemediationPendingAction(current, args.state);
    const target = {
      target_path: scan.get("target_path") as string,
      target_inode: scan.get("target_inode"),
      target_revision: scan.get("target_revision") as string,
      scan_dir: scan.get("scan_dir") as string,
    };
    let patchPath = current.get("patch_path") as string | null;
    if (args.patchPath !== null) {
      const requested = requireScanRelativeFile(target, args.patchPath);
      if (patchPath !== null && requested !== patchPath)
        throw new WorkbenchValidationError(
          "A remediation attempt cannot replace its reviewed patch path.",
        );
      patchPath = requested;
    }
    let patchDigest = current.get("patch_digest") as string | null;
    if (args.patchDigest !== null) {
      const requested = requireSha256Digest(args.patchDigest, "patch-digest");
      if (patchDigest !== null && requested !== patchDigest)
        throw new WorkbenchValidationError(
          "A remediation attempt cannot replace its reviewed patch digest.",
        );
      patchDigest = requested;
    }
    const baseRevision = optionalText(args.baseRevision, 512);
    if (
      ["generated", "applied", "verifying", "verified"].includes(args.state)
    ) {
      if (patchPath === null || patchDigest === null)
        throw new WorkbenchValidationError(
          "Generated remediation states require a scan-local patch path and digest.",
        );
      requireMatchingPatchDigest(target, patchPath, patchDigest);
    }
    const digests = {
      base_revision: current.get("base_revision") as string | null,
      base_content_digest: current.get("base_content_digest") as string | null,
      applied_content_digest: current.get("applied_content_digest") as
        | string
        | null,
    };
    if (args.state === "generated")
      requireRemediationCheckoutUnchanged(target, digests, {
        requireBaseContent: true,
      });
    if (["applied", "verifying", "verified"].includes(args.state)) {
      if (baseRevision !== current.get("base_revision"))
        throw new WorkbenchValidationError(
          "The remediation base revision changed. Regenerate the patch before applying it.",
        );
      if (args.state === "verifying" || args.state === "verified")
        requireRemediationCheckoutUnchanged(target, digests, {
          requireAppliedContent: true,
        });
    }
    if (args.state === "verified" && verificationSummary === null)
      throw new WorkbenchValidationError(
        "Verified remediation requires a verification summary.",
      );
    let appliedContentDigest = current.get("applied_content_digest");
    if (args.state === "applied")
      appliedContentDigest = context.requireReviewedPatchApplied(
        scan,
        current,
        patchPath!,
      );
    connection.prepare("BEGIN IMMEDIATE").run();
    const timestamp = context.now();
    occurrence = requireOccurrence(connection, args.occurrenceId);
    requireFindingOpen(connection, occurrence.get("id") as string);
    const replaceFailureSummary =
      current.get("state") === "failed" && args.state !== "failed";
    const updated = connection
      .prepare(
        `
      UPDATE finding_remediation_attempts
      SET state = ?, version = version + 1, patch_path = ?, patch_digest = ?,
          applied_content_digest = ?,
          pending_action = CASE
              WHEN ? IN ('verifying', 'failed') THEN pending_action ELSE NULL
          END,
          pending_action_claimed_at = CASE
              WHEN ? = 'verifying' THEN pending_action_claimed_at ELSE NULL
          END,
          pending_action_claim_token = CASE
              WHEN ? = 'verifying' THEN pending_action_claim_token ELSE NULL
          END,
          pending_action_delivered_at = CASE
              WHEN ? = 'verifying' THEN pending_action_delivered_at ELSE NULL
          END,
          summary = CASE WHEN ? THEN ? ELSE COALESCE(?, summary) END,
          verification_summary = COALESCE(?, verification_summary),
          updated_at = ?
      WHERE request_id = ? AND occurrence_id = ? AND version = ?
          AND pending_action_claim_token = ?
    `,
      )
      .run([
        args.state,
        patchPath,
        patchDigest,
        appliedContentDigest,
        args.state,
        args.state,
        args.state,
        args.state,
        replaceFailureSummary ? 1n : 0n,
        summary,
        summary,
        verificationSummary,
        timestamp,
        requestId,
        occurrence.get("id"),
        args.expectedVersion,
        actionToken,
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
