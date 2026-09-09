import type { Connection, Row } from "../../native/sqlite.mjs";
import { requireScan } from "./workbench-records";
import { remediationClaimIsActive } from "./workbench-remediation";
import { requireRemediationCheckoutUnchanged } from "./workbench-remediation-guards";
import {
  optionalText,
  requireCloseNote,
  requireOccurrence,
  WorkbenchValidationError,
} from "./workbench-validation";

export interface FindingTriageArguments {
  occurrenceId: string | null;
  status: string;
  closeReason: string | null;
  note: string | null;
}
export interface WorkbenchTriageContext {
  now(): string;
  nowMicroseconds(): bigint;
  uuid(): string;
  scanContext(connection: Connection, scanId: string): Record<string, unknown>;
}

export function setFindingTriage(
  context: WorkbenchTriageContext,
  connection: Connection,
  args: FindingTriageArguments,
): Record<string, unknown> {
  const closeReason = args.closeReason;
  if (args.status === "open" && closeReason !== null)
    throw new WorkbenchValidationError(
      "An open finding cannot keep a close reason.",
    );
  if (args.status === "closed" && closeReason === null)
    throw new WorkbenchValidationError(
      "Choose why this finding is being closed.",
    );
  const note = optionalText(args.note, 2400);
  requireCloseNote(closeReason, note);
  connection.prepare("BEGIN IMMEDIATE").run();
  let occurrence: Row;
  try {
    const timestamp = context.now();
    occurrence = requireOccurrence(connection, args.occurrenceId);
    if (args.status === "closed") {
      const remediation = connection
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
      if (
        remediation !== undefined &&
        remediation.get("pending_action") !== null &&
        !(
          remediation.get("state") === "failed" &&
          !remediationClaimIsActive(remediation, () =>
            context.nowMicroseconds(),
          )
        )
      )
        throw new WorkbenchValidationError(
          "Wait for the pending remediation operation to finish before closing this finding.",
        );
      if (
        closeReason === "already_fixed" &&
        remediation?.get("state") === "verified"
      ) {
        const scan = requireScan(
          connection,
          occurrence.get("scan_id") as string,
        );
        requireRemediationCheckoutUnchanged(
          {
            target_path: scan.get("target_path") as string,
            target_inode: scan.get("target_inode"),
            target_revision: scan.get("target_revision") as string,
            scan_dir: scan.get("scan_dir") as string,
          },
          {
            base_revision: remediation.get("base_revision") as string | null,
            base_content_digest: remediation.get("base_content_digest") as
              | string
              | null,
            applied_content_digest: remediation.get(
              "applied_content_digest",
            ) as string | null,
          },
          { requireAppliedContent: true },
        );
      }
    }
    const previous = connection
      .prepare(
        "SELECT status, close_reason, note FROM finding_triage WHERE occurrence_id = ?",
      )
      .get([occurrence.get("id")]);
    if (
      previous === undefined ||
      previous.get("status") !== args.status ||
      previous.get("close_reason") !== closeReason ||
      previous.get("note") !== note
    )
      connection
        .prepare(
          `
        INSERT INTO finding_decisions (
          id, occurrence_id, status, close_reason, note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `,
        )
        .run([
          context.uuid(),
          occurrence.get("id"),
          args.status,
          closeReason,
          note,
          timestamp,
        ]);
    connection
      .prepare(
        `
      INSERT INTO finding_triage (occurrence_id, status, close_reason, note, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(occurrence_id) DO UPDATE SET
          status = excluded.status,
          close_reason = excluded.close_reason,
          note = excluded.note,
          updated_at = excluded.updated_at
    `,
      )
      .run([occurrence.get("id"), args.status, closeReason, note, timestamp]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return context.scanContext(connection, occurrence.get("scan_id") as string);
}
