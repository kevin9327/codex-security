import type { Connection, Row } from "../../native/sqlite.mjs";
import { parsePythonDateTime } from "./helpers/python-date-time";
import { jsonItem } from "./helpers/python-json";
import { timestamp } from "./helpers/utc-timestamp";
import { requireScan } from "./workbench-records";
import {
  requireOccurrence,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export const REMEDIATION_COMMANDS = new Set([
  "request-finding-remediation",
  "request-finding-remediation-action",
  "claim-finding-remediation-resend",
  "mark-finding-remediation-delivered",
  "release-finding-remediation-claim",
  "cancel-finding-remediation-request",
  "set-finding-remediation",
]);
const claimLeaseSeconds = 120n,
  deliveredActionLeaseSeconds = 900n;

export function requireRemediationAvailable(
  connection: Connection,
  command: string,
  occurrenceId: string | null,
  scanForId: typeof requireScan = requireScan,
): void {
  if (!REMEDIATION_COMMANDS.has(command)) return;
  const occurrence = requireOccurrence(connection, occurrenceId);
  if (
    scanForId(connection, occurrence.get("scan_id") as string).get("status") !==
    "complete"
  )
    throw new WorkbenchValidationError(
      "Remediation is available only for successfully completed scans.",
    );
}

export function remediationClaimIsActive(
  remediation: Row,
  now: () => bigint,
): boolean {
  if (remediation.get("pending_action_claim_token") === null) return false;
  const deliveredAt = remediation.get("pending_action_delivered_at");
  const delivered = Buffer.isBuffer(deliveredAt)
    ? deliveredAt.length > 0
    : Boolean(deliveredAt);
  const claimedAt = delivered
    ? deliveredAt
    : remediation.get("pending_action_claimed_at");
  if (typeof claimedAt !== "string") return true;
  let parsed: ReturnType<typeof parsePythonDateTime>;
  try {
    parsed = parsePythonDateTime(
      claimedAt.endsWith("Z") || claimedAt.endsWith("z")
        ? claimedAt.slice(0, -1) + "+00:00"
        : claimedAt,
    );
    if (!parsed.aware) return true;
  } catch (error) {
    if (error instanceof Error && error.name === "ValueError") return true;
    throw error;
  }
  const seconds = delivered ? deliveredActionLeaseSeconds : claimLeaseSeconds;
  return parsed.microseconds > now() - seconds * 1_000_000n;
}

export function requireRemediationTransition(
  current: string,
  requested: string,
): void {
  const allowed: Record<string, readonly string[]> = {
    requested: ["requested", "generated", "failed"],
    generated: ["generated", "applied", "failed"],
    applied: ["applied", "verifying", "failed"],
    verifying: ["verifying", "verified", "failed"],
    verified: ["verifying", "verified"],
    failed: ["generated", "applied", "verifying", "verified", "failed"],
  };
  if (
    !Object.hasOwn(allowed, current) ||
    !allowed[current]!.includes(requested)
  )
    throw new WorkbenchValidationError(
      `Finding remediation cannot move from ${current} to ${requested}.`,
    );
}

export function requireRemediationPendingAction(
  current: Row,
  requested: string,
): void {
  const pending = current.get("pending_action");
  if (pending !== null) {
    const allowed = {
      generate: ["generated", "failed"],
      apply: ["applied", "failed"],
      verify: ["verifying", "verified", "failed"],
    };
    if (!(jsonItem(allowed, pending as string) as string[]).includes(requested))
      throw new WorkbenchValidationError(
        `Pending remediation action ${pending} cannot record state ${requested}.`,
      );
    return;
  }
  const state = current.get("state");
  const required =
    state === "requested" && requested === "generated"
      ? "generate"
      : state === "generated" && requested === "applied"
        ? "apply"
        : state === "applied" && requested === "verifying"
          ? "verify"
          : null;
  if (required !== null)
    throw new WorkbenchValidationError(
      `Request ${required} before recording remediation state ${requested}.`,
    );
}

export interface CancelRemediationArguments {
  occurrenceId: string | null;
  requestId: string;
  actionToken: string;
}

export function cancelFindingRemediationRequest(
  connection: Connection,
  args: CancelRemediationArguments,
  now: () => bigint,
): string {
  const requestId = requireUuid(args.requestId, "request-id");
  const actionToken = requireUuid(args.actionToken, "action-token");
  connection.prepare("BEGIN IMMEDIATE").run();
  let occurrence: Row;
  try {
    occurrence = requireOccurrence(connection, args.occurrenceId);
    const current = connection
      .prepare(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
      )
      .get([requestId]);
    if (current === undefined) {
      connection.commit();
      return String(occurrence.get("scan_id"));
    }
    if (current.get("occurrence_id") !== occurrence.get("id"))
      throw new WorkbenchValidationError(
        "This remediation request belongs to a different finding.",
      );
    if (current.get("pending_action") === null) {
      connection.commit();
      return String(occurrence.get("scan_id"));
    }
    if (
      current.get("state") === "failed" &&
      current.get("pending_action_claim_token") === null
    ) {
      connection.commit();
      return String(occurrence.get("scan_id"));
    }
    if (current.get("pending_action_claim_token") !== actionToken)
      throw new WorkbenchValidationError(
        "This remediation host request is owned by a different action token.",
      );
    const updatedAt = timestamp(now()).replace("+00:00", "Z");
    if (current.get("state") === "failed") {
      connection
        .prepare(
          `UPDATE finding_remediation_attempts
           SET pending_action_claimed_at = NULL, pending_action_claim_token = NULL,
               pending_action_delivered_at = NULL, updated_at = ?
           WHERE request_id = ? AND pending_action_claim_token = ?`,
        )
        .run([updatedAt, requestId, actionToken]);
    } else if (current.get("pending_action") === "generate") {
      cancelGeneration(
        connection,
        occurrence.get("id") as string,
        requestId,
        updatedAt,
        current.get("state") as string,
      );
      connection
        .prepare("UPDATE scans SET updated_at = ? WHERE id = ?")
        .run([updatedAt, occurrence.get("scan_id")]);
    } else {
      connection
        .prepare(
          `UPDATE finding_remediation_attempts
           SET pending_action = NULL, pending_action_claimed_at = NULL,
               pending_action_claim_token = NULL, pending_action_delivered_at = NULL,
               version = version + 1, updated_at = ?
           WHERE request_id = ? AND pending_action_claim_token = ?`,
        )
        .run([updatedAt, requestId, actionToken]);
    }
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return String(occurrence.get("scan_id"));
}

function cancelGeneration(
  connection: Connection,
  occurrenceId: string,
  requestId: string,
  updatedAt: string,
  state: string,
): void {
  if (state !== "requested")
    throw new WorkbenchValidationError(
      "Only a requested patch generation can be canceled.",
    );
  connection
    .prepare("DELETE FROM finding_remediation_attempts WHERE request_id = ?")
    .run([requestId]);
  const previous = connection
    .prepare(
      `SELECT * FROM finding_remediation_attempts
       WHERE occurrence_id = ?
       ORDER BY created_at DESC, rowid DESC
       LIMIT 1`,
    )
    .get([occurrenceId]);
  if (previous === undefined || previous.get("state") !== "superseded") return;
  const restored =
    previous.get("applied_content_digest") !== null ? "applied" : "generated";
  connection
    .prepare(
      `UPDATE finding_remediation_attempts
       SET state = ?, version = version + 1, updated_at = ?
       WHERE request_id = ? AND state = 'superseded'`,
    )
    .run([restored, updatedAt, previous.get("request_id")]);
}
