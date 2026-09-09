import { randomUUID } from "node:crypto";
import type { Row } from "../../../native/sqlite.mjs";
import { processBinding, sqliteBinding } from "../native";
import { connect } from "../workbench-db";
import { setFindingTriage } from "../workbench-finding-triage";
import {
  cancelFindingRemediationRequest,
  requireRemediationAvailable,
} from "../workbench-remediation";
import {
  requireMatchingPatchDigest,
  requireRemediationCheckoutUnchanged,
} from "../workbench-remediation-guards";
import {
  claimFindingRemediationResend,
  markFindingRemediationDelivered,
  releaseFindingRemediationClaim,
  requestFindingRemediation,
  requestFindingRemediationAction,
} from "../workbench-remediation-requests";
import { setFindingRemediation } from "../workbench-remediation-state";
import { requireReviewedPatchApplied } from "../workbench-reviewed-patch";
import { resultCallbacks, scanContext } from "../workbench-results";
import { WorkbenchValidationError } from "../workbench-validation";
import { stringifyJson } from "./python-json";
import { print } from "./rank-worklists";
import { timestamp } from "./utc-timestamp";
import {
  parseWorkbenchCommandArguments,
  type WorkbenchCommandSpecification,
} from "./workbench-command-arguments";

type Command =
  | "set-finding-triage"
  | "request-finding-remediation"
  | "request-finding-remediation-action"
  | "claim-finding-remediation-resend"
  | "mark-finding-remediation-delivered"
  | "release-finding-remediation-claim"
  | "cancel-finding-remediation-request"
  | "set-finding-remediation";
const request = ["occurrence-id", "request-id", "action-token"];
const specifications: Record<Command, WorkbenchCommandSpecification> = {
  "set-finding-triage": {
    required: ["occurrence-id", "status"],
    options: {
      status: ["open", "closed"],
      "close-reason": ["already_fixed", "wont_fix", "false_positive"],
      note: undefined,
    },
  },
  "request-finding-remediation": { required: request, options: {} },
  "request-finding-remediation-action": {
    required: [
      "occurrence-id",
      "request-id",
      "expected-version",
      "action",
      "action-token",
    ],
    options: { action: ["apply", "verify"] },
    positiveIntegers: ["expected-version"],
  },
  "claim-finding-remediation-resend": { required: request, options: {} },
  "mark-finding-remediation-delivered": { required: request, options: {} },
  "release-finding-remediation-claim": { required: request, options: {} },
  "cancel-finding-remediation-request": { required: request, options: {} },
  "set-finding-remediation": {
    required: [...request, "expected-version", "state"],
    options: {
      state: ["generated", "applied", "verifying", "verified", "failed"],
      summary: undefined,
      "patch-path": undefined,
      "patch-digest": undefined,
      "base-revision": undefined,
      "verification-summary": undefined,
    },
    positiveIntegers: ["expected-version"],
  },
};
const target = (scan: Row) => ({
  target_path: scan.get("target_path") as string,
  target_inode: scan.get("target_inode"),
  target_revision: scan.get("target_revision") as string,
  scan_dir: scan.get("scan_dir") as string,
});
const digests = (remediation: Row) => ({
  base_revision: remediation.get("base_revision") as string | null,
  base_content_digest: remediation.get("base_content_digest") as string | null,
  applied_content_digest: remediation.get("applied_content_digest") as
    | string
    | null,
  patch_digest: remediation.get("patch_digest") as string | null,
});
export async function workbenchFindingCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const parsed = parseWorkbenchCommandArguments(
    command,
    args,
    specifications[command],
  );
  if (typeof parsed === "number") return parsed;
  const { values } = parsed,
    text = (name: string) => (values[name] as string | undefined) ?? null;
  const nowMicroseconds = () => processBinding().wallClockMicroseconds();
  const now = () => timestamp(nowMicroseconds()).replace("+00:00", "Z");
  try {
    const connection = await connect(sqliteBinding(), now);
    try {
      const context = {
        now,
        nowMicroseconds,
        uuid: randomUUID,
        staleClaimBefore: (seconds = 120n) =>
          timestamp(nowMicroseconds() - seconds * 1_000_000n).replace(
            "+00:00",
            "Z",
          ),
        scanContext: (c: typeof connection, id: string) =>
          scanContext(c, id, resultCallbacks),
        requireMatchingPatchDigest: (scan: Row, path: string, digest: string) =>
          requireMatchingPatchDigest(target(scan), path, digest),
        requireRemediationCheckoutUnchanged: (
          scan: Row,
          remediation: Row,
          options: {
            requireBaseContent: boolean;
            requireAppliedContent: boolean;
          },
        ) =>
          requireRemediationCheckoutUnchanged(
            target(scan),
            digests(remediation),
            options,
          ),
        requireReviewedPatchApplied: (
          scan: Row,
          remediation: Row,
          path: string,
        ) =>
          requireReviewedPatchApplied(target(scan), digests(remediation), path),
      };
      const identity = {
        occurrenceId: text("occurrence-id"),
        requestId: text("request-id")!,
        actionToken: text("action-token")!,
      };
      requireRemediationAvailable(connection, command, identity.occurrenceId);
      let result: unknown;
      switch (command) {
        case "set-finding-triage":
          result = setFindingTriage(context, connection, {
            occurrenceId: identity.occurrenceId,
            status: text("status")!,
            closeReason: text("close-reason"),
            note: text("note"),
          });
          break;
        case "request-finding-remediation":
          result = requestFindingRemediation(context, connection, identity);
          break;
        case "request-finding-remediation-action":
          result = requestFindingRemediationAction(context, connection, {
            ...identity,
            expectedVersion: values["expected-version"] as bigint,
            action: text("action")!,
          });
          break;
        case "claim-finding-remediation-resend":
          result = claimFindingRemediationResend(context, connection, identity);
          break;
        case "mark-finding-remediation-delivered":
          result = markFindingRemediationDelivered(
            context,
            connection,
            identity,
          );
          break;
        case "release-finding-remediation-claim":
          result = releaseFindingRemediationClaim(
            context,
            connection,
            identity,
          );
          break;
        case "cancel-finding-remediation-request":
          result = context.scanContext(
            connection,
            cancelFindingRemediationRequest(
              connection,
              identity,
              nowMicroseconds,
            ),
          );
          break;
        case "set-finding-remediation":
          result = setFindingRemediation(context, connection, {
            ...identity,
            expectedVersion: values["expected-version"] as bigint,
            state: text("state")!,
            summary: text("summary"),
            patchPath: text("patch-path"),
            patchDigest: text("patch-digest"),
            baseRevision: text("base-revision"),
            verificationSummary: text("verification-summary"),
          });
          break;
      }
      print(
        stringifyJson(result, {
          compact: true,
          allowNan: false,
          sortKeys: true,
        }),
      );
      return 0;
    } finally {
      connection.close();
    }
  } catch (error) {
    if (!(error instanceof WorkbenchValidationError)) throw error;
    print(error.message, true);
    return 1;
  }
}
