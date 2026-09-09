import { readFileSync } from "node:fs";
import { processBinding, sqliteBinding } from "../native";
import { connect } from "../workbench-db";
import {
  attachScanContinuationThread,
  claimHandoffDelivery,
  markHandoffDelivered,
  releaseHandoffDelivery,
} from "../workbench-handoff";
import { PHASES, updateContext, updateProgress } from "../workbench-progress";
import { requireScan, requireWorkspace } from "../workbench-records";
import {
  resultCallbacks,
  scanContext,
  workspaceState,
} from "../workbench-results";
import { WorkbenchValidationError } from "../workbench-validation";
import { decodePosixBytes } from "./posix-path";
import { stringifyJson } from "./python-json";
import { print } from "./rank-worklists";
import { timestamp } from "./utc-timestamp";
import {
  parseWorkbenchCommandArguments,
  type WorkbenchCommandSpecification,
} from "./workbench-command-arguments";

type Command =
  | "update-progress"
  | "update-scan-context"
  | "claim-handoff-delivery"
  | "release-handoff-delivery"
  | "attach-scan-continuation-thread"
  | "mark-handoff-delivered";
const handoff = ["scan-id", "claim-token"];
const specifications: Record<Command, WorkbenchCommandSpecification> = {
  "update-progress": {
    required: ["scan-id"],
    options: {
      phase: PHASES,
      "phase-items-total": undefined,
      "phase-items-completed": undefined,
      "phase-progress-unit": [
        "checks",
        "threat_surfaces",
        "review_receipts",
        "candidate_findings",
        "validated_findings",
        "report_artifacts",
      ],
      "preflight-issues-json": undefined,
      "review-items-total": undefined,
      "review-items-completed": undefined,
      "reportable-findings-count": undefined,
      "deep-review-pass": undefined,
      "claim-token": undefined,
      "coordinator-generation": undefined,
      model: undefined,
      "reasoning-effort": undefined,
    },
    flags: ["preflight-issues-json-stdin"],
    exclusive: [
      { names: ["preflight-issues-json", "preflight-issues-json-stdin"] },
    ],
    nonNegativeIntegers: [
      "phase-items-total",
      "phase-items-completed",
      "review-items-total",
      "review-items-completed",
      "reportable-findings-count",
    ],
    positiveIntegers: ["deep-review-pass", "coordinator-generation"],
  },
  "update-scan-context": {
    required: ["scan-id"],
    options: {
      "user-context": undefined,
      "workspace-id": undefined,
      "thread-id": undefined,
      "claim-token": undefined,
    },
    flags: ["user-context-stdin"],
    exclusive: [
      { names: ["user-context", "user-context-stdin"], required: true },
      { names: ["workspace-id", "thread-id"], required: true },
    ],
  },
  "claim-handoff-delivery": {
    required: handoff,
    options: {},
    flags: ["take-over-stale"],
  },
  "release-handoff-delivery": { required: handoff, options: {} },
  "attach-scan-continuation-thread": {
    required: [...handoff, "thread-id"],
    options: {},
  },
  "mark-handoff-delivered": {
    required: handoff,
    options: { "thread-id": undefined },
  },
};
export async function workbenchProgressCommand(
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
    text = (name: string) => (values[name] as string | undefined) ?? null,
    integer = (name: string) => (values[name] as bigint | undefined) ?? null;
  const now = () =>
    timestamp(processBinding().wallClockMicroseconds()).replace("+00:00", "Z");
  try {
    const connection = await connect(sqliteBinding(), now);
    try {
      const callbacks = {
        now,
        readStdin: () =>
          decodePosixBytes(readFileSync(0)).replace(/\r\n?/g, "\n"),
        requireScan,
        requireWorkspace,
        scanContext: (c: typeof connection, id: string) =>
          scanContext(c, id, resultCallbacks),
        workspaceState: (c: typeof connection, id: string) =>
          workspaceState(c, id, resultCallbacks),
        staleClaimBefore: () =>
          timestamp(
            processBinding().wallClockMicroseconds() - 120_000_000n,
          ).replace("+00:00", "Z"),
      };
      const identity = {
        scanId: text("scan-id")!,
        claimToken: text("claim-token")!,
      };
      let result: unknown;
      switch (command) {
        case "update-progress":
          result = updateProgress(
            connection,
            {
              ...identity,
              phase: text("phase"),
              phaseItemsTotal: integer("phase-items-total"),
              phaseItemsCompleted: integer("phase-items-completed"),
              phaseProgressUnit: text("phase-progress-unit"),
              preflightIssuesJson: text("preflight-issues-json"),
              preflightIssuesJsonStdin:
                values["preflight-issues-json-stdin"] === true,
              reviewItemsTotal: integer("review-items-total"),
              reviewItemsCompleted: integer("review-items-completed"),
              reportableFindingsCount: integer("reportable-findings-count"),
              deepReviewPass: integer("deep-review-pass"),
              coordinatorGeneration: integer("coordinator-generation"),
              model: text("model"),
              reasoningEffort: text("reasoning-effort"),
            },
            callbacks,
          );
          break;
        case "update-scan-context":
          result = updateContext(
            connection,
            {
              ...identity,
              workspaceId: text("workspace-id"),
              threadId: text("thread-id"),
              userContext: text("user-context"),
              userContextStdin: values["user-context-stdin"] === true,
            },
            callbacks,
          );
          break;
        case "claim-handoff-delivery":
          result = claimHandoffDelivery(
            connection,
            { ...identity, takeOverStale: values["take-over-stale"] === true },
            callbacks,
          );
          break;
        case "release-handoff-delivery":
          result = releaseHandoffDelivery(connection, identity, callbacks);
          break;
        case "attach-scan-continuation-thread":
          result = attachScanContinuationThread(
            connection,
            { ...identity, threadId: text("thread-id") },
            callbacks,
          );
          break;
        case "mark-handoff-delivered":
          result = markHandoffDelivered(
            connection,
            { ...identity, threadId: text("thread-id") },
            callbacks,
          );
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
