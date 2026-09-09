import { processBinding, sqliteBinding } from "../native";
import { connect } from "../workbench-db";
import {
  preserveScanResults,
  recoverScanResults,
  writeScanDraft,
} from "../workbench-saved-result-actions";
import { completeBudgetExhaustedScan } from "../workbench-scan-budget";
import { completeScan } from "../workbench-scan-completion";
import { cancelScan, failScan } from "../workbench-scan-stop";
import { WorkbenchValidationError } from "../workbench-validation";
import { stringifyJson } from "./python-json";
import { print } from "./rank-worklists";
import { ContractError } from "./scan-contract-errors";
import { timestamp } from "./utc-timestamp";
import {
  parseWorkbenchCommandArguments,
  type WorkbenchCommandSpecification,
} from "./workbench-command-arguments";

type Command =
  | "prepare-scan-completion"
  | "complete-scan"
  | "complete-budget-exhausted-scan"
  | "cancel-scan"
  | "fail-scan"
  | "preserve-scan-results"
  | "recover-scan-results"
  | "write-scan-draft";
const specifications: Record<Command, WorkbenchCommandSpecification> = {
  "prepare-scan-completion": {
    required: ["scan-id"],
    options: { "claim-token": undefined },
  },
  "complete-scan": {
    required: ["scan-id"],
    options: {
      "claim-token": undefined,
      "cost-json": undefined,
      "thread-id": undefined,
    },
  },
  "complete-budget-exhausted-scan": {
    required: ["scan-id", "cost-json"],
    options: { message: undefined },
  },
  "cancel-scan": { required: ["scan-id"], options: { "thread-id": undefined } },
  "fail-scan": {
    required: ["scan-id", "message"],
    options: { "claim-token": undefined, "cost-json": undefined },
  },
  "preserve-scan-results": {
    required: ["scan-id"],
    options: {
      "thread-id": undefined,
      "claim-token": undefined,
      "coordinator-generation": undefined,
    },
    positiveIntegers: ["coordinator-generation"],
  },
  "recover-scan-results": {
    required: ["scan-id"],
    options: {},
    description:
      "Validate and republish retained checkpoints for a failed, non-canceled scan.",
    optionHelp: { "scan-id": "ID of the stopped scan to recover." },
  },
  "write-scan-draft": {
    required: ["scan-id", "draft-path"],
    options: {
      "checkpoint-path": undefined,
      "expected-draft-digest": undefined,
      "claim-token": undefined,
    },
  },
};
export async function workbenchCompletionCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const parsed = parseWorkbenchCommandArguments(
    command,
    args,
    specifications[command],
  );
  if (typeof parsed === "number") return parsed;
  const { values } = parsed;
  const text = (name: string) => (values[name] as string | undefined) ?? null;
  const context = {
    now: () =>
      timestamp(processBinding().wallClockMicroseconds()).replace(
        "+00:00",
        "Z",
      ),
  };
  try {
    const connection = await connect(sqliteBinding(), context.now);
    try {
      const scanId = text("scan-id")!,
        claimToken = text("claim-token"),
        threadId = text("thread-id"),
        costJson = text("cost-json");
      let result: unknown;
      switch (command) {
        case "prepare-scan-completion":
        case "complete-scan":
          result = completeScan(
            context,
            connection,
            { scanId, claimToken, threadId, costJson },
            command === "prepare-scan-completion",
          );
          break;
        case "complete-budget-exhausted-scan":
          result = completeBudgetExhaustedScan(context, connection, {
            scanId,
            costJson,
            message: text("message"),
          });
          break;
        case "cancel-scan":
          result = cancelScan(context, connection, { scanId, threadId });
          break;
        case "fail-scan":
          result = failScan(context, connection, {
            scanId,
            claimToken,
            costJson,
            message: text("message"),
          });
          break;
        case "preserve-scan-results":
          result = preserveScanResults(context, connection, {
            scanId,
            threadId,
            claimToken,
            coordinatorGeneration:
              (values["coordinator-generation"] as bigint | undefined) ?? null,
          });
          break;
        case "recover-scan-results":
          result = recoverScanResults(context, connection, { scanId });
          break;
        case "write-scan-draft":
          result = writeScanDraft(context, connection, {
            scanId,
            claimToken,
            draftPath: text("draft-path")!,
            checkpointPath: text("checkpoint-path"),
            expectedDraftDigest: text("expected-draft-digest"),
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
    if (
      !(error instanceof WorkbenchValidationError) &&
      !(error instanceof ContractError)
    )
      throw error;
    print(error.message, true);
    return 1;
  }
}
