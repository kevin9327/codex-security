import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { processBinding, sqliteBinding } from "../native";
import { connect } from "../workbench-db";
import { claimDeepScanCoordinator } from "../workbench-deep-coordinator";
import { claimDeepScanDedup } from "../workbench-deep-dedup-claim";
import { commitDeepScanDedup } from "../workbench-deep-dedup-commit";
import {
  failDeepScan,
  recordDeepScanPublicationFailure,
} from "../workbench-deep-failure";
import { finishDeepScan } from "../workbench-deep-finish";
import { beginDeepScan, getDeepScan } from "../workbench-deep-start";
import { upsertDeepScanWorker } from "../workbench-deep-worker";
import { TargetInspectionError } from "../workbench-git-snapshot";
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
  | "begin-deep-scan"
  | "get-deep-scan"
  | "claim-deep-scan-coordinator"
  | "upsert-deep-scan-worker"
  | "claim-deep-scan-dedup"
  | "commit-deep-scan-dedup"
  | "finish-deep-scan"
  | "fail-deep-scan"
  | "record-deep-scan-publication-failure";
const generation = { "coordinator-generation": undefined };
const specifications: Record<Command, WorkbenchCommandSpecification> = {
  "begin-deep-scan": {
    required: ["thread-id"],
    options: {
      "scan-id": undefined,
      "target-path": undefined,
      scope: undefined,
      "user-context": undefined,
      "scan-root": undefined,
      "claim-token": undefined,
      model: undefined,
      "reasoning-effort": undefined,
      "available-parallelism": undefined,
      "workflow-version": undefined,
    },
    flags: ["user-context-stdin"],
    exclusive: [
      { names: ["scan-id", "target-path"], required: true },
      { names: ["user-context", "user-context-stdin"] },
    ],
    positiveIntegers: ["available-parallelism"],
  },
  "get-deep-scan": { required: ["scan-id", "thread-id"], options: {} },
  "claim-deep-scan-coordinator": {
    required: ["scan-id", "thread-id"],
    options: { "claim-token": undefined, ...generation },
    positiveIntegers: ["coordinator-generation"],
  },
  "upsert-deep-scan-worker": {
    required: [
      "scan-id",
      "worker-id",
      "kind",
      "status",
      "prompt-path",
      "artifact-dir",
    ],
    options: {
      kind: ["setup", "discovery", "dedup"],
      status: ["queued", "running", "succeeded", "failed", "canceled"],
      "result-manifest-path": undefined,
      attempt: undefined,
      "sdk-thread-id": undefined,
      "error-message": undefined,
      "replaceable-failure-kind": [
        "policy_refusal",
        "transient_error",
        "invalid_discovery_artifacts",
      ],
      ...generation,
    },
    nonNegativeIntegers: ["attempt"],
    positiveIntegers: ["coordinator-generation"],
  },
  "claim-deep-scan-dedup": {
    required: [
      "scan-id",
      "worker-id",
      "prompt-path",
      "artifact-dir",
      "input-worker-id",
    ],
    options: { ...generation },
    repeated: ["input-worker-id"],
    positiveIntegers: ["coordinator-generation"],
  },
  "commit-deep-scan-dedup": {
    required: [
      "scan-id",
      "worker-id",
      "result-manifest-path",
      "new-findings-count",
    ],
    options: { "candidate-ledger-path": undefined, ...generation },
    nonNegativeIntegers: ["new-findings-count"],
    positiveIntegers: ["coordinator-generation"],
  },
  "finish-deep-scan": {
    required: ["scan-id", "terminal-reason", "manifest-path"],
    options: {
      "terminal-reason": ["saturated", "capped"],
      "staged-manifest-path": undefined,
      "omitted-worker-id": undefined,
      ...generation,
    },
    repeated: ["omitted-worker-id"],
    positiveIntegers: ["coordinator-generation"],
  },
  "fail-deep-scan": {
    required: ["scan-id", "message"],
    options: {
      "manifest-path": undefined,
      "staged-manifest-path": undefined,
      "deep-status": ["failed", "interrupted"],
      ...generation,
    },
    positiveIntegers: ["coordinator-generation"],
  },
  "record-deep-scan-publication-failure": {
    required: ["scan-id", "message"],
    options: generation,
    positiveIntegers: ["coordinator-generation"],
  },
};
export async function workbenchDeepCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const parsed = parseWorkbenchCommandArguments(
    command,
    args,
    specifications[command],
  );
  if (typeof parsed === "number") return parsed;
  const { values, repeated } = parsed;
  const text = (name: string) => (values[name] as string | undefined) ?? null;
  const integer = (name: string) =>
    (values[name] as bigint | undefined) ?? null;
  const context = {
    now: () =>
      timestamp(processBinding().wallClockMicroseconds()).replace(
        "+00:00",
        "Z",
      ),
    uuid: randomUUID,
    stdin: () => decodePosixBytes(readFileSync(0)).replace(/\r\n?/g, "\n"),
  };
  try {
    const connection = await connect(sqliteBinding(), context.now);
    try {
      const identity = {
        scanId: text("scan-id")!,
        coordinatorGeneration: integer("coordinator-generation"),
      };
      let result: unknown;
      switch (command) {
        case "begin-deep-scan":
          result = beginDeepScan(context, connection, {
            threadId: text("thread-id"),
            scanId: text("scan-id"),
            targetPath: text("target-path"),
            scope: text("scope") ?? ".",
            userContext: text("user-context"),
            userContextStdin: values["user-context-stdin"] === true,
            scanRoot: text("scan-root"),
            claimToken: text("claim-token"),
            model: text("model"),
            reasoningEffort: text("reasoning-effort"),
            availableParallelism: integer("available-parallelism"),
            workflowVersion:
              text("workflow-version") ?? "deep-security-scan/v1",
          });
          break;
        case "get-deep-scan":
          result = getDeepScan(context, connection, {
            scanId: identity.scanId,
            threadId: text("thread-id")!,
          });
          break;
        case "claim-deep-scan-coordinator":
          result = claimDeepScanCoordinator(context, connection, {
            ...identity,
            threadId: text("thread-id")!,
            claimToken: text("claim-token"),
          });
          break;
        case "upsert-deep-scan-worker":
          result = upsertDeepScanWorker(context, connection, {
            ...identity,
            workerId: text("worker-id")!,
            kind: text("kind")!,
            status: text("status")!,
            promptPath: text("prompt-path")!,
            artifactDir: text("artifact-dir")!,
            resultManifestPath: text("result-manifest-path"),
            attempt: integer("attempt"),
            sdkThreadId: text("sdk-thread-id"),
            errorMessage: text("error-message"),
            replaceableFailureKind: text("replaceable-failure-kind"),
          });
          break;
        case "claim-deep-scan-dedup":
          result = claimDeepScanDedup(context, connection, {
            ...identity,
            workerId: text("worker-id")!,
            promptPath: text("prompt-path")!,
            artifactDir: text("artifact-dir")!,
            inputWorkerId: repeated["input-worker-id"]!,
          });
          break;
        case "commit-deep-scan-dedup":
          result = commitDeepScanDedup(context, connection, {
            ...identity,
            workerId: text("worker-id")!,
            resultManifestPath: text("result-manifest-path")!,
            candidateLedgerPath: text("candidate-ledger-path"),
            newFindingsCount: integer("new-findings-count")!,
          });
          break;
        case "finish-deep-scan":
          result = finishDeepScan(context, connection, {
            ...identity,
            terminalReason: text("terminal-reason")!,
            manifestPath: text("manifest-path")!,
            stagedManifestPath: text("staged-manifest-path"),
            omittedWorkerId: repeated["omitted-worker-id"] ?? [],
          });
          break;
        case "fail-deep-scan":
          result = failDeepScan(context, connection, {
            ...identity,
            message: text("message"),
            deepStatus: text("deep-status") ?? "failed",
            manifestPath: text("manifest-path"),
            stagedManifestPath: text("staged-manifest-path"),
          });
          break;
        case "record-deep-scan-publication-failure":
          result = recordDeepScanPublicationFailure(context, connection, {
            ...identity,
            message: text("message"),
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
      !(error instanceof TargetInspectionError)
    )
      throw error;
    print(error.message, true);
    return 1;
  }
}
