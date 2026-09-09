import { readFileSync } from "node:fs";
import { Row, type SqlValue } from "../../../native/sqlite.mjs";
import { processBinding, sqliteBinding } from "../native";
import { connect, databasePath } from "../workbench-db";
import { exportFindings } from "../workbench-export";
import { findingWorkflow } from "../workbench-finding-workflows";
import { backfillLegacyFindingDetails } from "../workbench-legacy-findings";
import { coverageForComparison } from "../workbench-preserve-saved-results";
import {
  inspectLinearPublication,
  prepareLinearPublication,
  recordLinearPublications,
} from "../workbench-publication";
import {
  resultCallbacks,
  scanResult,
  workspaceState,
} from "../workbench-results";
import {
  compareScans,
  listUnmatchedScanPairs,
  requireScan,
  saveScanComparison,
  type ComparisonScan,
} from "../workbench-scan-comparison";
import { setScanCostLimit } from "../workbench-scan-budget";
import {
  readSeverityClassification,
  severityCheckpoint,
} from "../workbench-severity";
import { WorkbenchValidationError } from "../workbench-validation";
import { decodePosixBytes } from "./posix-path";
import { preflightInteger } from "./preflight-config";
import { parseJson, stringifyJson } from "./python-json";
import { print } from "./rank-worklists";
import { ContractError } from "./scan-contract-errors";
import { timestamp } from "./utc-timestamp";
import {
  parseWorkbenchCommandArguments,
  type WorkbenchCommandSpecification,
} from "./workbench-command-arguments";

type Command =
  | "compare-scans"
  | "list-unmatched-scan-pairs"
  | "save-scan-comparison"
  | "export-findings"
  | "inspect-linear-publication"
  | "prepare-linear-publication"
  | "record-linear-publications"
  | "set-scan-cost-limit"
  | "finding-workflow"
  | "severity-classification"
  | "read-severity-classification";
const pair = ["before-scan-id", "after-scan-id"];
const specifications: Record<Command, WorkbenchCommandSpecification> = {
  "compare-scans": {
    required: pair,
    options: {},
    flags: ["include-matching-inputs", "require-matches"],
  },
  "list-unmatched-scan-pairs": {
    required: ["repository"],
    options: {},
    flags: ["force"],
  },
  "save-scan-comparison": {
    required: pair,
    options: { "matches-json": undefined },
    flags: ["matches-json-stdin"],
    exclusive: [
      { names: ["matches-json", "matches-json-stdin"], required: true },
    ],
    description: "Comparison payload supports related findings.",
  },
  "export-findings": {
    required: ["scan-id", "format"],
    options: { format: ["csv", "json", "sarif"] },
  },
  "inspect-linear-publication": { required: ["input-file"], options: {} },
  "prepare-linear-publication": { required: ["input-file"], options: {} },
  "record-linear-publications": { required: ["input-file"], options: {} },
  "set-scan-cost-limit": {
    required: ["scan-id", "max-cost-usd"],
    options: {},
    floats: ["max-cost-usd"],
  },
  "finding-workflow": { required: [], options: {} },
  "severity-classification": { required: [], options: {} },
  "read-severity-classification": { required: ["scan-id"], options: {} },
};
const row = (scan: ComparisonScan) =>
  new Row(Object.keys(scan), Object.values(scan) as SqlValue[]);
export async function workbenchDataCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const parsed = parseWorkbenchCommandArguments(
    command,
    args,
    specifications[command],
  );
  if (typeof parsed === "number") return parsed;
  const { values, floats } = parsed,
    text = (name: string) => (values[name] as string | undefined) ?? null;
  const now = () =>
    timestamp(processBinding().wallClockMicroseconds()).replace("+00:00", "Z");
  const stdin = () => decodePosixBytes(readFileSync(0)).replace(/\r\n?/g, "\n");
  try {
    let result: unknown;
    if (command === "read-severity-classification")
      result = readSeverityClassification(databasePath(), text("scan-id")!);
    else if (command === "inspect-linear-publication")
      result = inspectLinearPublication(
        { databasePath },
        { inputFile: text("input-file")! },
      );
    else {
      const connection = await connect(sqliteBinding(), now);
      try {
        const callbacks = {
          requireScan,
          readCoverage: (scan: ComparisonScan) =>
            coverageForComparison(row(scan)),
          backfillFindingDetails: (
            c: typeof connection,
            scan: ComparisonScan,
          ) => backfillLegacyFindingDetails(c, row(scan)),
        };
        const identity = {
          beforeScanId: text("before-scan-id")!,
          afterScanId: text("after-scan-id")!,
        };
        switch (command) {
          case "compare-scans":
            result = compareScans(
              connection,
              {
                ...identity,
                includeMatchingInputs:
                  values["include-matching-inputs"] === true,
                requireMatches: values["require-matches"] === true,
              },
              callbacks,
            );
            break;
          case "list-unmatched-scan-pairs":
            result = listUnmatchedScanPairs(
              connection,
              {
                repository: text("repository")!,
                force: values["force"] === true,
              },
              callbacks,
            );
            break;
          case "save-scan-comparison":
            result = saveScanComparison(connection, identity, {
              ...callbacks,
              now,
              readMatches: () =>
                values["matches-json-stdin"] === true
                  ? stdin()
                  : text("matches-json")!,
            });
            break;
          case "export-findings":
            result = exportFindings(
              {
                scanResult: (c, scan) => scanResult(c, scan, resultCallbacks),
                workspaceState: (c, id) =>
                  workspaceState(c, id, resultCallbacks),
              },
              connection,
              { scanId: text("scan-id")!, format: text("format")! },
            );
            break;
          case "prepare-linear-publication":
            result = prepareLinearPublication(connection, {
              inputFile: text("input-file")!,
            });
            break;
          case "record-linear-publications":
            result = recordLinearPublications({ now }, connection, {
              inputFile: text("input-file")!,
            });
            break;
          case "set-scan-cost-limit":
            result = setScanCostLimit({ now }, connection, {
              scanId: text("scan-id")!,
              maxCostUsd: floats["max-cost-usd"]!,
            });
            break;
          case "finding-workflow":
            result = findingWorkflow(
              connection,
              parseJson(stdin(), false, preflightInteger),
              now(),
            );
            break;
          case "severity-classification":
            result = severityCheckpoint(
              connection,
              parseJson(stdin(), false, preflightInteger),
              now(),
            );
            break;
        }
      } finally {
        connection.close();
      }
    }
    print(
      stringifyJson(result, { compact: true, allowNan: false, sortKeys: true }),
    );
    return 0;
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
