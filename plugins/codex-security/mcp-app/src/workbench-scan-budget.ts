import type { Connection } from "../../native/sqlite.mjs";
import { preflightInteger } from "./helpers/preflight-config";
import {
  JsonFloat,
  jsonContains,
  jsonGet,
  jsonItem,
  object,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import {
  budgetExhaustedCandidates,
  budgetExhaustedDraft,
} from "./workbench-budget-exhausted";
import { withScanCompletionLock } from "./workbench-completion-lock";
import {
  rejectNonFiniteJson,
  requireCanonicalScanDirectory,
} from "./workbench-files";
import type { PreservedResultsContext } from "./workbench-preserve-saved-results";
import { requireScan } from "./workbench-records";
import { storedWarningValues } from "./workbench-saved-result-sources";
import { completeScanLocked } from "./workbench-scan-completion";
import {
  optionalText,
  parseScanCost,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export interface BudgetCompletionArguments {
  scanId: string;
  costJson: string | null;
  message?: string | null;
}
export interface SetCostLimitArguments {
  scanId: string;
  maxCostUsd: number;
}
const recipeJson = (value: unknown) =>
  parseJson(
    value as string | Buffer,
    false,
    preflightInteger,
    rejectNonFiniteJson,
  );
const numeric = (value: unknown): value is number | bigint | JsonFloat =>
  typeof value === "number" ||
  typeof value === "bigint" ||
  value instanceof JsonFloat;
const numberValue = (value: number | bigint | JsonFloat): number | bigint =>
  value instanceof JsonFloat ? Number(value.source) : value;

// Python's .6g uses six significant digits with ties rounded to even.
// Round the exact binary value so halfway amounts retain the existing warning.
function estimatedCostText(value: number): string {
  if (value === 0) return Object.is(value, -0) ? "-0" : "0";
  let exponent = Number(value.toExponential().split("e")[1]);
  const bytes = Buffer.alloc(8);
  bytes.writeDoubleBE(value);
  const bits = bytes.readBigUInt64BE(),
    encodedExponent = Number((bits >> 52n) & 0x7ffn),
    mantissa = (bits & ((1n << 52n) - 1n)) | (encodedExponent ? 1n << 52n : 0n),
    binaryExponent = encodedExponent ? encodedExponent - 1075 : -1074;
  let numerator = mantissa,
    denominator = 1n;
  if (binaryExponent >= 0) numerator <<= BigInt(binaryExponent);
  else denominator <<= BigInt(-binaryExponent);
  const scale = 5 - exponent;
  if (scale >= 0) numerator *= 10n ** BigInt(scale);
  else denominator *= 10n ** BigInt(-scale);
  let rounded = numerator / denominator;
  const remainder = numerator % denominator;
  if (
    remainder * 2n > denominator ||
    (remainder * 2n === denominator && rounded % 2n !== 0n)
  )
    rounded++;
  if (rounded === 1000000n) {
    rounded /= 10n;
    exponent++;
  }
  const digits = rounded.toString().padStart(6, "0").replace(/0+$/u, "");
  if (exponent < -4 || exponent >= 6) {
    const fraction = digits.length > 1 ? "." + digits.slice(1) : "";
    return `${digits[0]}${fraction}e${exponent < 0 ? "-" : "+"}${Math.abs(exponent).toString().padStart(2, "0")}`;
  }
  if (exponent < 0) return "0." + "0".repeat(-exponent - 1) + digits;
  const point = exponent + 1;
  return digits.length <= point
    ? digits.padEnd(point, "0")
    : digits.slice(0, point) + "." + digits.slice(point);
}

export function completeBudgetExhaustedScan(
  context: PreservedResultsContext,
  connection: Connection,
  args: BudgetCompletionArguments,
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id"),
    costJson = parseScanCost(args.costJson);
  if (costJson === null)
    throw new WorkbenchValidationError(
      "Budget-exhausted scan completion requires the measured scan cost.",
    );
  return withScanCompletionLock(scanId, () => {
    const scan = requireScan(connection, scanId);
    if (
      scan.get("status") !== "running" ||
      scan.get("mode") !== "deep" ||
      scan.get("recipe_json") === null
    )
      throw new WorkbenchValidationError(
        "Only a running CLI Deep Scan can complete after its cost limit.",
      );
    const recipe = recipeJson(scan.get("recipe_json"));
    if (!object(recipe) || recipe["mode"] !== "deep")
      throw new WorkbenchValidationError(
        "Budget-exhausted scan completion requires a Deep Scan launch recipe.",
      );
    const cost = parseJson(costJson),
      measured = jsonGet(cost, "cost", cost),
      limit = recipe["maxCostUsd"];
    if (
      !numeric(limit) ||
      !object(measured) ||
      numberValue(
        (measured["estimatedUsd"] ?? 0n) as number | bigint | JsonFloat,
      ) <= numberValue(limit)
    )
      throw new WorkbenchValidationError(
        "Deep Scan has not exceeded its configured cost limit.",
      );
    const run = connection
      .prepare(
        "SELECT status, terminal_reason, manifest_path FROM deep_scan_runs WHERE scan_id = ?",
      )
      .get([scanId]);
    if (
      run === undefined ||
      run.get("status") !== "succeeded" ||
      !["saturated", "capped"].includes(run.get("terminal_reason") as string) ||
      !run.get("manifest_path")
    )
      throw new WorkbenchValidationError(
        "Budget-exhausted scan completion requires successfully completed Deep Scan discovery.",
      );
    const scanDir = requireCanonicalScanDirectory(
        parsedPath(scan.get("scan_dir") as string),
      ),
      candidates =
        run.get("manifest_path") === appendPath(scanDir, "scan-manifest.json")
          ? []
          : budgetExhaustedCandidates(scan, scanDir),
      warning =
        optionalText(args.message, 2400) ??
        `Deep Scan reached its cost limit after an estimated $${estimatedCostText(Number(numberValue(jsonItem(measured, "estimatedUsd") as number | bigint | JsonFloat)))}; completed discovery was preserved.`;
    budgetExhaustedDraft(scan, scanDir, candidates, warning);
    const warnings = parseJson(
      scan.get("completion_warnings_json") as string | Buffer,
      false,
      preflightInteger,
    );
    if (!jsonContains(warnings, warning)) {
      connection
        .prepare(
          "UPDATE scans SET completion_warnings_json = ? WHERE id = ? AND status = 'running'",
        )
        .run([
          stringifyJson([...storedWarningValues(warnings, true), warning], {
            compact: true,
          }),
          scanId,
        ]);
      connection.commit();
    }
    return completeScanLocked(context, connection, scanId, null, costJson);
  });
}

export function setScanCostLimit(
  context: PreservedResultsContext,
  connection: Connection,
  args: SetCostLimitArguments,
): { scanId: string; maxCostUsd: number } {
  const scanId = requireUuid(args.scanId, "scan-id"),
    limit = args.maxCostUsd;
  if (!Number.isFinite(limit) || limit <= 0)
    throw new WorkbenchValidationError(
      "The scan cost limit must be a positive finite USD amount.",
    );
  return withScanCompletionLock(scanId, () =>
    connection.transaction(() => {
      const scan = requireScan(connection, scanId);
      if (scan.get("status") !== "running" || scan.get("recipe_json") === null)
        throw new WorkbenchValidationError(
          "Only a running CLI scan can increase its cost limit.",
        );
      const recipe = recipeJson(scan.get("recipe_json")),
        previous = jsonGet(recipe, "maxCostUsd");
      if (!numeric(previous) || limit <= numberValue(previous))
        throw new WorkbenchValidationError(
          "The new cost limit must exceed the current limit.",
        );
      (recipe as Record<string, unknown>)["maxCostUsd"] = new JsonFloat(
        String(limit),
      );
      connection
        .prepare(
          "UPDATE scans SET recipe_json = ?, updated_at = ? WHERE id = ?",
        )
        .run([
          stringifyJson(recipe, { compact: true, allowNan: false }),
          context.now(),
          scan.get("id"),
        ]);
      return { scanId, maxCostUsd: limit };
    }),
  );
}
