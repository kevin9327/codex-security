import decimalDigit from "@unicode/unicode-15.0.0/General_Category/Decimal_Number/regex.js";
import type { Connection } from "../../native/sqlite.mjs";
import {
  JsonFloat,
  object,
  parseJson,
  pythonRepr,
  stringifyJson,
} from "./helpers/python-json";
import { encodeUtf8 } from "./helpers/utf8";
import { lowercase } from "./helpers/unicode-case";

export class WorkbenchValidationError extends Error {}

export function normalizedUuid(value: string): string | null {
  const hex = value
    .replaceAll("urn:", "")
    .replaceAll("uuid:", "")
    .replace(/^[{}]+|[{}]+$/gu, "")
    .replaceAll("-", "");
  if (Array.from(hex).length === 32) {
    const normalized = Array.from(hex, (character) => {
      if (!decimalDigit.test(character)) return character;
      const point = character.codePointAt(0)!;
      let first = point;
      while (decimalDigit.test(String.fromCodePoint(first - 1))) first--;
      return String((point - first) % 10);
    })
      .join("")
      .replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
    if (/^\+?(?:0[xX]_?)?[\da-fA-F]+(?:_[\da-fA-F]+)*$/u.test(normalized)) {
      const digits = normalized
        .replace(/^\+/, "")
        .replace(/^0[xX]/u, "")
        .replaceAll("_", "");
      const canonical = BigInt(`0x${digits}`).toString(16).padStart(32, "0");
      return [
        canonical.slice(0, 8),
        canonical.slice(8, 12),
        canonical.slice(12, 16),
        canonical.slice(16, 20),
        canonical.slice(20),
      ].join("-");
    }
  }
  return null;
}

export function requireUuid(value: string, label: string): string {
  const canonical = normalizedUuid(value);
  if (canonical === null)
    throw new WorkbenchValidationError(`${label} must be a UUID.`);
  return canonical;
}

export function optionalText(
  value: string | null | undefined,
  maximum?: number | null,
): string | null {
  if (value == null) return null;
  const normalized = value.replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );
  if (maximum != null && Array.from(normalized).length > maximum)
    throw new WorkbenchValidationError(
      `Text value must be no longer than ${maximum} characters.`,
    );
  return normalized || null;
}

export function sqliteBusy(error: Error): boolean {
  return /locked|busy/u.test(lowercase(error.message));
}

export function pathWithinScope(path: string, scope: string): boolean {
  const parts = (value: string) =>
    value.split("/").filter((part) => part && part !== ".");
  const candidate = parts(path),
    requested = parts(scope);
  if (path.startsWith("/") || candidate.includes("..")) return false;
  if (!requested.length && !scope.startsWith("/")) return true;
  return (
    !scope.startsWith("/") &&
    requested.every((part, index) => candidate[index] === part)
  );
}

export function requireCloseNote(
  closeReason: string | null,
  note: string | null,
): void {
  if (note === null && closeReason === "false_positive")
    throw new WorkbenchValidationError(
      "Explain why this finding is a false positive.",
    );
  if (note === null && closeReason === "wont_fix")
    throw new WorkbenchValidationError(
      "Explain why this finding will not be fixed.",
    );
}

export const userText = (value: string | null | undefined): string | null =>
  optionalText(value);

export function userContextArgument(
  args: { userContext: string | null; userContextStdin?: boolean },
  readStdin: () => string,
): string | null {
  return userText(args.userContextStdin ? readStdin() : args.userContext);
}

export function rejectNonstandardJsonNumber(value: string): never {
  throw new Error(`invalid JSON number ${value}`);
}

export const SCAN_USAGE_TOKEN_KEYS = [
  "inputTokens",
  "cachedInputTokens",
  "cacheWriteInputTokens",
  "outputTokens",
  "reasoningOutputTokens",
  "totalTokens",
] as const;
const legacyTokenKeys = SCAN_USAGE_TOKEN_KEYS.slice(0, 4);
const integer = (value: unknown): value is bigint | number =>
  typeof value === "bigint" ||
  (typeof value === "number" && Number.isInteger(value));
const nonnegativeInteger = (value: unknown) => integer(value) && value >= 0;
const keysWithin = (value: Record<string, unknown>, keys: readonly string[]) =>
  Object.keys(value).every((key) => keys.includes(key));
function validCounts(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  return (
    keys.every((key) => nonnegativeInteger(value[key])) &&
    BigInt(value["cachedInputTokens"] as bigint | number) +
      BigInt(value["cacheWriteInputTokens"] as bigint | number) <=
      BigInt(value["inputTokens"] as bigint | number)
  );
}

function finiteNumber(value: unknown): boolean {
  if (
    !(
      typeof value === "number" ||
      typeof value === "bigint" ||
      value instanceof JsonFloat
    )
  )
    return false;
  const numeric = Number(value instanceof JsonFloat ? value["source"] : value);
  if (typeof value === "bigint" && !Number.isFinite(numeric))
    throw new RangeError("int too large to convert to float");
  return Number.isFinite(numeric) && numeric >= 0;
}

export function validLegacyScanCost(cost: unknown): boolean {
  return (
    object(cost) &&
    typeof cost["model"] === "string" &&
    !!cost["model"] &&
    validCounts(cost, legacyTokenKeys) &&
    finiteNumber(cost["estimatedUsd"])
  );
}

export function validScanTokenCounts(usage: unknown): boolean {
  return (
    object(usage) &&
    Object.keys(usage).length === SCAN_USAGE_TOKEN_KEYS.length &&
    keysWithin(usage, SCAN_USAGE_TOKEN_KEYS) &&
    validCounts(usage, SCAN_USAGE_TOKEN_KEYS)
  );
}

export function validMeasuredScanUsage(usage: unknown): boolean {
  if (!object(usage)) return false;
  const coverage = usage["coverage"] ?? null,
    threadCount = usage["threadCount"];
  if (Array.isArray(coverage) || object(coverage))
    throw new TypeError(
      `unhashable type: '${Array.isArray(coverage) ? "list" : "dict"}'`,
    );
  if (
    !["complete", "partial", "unavailable"].includes(coverage as string) ||
    usage["source"] !== "codex_rollout" ||
    !nonnegativeInteger(threadCount)
  )
    return false;
  const warnings = Object.hasOwn(usage, "warnings") ? usage["warnings"] : [];
  if (
    !Array.isArray(warnings) ||
    warnings.length > 32 ||
    warnings.some(
      (warning) =>
        typeof warning !== "string" ||
        /^[a-z][a-z0-9_]{0,63}/u.exec(warning)?.[0] !== warning,
    ) ||
    new Set(warnings).size !== warnings.length
  )
    return false;
  const commonKeys = ["coverage", "source", "threadCount", "warnings"];
  if (coverage === "unavailable")
    return (
      BigInt(threadCount as bigint | number) === 0n &&
      keysWithin(usage, commonKeys)
    );
  if (
    BigInt(threadCount as bigint | number) === 0n ||
    !keysWithin(usage, [
      ...commonKeys,
      "missingThreadCount",
      ...SCAN_USAGE_TOKEN_KEYS,
    ])
  )
    return false;
  const counts = Object.fromEntries(
    SCAN_USAGE_TOKEN_KEYS.map((key) => [key, usage[key]]),
  );
  if (!validScanTokenCounts(counts)) return false;
  const missing = Object.hasOwn(usage, "missingThreadCount")
    ? usage["missingThreadCount"]
    : 0n;
  if (!nonnegativeInteger(missing)) return false;
  if (
    coverage === "complete" &&
    (warnings.length || BigInt(missing as bigint | number))
  )
    return false;
  if (
    coverage === "partial" &&
    !(warnings.length || BigInt(missing as bigint | number))
  )
    return false;
  return true;
}

export function parseScanCost(value: string | null): string | null {
  if (value === null) return null;
  if (encodeUtf8(value).length > 8192)
    throw new WorkbenchValidationError(
      "Scan cost must be no larger than 8 KiB.",
    );
  let cost: unknown;
  try {
    cost = parseJson(
      value,
      false,
      (source) => {
        if (source.replace(/^-/, "").length > 4300)
          throw new Error("integer exceeds Python's decimal conversion limit");
        return BigInt(source);
      },
      rejectNonstandardJsonNumber,
    );
  } catch (error) {
    if (error instanceof RangeError) throw error;
    throw new WorkbenchValidationError(
      "Scan cost must be a valid JSON object.",
    );
  }
  if (object(cost) && Object.hasOwn(cost, "usage")) {
    if (
      !keysWithin(cost, ["usage", "cost"]) ||
      !validMeasuredScanUsage(cost["usage"]) ||
      (Object.hasOwn(cost, "cost") && !validLegacyScanCost(cost["cost"]))
    )
      throw new WorkbenchValidationError(
        "Scan cost includes invalid measured token usage.",
      );
  } else if (!validLegacyScanCost(cost)) {
    throw new WorkbenchValidationError(
      "Scan cost must include a model, nonnegative token counts, and an estimated USD amount.",
    );
  }
  return stringifyJson(cost, {
    compact: true,
    allowNan: false,
    separators: [",", ":"],
  });
}

export function boundedOutputText(
  value: unknown,
  maximumBytes: number,
): string {
  const encoded = encodeUtf8(
    typeof value === "string" ? value : pythonRepr(value),
  );
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(
    encoded.subarray(0, maximumBytes),
    {
      stream: true,
    },
  );
}

export function requireOccurrence(
  connection: Connection,
  occurrenceId: string | null,
): Record<string, unknown> {
  const normalized = optionalText(occurrenceId, 256);
  if (normalized === null)
    throw new WorkbenchValidationError("occurrence-id is required.");
  const row = connection
    .prepare("SELECT * FROM finding_occurrences WHERE id = ?")
    .get([normalized]);
  if (row === undefined)
    throw new WorkbenchValidationError(
      "Codex Security finding occurrence not found.",
    );
  return row.toObject();
}
