import { readFile } from "./helper-files";
import { parsedPath } from "./resolve-security-md";
import {
  JsonFloat,
  JsonSyntaxError,
  object,
  objectEntries,
  parseJson,
  parseJsonBytes,
  pythonRepr,
  stringifyJson,
} from "./python-json";
import { ContractError } from "./scan-contract-errors";
import { readScanLocalBytes, writeScanLocalBytes } from "./scan-local-files";
import { decodePythonUtf8, UnicodeDecodeError } from "./utf8";

type JsonObject = Record<string, unknown>;
export class JsonValueError extends Error {}

export function loadsJson(value: string | Buffer): unknown {
  const integer = (source: string): bigint => {
    const digits = source.replace(/^-/, "").length;
    if (digits > 4300)
      throw new JsonValueError(
        `Exceeds the limit (4300 digits) for integer string conversion: value has ${digits} digits; use sys.set_int_max_str_digits() to increase the limit`,
      );
    return BigInt(source);
  };
  const constant = (source: string): never => {
    throw new JsonValueError(
      `non-finite JSON number ${pythonRepr(source)} is not supported`,
    );
  };
  return typeof value === "string"
    ? parseJson(value, false, integer, constant)
    : parseJsonBytes(value, false, integer, constant);
}

function loadUtf8(raw: Buffer, context: string, textFile = false): unknown {
  try {
    const text = decodePythonUtf8(raw);
    return loadsJson(textFile ? text.replace(/\r\n?/gu, "\n") : text);
  } catch (error) {
    if (
      error instanceof JsonSyntaxError ||
      error instanceof JsonValueError ||
      error instanceof UnicodeDecodeError
    )
      throw new ContractError(`${context}: invalid JSON: ${error.message}`);
    throw error;
  }
}

export function readJson(path: string): JsonObject {
  path = parsedPath(path);
  let raw: Buffer;
  try {
    raw = readFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      throw new ContractError(`missing required contract artifact: ${path}`);
    throw error;
  }
  const payload = loadUtf8(raw, path, true);
  requireSafeJsonValue(payload, path);
  if (!object(payload))
    throw new ContractError(`${path}: expected a JSON object`);
  return payload;
}

export function requireSafeJsonString(value: string, context: string): void {
  if (/[\ud800-\udfff]/u.test(value))
    throw new ContractError(
      `${context}: expected well-formed Unicode JSON strings`,
    );
}

export function requireSafeJsonValue(
  value: unknown,
  context: string,
  validateStrings = true,
): void {
  if (object(value)) {
    for (const [key, child] of objectEntries(value)) {
      if (validateStrings) requireSafeJsonString(key, context);
      requireSafeJsonValue(child, `${context}.<property>`, validateStrings);
    }
  } else if (Array.isArray(value)) {
    let index = 0;
    for (const child of value)
      requireSafeJsonValue(child, `${context}[${index++}]`, validateStrings);
  } else if (typeof value === "string" && validateStrings) {
    requireSafeJsonString(value, context);
  } else {
    const number = value instanceof JsonFloat ? Number(value.source) : value;
    if (typeof number === "number" && !Number.isFinite(number))
      throw new ContractError(
        `${context}: non-finite JSON numbers are not supported`,
      );
    if (
      (typeof number === "bigint" ||
        (typeof number === "number" && Number.isInteger(number))) &&
      (number > 9007199254740991n || number < -9007199254740991n)
    )
      throw new ContractError(
        `${context}: unsafe integer-valued JSON numbers are not supported`,
      );
  }
}

export function jsonBytes(payload: unknown): Buffer {
  let encoded: string;
  try {
    encoded = stringifyJson(payload, { allowNan: false, sortKeys: true });
  } catch (error) {
    if (
      error instanceof Error &&
      !(error instanceof TypeError) &&
      !(error instanceof RangeError)
    )
      throw new ContractError(`cannot encode canonical JSON: ${error.message}`);
    throw error;
  }
  return Buffer.from(encoded + "\n", "utf8");
}

export function contractJsonBytes(relative: string, payload: unknown): Buffer {
  requireSafeJsonValue(payload, relative);
  return jsonBytes(payload);
}

export function readScanLocalJsonBytes(
  scanDir: string,
  relative: string,
  context: string,
): [JsonObject, Buffer] {
  const raw = readScanLocalBytes(scanDir, relative, context);
  const payload = loadUtf8(raw, context);
  if (!object(payload))
    throw new ContractError(`${context}: expected a JSON object`);
  requireSafeJsonValue(payload, context, false);
  return [payload, raw];
}

export function readScanLocalJson(
  scanDir: string,
  relative: string,
  context: string,
): JsonObject {
  return readScanLocalJsonBytes(scanDir, relative, context)[0];
}

export function writeScanLocalJson(
  scanDir: string,
  relative: string,
  payload: unknown,
): void {
  writeScanLocalBytes(scanDir, relative, contractJsonBytes(relative, payload));
}
