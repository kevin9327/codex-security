import { environment } from "./environment";
import { filesystemErrorMessage } from "./file-errors";
import { fileInfo } from "./helper-files";
import { preflightInteger } from "./preflight-config";
import { JsonFloat, object, stringifyJson } from "./python-json";
import { appendPath } from "./rank-selection";
import { ArgumentError, argumentsFor, compare, print } from "./rank-worklists";
import {
  HomeExpansionError,
  expandHome,
  parsedPath,
} from "./resolve-security-md";
import { readToml } from "./toml-file";
import { TomlDecodeError } from "./toml";
import { UnicodeDecodeError } from "./utf8";

export class DeepScanConfigError extends Error {}

export interface DeepScanConfig {
  workers: bigint;
  subagents: bigint;
  stopAfterNoNew: bigint;
  stopAfterConsecutiveErrors: bigint;
  maxDiscoveryRuns: bigint;
  maxTimeHours: bigint | number;
}

const configKeys = new Set([
  "workers",
  "subagents",
  "stop_after_no_new",
  "stop_after_consecutive_errors",
  "max_discovery_runs",
  "max_time_hours",
]);

export function deepScanConfigPath(): string {
  const configured = (
    environment("CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH") ?? ""
  ).replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );
  const home = environment("HOME");
  return configured
    ? expandHome(parsedPath(configured), home)
    : appendPath(
        expandHome(parsedPath(environment("CODEX_HOME") ?? "~/.codex"), home),
        "codex-security/config.toml",
      );
}

function requireInteger(
  value: unknown,
  label: string,
  minimum: bigint,
): bigint {
  if (typeof value !== "bigint" || value < minimum)
    throw new DeepScanConfigError(
      `${label} must be ${minimum === 0n ? "a non-negative integer" : "a positive integer"}.`,
    );
  return value;
}

function requirePositiveNumber(value: unknown): bigint | number {
  const number = value instanceof JsonFloat ? Number(value.source) : value;
  if (
    !(
      (typeof number === "bigint" || typeof number === "number") &&
      (typeof number === "bigint" || Number.isFinite(number)) &&
      number > 0 &&
      number <= 96
    )
  )
    throw new DeepScanConfigError(
      "deep_scan.max_time_hours must be a positive finite number no greater than 96.",
    );
  return number as bigint | number;
}

function parseInteger(source: string): bigint {
  try {
    return preflightInteger(source);
  } catch (error) {
    (error as Error).name = "ValueError";
    throw error;
  }
}

export function resolveDeepScanConfig(
  availableParallelism: bigint | number,
): DeepScanConfig {
  if (typeof availableParallelism === "boolean" || availableParallelism < 1)
    throw new DeepScanConfigError(
      "Available parallelism must be a positive integer.",
    );
  const path = deepScanConfigPath();
  let configured: Record<string, unknown> = {};
  if (fileInfo(path) !== undefined) {
    let document: unknown;
    try {
      document = readToml(path, true, parseInteger);
    } catch (error) {
      if (
        !(error instanceof TomlDecodeError) &&
        (error as { errno?: number }).errno === undefined &&
        (error as { winerror?: number }).winerror === undefined
      )
        throw error;
      throw new DeepScanConfigError(
        `Cannot read Codex Security configuration at ${path}: ${filesystemErrorMessage(error)}`,
      );
    }
    if (!object(document))
      throw new DeepScanConfigError(
        `Codex Security configuration at ${path} must be a TOML table.`,
      );
    const deepScan = Object.hasOwn(document, "deep_scan")
      ? document["deep_scan"]
      : {};
    if (!object(deepScan))
      throw new DeepScanConfigError(
        `Codex Security configuration [deep_scan] at ${path} must be a TOML table.`,
      );
    const unknown = Object.keys(deepScan)
      .filter((key) => !configKeys.has(key))
      .sort(compare);
    if (unknown.length)
      throw new DeepScanConfigError(
        `Unknown Codex Security Deep Scan configuration ${unknown.join(", ")} in ${path}.`,
      );
    configured = deepScan;
  }
  const setting = (key: string, fallback: bigint): unknown =>
    Object.hasOwn(configured, key) ? configured[key] : fallback;
  const workers = setting("workers", 4n);
  const resolvedWorkers =
    workers === "auto" ? 4n : requireInteger(workers, "deep_scan.workers", 1n);
  const stopAfterNoNew = requireInteger(
    setting("stop_after_no_new", 4n),
    "deep_scan.stop_after_no_new",
    1n,
  );
  return {
    workers: resolvedWorkers,
    subagents: requireInteger(
      setting("subagents", 3n),
      "deep_scan.subagents",
      0n,
    ),
    stopAfterNoNew,
    stopAfterConsecutiveErrors: requireInteger(
      setting("stop_after_consecutive_errors", 3n),
      "deep_scan.stop_after_consecutive_errors",
      1n,
    ),
    maxDiscoveryRuns: requireInteger(
      setting("max_discovery_runs", 40n),
      "deep_scan.max_discovery_runs",
      1n,
    ),
    maxTimeHours: requirePositiveNumber(setting("max_time_hours", 96n)),
  };
}

const usage =
  "usage: launch_codex_security_mcp[.cmd] --helper deep-scan-config [-h] --available-parallelism AVAILABLE_PARALLELISM";
export function deepScanConfigCommand(args: string[]): number {
  let options: ReturnType<typeof argumentsFor>;
  try {
    options = argumentsFor(
      args,
      ["available-parallelism"],
      ["available-parallelism"],
    );
    if (options["help"]) {
      print(
        `${usage}\n\nResolve per-user Codex Security Deep Scan orchestration settings.\n\noptions:\n  -h, --help            show this help message and exit\n  --available-parallelism AVAILABLE_PARALLELISM`,
      );
      return 0;
    }
  } catch (error) {
    if (!(error instanceof ArgumentError)) throw error;
    print(usage, true);
    print(`deep-scan-config: error: ${error.message}`, true);
    return 2;
  }
  try {
    const config = resolveDeepScanConfig(
      options["available-parallelism"] as bigint,
    );
    // json.dumps applies Python's decimal conversion limit to hexadecimal TOML integers too.
    for (const value of Object.values(config)) {
      if (typeof value !== "bigint") continue;
      try {
        parseInteger(String(value));
      } catch (error) {
        (error as Error).message = (error as Error).message.replace(
          /: value has \d+ digits/u,
          "",
        );
        throw error;
      }
    }
    print(
      stringifyJson(
        {
          ...config,
          maxTimeHours:
            typeof config.maxTimeHours === "number"
              ? new JsonFloat(String(config.maxTimeHours))
              : config.maxTimeHours,
        },
        { compact: true, sortKeys: true },
      ),
    );
    return 0;
  } catch (error) {
    if (error instanceof DeepScanConfigError) print(error.message, true);
    else {
      const failure = error as NodeJS.ErrnoException & { winerror?: number };
      const name =
        error instanceof UnicodeDecodeError
          ? "UnicodeDecodeError"
          : error instanceof HomeExpansionError
            ? "RuntimeError"
            : ["EACCES", "EPERM"].includes(failure.code ?? "") ||
                failure.winerror === 5
              ? "PermissionError"
              : failure.name;
      print(`${name}: ${filesystemErrorMessage(error)}`, true);
    }
    return 1;
  }
}
