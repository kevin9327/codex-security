import { dirname, basename, isAbsolute } from "node:path";
import type { Row } from "../../native/sqlite.mjs";
import { windowsParts } from "../../native/windows-files.mjs";
import { environment } from "./helpers/environment";
import { fileInfo } from "./helpers/helper-files";
import { encodePosixPath } from "./helpers/posix-path";
import { parsePythonDateTime } from "./helpers/python-date-time";
import { JsonFloat, jsonTypeName, pythonRepr } from "./helpers/python-json";
import { appendPath, pathKey, relativePath } from "./helpers/rank-selection";
import { resolvedPath } from "./helpers/resolve-path";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { WorkbenchValidationError } from "./workbench-validation";

type CanonicalScanDirectory = (path: string) => string;
const suppliedPath = (value: string) =>
  parsedPath(expandHome(parsedPath(value), environment("HOME")));
function requireAbsolute(path: string, label: string): void {
  const absolute =
    process.platform === "win32"
      ? windowsParts(path).slice(0, 2).every(Boolean)
      : isAbsolute(path);
  if (!absolute)
    throw new WorkbenchValidationError(
      `${label} must be an absolute path inside the scan directory.`,
    );
}
function requireSamePath(left: string, right: string, label: string): void {
  if (pathKey(left) !== pathKey(right))
    throw new WorkbenchValidationError(
      `${label} must be a canonical non-symlink path.`,
    );
}

function pathExists(path: string): boolean {
  // Path.exists suppresses encoding and embedded-NUL failures.
  if (path.includes("\0")) return false;
  if (process.platform !== "win32") {
    try {
      encodePosixPath(path);
    } catch {
      return false;
    }
  }
  return fileInfo(path) !== undefined;
}

export function deepScanPath(
  scan: Row,
  value: string,
  label: string,
  kind: string,
  requireCanonicalScanDirectory: CanonicalScanDirectory,
): string {
  const supplied = suppliedPath(value);
  requireAbsolute(supplied, label);
  const invalid = () =>
    new WorkbenchValidationError(
      `${label} must be an existing path inside the scan directory.`,
    );
  let resolved: string;
  try {
    resolved = resolvedPath(supplied);
  } catch {
    throw invalid();
  }
  let scanDirectory: string;
  try {
    scanDirectory = requireCanonicalScanDirectory(
      scan.get("scan_dir") as string,
    );
  } catch (error) {
    if (error instanceof WorkbenchValidationError || error instanceof TypeError)
      throw error;
    throw invalid();
  }
  if (relativePath(resolved, scanDirectory) === undefined) throw invalid();
  requireSamePath(resolved, supplied, label);
  if (kind === "file" && !fileInfo(resolved)?.isFile())
    throw new WorkbenchValidationError(`${label} must be a regular file.`);
  if (kind === "directory" && !fileInfo(resolved)?.isDirectory())
    throw new WorkbenchValidationError(`${label} must be a directory.`);
  return resolved;
}

export function deepScanOutputPath(
  scan: Row,
  value: string,
  label: string,
  requireCanonicalScanDirectory: CanonicalScanDirectory,
): string {
  const supplied = suppliedPath(value);
  requireAbsolute(supplied, label);
  if (pathExists(supplied))
    return deepScanPath(
      scan,
      supplied,
      label,
      "file",
      requireCanonicalScanDirectory,
    );
  const parent = deepScanPath(
    scan,
    dirname(supplied),
    label,
    "directory",
    requireCanonicalScanDirectory,
  );
  const output = appendPath(parent, basename(supplied));
  requireSamePath(output, supplied, label);
  return output;
}

export function canonicalDiscoveryArtifacts(scan: Row): Record<string, string> {
  const directory = appendPath(
    parsedPath(scan.get("scan_dir") as string),
    "artifacts/02_discovery",
  );
  return {
    inScopeFilesPath: deepScanPath(
      scan,
      appendPath(directory, "in_scope_files.txt"),
      "Canonical in-scope inventory path",
      "file",
      requireCanonicalScanDirectory,
    ),
    candidateLedgerPath: deepScanPath(
      scan,
      appendPath(directory, "candidate_ledger.jsonl"),
      "Canonical candidate ledger path",
      "file",
      requireCanonicalScanDirectory,
    ),
  };
}

export function deepScanDeadlineReached(run: Row, now: () => string): boolean {
  const parse = (value: string) =>
    parsePythonDateTime(
      value.endsWith("Z") || value.endsWith("z")
        ? value.slice(0, -1) + "+00:00"
        : value,
    );
  const current = parse(now());
  const created = run.get("created_at");
  const started = parse(
    typeof created === "string"
      ? created
      : pythonRepr(
          typeof created === "number"
            ? new JsonFloat(String(created))
            : created,
        ),
  );
  if (current.aware !== started.aware)
    throw new TypeError(
      "can't subtract offset-naive and offset-aware datetimes",
    );
  const hours =
    Number(current.microseconds - started.microseconds) / 1_000_000 / 3600;
  const maximum = run.get("max_time_hours");
  if (
    typeof maximum !== "number" &&
    typeof maximum !== "bigint" &&
    typeof maximum !== "boolean"
  )
    throw new TypeError(
      `'>=' not supported between instances of 'float' and '${jsonTypeName(maximum)}'`,
    );
  return hours >= (typeof maximum === "boolean" ? Number(maximum) : maximum);
}
