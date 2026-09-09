import { createHash } from "node:crypto";
import { lstatSync, readdirSync } from "node:fs";
import { basename, dirname, parse, sep } from "node:path";
import decimalDigit from "@unicode/unicode-15.0.0/General_Category/Decimal_Number/regex.js";
import type { Connection, Row } from "../../native/sqlite.mjs";
import {
  widePath,
  windowsFileSystem,
  windowsParts,
} from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { contractValuesEqual } from "./helpers/contract-validation";
import { decodePosixBytes, encodePosixPath } from "./helpers/posix-path";
import { preflightInteger } from "./helpers/preflight-config";
import {
  JsonFloat,
  JsonSyntaxError,
  jsonTypeName,
  object,
  objectEntries,
  objectFromEntries,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { appendPath, relativePath } from "./helpers/rank-selection";
import { compare } from "./helpers/rank-worklists";
import { parsedPath } from "./helpers/resolve-security-md";
import { ContractError } from "./helpers/scan-contract-errors";
import {
  JsonValueError,
  readScanLocalJson,
} from "./helpers/scan-contract-json";
import { UnicodeDecodeError } from "./helpers/utf8";
import { artifactPath, requireCanonicalScanDirectory } from "./workbench-files";
import { WorkbenchValidationError } from "./workbench-validation";

type Table = Record<string, unknown>;
const windows = process.platform === "win32";
const get = (value: Table, key: string, fallback: unknown = null) =>
  Object.hasOwn(value, key) ? value[key] : fallback;
const truth = (value: unknown): boolean =>
  value instanceof JsonFloat
    ? Number(value.source) !== 0
    : Array.isArray(value) || Buffer.isBuffer(value)
      ? value.length !== 0
      : object(value)
        ? objectEntries(value).length !== 0
        : Boolean(value);
const sourceError = (error: unknown): boolean => {
  const system = error as { errno?: number; winerror?: number };
  return (
    error instanceof ContractError ||
    error instanceof JsonValueError ||
    error instanceof JsonSyntaxError ||
    error instanceof UnicodeDecodeError ||
    system.errno !== undefined ||
    system.winerror !== undefined
  );
};
function storedJson(value: unknown): unknown {
  return parseJson(value as string | Buffer, false, (source) => {
    try {
      return preflightInteger(source);
    } catch (error) {
      throw new JsonValueError((error as Error).message);
    }
  });
}
function path(value: unknown): string {
  if (typeof value !== "string")
    throw new TypeError(
      `argument should be a str or an os.PathLike object where __fspath__ returns a str, not '${Buffer.isBuffer(value) ? "bytes" : jsonTypeName(value)}'`,
    );
  return parsedPath(value);
}
const posix = (value: string) =>
  windows ? value.replaceAll("\\", "/") : value;

export function encodedSavedResult(value: unknown): Buffer {
  try {
    return Buffer.from(
      stringifyJson(value, {
        allowNan: false,
        sortKeys: true,
        compact: true,
        separators: [",", ":"],
      }),
    );
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) throw error;
    throw new JsonValueError((error as Error).message);
  }
}
export function savedResultDigest(value: unknown): string {
  return createHash("sha256").update(encodedSavedResult(value)).digest("hex");
}

export function savedResultChildren(
  scanDir: string,
  relative: string,
): string[] {
  const supplied = parsedPath(relative);
  const root = windows
    ? windowsParts(supplied).slice(0, 2).join("")
    : parse(supplied).root;
  const parts = [
    ...(root ? [root] : []),
    ...supplied
      .slice(root.length)
      .split(sep)
      .filter((part) => part && part !== "."),
  ];
  let cursor = scanDir;
  for (const part of parts) {
    if (part === ".." || part === ".") return [];
    cursor = appendPath(cursor, part);
    if (cursor.includes("\0"))
      throw new JsonValueError("stat: embedded null character in path");
    try {
      const info = windows
        ? windowsFileSystem(windowsBinding()).stat(widePath(cursor), false)
        : lstatSync(encodePosixPath(cursor));
      if (!info.isDirectory()) return [];
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }
  const children = windows
    ? windowsFileSystem(windowsBinding())
        .entriesWithTypes(widePath(cursor))
        .map(({ name }) => name.toString("utf16le"))
    : readdirSync(encodePosixPath(cursor), { encoding: "buffer" }).map(
        decodePosixBytes,
      );
  return children.sort(compare);
}

export function latestSuccessfulReducer(workers: readonly Row[]): Row | null {
  let latest: Row | null = null;
  for (const worker of workers) {
    if (
      worker.get("kind") !== "dedup" ||
      worker.get("status") !== "succeeded" ||
      !truth(worker.get("result_manifest_path"))
    )
      continue;
    const completed = (worker.get("completed_at") || "") as string;
    const previous = (latest?.get("completed_at") || "") as string;
    if (
      latest === null ||
      compare(completed, previous) > 0 ||
      (completed === previous &&
        compare(worker.get("id") as string, latest.get("id") as string) > 0)
    )
      latest = worker;
  }
  return latest;
}
const attemptName = new RegExp(
  `^attempt-(?:${decimalDigit.source})+$(?![\\s\\S])`,
  "u",
);
export function* savedResultPaths(
  scanDir: string,
  workers: readonly Row[],
): Generator<[string, string | null]> {
  const latest = latestSuccessfulReducer(workers);
  function* checkpoints(
    directory: string,
    kind: string | null = null,
  ): Generator<[string, string | null]> {
    for (const name of savedResultChildren(scanDir, directory))
      if (/^[0-9a-f]{64}\.json$(?![\s\S])/u.test(name))
        yield [`${directory}/${name}`, kind];
  }
  yield* checkpoints("checkpoints");
  for (const worker of workers) {
    if (worker.get("kind") !== "dedup" && worker.get("kind") !== "discovery")
      continue;
    let output: string;
    try {
      const relative = relativePath(
        path(worker.get("artifact_dir")),
        parsedPath(scanDir),
      );
      if (relative === undefined) continue;
      output = posix(relative || ".");
    } catch (error) {
      if (error instanceof TypeError || error instanceof JsonValueError)
        continue;
      throw error;
    }
    const outputPath = parsedPath(output);
    const attempts = appendPath(
      basename(outputPath) === "output" ? dirname(outputPath) : outputPath,
      "attempts",
    );
    const directories = [
      output,
      ...savedResultChildren(scanDir, posix(attempts))
        .filter((name) => attemptName.test(name))
        .map((name) => posix(appendPath(attempts, name))),
    ];
    for (const directory of directories) {
      const paths = [
        ...checkpoints(
          `${directory}/checkpoints`,
          worker.get("kind") as string,
        ),
      ];
      if (worker.get("kind") === "discovery" || paths.length) {
        yield [`${directory}/result.json`, worker.get("kind") as string];
        yield* paths;
      }
    }
    if (
      truth(worker.get("result_manifest_path")) &&
      (worker.get("kind") === "discovery" ||
        latest?.get("id") === worker.get("id"))
    ) {
      const relative = relativePath(
        path(worker.get("result_manifest_path")),
        parsedPath(scanDir),
      );
      if (relative !== undefined)
        yield [posix(relative || "."), worker.get("kind") as string];
    }
  }
}

export function readSavedResult(
  scanDir: string,
  relative: string,
  scanId: string,
  kind: string | null = null,
): [Table, string] {
  const draft = readScanLocalJson(scanDir, relative, "Saved scan checkpoint");
  if (!contractValuesEqual(get(draft, "scanId"), scanId))
    throw new ContractError("checkpoint belongs to a different scan");
  if (
    !Array.isArray(draft["findings"]) ||
    !object(get(draft, "coverage", kind === "dedup" ? {} : null))
  )
    throw new ContractError("checkpoint has no semantic findings or coverage");
  return [draft, savedResultDigest(draft)];
}
export function readSavedParentResult(
  scanDir: string,
  scanId: string,
): [Table, Table] {
  const manifest = readScanLocalJson(
    scanDir,
    "scan-manifest.json",
    "Saved parent manifest",
  );
  const findings = readScanLocalJson(
    scanDir,
    "findings.json",
    "Saved parent findings",
  );
  const coverage = readScanLocalJson(
    scanDir,
    "coverage.json",
    "Saved parent coverage",
  );
  const scan = manifest["scan"];
  if (!object(scan))
    throw new ContractError("Saved parent manifest has no scan object");
  if (
    (truth(scan["sealedAt"]) || truth(scan["artifacts"])) &&
    (!contractValuesEqual(get(scan, "id", scanId), scanId) ||
      !contractValuesEqual(get(findings, "scanId", scanId), scanId) ||
      !contractValuesEqual(get(coverage, "scanId", scanId), scanId))
  )
    throw new ContractError(
      "Saved parent documents belong to a different scan",
    );
  const parent: Table = {
    scanId,
    findings: get(findings, "findings"),
    coverage,
  };
  for (const key of ["scope", "threatModel", "complete"])
    if (Object.hasOwn(scan, key)) parent[key] = scan[key];
  if (!Array.isArray(parent["findings"]))
    throw new ContractError("Saved parent draft has no findings array");
  return [manifest, parent];
}
export function sourceDigests(
  value: unknown,
  label: string,
): Record<string, string> {
  if (
    !object(value) ||
    !objectEntries(value).every(([, digest]) => typeof digest === "string")
  )
    throw new ContractError(`${label} source digests are malformed.`);
  return value as Record<string, string>;
}
function workers(connection: Connection, scan: Row): Row[] {
  return connection
    .prepare(
      "SELECT id, kind, status, completed_at, artifact_dir, result_manifest_path FROM deep_scan_workers WHERE scan_id = ?",
    )
    .all([scan.get("id")]);
}

export function savedResultsChanged(
  connection: Connection,
  scan: Row,
): boolean {
  try {
    const scanDir = requireCanonicalScanDirectory(path(scan.get("scan_dir")));
    const manifestPath = artifactPath(scanDir, "scan-manifest.json", false);
    const paths = new Map(savedResultPaths(scanDir, workers(connection, scan)));
    const frozen = scan.get("retained_source_digests_json");
    const hasSavedSource = () => {
      for (const [relative, kind] of paths) {
        try {
          readSavedResult(scanDir, relative, scan.get("id") as string, kind);
          return true;
        } catch (error) {
          if (!sourceError(error)) throw error;
        }
      }
      return false;
    };
    if (manifestPath === null)
      return frozen !== null
        ? truth(sourceDigests(storedJson(frozen), "Frozen stopped-scan"))
        : hasSavedSource();
    if (scan.get("seal_manifest_digest") === null) {
      try {
        readSavedParentResult(scanDir, scan.get("id") as string);
        return true;
      } catch (error) {
        if (!sourceError(error)) throw error;
      }
      return hasSavedSource();
    }
    const manifest = readScanLocalJson(
      scanDir,
      relativePath(manifestPath, scanDir)!,
      "Saved scan manifest",
    );
    const manifestScan = manifest["scan"];
    if (!object(manifestScan)) return true;
    const published = sourceDigests(
      get(manifestScan, "preservedSources", {}),
      "Published scan",
    );
    const current = objectFromEntries(objectEntries(published));
    for (const [relative, kind] of paths) {
      try {
        current[relative] = readSavedResult(
          scanDir,
          relative,
          scan.get("id") as string,
          kind,
        )[1];
      } catch (error) {
        if (!sourceError(error)) throw error;
      }
    }
    return !contractValuesEqual(current, published);
  } catch (error) {
    if (sourceError(error) || error instanceof WorkbenchValidationError)
      return false;
    throw error;
  }
}

export function recoverySourceDigests(
  connection: Connection,
  scan: Row,
): [Record<string, string>, boolean] {
  const scanDir = requireCanonicalScanDirectory(path(scan.get("scan_dir")));
  let frozen: Record<string, string> | null = null,
    includeParent = true;
  const raw = scan.get("retained_source_digests_json");
  if (raw !== null) {
    frozen = sourceDigests(storedJson(raw), "Saved stopped-scan");
    includeParent = false;
  }
  const manifestPath = artifactPath(scanDir, "scan-manifest.json", false);
  if (manifestPath !== null) {
    const manifest = readScanLocalJson(
      scanDir,
      relativePath(manifestPath, scanDir)!,
      "Saved scan manifest",
    );
    const manifestScan = manifest["scan"];
    if (!object(manifestScan))
      throw new ContractError("Saved scan manifest has no scan object");
    if (
      scan.get("seal_manifest_digest") !== null ||
      get(manifestScan, "sealedAt") !== null ||
      get(manifestScan, "artifacts") !== null
    ) {
      if (Object.hasOwn(manifestScan, "preservedSources")) {
        const published = sourceDigests(
          manifestScan["preservedSources"],
          "Published scan",
        );
        includeParent = !truth(published);
        if (truth(published)) {
          if (frozen !== null && !contractValuesEqual(frozen, published))
            throw new ContractError(
              "Stopped scan sources changed after terminal publication.",
            );
          frozen = published;
        } else if (frozen === null) frozen = {};
      } else includeParent = true;
    }
  }
  const paths = new Map(savedResultPaths(scanDir, workers(connection, scan)));
  const sources = objectFromEntries(objectEntries(frozen ?? {})) as Record<
    string,
    string
  >;
  for (const [relative, expected] of objectEntries(sources)) {
    let digest: string;
    try {
      digest = readSavedResult(
        scanDir,
        relative,
        scan.get("id") as string,
        paths.get(relative) ?? null,
      )[1];
    } catch (error) {
      if (!sourceError(error)) throw error;
      throw new ContractError(
        "Frozen stopped-scan checkpoint set is incomplete.",
      );
    }
    if (digest !== expected)
      throw new ContractError("checkpoint changed after the scan stopped");
  }
  for (const [relative, kind] of paths) {
    if (Object.hasOwn(sources, relative)) continue;
    try {
      sources[relative] = readSavedResult(
        scanDir,
        relative,
        scan.get("id") as string,
        kind,
      )[1];
    } catch (error) {
      if (!sourceError(error)) throw error;
    }
  }
  return [sources, includeParent];
}

export function scanResultsRecoveryNeeded(
  connection: Connection,
  scan: Row,
): boolean {
  if (scan.get("status") !== "failed" || scan.get("canceled_at") !== null)
    return false;
  const warnings = storedJson(scan.get("completion_warnings_json"));
  const items = object(warnings)
    ? objectEntries(warnings).map(([key]) => key)
    : typeof warnings === "string"
      ? Array.from(warnings)
      : warnings;
  if (!Array.isArray(items))
    throw new TypeError(`'${jsonTypeName(warnings)}' object is not iterable`);
  if (
    items.some(
      (warning) =>
        typeof warning === "string" &&
        warning.startsWith(
          "Saved scan evidence remains on disk; result publication needs follow-up:",
        ),
    )
  )
    return true;
  const publication = connection
    .prepare(
      "SELECT publication_error_message FROM deep_scan_runs WHERE scan_id = ?",
    )
    .get([scan.get("id")]);
  if (
    publication !== undefined &&
    truth(publication.get("publication_error_message"))
  )
    return true;
  return savedResultsChanged(connection, scan);
}
