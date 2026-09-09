import { dirname } from "node:path";
import type { Connection, Row } from "../../native/sqlite.mjs";
import { contractValuesEqual as equal } from "./helpers/contract-validation";
import { fileInfo } from "./helpers/helper-files";
import { preflightInteger } from "./helpers/preflight-config";
import {
  jsonGet,
  jsonItem,
  jsonTypeName,
  JsonFloat,
  object,
  objectEntries,
  parseJson,
  pythonRepr,
  stringifyJson,
} from "./helpers/python-json";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { ContractError } from "./helpers/scan-contract-errors";
import {
  finalizeScan,
  prepareScanFinalization,
  writePreparedScanFinalization,
} from "./helpers/scan-finalization";
import {
  readScanLocalBytes,
  removeScanLocalFileIfExists,
  writeScanLocalBytes,
} from "./helpers/scan-local-files";
import { schemaDirectory } from "./helpers/sealed-scan";
import {
  publishedManifestDigest,
  requireRecordedManifestDigest,
  verifyManifestBinding,
  workbenchCompletionBinding,
} from "./workbench-binding";
import {
  artifactPath,
  readJsonObject,
  requireCanonicalScanDirectory,
} from "./workbench-files";
import { indexFindings } from "./workbench-finding-index";
import {
  mergeSavedResults,
  type SavedMergeBinding,
} from "./workbench-merge-saved-results";
import { requireScan } from "./workbench-records";
import { expectedCoverageMode } from "./workbench-results";
import { sourceDigests } from "./workbench-saved-result-sources";
import { WorkbenchValidationError } from "./workbench-validation";

type Table = Record<string, unknown>;
export interface PreservedResultsContext {
  now(): string;
}
export interface PreserveResultsOptions {
  recoverySourceDigests?: Record<string, string> | null;
  includeParentWithRecovery?: boolean;
}
const artifacts = {
  coverage: "coverage.json",
  findings: "findings.json",
  manifest: "scan-manifest.json",
  markdownReport: "report.md",
};
const publishedOutputs = [
  "findings.json",
  "coverage.json",
  "scan-manifest.json",
  "report.md",
  "report.html",
  "exports/results.sarif",
];
const publicationFollowUpWarning =
  "Saved scan evidence remains on disk; result publication needs follow-up:";
const pathExists = (path: string): boolean =>
  fileInfo(path) !== undefined ||
  fileInfo(path, false)?.isSymbolicLink() === true;
const storedJson = (value: unknown): unknown =>
  parseJson(value as string | Buffer, false, preflightInteger);
const json = (value: unknown, sortKeys = false): string =>
  stringifyJson(value, { compact: true, sortKeys });
function iterable(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") return Array.from(value);
  if (object(value)) return objectEntries(value).map(([key]) => key);
  throw new TypeError(`'${jsonTypeName(value)}' object is not iterable`);
}
function unique(values: unknown[]): unknown[] {
  const seen = new Set<unknown>(),
    result: unknown[] = [];
  for (const value of values) {
    if (Array.isArray(value) || object(value))
      throw new TypeError(`unhashable type: '${jsonTypeName(value)}'`);
    const key = value instanceof JsonFloat ? Number(value.source) : value;
    if (
      seen.has(key) ||
      (typeof value !== "string" && result.some((item) => equal(item, value)))
    )
      continue;
    seen.add(key);
    result.push(value);
  }
  return result;
}
function retainedSources(manifest: Table): Record<string, string> {
  const sources = jsonGet(jsonGet(manifest, "scan", {}), "preservedSources");
  if (
    !object(sources) ||
    !objectEntries(sources).every(([, digest]) => typeof digest === "string")
  )
    throw new ContractError("Stopped scan source digests could not be frozen.");
  return sources as Record<string, string>;
}

export function coverageForComparison(scan: Row): Table {
  if (scan.get("seal_manifest_digest") === null)
    throw new WorkbenchValidationError("Only sealed scans can be compared.");
  const scanDir = requireCanonicalScanDirectory(
    parsedPath(scan.get("scan_dir") as string),
  );
  requireRecordedManifestDigest(scan, scanDir);
  let prepared;
  try {
    prepared = prepareScanFinalization(scanDir);
  } catch (error) {
    if (!(error instanceof ContractError)) throw error;
    throw new WorkbenchValidationError(error.message);
  }
  if (
    !prepared.wasSealed ||
    !equal(jsonItem(jsonItem(prepared.manifest, "scan"), "id"), scan.get("id"))
  )
    throw new WorkbenchValidationError("Only sealed scans can be compared.");
  return prepared.coverage;
}

export function snapshotPublishedOutputs(
  scanDir: string,
): Record<string, Buffer | null> {
  const snapshots: Record<string, Buffer | null> = {};
  for (const relative of publishedOutputs) {
    try {
      snapshots[relative] = readScanLocalBytes(
        scanDir,
        relative,
        "Published scan output",
      );
    } catch (error) {
      if (
        !(error instanceof ContractError) ||
        pathExists(appendPath(scanDir, relative))
      )
        throw error;
      snapshots[relative] = null;
    }
  }
  return snapshots;
}

export function restorePublishedOutputs(
  scanDir: string,
  snapshots: Record<string, Buffer | null>,
): void {
  for (const [relative, contents] of Object.entries(snapshots)) {
    if (contents === null) {
      if (pathExists(appendPath(scanDir, relative)))
        removeScanLocalFileIfExists(scanDir, relative);
    } else writeScanLocalBytes(scanDir, relative, contents);
  }
}

export function preserveScanResultsLocked(
  db: PreservedResultsContext,
  connection: Connection,
  scanId: string,
  options: PreserveResultsOptions = {},
): boolean {
  const scan = requireScan(connection, scanId);
  if (scan.get("status") !== "failed") return false;
  const recovery = options.recoverySourceDigests ?? null,
    rawFrozenSources = scan.get("retained_source_digests_json");
  let frozen =
    recovery !== null
      ? recovery
      : rawFrozenSources !== null
        ? sourceDigests(storedJson(rawFrozenSources), "Saved stopped-scan")
        : null;
  const scanDir = requireCanonicalScanDirectory(
      parsedPath(scan.get("scan_dir") as string),
    ),
    deepRun = connection
      .prepare("SELECT status FROM deep_scan_runs WHERE scan_id = ?")
      .get([scanId]),
    canceledAt = scan.get("canceled_at"),
    outcome = (
      Buffer.isBuffer(canceledAt)
        ? canceledAt.length !== 0
        : Boolean(canceledAt)
    )
      ? "canceled"
      : deepRun?.get("status") === "interrupted"
        ? "interrupted"
        : "failed",
    storedWarnings = storedJson(scan.get("completion_warnings_json")),
    warningValues = iterable(storedWarnings),
    followUpWarnings = warningValues.filter(
      (warning) =>
        typeof warning === "string" &&
        warning.startsWith(publicationFollowUpWarning),
    ),
    warnings = warningValues.filter(
      (warning) => !followUpWarnings.includes(warning),
    ) as string[];
  const recordPublication = (manifest: Table, findings: Table): void => {
    const sources = retainedSources(manifest),
      digest = publishedManifestDigest(scanDir, manifest),
      timestamp = db.now();
    connection.transaction(() => {
      for (const [kind, filename] of Object.entries(artifacts)) {
        const path = artifactPath(scanDir, filename, true);
        connection
          .prepare(
            "INSERT OR REPLACE INTO scan_artifacts " +
              "(scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
          )
          .run([scanId, kind, path, scan.get("completed_at")]);
      }
      const existing = connection
          .prepare("SELECT id FROM finding_occurrences WHERE scan_id = ?")
          .all([scanId]),
        retained = new Set(
          (jsonItem(findings, "findings") as Table[]).map((finding) =>
            jsonItem(finding, "occurrenceId"),
          ),
        );
      // Stable occurrences retain their triage and remediation records.
      for (const row of existing)
        if (!retained.has(row.get("id")))
          connection
            .prepare(
              "DELETE FROM finding_occurrences WHERE id = ? AND scan_id = ?",
            )
            .run([row.get("id"), scanId]);
      indexFindings(
        connection,
        scanId,
        findings,
        scan.get("completed_at") as string,
      );
      connection
        .prepare(
          "UPDATE scans SET seal_manifest_digest = ?, retained_source_digests_json = ?, " +
            "completion_warnings_json = ?, updated_at = ? WHERE id = ? AND status = 'failed'",
        )
        .run([
          digest,
          json(sources, true),
          json(unique(warnings)),
          timestamp,
          scanId,
        ]);
      connection
        .prepare(
          "UPDATE scan_progress SET reportable_findings_count = ?, updated_at = ? WHERE scan_id = ?",
        )
        .run([
          BigInt((findings["findings"] as Table[]).length),
          timestamp,
          scanId,
        ]);
    });
  };
  const existingPath = artifactPath(scanDir, artifacts.manifest, false),
    existingScan = existingPath
      ? jsonGet(readJsonObject(existingPath), "scan", {})
      : {};
  if (
    scan.get("seal_manifest_digest") !== null ||
    (object(existingScan) &&
      (jsonGet(existingScan, "sealedAt") !== null ||
        jsonGet(existingScan, "artifacts") !== null))
  ) {
    requireRecordedManifestDigest(scan, scanDir);
    const [existing, existingFindings] = finalizeScan(
      scanDir,
      undefined,
      undefined,
      { expectedCoverageMode: expectedCoverageMode(scan) },
    );
    verifyManifestBinding(scan, existing);
    if (jsonGet(existingScan, "status") === outcome) {
      const existingSources = jsonGet(existingScan, "preservedSources");
      if (frozen === null) frozen = retainedSources({ scan: existingScan });
      if (equal(existingSources, frozen)) {
        if (
          rawFrozenSources !== null &&
          scan.get("seal_manifest_digest") !== null &&
          followUpWarnings.length === 0
        )
          return true;
        recordPublication(existing, existingFindings);
        return true;
      }
      if (recovery === null)
        throw new ContractError(
          "Stopped scan sources changed after terminal publication.",
        );
    }
  }
  const binding = {
      ...workbenchCompletionBinding(
        scan,
        scan.get("completed_at") as string,
        dirname(schemaDirectory()),
      ),
      status: outcome,
    },
    workers = connection
      .prepare(
        "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
      )
      .all([scanId]),
    failure = scan.get("failure_message"),
    failureText = (
      Buffer.isBuffer(failure) ? failure.length !== 0 : Boolean(failure)
    )
      ? typeof failure === "string"
        ? failure
        : Buffer.isBuffer(failure)
          ? `b${pythonRepr(failure.toString("latin1")).replace(/[\x80-\xff]/gu, (character) => `\\x${character.charCodeAt(0).toString(16)}`)}`
          : pythonRepr(failure)
      : "";
  const documents = mergeSavedResults(
    scanDir,
    scanId,
    binding as unknown as SavedMergeBinding,
    workers,
    warnings,
    {
      stopped: true,
      reason:
        `Scan ${outcome}; saved findings and pending review were preserved. ${failureText}`.replace(
          /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
          "",
        ),
      frozenSourceDigests: frozen,
      allowFrozenLegacyParent:
        options.includeParentWithRecovery ||
        (recovery === null &&
          equal(frozen, {}) &&
          object(existingScan) &&
          jsonGet(existingScan, "sealedAt") !== null &&
          !Object.hasOwn(existingScan, "preservedSources")),
    },
  );
  if (documents === null) {
    const unpublishedWarnings = unique([...warnings, ...followUpWarnings]);
    const unchanged =
      Array.isArray(storedWarnings) &&
      unpublishedWarnings.length === storedWarnings.length &&
      unpublishedWarnings.every(
        (warning, index) =>
          warning === storedWarnings[index] ||
          equal(warning, storedWarnings[index]),
      );
    if (!unchanged)
      connection.transaction(() => {
        const args = [json(unpublishedWarnings), db.now(), scanId];
        connection
          .prepare(
            "UPDATE scans SET completion_warnings_json = ?, updated_at = ? WHERE id = ? AND status = 'failed'",
          )
          .run(args);
      });
    return false;
  }
  if (frozen === null) {
    frozen = retainedSources(documents[0]);
    connection.transaction(() => {
      connection
        .prepare(
          "UPDATE scans SET retained_source_digests_json = ? WHERE id = ? AND retained_source_digests_json IS NULL",
        )
        .run([json(frozen, true), scanId]);
    });
  }
  const prepared = prepareScanFinalization(scanDir, undefined, {
      expectedCoverageMode: expectedCoverageMode(scan),
      completionBinding: binding,
      completionWarnings: warnings,
      draftDocuments: documents,
    }),
    snapshots = snapshotPublishedOutputs(scanDir);
  try {
    const [manifest, findings] = writePreparedScanFinalization(prepared);
    verifyManifestBinding(scan, manifest);
    recordPublication(manifest, findings);
  } catch (error) {
    restorePublishedOutputs(scanDir, snapshots);
    throw error;
  }
  return true;
}
