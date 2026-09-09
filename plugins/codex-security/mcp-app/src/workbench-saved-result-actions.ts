import { createHash } from "node:crypto";
import { lstatSync } from "node:fs";
import { dirname } from "node:path";
import type { Connection } from "../../native/sqlite.mjs";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import {
  populateUnsealedArtifactEnvelope,
  populateUnsealedManifestEnvelope,
  validateCompletionBinding,
} from "./helpers/contract-completion-binding";
import { encodePosixPath } from "./helpers/posix-path";
import {
  copyJson,
  jsonItem,
  jsonTypeName,
  object,
  stringifyJson,
} from "./helpers/python-json";
import { appendPath, relativePath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import {
  readScanLocalJson,
  readScanLocalJsonBytes,
} from "./helpers/scan-contract-json";
import { writeScanLocalBytes } from "./helpers/scan-local-files";
import { schemaDirectory } from "./helpers/sealed-scan";
import { workbenchCompletionBinding } from "./workbench-binding";
import { withScanCompletionLock } from "./workbench-completion-lock";
import { requireCurrentCoordinator } from "./workbench-deep-lease";
import { requireDeepScanRun } from "./workbench-deep-state";
import { clearDeepScanPublicationFailure } from "./workbench-deep-terminal";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { requireCurrentContinuation } from "./workbench-handoff";
import { preserveScanResultsLocked } from "./workbench-preserve-saved-results";
import { requireScan, requireWorkspace } from "./workbench-records";
import { resultCallbacks, scanContext } from "./workbench-results";
import { recoverySourceDigests } from "./workbench-saved-result-sources";
import { requireUuid, WorkbenchValidationError } from "./workbench-validation";

type Table = Record<string, unknown>;
export interface SavedResultActionsContext {
  now(): string;
}
export interface PreserveScanResultsArguments {
  scanId: string;
  threadId: string | null;
  claimToken: string | null;
  coordinatorGeneration: bigint | null;
}
export interface WriteScanDraftArguments {
  scanId: string;
  claimToken: string | null;
  draftPath: string;
  checkpointPath: string | null;
  expectedDraftDigest: string | null;
}

function writableObject(value: unknown): Table {
  if (object(value)) return value;
  if (Array.isArray(value))
    throw new TypeError("list indices must be integers or slices, not str");
  throw new TypeError(
    `'${jsonTypeName(value)}' object does not support item assignment`,
  );
}

export function recoverScanResults(
  context: SavedResultActionsContext,
  connection: Connection,
  args: { scanId: string },
): Table {
  const scanId = requireUuid(args.scanId, "scan-id");
  withScanCompletionLock(scanId, () => {
    const scan = requireScan(connection, scanId);
    if (scan.get("status") !== "failed")
      throw new WorkbenchValidationError(
        "Only a stopped scan can recover terminal results.",
      );
    if (scan.get("canceled_at") !== null)
      throw new WorkbenchValidationError(
        "Canceled scans cannot recover terminal results.",
      );
    const [digests, includeParent] = recoverySourceDigests(connection, scan);
    if (
      !preserveScanResultsLocked(context, connection, scanId, {
        recoverySourceDigests: digests,
        includeParentWithRecovery: includeParent,
      })
    )
      throw new WorkbenchValidationError(
        "No saved stopped-scan results were available to recover.",
      );
    clearDeepScanPublicationFailure(connection, scanId, () => context.now());
  });
  return scanContext(connection, scanId, resultCallbacks);
}

export function preserveScanResults(
  context: SavedResultActionsContext,
  connection: Connection,
  args: PreserveScanResultsArguments,
): Table {
  const scanId = requireUuid(args.scanId, "scan-id");
  withScanCompletionLock(scanId, () => {
    const scan = requireScan(connection, scanId);
    if (scan.get("status") !== "failed")
      throw new WorkbenchValidationError(
        "Only a stopped scan can preserve terminal results.",
      );
    const workspace = requireWorkspace(
      connection,
      scan.get("workspace_id") as string,
    );
    const truth = (value: unknown) =>
      Buffer.isBuffer(value) ? value.length !== 0 : Boolean(value);
    const continuation = scan.get("continuation_thread_id"),
      coordinator = scan.get("deep_scan_owner_thread_id"),
      owner = truth(continuation)
        ? continuation
        : truth(coordinator)
          ? coordinator
          : workspace.get("thread_id");
    if (args.threadId !== null && args.threadId !== owner)
      throw new WorkbenchValidationError(
        "Saved results can only be published from the owning Codex thread.",
      );
    if (args.coordinatorGeneration !== null) {
      if (args.threadId === null)
        throw new WorkbenchValidationError(
          "A coordinator result refresh requires its owning thread.",
        );
      requireCurrentCoordinator(requireDeepScanRun(connection, scanId), args);
    } else
      requireCurrentContinuation(scan, args.claimToken, {
        errorMessage: "Saved results are owned by another continuation.",
      });
    const published = preserveScanResultsLocked(context, connection, scanId);
    if (!published && scan.get("canceled_at") !== null)
      throw new WorkbenchValidationError(
        "Saved scan results could not be published or verified.",
      );
    if (published)
      clearDeepScanPublicationFailure(connection, scanId, () => context.now());
  });
  return scanContext(connection, scanId, resultCallbacks);
}

export function writeScanDraft(
  context: SavedResultActionsContext,
  connection: Connection,
  args: WriteScanDraftArguments,
): { scanId: string; status: "draft_written" } {
  const scanId = requireUuid(args.scanId, "scan-id");
  withScanCompletionLock(scanId, () => {
    const scan = requireScan(connection, scanId);
    requireCurrentContinuation(scan, args.claimToken, {
      errorMessage: "Scan draft is owned by another continuation.",
    });
    if (
      scan.get("status") !== "running" ||
      scan.get("seal_manifest_digest") !== null
    )
      throw new WorkbenchValidationError(
        "The scan stopped; its saved checkpoint was retained without replacing sealed results.",
      );
    const scanDir = requireCanonicalScanDirectory(
      parsedPath(scan.get("scan_dir") as string),
    );
    if (args.checkpointPath !== null) {
      const relative = relativePath(parsedPath(args.checkpointPath), scanDir);
      if (
        relative === undefined ||
        !/^drafts\/[0-9a-fA-F-]+\.checkpoint\.json$(?![\s\S])/u.test(relative)
      )
        throw new WorkbenchValidationError(
          "Scan checkpoint must be inside the registered scan drafts directory.",
        );
      const [checkpoint, contents] = readScanLocalJsonBytes(
        scanDir,
        relative,
        "Staged scan checkpoint",
      );
      if (checkpoint["scanId"] !== scanId)
        throw new WorkbenchValidationError(
          "Staged scan checkpoint belongs to another scan.",
        );
      const digest = createHash("sha256").update(contents).digest("hex");
      writeScanLocalBytes(scanDir, `checkpoints/${digest}.json`, contents);
    }
    if (
      args.expectedDraftDigest !== null &&
      args.expectedDraftDigest !== scanDraftDigest(scanDir)
    )
      throw new WorkbenchValidationError(
        "scan_draft_conflict: canonical scan results changed; reconcile the saved checkpoint again.",
      );
    const relative = relativePath(parsedPath(args.draftPath), scanDir);
    if (
      relative === undefined ||
      !/^drafts\/[0-9a-fA-F-]+\.json$(?![\s\S])/u.test(relative)
    )
      throw new WorkbenchValidationError(
        "Scan draft must be inside the registered scan drafts directory.",
      );
    const draft = readScanLocalJson(scanDir, relative, "Staged scan draft"),
      manifest = jsonItem(draft, "manifest"),
      findings = jsonItem(draft, "findings"),
      coverage = jsonItem(draft, "coverage"),
      binding = workbenchCompletionBinding(
        scan,
        context.now(),
        dirname(schemaDirectory()),
      ),
      copiedManifest = copyJson(manifest) as Table,
      copiedFindings = copyJson(findings) as Table,
      copiedCoverage = copyJson(coverage) as Table;
    populateUnsealedManifestEnvelope(
      copiedManifest,
      writableObject(jsonItem(copiedManifest, "scan")),
      binding,
    );
    populateUnsealedArtifactEnvelope(
      copiedManifest,
      writableObject(copiedFindings),
      writableObject(copiedCoverage),
      binding,
    );
    validateCompletionBinding(
      copiedManifest,
      copiedFindings,
      copiedCoverage,
      binding,
    );
    for (const [filename, document] of [
      ["findings.json", findings],
      ["coverage.json", coverage],
      ["scan-manifest.json", manifest],
    ] as const)
      writeScanLocalBytes(
        scanDir,
        filename,
        Buffer.from(stringifyJson(document, { allowNan: false }) + "\n"),
      );
  });
  return { scanId, status: "draft_written" };
}

export function scanDraftDigest(scanDir: string): string {
  const digest = createHash("sha256");
  for (const filename of [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
  ]) {
    digest.update(filename).update("\0");
    try {
      const path = appendPath(scanDir, filename);
      if (process.platform === "win32")
        windowsFileSystem(windowsBinding()).stat(widePath(path), false);
      else lstatSync(encodePosixPath(path));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      digest.update("missing\0");
      continue;
    }
    const [, contents] = readScanLocalJsonBytes(scanDir, filename, filename);
    digest.update("present\0").update(contents).update("\0");
  }
  return digest.digest("hex");
}
