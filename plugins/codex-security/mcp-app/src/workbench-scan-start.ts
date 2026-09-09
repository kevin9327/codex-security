import { temporaryNameAttempts } from "./helpers/temporary-name-attempts";
import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { basename, dirname, sep } from "node:path";
import letter from "@unicode/unicode-15.0.0/General_Category/Letter/regex.js";
import number from "@unicode/unicode-15.0.0/General_Category/Number/regex.js";
import type { Connection, Row, SqlValue } from "../../native/sqlite.mjs";
import {
  widePath,
  windowsJoin,
  windowsParts,
} from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { environment } from "./helpers/environment";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { encodePosixPath } from "./helpers/posix-path";
import { stringifyJson } from "./helpers/python-json";
import { resolvedPath } from "./helpers/resolve-path";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { writeScanLocalBytes } from "./helpers/scan-local-files";
import { lowercase } from "./helpers/unicode-case";
import { getScanFeedback } from "./workbench-feedback";
import {
  optionalText,
  userText,
  WorkbenchValidationError,
} from "./workbench-validation";

const windows = process.platform === "win32";
const append = (parent: string, name: string) =>
  parsedPath(windows ? windowsJoin(parent, name) : `${parent}/${name}`);
const pathKey = (path: string) => (windows ? lowercase(path) : path);

export function safeSegment(value: string): string {
  return (
    Array.from(value, (character) =>
      letter.test(character) ||
      number.test(character) ||
      "._-".includes(character)
        ? character
        : "-",
    )
      .join("")
      .replace(/^-+|-+$/gu, "") || "scan"
  );
}

export function compactTimestamp(): string {
  return (
    new Date()
      .toISOString()
      .slice(0, 19)
      .replaceAll("-", "")
      .replaceAll(":", "") + "Z"
  );
}

function temporaryDirectory(parent: string, prefix: string): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_";
  // tempfile.mkdtemp uses eight characters and the platform TMP_MAX retry count.
  for (let attempt = 0; attempt < temporaryNameAttempts; attempt++) {
    const suffix = Array.from(
      randomBytes(8),
      (byte) => alphabet[byte % alphabet.length],
    ).join("");
    const path = append(parent, prefix + suffix);
    try {
      if (windows) {
        const result = windowsBinding().createWindowsPrivateDirectory(
          widePath(path),
        );
        if (result.error !== 0) {
          const error = {
            winerror: result.error,
            ...(result.path === null ? {} : { path }),
          };
          throw Object.assign(new Error(filesystemErrorMessage(error)), error);
        }
      } else mkdirSync(encodePosixPath(path), { mode: 0o700 });
    } catch (error) {
      const failure = error as NodeJS.ErrnoException & { winerror?: number };
      if (
        failure.code === "EEXIST" ||
        failure.winerror === 80 ||
        failure.winerror === 183
      )
        continue;
      throw error;
    }
    return resolvedPath(path, false);
  }
  throw Object.assign(new Error("No usable temporary directory name found"), {
    code: "EEXIST",
    errno: 17,
  });
}

export function scanDiffIdentity(
  diffTarget: Readonly<Record<string, string>> | null,
): [string | null, string | null, string | null, string | null] {
  const required = (key: string) => {
    if (!Object.hasOwn(diffTarget!, key)) throw new Error(`'${key}'`);
    return diffTarget![key]!;
  };
  return diffTarget === null
    ? [null, null, null, null]
    : [
        required("kind"),
        required("baseRevision"),
        required("headRevision"),
        diffTarget["contentDigest"] ?? null,
      ];
}

export function storedDiffTarget(row: Row): Record<string, SqlValue> | null {
  if (!row.get("diff_target_kind")) return null;
  const target: Record<string, SqlValue> = {
    baseRevision: row.get("diff_base_revision"),
    headRevision: row.get("diff_head_revision"),
    kind: row.get("diff_target_kind"),
  };
  if (row.get("diff_content_digest"))
    target["contentDigest"] = row.get("diff_content_digest");
  return target;
}

export function archiveScan(
  connection: Connection,
  args: { archivedScanDir: string | null; archiveExisting: boolean },
  scanDir: string,
  timestamp: string,
  canonicalDirectory: (path: string) => string,
): void {
  let archivedScanDir =
    args.archivedScanDir === null
      ? null
      : canonicalDirectory(
          expandHome(parsedPath(args.archivedScanDir), environment("HOME")),
        );
  if (
    archivedScanDir !== null &&
    (!args.archiveExisting ||
      pathKey(dirname(archivedScanDir)) !== pathKey(dirname(scanDir)) ||
      !basename(archivedScanDir).startsWith(`${basename(scanDir)}.previous-`))
  )
    throw new WorkbenchValidationError(
      "The archived scan must be a previous sibling of the scan directory.",
    );
  const previousScan = connection
    .prepare("SELECT id, status FROM scans WHERE scan_dir = ?")
    .get([scanDir]);
  if (previousScan === undefined) return;
  if (!args.archiveExisting)
    throw new WorkbenchValidationError(
      "The scan artifact directory belongs to an existing scan. Use --archive-existing to preserve that scan and start a new one.",
    );
  if (previousScan.get("status") === "running")
    throw new WorkbenchValidationError(
      "Cannot archive the output of a running scan.",
    );
  const artifacts = connection
    .prepare("SELECT kind, path FROM scan_artifacts WHERE scan_id = ?")
    .all([previousScan.get("id")]);
  if (archivedScanDir === null) {
    if (artifacts.length)
      throw new WorkbenchValidationError(
        "The archived scan directory is required to preserve existing scan artifacts.",
      );
    archivedScanDir = temporaryDirectory(
      dirname(scanDir),
      `${basename(scanDir)}.previous-`,
    );
  }
  connection
    .prepare("UPDATE scans SET scan_dir = ?, updated_at = ? WHERE id = ?")
    .run([archivedScanDir, timestamp, previousScan.get("id")]);
  const parts = (path: string) => {
    const parsed = parsedPath(path);
    const anchor = windows
      ? windowsParts(parsed).slice(0, 2).join("")
      : parsed.startsWith("//")
        ? "//"
        : parsed.startsWith("/")
          ? "/"
          : "";
    return [
      anchor,
      ...parsed
        .slice(anchor.length)
        .split(sep)
        .filter((part) => part && part !== "."),
    ];
  };
  const root = parts(scanDir);
  for (const artifact of artifacts) {
    const path = parts(artifact.get("path") as string);
    if (
      !root.every(
        (part, index) =>
          path[index] !== undefined && pathKey(part) === pathKey(path[index]!),
      )
    )
      continue;
    const relative = path.slice(root.length).join(sep);
    connection
      .prepare(
        "UPDATE scan_artifacts SET path = ? WHERE scan_id = ? AND kind = ?",
      )
      .run([
        append(archivedScanDir, relative),
        previousScan.get("id"),
        artifact.get("kind"),
      ]);
  }
}

export interface RunningScan {
  scanId: string;
  workspace: Row;
  target: string;
  scope: string;
  diffTarget: Readonly<Record<string, string>> | null;
  targetIdentity: readonly [
    string,
    string | null,
    bigint | string,
    bigint | string,
  ];
  targetRoot: string;
  targetSummary: string | null;
  scopeFileCount: bigint | number;
  timestamp: string;
  handoffStatus?: string;
  model?: string | null;
  reasoningEffort?: string | null;
  scanDir?: string | null;
}

export function insertRunningScan(
  connection: Connection,
  args: RunningScan,
): string {
  const {
    scanId,
    workspace,
    target,
    scope,
    diffTarget,
    targetIdentity,
    targetRoot,
    targetSummary,
    scopeFileCount,
    timestamp,
    handoffStatus = "pending",
    model = null,
    reasoningEffort = null,
  } = args;
  let scanDir = args.scanDir ?? null;
  const nativeScan = scanDir === null;
  const userContext = userText(workspace.get("user_context") as string | null);
  if (scanDir === null)
    scanDir = temporaryDirectory(
      targetRoot,
      `${safeSegment(targetIdentity[0])}_${compactTimestamp()}_`,
    );
  connection
    .prepare(
      `
    INSERT INTO scans (
      id, workspace_id, target_id, target_path, target_revision, target_snapshot_digest,
      target_device, target_inode, scope, mode, user_context,
      deep_scan_owner_thread_id, diff_target_kind, diff_base_revision,
      diff_head_revision, diff_content_digest, target_summary, scan_dir, model,
      reasoning_effort, status, phase, handoff_status, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      'running', 'preflight', ?, ?, ?, ?)
  `,
    )
    .run([
      scanId,
      workspace.get("id"),
      workspace.get("target_id"),
      target,
      ...targetIdentity,
      scope,
      workspace.get("default_mode"),
      userContext,
      workspace.get("default_mode") === "deep"
        ? workspace.get("thread_id")
        : null,
      ...scanDiffIdentity(
        diffTarget && Object.keys(diffTarget).length ? diffTarget : null,
      ),
      targetSummary,
      scanDir,
      optionalText(model, 200),
      optionalText(reasoningEffort, 32),
      handoffStatus,
      timestamp,
      timestamp,
      timestamp,
    ]);
  connection
    .prepare(
      `
    INSERT INTO scan_progress (
      scan_id, scope_file_count, review_items_total, review_items_completed,
      reportable_findings_count, updated_at
    ) VALUES (?, ?, 0, 0, 0, ?)
  `,
    )
    .run([scanId, scopeFileCount, timestamp]);
  connection
    .prepare(
      "UPDATE workspaces SET active_scan_id = ?, updated_at = ? WHERE id = ?",
    )
    .run([scanId, timestamp, workspace.get("id")]);
  if (nativeScan) {
    const scan = connection
      .prepare("SELECT * FROM scans WHERE id = ?")
      .get([scanId])!;
    const falsePositives = getScanFeedback(connection, scan).falsePositives;
    if (falsePositives.length)
      writeScanLocalBytes(
        scanDir,
        "artifacts/01_context/false_positive_feedback.json",
        Buffer.from(
          stringifyJson(falsePositives, { compact: true, allowNan: false }) +
            "\n",
        ),
      );
  }
  return scanId;
}
