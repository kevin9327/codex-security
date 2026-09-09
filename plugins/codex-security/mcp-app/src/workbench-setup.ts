import { isAbsolute, parse } from "node:path";
import type { Connection, Row } from "../../native/sqlite.mjs";
import { windowsParts } from "../../native/windows-files.mjs";
import { environment } from "./helpers/environment";
import { fileInfo } from "./helpers/helper-files";
import { SymlinkLoopError } from "./helpers/posix-path";
import { appendPath, pathKey, relativePath } from "./helpers/rank-selection";
import { resolvedPath } from "./helpers/resolve-path";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { UnicodeDecodeError } from "./helpers/utf8";
import { ensureSecurityTarget, stateDir } from "./workbench-db";
import { gitBytes, gitOutput } from "./workbench-git";
import { TargetInspectionError } from "./workbench-git-snapshot";
import { safeSegment } from "./workbench-scan-start";
import {
  gitTargetMetadata,
  requireGitWorktreeHead,
  worktreeContentDigest,
  type GitTargetMetadata,
} from "./workbench-target";
import {
  optionalText,
  requireUuid,
  userContextArgument,
  WorkbenchValidationError,
} from "./workbench-validation";

const windows = process.platform === "win32";
const absolute = (path: string) =>
  windows ? windowsParts(path).slice(0, 2).every(Boolean) : isAbsolute(path);
const resolve = (path: string) =>
  resolvedPath(path, false, { preserveRelativeErrors: true });
const expanded = (path: string) =>
  expandHome(parsedPath(path), environment("HOME"));
const emptyGitTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

export function requireTarget(value: string): string {
  const path = expanded(value);
  if (!absolute(path))
    throw new WorkbenchValidationError(
      "Scan target must be an absolute local directory path.",
    );
  const target = resolve(path);
  if (!fileInfo(target)?.isDirectory())
    throw new WorkbenchValidationError(
      `Scan target is not a readable local directory: ${target}`,
    );
  return target;
}

export interface InspectedTarget {
  displayName: string;
  targetMetadata: GitTargetMetadata;
  targetPath: string;
}
export function inspectTarget(targetPath: string): InspectedTarget {
  const target = requireTarget(targetPath);
  return {
    displayName: parse(target).base,
    targetMetadata: gitTargetMetadata(target),
    targetPath: target,
  };
}

export function resolveGitCommit(
  target: string,
  revision: string,
  label: string,
): string {
  const value = optionalText(revision, 512);
  if (!value) throw new WorkbenchValidationError(`${label} is required.`);
  const resolved = gitOutput(parsedPath(target), [
    "rev-parse",
    "--verify",
    "--end-of-options",
    `${value}^{commit}`,
  ]);
  if (resolved === null)
    throw new WorkbenchValidationError(
      `${label} does not resolve to a local Git commit: ${value}`,
    );
  return resolved;
}

export type DiffTarget = {
  kind: string;
  baseRevision: string;
  headRevision: string;
  contentDigest?: string;
};
export function requireDiffTarget(
  target: string,
  kind: string | null,
  baseRevision: string | null,
  headRevision: string | null,
  contentDigest: string | null,
): DiffTarget {
  target = parsedPath(target);
  const currentHead = requireReviewChangesTarget(target);
  if (kind === null || !["working_tree", "commit", "range"].includes(kind))
    throw new WorkbenchValidationError(
      "Choose which Git changes to review before starting a diff scan.",
    );
  if (kind === "working_tree") {
    const base = resolveGitCommit(
      target,
      baseRevision || "HEAD",
      "Working-tree base",
    );
    const head = resolveGitCommit(
      target,
      headRevision || currentHead,
      "Working-tree HEAD",
    );
    const currentDigest = worktreeContentDigest(target);
    if (base !== currentHead || head !== currentHead)
      throw new WorkbenchValidationError(
        "Repository HEAD changed after these working-tree changes were selected. Select Uncommitted changes again.",
      );
    if (contentDigest && contentDigest !== currentDigest)
      throw new WorkbenchValidationError(
        "Working-tree contents changed after they were selected. Select Uncommitted changes again.",
      );
    return {
      kind,
      baseRevision: currentHead,
      headRevision: currentHead,
      contentDigest: currentDigest,
    };
  }
  if (kind === "commit") {
    const head = resolveGitCommit(target, headRevision || "", "Commit");
    const commit = gitBytes(target, ["cat-file", "-p", head]);
    if (commit === null)
      throw new WorkbenchValidationError(
        `Commit is not available in the local checkout: ${head}`,
      );
    const parentLine = commit
      .toString("latin1")
      .split(/\r\n|\r|\n/u)
      .find((line) => line.startsWith("parent "));
    let parent = emptyGitTree;
    if (parentLine !== undefined) {
      const bytes = Buffer.from(parentLine.slice(7), "latin1");
      const invalid = bytes.findIndex((byte) => byte > 127);
      if (invalid !== -1)
        throw new UnicodeDecodeError(
          "ascii",
          bytes,
          invalid,
          invalid + 1,
          "ordinal not in range(128)",
        );
      parent = resolveGitCommit(
        target,
        bytes.toString("ascii"),
        "Commit parent",
      );
    }
    if (baseRevision && baseRevision !== parent) {
      const suppliedBase =
        baseRevision === emptyGitTree
          ? baseRevision
          : resolveGitCommit(target, baseRevision, "Commit base");
      if (suppliedBase !== parent)
        throw new WorkbenchValidationError(
          "Commit base revision must match the selected commit's parent.",
        );
    }
    return { kind, baseRevision: parent, headRevision: head };
  }
  const base = resolveGitCommit(target, baseRevision || "", "Base revision");
  const head = resolveGitCommit(target, headRevision || "", "Head revision");
  if (base === head)
    throw new WorkbenchValidationError(
      "Base and head revisions must identify different commits.",
    );
  return { kind, baseRevision: base, headRevision: head };
}

export interface SetupArguments {
  targetPath: string;
  scope: string;
  mode: string;
  diffTargetKind: string | null;
  diffBaseRevision: string | null;
  diffHeadRevision: string | null;
  diffContentDigest: string | null;
}
export interface InspectedSetup {
  diffTarget: DiffTarget | null;
  scope: string;
  target: InspectedTarget;
}
export function inspectSetupValues(
  targetPath: string,
  scope: string,
  mode: string,
  diffTargetKind: string | null,
  diffBaseRevision: string | null,
  diffHeadRevision: string | null,
  diffContentDigest: string | null,
): InspectedSetup {
  const target = requireTarget(targetPath);
  requireScannableTarget(target);
  const normalizedScope = requireScope(scope, mode, target);
  if (mode === "diff" && normalizedScope !== ".")
    throw new WorkbenchValidationError(
      "Review changes requires the whole target; use scope '.'.",
    );
  if (
    mode !== "diff" &&
    [
      diffTargetKind,
      diffBaseRevision,
      diffHeadRevision,
      diffContentDigest,
    ].some((value) => value !== null)
  )
    throw new WorkbenchValidationError(
      "A Git diff target requires Review changes mode.",
    );
  const diffTarget =
    mode === "diff"
      ? requireDiffTarget(
          target,
          diffTargetKind,
          diffBaseRevision,
          diffHeadRevision,
          diffContentDigest,
        )
      : null;
  return {
    diffTarget,
    scope: normalizedScope,
    target: inspectTarget(target),
  };
}
export function inspectSetup(args: SetupArguments): InspectedSetup {
  return inspectSetupValues(
    args.targetPath,
    args.scope,
    args.mode,
    args.diffTargetKind,
    args.diffBaseRevision,
    args.diffHeadRevision,
    args.diffContentDigest,
  );
}

export function requireReviewChangesTarget(target: string): string {
  target = parsedPath(target);
  const revision = requireGitWorktreeHead(target);
  const repositoryRoot = gitOutput(target, ["rev-parse", "--show-toplevel"]);
  if (
    repositoryRoot === null ||
    pathKey(resolve(repositoryRoot)) !== pathKey(target)
  )
    throw new WorkbenchValidationError(
      "Review changes requires the checked-out Git repository root as the target.",
    );
  return revision;
}
export function requireScannableTarget(target: string): void {
  const metadata = gitTargetMetadata(parsedPath(target));
  if (metadata.isGit && !metadata.isWorktree)
    throw new WorkbenchValidationError(
      "Codex Security requires a checked-out worktree, not a bare Git repository.",
    );
}
export function requireScope(
  scope: string,
  mode: string,
  target: string,
): string {
  target = parsedPath(target);
  const value = optionalText(scope) || ".";
  const requested = parsedPath(value);
  if (value.includes("\\") && (!windows || !absolute(requested)))
    throw new WorkbenchValidationError(
      "Scan scope must use repository-relative POSIX paths.",
    );
  if (requested.split(windows ? /[/\\]/u : /\//u).includes(".."))
    throw new WorkbenchValidationError(
      "Scan scope must stay inside the scanned target.",
    );
  let resolvedScope: string;
  try {
    const candidate = absolute(requested)
      ? requested
      : appendPath(target, requested);
    // pathlib.resolve raises ValueError for NULs before the later scope checks.
    if (candidate.includes("\0"))
      throw new WorkbenchValidationError(
        "Scan scope must stay inside the scanned target.",
      );
    resolvedScope = resolve(candidate);
  } catch (error) {
    if (!(error instanceof SymlinkLoopError)) throw error;
    throw new WorkbenchValidationError(
      "Scan scope must stay inside the scanned target.",
    );
  }
  const relative = relativePath(resolvedScope, target);
  if (relative === undefined)
    throw new WorkbenchValidationError(
      "Scan scope must stay inside the scanned target.",
    );
  const normalized = relative || ".";
  if (mode === "deep" && normalized !== ".")
    throw new WorkbenchValidationError(
      "Deep Scan is repository-wide and cannot use a scoped path.",
    );
  if (!fileInfo(resolvedScope)?.isDirectory())
    throw new WorkbenchValidationError(
      "Scan scope must reference an existing directory inside the target.",
    );
  return normalized;
}

export interface WorkspaceArguments
  extends Omit<SetupArguments, "targetPath" | "scope"> {
  workspaceId: string;
  targetPath: string | null;
  scope: string | null;
  targetSummary: string | null;
  userContext: string | null;
  userContextStdin?: boolean;
}
export interface CreateWorkspaceArguments extends WorkspaceArguments {
  threadId: string | null;
  targetTitle: string | null;
}
export interface WorkspaceCallbacks<T> {
  now: () => string;
  readStdin: () => string;
  workspaceState: (connection: Connection, workspaceId: string) => T;
}
export function createWorkspace<T>(
  connection: Connection,
  args: CreateWorkspaceArguments,
  callbacks: WorkspaceCallbacks<T>,
): T {
  const workspaceId = requireUuid(args.workspaceId, "workspace-id");
  const timestamp = callbacks.now();
  let targetPath = optionalText(args.targetPath, 4096);
  let defaultScope = optionalText(args.scope, 4096) || ".";
  let diffTargetKind = args.mode === "diff" ? args.diffTargetKind : null;
  let diffBaseRevision =
    args.mode === "diff" ? optionalText(args.diffBaseRevision, 512) : null;
  let diffHeadRevision =
    args.mode === "diff" ? optionalText(args.diffHeadRevision, 512) : null;
  let diffContentDigest =
    args.mode === "diff" ? optionalText(args.diffContentDigest, 128) : null;
  if (targetPath) {
    try {
      const inspected = inspectSetupValues(
        targetPath,
        defaultScope,
        args.mode,
        diffTargetKind,
        diffBaseRevision,
        diffHeadRevision,
        diffContentDigest,
      );
      targetPath = inspected.target.targetPath;
      defaultScope = inspected.scope;
      if (inspected.diffTarget) {
        diffTargetKind = inspected.diffTarget.kind;
        diffBaseRevision = inspected.diffTarget.baseRevision;
        diffHeadRevision = inspected.diffTarget.headRevision;
        diffContentDigest = inspected.diffTarget.contentDigest ?? null;
      }
    } catch (error) {
      if (
        !(error instanceof WorkbenchValidationError) &&
        !(error instanceof TargetInspectionError)
      )
        throw error;
    }
  }
  connection.transaction(() => {
    const targetId =
      targetPath === null
        ? null
        : ensureSecurityTarget(connection, targetPath, callbacks.now);
    connection
      .prepare(
        `
      INSERT INTO workspaces (
        id, thread_id, target_id, target_path, target_title, target_summary,
        default_scope, default_mode, user_context, diff_target_kind,
        diff_base_revision, diff_head_revision, diff_content_digest, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
      )
      .run([
        workspaceId,
        optionalText(args.threadId, 512),
        targetId,
        targetPath,
        optionalText(args.targetTitle, 200),
        optionalText(args.targetSummary, 2400),
        defaultScope,
        args.mode,
        userContextArgument(args, callbacks.readStdin),
        diffTargetKind,
        diffBaseRevision,
        diffHeadRevision,
        diffContentDigest,
        timestamp,
        timestamp,
      ]);
  });
  return callbacks.workspaceState(connection, workspaceId);
}

export function saveWorkspace<T>(
  connection: Connection,
  args: WorkspaceArguments & SetupArguments,
  callbacks: WorkspaceCallbacks<T> & {
    requireWorkspace: (connection: Connection, workspaceId: string) => Row;
  },
): T {
  const workspace = callbacks.requireWorkspace(connection, args.workspaceId);
  if (workspace.get("active_scan_id"))
    throw new WorkbenchValidationError(
      "This workspace already has a scan. Open a new workspace to change setup.",
    );
  const inspected = inspectSetup(args);
  const target = inspected.target.targetPath;
  const targetChanged = workspace.get("target_path") !== target;
  const targetTitle = targetChanged
    ? parse(target).base
    : workspace.get("target_title");
  let targetSummary =
    args.targetSummary !== null
      ? optionalText(args.targetSummary, 2400)
      : targetChanged
        ? null
        : workspace.get("target_summary");
  const diffTarget = inspected.diffTarget;
  if (diffTarget && !targetSummary)
    targetSummary = diffTargetSummary(diffTarget);
  const timestamp = callbacks.now();
  connection.transaction(() => {
    const targetId = ensureSecurityTarget(connection, target, callbacks.now);
    const updated = connection
      .prepare(
        `
      UPDATE workspaces
      SET target_id = ?, target_path = ?, target_title = ?, target_summary = ?, default_scope = ?,
        default_mode = ?, user_context = ?, diff_target_kind = ?,
        diff_base_revision = ?, diff_head_revision = ?, diff_content_digest = ?,
        submitted = 1, updated_at = ?
      WHERE id = ? AND active_scan_id IS NULL
    `,
      )
      .run([
        targetId,
        target,
        targetTitle,
        targetSummary,
        inspected.scope,
        args.mode,
        userContextArgument(args, callbacks.readStdin),
        diffTarget?.kind ?? null,
        diffTarget?.baseRevision ?? null,
        diffTarget?.headRevision ?? null,
        diffTarget?.contentDigest ?? null,
        timestamp,
        workspace.get("id"),
      ]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "This workspace already has a scan. Open a new workspace to change setup.",
      );
  });
  return callbacks.workspaceState(connection, workspace.get("id") as string);
}

export function scanTargetRoot(
  scanRoot: string | null,
  target: string,
): string {
  target = parsedPath(target);
  const root = scanRoot
    ? resolve(expanded(scanRoot))
    : appendPath(stateDir(), "scans");
  const targetRoot = resolve(
    appendPath(root, safeSegment(target === "." ? "" : parse(target).base)),
  );
  if (relativePath(targetRoot, target) !== undefined)
    throw new WorkbenchValidationError(
      "The scan artifact directory must be outside the selected target.",
    );
  return targetRoot;
}
export function diffTargetSummary(diffTarget: DiffTarget): string {
  const short = (value: string) => Array.from(value).slice(0, 7).join("");
  if (diffTarget.kind === "working_tree") return "Uncommitted changes";
  if (diffTarget.kind === "commit")
    return `Commit ${short(diffTarget.headRevision)}`;
  return `${short(diffTarget.baseRevision)}…${short(diffTarget.headRevision)}`;
}
