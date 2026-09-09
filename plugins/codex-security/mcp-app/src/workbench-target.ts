import { createHash, randomUUID, type Hash } from "node:crypto";
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readlinkSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { isAbsolute, sep } from "node:path";
import { getSystemErrorName } from "node:util";
import { readDescriptor } from "../../native/binding.mjs";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsParts,
} from "../../native/windows-files.mjs";
import { unixBinding, windowsBinding } from "./native";
import {
  decodeFilename,
  encodeFilename,
  gitBytes,
  gitCommand,
  gitOutput,
  type GitContext,
} from "./workbench-git";
import {
  descendants,
  gitDirectorySnapshotPaths,
  gitWorktreeContext,
  TargetInspectionError,
  updateDigestField,
  updateDigestFieldHeader,
} from "./workbench-git-snapshot";
import { temporaryDirectoryParent } from "./workbench-temporary";
import { environment } from "./helpers/environment";
import { fileInfo } from "./helpers/helper-files";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { encodePosixPath, SymlinkLoopError } from "./helpers/posix-path";
import { pythonRepr } from "./helpers/python-json";
import {
  appendPath,
  comparePaths,
  nulFields,
  pathKey,
  relativePath,
} from "./helpers/rank-selection";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { resolvedPath } from "./helpers/resolve-path";
import { decodePythonUtf8, UnicodeDecodeError } from "./helpers/utf8";
import { windowsFileIdentity } from "./helpers/windows-scan-files";

const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const osError = (error: unknown) =>
  (error as { errno?: number }).errno !== undefined ||
  (error as { winerror?: number }).winerror !== undefined;
const metadata = (path: string) =>
  windows
    ? windowsFiles().stat(widePath(path), false)
    : lstatSync(encodePosixPath(path));
const nameSurrogate = (info: ReturnType<typeof metadata>) =>
  ((info as { reparseTag?: number }).reparseTag ?? 0) & 0x20000000;
const readlink = (path: string) =>
  windows
    ? pathText(windowsFiles().readlink(widePath(path)))
    : decodeFilename(
        readlinkSync(encodePosixPath(path), { encoding: "buffer" }),
      );
const trim = (value: string) =>
  value.replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );

function relativeTo(path: string, target: string): string {
  const relative = relativePath(path, target);
  if (relative === undefined)
    throw new Error(
      `${pythonRepr(path)} is not in the subpath of ${pythonRepr(target)}`,
    );
  return relative || ".";
}

function fileReader(path: string) {
  const descriptor = windows ? undefined : openSync(encodePosixPath(path), "r");
  return windows
    ? windowsFiles().openRead(widePath(path))
    : {
        size: () => fstatSync(descriptor!, { bigint: true }).size,
        read: (buffer: Buffer) =>
          readDescriptor(descriptor!, buffer, 0, buffer.length, null),
        close: () => closeSync(descriptor!),
      };
}

function fileContent(path: string): [bigint, Buffer] {
  const digest = createHash("sha256");
  let size = 0n;
  const reader = fileReader(path);
  try {
    const buffer = Buffer.alloc(1024 * 1024);
    for (;;) {
      const count = reader.read(buffer);
      if (!count) break;
      digest.update(buffer.subarray(0, count));
      size += BigInt(count);
    }
  } finally {
    reader.close();
  }
  return [size, digest.digest()];
}

function updateDigestFieldFromGit(
  digest: Hash,
  label: Buffer,
  repository: string,
  args: readonly string[],
  context: GitContext,
): boolean {
  const directory = temporaryDirectoryParent();
  const path = appendPath(directory, `codex-security-git-${randomUUID()}`);
  if (windows) windowsFiles().writeFile(widePath(path), Buffer.alloc(0), true);
  else closeSync(openSync(encodePosixPath(path), "wx", 0o600));
  try {
    if (
      gitCommand(repository, args, { ...context, stdoutPath: path })
        .returnCode !== 0
    )
      return false;
    const reader = fileReader(path);
    try {
      updateDigestFieldHeader(digest, label, reader.size());
      const buffer = Buffer.alloc(1024 * 1024);
      for (;;) {
        const count = reader.read(buffer);
        if (!count) break;
        digest.update(buffer.subarray(0, count));
      }
    } finally {
      reader.close();
    }
    return true;
  } finally {
    if (windows) windowsFiles().unlink(widePath(path));
    else unlinkSync(encodePosixPath(path));
  }
}

/** Enumerate source paths without following name-surrogate reparse points. */
export function sourceDirectorySnapshotPaths(target: string): string[] {
  const paths: string[] = [],
    pending = [parsedPath(target)];
  while (pending.length) {
    const parent = pending.pop()!;
    let names: string[];
    if (windows)
      names = windowsFiles()
        .entriesWithTypes(widePath(parent))
        .map((entry) => pathText(entry.name));
    else {
      const result = unixBinding().directoryEntries(
        encodePosixPath(parent),
        false,
      );
      if (result.errno) {
        const error = { errno: result.errno, path: parent };
        throw Object.assign(new Error(filesystemErrorMessage(error)), error, {
          code: getSystemErrorName(-result.errno),
        });
      }
      names = result.value.map((entry) => decodeFilename(entry.name));
    }
    for (const name of names) {
      if (name === ".git") continue;
      const path = appendPath(parent, name);
      paths.push(path);
      const info = metadata(path);
      if (info.isDirectory() && !nameSurrogate(info)) pending.push(path);
    }
  }
  return paths.sort(comparePaths);
}

export function directoryContentDigest(
  target: string,
  options: { excluded?: readonly string[]; includeIgnored?: boolean } = {},
): string {
  target = parsedPath(target);
  const excluded = (options.excluded ?? []).flatMap((path) => {
    const relative = relativePath(parsedPath(path), target);
    return relative === undefined ? [] : [pathKey(relative || ".")];
  });
  const paths =
    (options.includeIgnored
      ? sourceDirectorySnapshotPaths(target)
      : gitDirectorySnapshotPaths(target)) ??
    [...descendants(target)].sort(comparePaths);
  const digest = createHash("sha256");
  const field = (label: string, value: string | Buffer) =>
    updateDigestField(
      digest,
      Buffer.from(label),
      Buffer.isBuffer(value) ? value : Buffer.from(value),
    );
  field("format", "codex-security-directory/v1");
  for (const path of paths) {
    const relative = relativeTo(path, target),
      key = pathKey(relative);
    if (
      excluded.some(
        (excluded) =>
          excluded === "." ||
          key === excluded ||
          key.startsWith(excluded + "/"),
      )
    )
      continue;
    let info: ReturnType<typeof metadata>;
    try {
      info = metadata(path);
    } catch (error) {
      if (!osError(error)) throw error;
      throw new TargetInspectionError(
        `Could not read local file: ${relative.split("/").join(sep)}`,
      );
    }
    field("path", encodeFilename(relative));
    field("mode", String(info.mode & 0o7777));
    if (
      info.isSymbolicLink() ||
      (options.includeIgnored && nameSurrogate(info))
    ) {
      field("kind", "symlink");
      field("content", encodeFilename(readlink(path)));
    } else if (info.isDirectory()) field("kind", "directory");
    else if (info.isFile()) {
      let content: [bigint, Buffer];
      try {
        content = fileContent(path);
      } catch (error) {
        if (!osError(error)) throw error;
        throw new TargetInspectionError(
          `Could not read local file: ${relative.split("/").join(sep)}`,
        );
      }
      field("kind", "file");
      field("size", String(content[0]));
      field("content-sha256", content[1]);
    } else
      throw new TargetInspectionError(
        `Unsupported local file type: ${relative.split("/").join(sep)}`,
      );
  }
  return `codex-security-snapshot/v1:sha256:${digest.digest("hex")}`;
}

export function directorySnapshotRegularFileCount(target: string): number {
  target = parsedPath(target);
  const paths =
    gitDirectorySnapshotPaths(target) ??
    [...descendants(target)].sort(comparePaths);
  let count = 0;
  for (const path of paths) {
    let info: ReturnType<typeof metadata>;
    try {
      info = metadata(path);
    } catch (error) {
      if (!osError(error)) throw error;
      throw new TargetInspectionError(
        `Could not inspect local file: ${relativeTo(path, target).split("/").join(sep)}`,
      );
    }
    if (info.isFile()) count++;
  }
  return count;
}

export function gitSubmoduleEntries(target: string): [string, string][] {
  const [repository, pathspec] = gitWorktreeContext(parsedPath(target));
  const staged = gitBytes(repository, [
    "ls-files",
    "--stage",
    "-z",
    "--",
    pathspec,
  ]);
  const invalid = () =>
    new TargetInspectionError(
      "Could not inspect Git submodules in the selected working tree.",
    );
  if (staged === null) throw invalid();
  const entries: [string, string][] = [];
  for (const record of nulFields(staged).filter((record) => record.length)) {
    const tab = record.indexOf(9),
      first = record.indexOf(32),
      second = record.indexOf(32, first + 1);
    if (tab < 0 || first < 0 || second < 0 || first > tab || second > tab)
      throw invalid();
    if (!record.subarray(0, first).equals(Buffer.from("160000"))) continue;
    const objectId = record.subarray(first + 1, second);
    const nonAscii = objectId.findIndex((byte) => byte > 127);
    if (nonAscii !== -1)
      throw new UnicodeDecodeError(
        "ascii",
        objectId,
        nonAscii,
        nonAscii + 1,
        "ordinal not in range(128)",
      );
    entries.push([
      appendPath(repository, decodeFilename(record.subarray(tab + 1))),
      objectId.toString("ascii"),
    ]);
  }
  return entries;
}

export function gitSubmodulePaths(target: string): string[] {
  return gitSubmoduleEntries(target).map(([path]) => path);
}

export function requireCleanSubmoduleWorktrees(target: string): void {
  target = parsedPath(target);
  for (const [submodule, expectedRevision] of gitSubmoduleEntries(target)) {
    const relative = relativeTo(submodule, target).split("/").join(sep);
    if (fileInfo(submodule) === undefined) continue;
    try {
      metadata(appendPath(submodule, ".git"));
    } catch (error) {
      if ((error as { code?: string }).code === "ENOENT") continue;
      throw error;
    }
    const root = gitOutput(submodule, ["rev-parse", "--show-toplevel"]);
    let initialized: boolean;
    try {
      initialized =
        root !== null &&
        pathKey(resolvedPath(root, false)) ===
          pathKey(resolvedPath(submodule, false));
    } catch (error) {
      if (!osError(error)) throw error;
      initialized = false;
    }
    if (!initialized)
      throw new TargetInspectionError(
        `Could not inspect initialized Git submodule contents: ${relative}`,
      );
    if (gitOutput(submodule, ["rev-parse", "HEAD"]) !== expectedRevision)
      throw new TargetInspectionError(
        `Initialized Git submodules must be checked out at the revision recorded by the parent repository: ${relative}`,
      );
    const status = gitBytes(submodule, [
      "status",
      "--porcelain=v1",
      "-z",
      "--untracked-files=all",
      "--ignore-submodules=none",
    ]);
    if (status === null)
      throw new TargetInspectionError(
        `Could not inspect Git submodule contents: ${relative}`,
      );
    if (status.length)
      throw new TargetInspectionError(
        `Dirty Git submodules are not supported for remediation integrity checks: ${relative}`,
      );
    requireCleanSubmoduleWorktrees(submodule);
  }
}

export function worktreeContentDigestForContext(
  repository: string,
  pathspec: string,
  context: GitContext = {},
): string {
  repository = parsedPath(repository);
  context = {
    gitDir:
      context.gitDir === undefined ? undefined : parsedPath(context.gitDir),
    workTree:
      context.workTree === undefined ? undefined : parsedPath(context.workTree),
  };
  const digest = createHash("sha256");
  const field = (label: string, value: string | Buffer) =>
    updateDigestField(
      digest,
      Buffer.from(label),
      Buffer.isBuffer(value) ? value : Buffer.from(value),
    );
  field("format", "codex-security-snapshot/v1");
  const tracked = updateDigestFieldFromGit(
    digest,
    Buffer.from("tracked-diff"),
    repository,
    [
      "diff",
      "--binary",
      "--full-index",
      "--no-ext-diff",
      "--no-textconv",
      "--ignore-submodules=none",
      "HEAD",
      "--",
      pathspec,
    ],
    context,
  );
  const untracked = gitBytes(
    repository,
    ["ls-files", "--others", "--exclude-standard", "-z", "--", pathspec],
    context,
  );
  if (!tracked || untracked === null)
    throw new TargetInspectionError(
      "Could not snapshot the selected working-tree changes.",
    );
  for (const raw of nulFields(untracked)
    .filter((path) => path.length)
    .sort(Buffer.compare)) {
    const relative = decodeFilename(raw),
      path = appendPath(context.workTree ?? repository, relative);
    let info: ReturnType<typeof metadata>;
    try {
      info = metadata(path);
    } catch (error) {
      if (!osError(error)) throw error;
      throw new TargetInspectionError(
        `Could not read untracked file: ${relative}`,
      );
    }
    field("untracked-path", raw);
    field("untracked-mode", String(info.mode & 0o7777));
    if (info.isSymbolicLink()) {
      field("untracked-kind", "symlink");
      field("untracked-content", encodeFilename(readlink(path)));
    } else if (info.isDirectory()) {
      field("untracked-kind", "directory");
      field(
        "untracked-content",
        directoryContentDigest(resolvedPath(path, false)),
      );
    } else if (info.isFile()) {
      let content: [bigint, Buffer];
      try {
        content = fileContent(path);
      } catch (error) {
        if (!osError(error)) throw error;
        throw new TargetInspectionError(
          `Could not read untracked file: ${relative}`,
        );
      }
      field("untracked-kind", "file");
      field("untracked-size", String(content[0]));
      field("untracked-content-sha256", content[1]);
    } else
      throw new TargetInspectionError(
        `Unsupported untracked file type: ${relative}`,
      );
  }
  return `codex-security-snapshot/v1:sha256:${digest.digest("hex")}`;
}

export function worktreeContentDigest(target: string): string {
  target = parsedPath(target);
  requireCleanSubmoduleWorktrees(target);
  return worktreeContentDigestForContext(...gitWorktreeContext(target));
}

export interface GitTargetMetadata {
  hasHead: boolean;
  isGit: boolean;
  isWorktree: boolean;
  reviewChangesSupported: boolean;
  branch?: string | null;
  detachedHead?: boolean;
  commitSubject?: string | null;
  revision?: string;
  shortRevision?: string;
}
export function gitRevision(target: string): string {
  return gitOutput(parsedPath(target), ["rev-parse", "HEAD"]) || "unversioned";
}
export function gitTargetMetadata(target: string): GitTargetMetadata {
  target = parsedPath(target);
  const isGit = gitOutput(target, ["rev-parse", "--git-dir"]) !== null;
  const isWorktree =
    gitOutput(target, ["rev-parse", "--is-inside-work-tree"]) === "true";
  const revision = gitOutput(target, ["rev-parse", "--verify", "HEAD"]);
  const root = isWorktree
    ? gitOutput(target, ["rev-parse", "--show-toplevel"])
    : null;
  const supported =
    isGit &&
    isWorktree &&
    revision !== null &&
    root !== null &&
    pathKey(resolvedPath(root, false)) === pathKey(target);
  const result: GitTargetMetadata = {
    hasHead: revision !== null,
    isGit,
    isWorktree,
    reviewChangesSupported: supported,
  };
  if (!isGit) return result;
  const branch = gitOutput(target, [
    "symbolic-ref",
    "--quiet",
    "--short",
    "HEAD",
  ]);
  Object.assign(result, {
    branch,
    detachedHead: revision !== null && branch === null,
  });
  if (revision !== null) {
    const subject = gitBytes(target, ["show", "-s", "--format=%s", "HEAD"]);
    Object.assign(result, {
      commitSubject: trim(decodePythonUtf8(subject ?? Buffer.alloc(0))) || null,
      revision,
      shortRevision: Array.from(revision).slice(0, 7).join(""),
    });
  }
  return result;
}

export function serializeFilesystemIdentity(value: bigint): bigint | string {
  return -(1n << 63n) <= value && value < 1n << 63n
    ? value
    : `stat:${value.toString(16)}`;
}
export function storedFilesystemIdentityMatches(
  stored: unknown,
  current: bigint,
): boolean {
  const serialized = serializeFilesystemIdentity(current);
  if (typeof serialized === "string") return stored === serialized;
  if (typeof stored === "boolean") return BigInt(stored) === serialized;
  if (typeof stored === "number")
    return Number.isInteger(stored) && BigInt(stored) === serialized;
  return stored === serialized;
}

export function filesystemIdentity(path: string): { dev: bigint; ino: bigint } {
  if (!windows) return statSync(encodePosixPath(path), { bigint: true });
  const [dev, ino] = windowsFileIdentity(
    windowsFiles().identity(widePath(path)),
  );
  return { dev, ino };
}

export function scanTargetIdentity(
  target: string,
  diffTarget: Readonly<Record<string, string>> | null,
  info?: { dev: bigint; ino: bigint } | null,
): [string, string | null, bigint | string, bigint | string] {
  target = parsedPath(target);
  info ??= filesystemIdentity(target);
  let revision: string;
  if (diffTarget !== null && Object.keys(diffTarget).length) {
    if (!Object.hasOwn(diffTarget, "headRevision"))
      throw new Error("'headRevision'");
    revision = diffTarget["headRevision"]!;
  } else revision = gitRevision(target);
  const snapshot =
    diffTarget === null
      ? revision === "unversioned"
        ? directoryContentDigest(target)
        : worktreeContentDigest(target)
      : null;
  return [
    revision,
    snapshot,
    serializeFilesystemIdentity(info.dev),
    serializeFilesystemIdentity(info.ino),
  ];
}

export interface TargetIdentityScan {
  target_path: string;
  target_inode: unknown;
}
export interface RemediationScan extends TargetIdentityScan {
  target_revision: string;
  scan_dir: string;
}
export interface SnapshotScan extends RemediationScan {
  diff_target_kind: string | null;
  target_snapshot_digest: string | null;
  diff_head_revision: string | null;
  diff_content_digest: string | null;
}
export function requireRemediationTarget(value: string): string {
  const stored = parsedPath(expandHome(parsedPath(value), environment("HOME")));
  if (
    !(windows
      ? windowsParts(stored).slice(0, 2).every(Boolean)
      : isAbsolute(stored))
  )
    throw new TargetInspectionError(
      "Remediation target must be an absolute local directory path.",
    );
  let resolved: string;
  try {
    resolved = resolvedPath(stored);
  } catch (error) {
    if (error instanceof SymlinkLoopError)
      throw new SymlinkLoopError(
        `Symlink loop from ${pythonRepr(error.message.slice("Symlink loop from ".length))}`,
      );
    if (!osError(error)) throw error;
    throw new TargetInspectionError(
      "Remediation is unavailable because the selected checkout is no longer accessible.",
    );
  }
  if (pathKey(resolved) !== pathKey(stored) || !fileInfo(stored)?.isDirectory())
    throw new TargetInspectionError(
      "Remediation is unavailable because the selected checkout path was replaced. Start a new scan.",
    );
  return stored;
}
export function requireScanTargetIdentity(scan: TargetIdentityScan): string {
  const target = requireRemediationTarget(scan.target_path);
  if (scan.target_inode === null)
    throw new TargetInspectionError(
      "Remediation is unavailable because this scan does not record checkout identity. Start a new scan.",
    );
  let inode: bigint;
  try {
    inode = filesystemIdentity(target).ino;
  } catch (error) {
    if (!osError(error)) throw error;
    throw new TargetInspectionError(
      "Remediation is unavailable because the selected checkout is no longer accessible.",
    );
  }
  if (!storedFilesystemIdentityMatches(scan.target_inode, inode))
    throw new TargetInspectionError(
      "Remediation is unavailable because the selected checkout path was replaced. Start a new scan.",
    );
  return target;
}
export function requireGitWorktreeHead(target: string): string {
  const info = gitTargetMetadata(target);
  if (!info.isGit || !info.isWorktree || !info.hasHead)
    throw new TargetInspectionError(
      "Review changes requires a non-bare Git worktree with a resolvable HEAD.",
    );
  return info.revision!;
}
export function remediationCheckoutSnapshot(
  scan: RemediationScan,
  expectedRevision?: string | null,
): [string, string] {
  const target = requireScanTargetIdentity(scan),
    revision = gitRevision(target);
  if (revision !== (expectedRevision || scan.target_revision))
    throw new TargetInspectionError(
      "Repository HEAD changed. Regenerate the remediation patch against the current checkout.",
    );
  return [
    revision,
    revision !== "unversioned"
      ? worktreeContentDigest(target)
      : directoryContentDigest(target, { excluded: [scan.scan_dir] }),
  ];
}
export function scanTargetWarning(scan: SnapshotScan): string | null {
  if (scan.diff_target_kind !== "working_tree" && !scan.target_snapshot_digest)
    return null;
  try {
    const target = requireScanTargetIdentity(scan);
    if (scan.target_revision === "unversioned")
      return directoryContentDigest(target, { excluded: [scan.scan_dir] }) !==
        scan.target_snapshot_digest
        ? "Directory contents changed while the scan was running; results were saved for the original snapshot."
        : null;
    if (gitRevision(target) === "unversioned")
      return "The scanned Git repository became unavailable while the scan was running; results were saved for the original revision.";
    const workingTree = scan.diff_target_kind === "working_tree";
    if (
      requireGitWorktreeHead(target) !==
      (workingTree ? scan.diff_head_revision : scan.target_revision)
    )
      return "Repository HEAD changed while the scan was running; results were saved for the original revision.";
    if (
      worktreeContentDigest(target) !==
      (workingTree ? scan.diff_content_digest : scan.target_snapshot_digest)
    )
      return "Working-tree contents changed while the scan was running; results were saved for the original snapshot.";
  } catch (error) {
    if (!(error instanceof TargetInspectionError) && !osError(error))
      throw error;
    return "The scan target became unavailable while the scan was running; results were saved for the original revision or snapshot.";
  }
  return null;
}
