import { readFileSync, writeFileSync } from "node:fs";
import {
  processBinding,
  windowsBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import { decodeFilename } from "../../../../plugins/codex-security/mcp-app/src/workbench-git";
import {
  cleanWorktreeContentDigest,
  TargetInspectionError,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import * as target from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  widePath,
  windowsFileSystem,
} from "../../../../plugins/codex-security/native/windows-files.mjs";
import type { WindowsBinding } from "../../../../plugins/codex-security/native/windows-binding.mjs";

export interface Request {
  action:
    | "directory"
    | "count"
    | "sourcePaths"
    | "worktree"
    | "context"
    | "clean"
    | "submodules"
    | "cleanSubmodules"
    | "revision"
    | "metadata"
    | "remediationTarget"
    | "identity"
    | "scanIdentity"
    | "head"
    | "snapshot"
    | "warning"
    | "serialize"
    | "matches"
    | "windowsMode";
  target: string;
  excluded?: string[];
  includeIgnored?: boolean;
  pathspec?: string;
  gitDir?: string;
  workTree?: string;
  expectedRevision?: string | null;
  scan?: target.SnapshotScan;
  current?: string;
  stored?: unknown;
  git?: { stdout?: string; stderr?: string; status?: number }[];
  attributes?: number;
  reparseTag?: number;
  fileType?: number;
  diffTarget?: Record<string, string> | null;
  metadata?: { dev: string; ino: string };
  requireStreamedDiff?: boolean;
}
export interface Response {
  result?: unknown;
  error?: string;
  systemExit?: boolean;
  calls?: string[][];
}
const integer = (value: unknown) => {
  if (value && typeof value === "object" && "integer" in value)
    return BigInt((value as { integer: string }).integer);
  return value;
};
function run(request: Request): Response {
  const native = processBinding(),
    original = native.rawProcess;
  const calls: string[][] = [];
  let response = 0;
  if (request.git || request.requireStreamedDiff)
    native.rawProcess = (options) => {
      calls.push(
        options.args.map((arg) =>
          process.platform === "win32"
            ? arg.toString("utf16le")
            : decodeFilename(arg),
        ),
      );
      const diff = calls.at(-1)![6] === "diff";
      if (request.requireStreamedDiff && diff && !options.stdoutPath)
        throw new Error("Git diff must stream to a file");
      if (!request.git) {
        const result = original(options);
        if (request.requireStreamedDiff && diff && result.stdout.length)
          throw new Error("Git diff must not retain stdout in memory");
        return result;
      }
      const value = request.git![response++];
      if (!value) throw new Error("Unexpected Git probe");
      const stdout = Buffer.from(value.stdout ?? "", "base64");
      if (options.stdoutPath) {
        if (process.platform === "win32")
          windowsFileSystem(windowsBinding()).writeFile(
            options.stdoutPath,
            stdout,
          );
        else writeFileSync(options.stdoutPath, stdout);
      }
      return {
        error: 0,
        returnCode: value.status ?? 0,
        stdout: options.stdoutPath ? Buffer.alloc(0) : stdout,
        stderr: Buffer.from(value.stderr ?? "", "base64"),
      };
    };
  const scan = request.scan && {
    ...request.scan,
    target_inode: integer(request.scan.target_inode),
  };
  try {
    let result: unknown;
    switch (request.action) {
      case "directory":
        result = target.directoryContentDigest(request.target, request);
        break;
      case "count":
        result = target.directorySnapshotRegularFileCount(request.target);
        break;
      case "sourcePaths":
        result = target.sourceDirectorySnapshotPaths(request.target);
        break;
      case "worktree":
        result = target.worktreeContentDigest(request.target);
        break;
      case "context":
        result = target.worktreeContentDigestForContext(
          request.target,
          request.pathspec ?? ".",
          request,
        );
        break;
      case "clean":
        result = cleanWorktreeContentDigest();
        break;
      case "submodules":
        result = target.gitSubmoduleEntries(request.target);
        break;
      case "cleanSubmodules":
        target.requireCleanSubmoduleWorktrees(request.target);
        result = null;
        break;
      case "revision":
        result = target.gitRevision(request.target);
        break;
      case "metadata":
        result = target.gitTargetMetadata(request.target);
        break;
      case "remediationTarget":
        result = target.requireRemediationTarget(request.target);
        break;
      case "identity":
        result = target.requireScanTargetIdentity(scan!);
        break;
      case "scanIdentity":
        result = target.scanTargetIdentity(
          request.target,
          request.diffTarget ?? null,
          request.metadata && {
            dev: BigInt(request.metadata.dev),
            ino: BigInt(request.metadata.ino),
          },
        );
        break;
      case "head":
        result = target.requireGitWorktreeHead(request.target);
        break;
      case "snapshot":
        result = target.remediationCheckoutSnapshot(
          scan!,
          request.expectedRevision,
        );
        break;
      case "warning":
        result = target.scanTargetWarning(scan!);
        break;
      case "serialize":
        result = target.serializeFilesystemIdentity(BigInt(request.current!));
        break;
      case "matches":
        result = target.storedFilesystemIdentityMatches(
          integer(request.stored),
          BigInt(request.current!),
        );
        break;
      case "windowsMode": {
        let closed = 0;
        const files = windowsFileSystem({
          windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
          openWindowsFile: () => ({
            error: 0,
            handle: {
              attributes: () => ({
                error: 0,
                attributes: request.attributes ?? 0x80,
                reparseTag: request.reparseTag ?? 0,
              }),
              fileType: () => ({ error: 0, value: request.fileType ?? 1 }),
              size: () => ({ error: 0, value: "0" }),
              close: () => {
                closed++;
                return 0;
              },
            },
          }),
        } as unknown as WindowsBinding);
        const info = files.stat(widePath(request.target), false);
        result = {
          mode: info.mode,
          reparseTag: info.reparseTag,
          directory: info.isDirectory(),
          file: info.isFile(),
          symlink: info.isSymbolicLink(),
          closed,
        };
        break;
      }
    }
    return { result, ...(request.git ? { calls } : {}) };
  } catch (error) {
    return {
      error:
        (error as { errno?: number }).errno !== undefined ||
        (error as { winerror?: number }).winerror !== undefined
          ? filesystemErrorMessage(error)
          : (error as Error).message,
      systemExit: error instanceof TargetInspectionError,
      ...(request.git ? { calls } : {}),
    };
  } finally {
    native.rawProcess = original;
  }
}
console.log(
  JSON.stringify(
    (JSON.parse(readFileSync(0, "utf8")) as Request[]).map(run),
    (_key, value) =>
      typeof value === "bigint" ? { integer: String(value) } : value,
  ),
);
