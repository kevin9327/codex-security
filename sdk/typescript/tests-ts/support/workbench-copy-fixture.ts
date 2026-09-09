import { readFileSync } from "node:fs";
import {
  processBinding,
  unixBinding,
  windowsBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  copyDirectoryExcluding,
  copyGitWorktreeFiles,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-copy";
import { decodeFilename } from "../../../../plugins/codex-security/mcp-app/src/workbench-git";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";

export interface Request {
  kind: "directory" | "git";
  source: string;
  destination: string;
  excluded?: string[];
  cwd?: string;
  git?: { stdout: string; status?: number }[];
  copyStatError?: { errno: number; path: string | null };
  copyFileErrors?: number[];
  symlinkErrors?: number[];
  timesError?: number;
  stamp?: { path: string; atimeNs: string; mtimeNs: string };
  inspect?: string[];
}
export interface Response {
  result?: string | null;
  error?: string;
  systemExit?: boolean;
  calls: string[][];
  copies: { source: string; destination: string; flags: number }[];
  links: { target: string; destination: string; flags: number }[];
  metadata?: { atimeNs: string; mtimeNs: string }[];
}

function run(request: Request): Response {
  const native = processBinding(),
    rawProcess = native.rawProcess;
  const windows = process.platform === "win32";
  const unix = windows ? undefined : unixBinding(),
    copyStat = unix?.copyStat;
  const win = windows ? windowsBinding() : undefined;
  const copyFile = win?.copyFile2,
    symlink = win?.createWindowsSymlink,
    times = win?.setWindowsTimes;
  const calls: Response["calls"] = [],
    copies: Response["copies"] = [],
    links: Response["links"] = [];
  const cwd = process.cwd();
  let probe = 0,
    copyIndex = 0,
    linkIndex = 0;
  if (request.git)
    native.rawProcess = (options) => {
      calls.push(
        options.args.map((value) =>
          windows ? value.toString("utf16le") : decodeFilename(value),
        ),
      );
      const result = request.git![probe++];
      if (!result) throw new Error("Unexpected Git probe");
      return {
        error: 0,
        returnCode: result.status ?? 0,
        stdout: Buffer.from(result.stdout, "base64"),
        stderr: Buffer.alloc(0),
      };
    };
  if (unix && request.copyStatError)
    unix.copyStat = () => ({
      errno: request.copyStatError!.errno,
      path:
        request.copyStatError!.path === null
          ? null
          : Buffer.from(request.copyStatError!.path),
    });
  if (win) {
    win.copyFile2 = (source, destination, flags) => {
      copies.push({
        source: source.toString("utf16le"),
        destination: destination.toString("utf16le"),
        flags,
      });
      return (
        request.copyFileErrors?.[copyIndex++] ??
        copyFile!(source, destination, flags)
      );
    };
    win.createWindowsSymlink = (target, destination, flags) => {
      links.push({
        target: target.toString("utf16le"),
        destination: destination.toString("utf16le"),
        flags,
      });
      return (
        request.symlinkErrors?.[linkIndex++] ??
        symlink!(target, destination, flags)
      );
    };
    if (request.timesError)
      win.setWindowsTimes = (path) => ({ error: request.timesError!, path });
  }
  try {
    if (request.cwd) process.chdir(request.cwd);
    if (request.stamp && unix) {
      const path = Buffer.from(request.stamp.path);
      const read = unix.readCopyStat(path, true);
      if (read.errno)
        throw new Error(`Unable to read timestamp fixture: ${read.errno}`);
      const result = copyStat!(path, path, true, {
        ...read.metadata!,
        atimeNs: BigInt(request.stamp.atimeNs),
        mtimeNs: BigInt(request.stamp.mtimeNs),
      });
      if (result.errno)
        throw new Error(`Unable to write timestamp fixture: ${result.errno}`);
    }
    const result =
      request.kind === "directory"
        ? (copyDirectoryExcluding(
            request.source,
            request.destination,
            request.excluded ?? [],
          ),
          null)
        : copyGitWorktreeFiles(
            request.source,
            request.destination,
            request.excluded ?? [],
          );
    const metadata = request.inspect?.map((path) => {
      const read = unix!.readCopyStat(Buffer.from(path), true);
      if (read.errno)
        throw new Error(`Unable to inspect timestamp fixture: ${read.errno}`);
      return {
        atimeNs: String(read.metadata!.atimeNs),
        mtimeNs: String(read.metadata!.mtimeNs),
      };
    });
    return { result, calls, copies, links, ...(metadata ? { metadata } : {}) };
  } catch (error) {
    return {
      error: (error as Error).message,
      systemExit: error instanceof TargetInspectionError,
      calls,
      copies,
      links,
    };
  } finally {
    process.chdir(cwd);
    native.rawProcess = rawProcess;
    if (unix) unix.copyStat = copyStat!;
    if (win) {
      win.copyFile2 = copyFile!;
      win.createWindowsSymlink = symlink!;
      win.setWindowsTimes = times!;
    }
  }
}
console.log(
  JSON.stringify((JSON.parse(readFileSync(0, "utf8")) as Request[]).map(run)),
);
