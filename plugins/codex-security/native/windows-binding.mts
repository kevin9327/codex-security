import { createRequire } from "node:module";
import { binaryPath, type CopyStatMetadata } from "./binding.mjs";

export interface WindowsResult<T = number> {
  error: number;
  value: T;
}

/** Owns a non-inheritable CRT descriptor used only by completion-file locking. */
export interface WindowsCompletionFile {
  size(): WindowsResult<string>;
  seekStart(): number;
  writeZero(): { errno: number; value: number };
  locking(unlock: boolean): number;
  close(): number;
}

/** Owns a binary, non-inheritable CRT descriptor created exclusively for writing. */
export interface WindowsExclusiveFile {
  write(buffer: Buffer): { errno: number; value: number };
  close(): number;
}

/** Owns a synchronous Windows file. close() is idempotent; GC also closes it. */
export interface WindowsHandle {
  close(): number;
  attributes(): { error: number; attributes: number; reparseTag: number };
  identity(): { error: number; volume: string; fileId: Buffer };
  fileType(): WindowsResult;
  finalPath(flags: number): { error: number; path: Buffer };
  read(buffer: Buffer, offset: number, length: number): WindowsResult;
  write(buffer: Buffer, offset: number, length: number): WindowsResult;
  seek(distance: bigint, origin: number): WindowsResult<string>;
  size(): WindowsResult<string>;
  setEndOfFile(): number;
  flush(): number;
  rename(destination: Buffer, replace: boolean): number;
  setDisposition(deleteFile: boolean): number;
  /** Acquires an exclusive whole-file lock; contention returns Windows error 33. */
  lock(nonblocking: boolean): number;
  unlock(): number;
}

/** Paths are UTF-16LE code units without a terminator, including lone surrogates. */
export interface WindowsBinding {
  errnoMessage(error: number): Buffer;
  windowsErrorMessage(error: number): Buffer;
  windowsReadFileCrt(path: Buffer): { errno: number; value: Buffer };
  windowsArguments(): Buffer[];
  windowsEnvironment(name: Buffer): Buffer | null;
  windowsInvariantLowercase(value: Buffer): WindowsResult<Buffer>;
  windowsAbsolutePath(path: Buffer): WindowsResult<Buffer>;
  windowsDirectoryEntries(
    path: Buffer,
  ): WindowsResult<
    { name: Buffer; isDirectory: boolean; isSymbolicLink: boolean }[]
  >;
  windowsReadLink(path: Buffer): WindowsResult<Buffer>;
  openWindowsFile(
    path: Buffer,
    access: number,
    share: number,
    disposition: number,
    flags: number,
  ): { error: number; handle?: WindowsHandle | null };
  createWindowsHardLink(source: Buffer, destination: Buffer): number;
  replaceWindowsPath(source: Buffer, destination: Buffer): number;
  unlinkWindowsPath(path: Buffer): number;
  createWindowsDirectory(path: Buffer): number;
  createWindowsDirectories(path: Buffer): number;
  createWindowsPrivateDirectory(path: Buffer): {
    error: number;
    path: Buffer | null;
  };
  setWindowsWritable(path: Buffer, writable: boolean): number;
  readCopyStat(
    source: Buffer,
    followSymlinks: boolean,
  ): { error: number; metadata: CopyStatMetadata | null };
  /** Follows links; reports null path for a SetFileTime failure. */
  setWindowsTimes(
    destination: Buffer,
    atimeNs: bigint,
    mtimeNs: bigint,
  ): { error: number; path: Buffer | null };
  /** Returns the Win32 error derived from CopyFile2's HRESULT, or zero. */
  copyFile2(source: Buffer, destination: Buffer, flags: number): number;
  /** Passes flags directly to CreateSymbolicLinkW; no target inference or retry. */
  createWindowsSymlink(
    target: Buffer,
    destination: Buffer,
    flags: number,
  ): number;
  /** Copies binary bytes through the CRT; only open failures include a path. */
  copyFileCrt(
    source: Buffer,
    destination: Buffer,
  ): { errno: number; path: Buffer | null };
  openWindowsCompletionFile(path: Buffer): {
    errno: number;
    file: WindowsCompletionFile | null;
  };
  openWindowsExclusiveFile(
    path: Buffer,
    mode: number,
    readWrite?: boolean,
  ): {
    errno: number;
    file: WindowsExclusiveFile | null;
  };
}

export { windowsFlags } from "./windows-flags.mjs";

export function loadWindowsBinding(): WindowsBinding {
  return createRequire(import.meta.url)(binaryPath) as WindowsBinding;
}
