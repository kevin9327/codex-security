import { closeSync, constants as fileFlags, openSync } from "node:fs";
import { constants as osConstants } from "node:os";
import type { WindowsCompletionFile } from "../../native/windows-binding.mjs";
import { widePath } from "../../native/windows-files.mjs";
import { unixBinding, windowsBinding } from "./native";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { mkdir } from "./helpers/helper-files";
import { encodePosixPath } from "./helpers/posix-path";
import { appendPath } from "./helpers/rank-selection";
import { stateDir } from "./workbench-db";
import { requireUuid } from "./workbench-validation";

type CompletionFile = number | WindowsCompletionFile;

function checkErrno(errno: number, path?: string): void {
  if (errno === 0) return;
  const details = { errno, path };
  throw Object.assign(new Error(filesystemErrorMessage(details)), details);
}

export function isFileLockContention(error: unknown): boolean {
  const { EACCES, EAGAIN, EDEADLK } = osConstants.errno;
  return [EACCES, EAGAIN, EDEADLK].includes((error as { errno: number }).errno);
}

function waitForLock(): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
}

export function acquireCompletionFileLock(
  file: CompletionFile,
  wait: () => void = waitForLock,
): void {
  if (typeof file === "number") {
    checkErrno(unixBinding().fileLock(file, false, false).errno);
    return;
  }
  for (;;) {
    const size = file.size();
    if (size.error !== 0) {
      const details = { winerror: size.error };
      throw Object.assign(new Error(filesystemErrorMessage(details)), details);
    }
    if (BigInt(size.value) !== 0n) break;
    checkErrno(file.seekStart());
    try {
      checkErrno(file.writeZero().errno);
    } catch (error) {
      if (!isFileLockContention(error)) throw error;
      wait();
    }
  }
  for (;;) {
    checkErrno(file.seekStart());
    try {
      checkErrno(file.locking(false));
      return;
    } catch (error) {
      if (!isFileLockContention(error)) throw error;
      wait();
    }
  }
}

export function releaseCompletionFileLock(file: CompletionFile): void {
  if (typeof file === "number") {
    checkErrno(unixBinding().fileLock(file, true, false).errno);
    return;
  }
  checkErrno(file.seekStart());
  checkErrno(file.locking(true));
}

export function withScanCompletionLock<T>(
  scanId: string,
  operation: () => T &
    (Extract<T, PromiseLike<unknown>> extends never ? unknown : never),
): T {
  const directory = appendPath(stateDir(), "completion-locks");
  mkdir(directory);
  const path = appendPath(directory, `${requireUuid(scanId, "scan-id")}.lock`);
  let file: CompletionFile;
  if (process.platform === "win32") {
    const opened = windowsBinding().openWindowsCompletionFile(widePath(path));
    checkErrno(opened.errno, path);
    file = opened.file!;
  } else {
    file = openSync(
      encodePosixPath(path),
      fileFlags.O_RDWR | fileFlags.O_CREAT,
      0o600,
    );
  }
  let locked = false;
  try {
    acquireCompletionFileLock(file);
    locked = true;
    return operation();
  } finally {
    try {
      if (locked) releaseCompletionFileLock(file);
    } finally {
      if (typeof file === "number") closeSync(file);
      else checkErrno(file.close());
    }
  }
}
