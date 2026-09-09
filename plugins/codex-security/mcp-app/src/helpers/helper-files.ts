import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";
import { encodePosixPath } from "./posix-path";

export function fileInfo(path: string, follow = true) {
  try {
    return process.platform === "win32"
      ? windowsFileSystem(windowsBinding()).stat(widePath(path), follow)
      : follow
        ? statSync(encodePosixPath(path))
        : lstatSync(encodePosixPath(path));
  } catch (error) {
    const { code, winerror } = error as NodeJS.ErrnoException & {
      winerror?: number;
    };
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "EBADF"].includes(code ?? "") ||
      (process.platform === "win32" && [21, 123].includes(winerror ?? 0))
    )
      return undefined;
    throw error;
  }
}

export function readFile(path: string | number): Buffer {
  if (typeof path === "number") return readFileSync(path);
  return process.platform === "win32"
    ? windowsFileSystem(windowsBinding()).readFile(widePath(path))
    : readFileSync(encodePosixPath(path));
}

export function exists(path: string): boolean {
  if (process.platform !== "win32") return existsSync(encodePosixPath(path));
  try {
    windowsFileSystem(windowsBinding()).stat(widePath(path));
    return true;
  } catch (error) {
    const { code, winerror } = error as NodeJS.ErrnoException & {
      winerror?: number;
    };
    if (
      ["ENOENT", "ENOTDIR", "ELOOP"].includes(code ?? "") ||
      winerror === 21 ||
      winerror === 123
    )
      return false;
    throw error;
  }
}

export function mkdir(path: string): void {
  if (process.platform === "win32")
    windowsFileSystem(windowsBinding()).mkdir(widePath(path));
  else mkdirSync(encodePosixPath(path), { recursive: true });
}

export function writeFile(path: string, chunks: Iterable<Buffer>): void {
  if (process.platform === "win32") {
    windowsFileSystem(windowsBinding()).writeFile(widePath(path), chunks);
    return;
  }
  const descriptor = openSync(encodePosixPath(path), "w");
  try {
    for (const chunk of chunks) writeFileSync(descriptor, chunk);
  } finally {
    closeSync(descriptor);
  }
}

export function chmod(path: string, mode: number): void {
  if (process.platform === "win32")
    windowsFileSystem(windowsBinding()).chmod(widePath(path), mode);
  else chmodSync(encodePosixPath(path), mode);
}
