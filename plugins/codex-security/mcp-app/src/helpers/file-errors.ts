import { unixBinding, windowsBinding } from "../native";
import { decodePosixBytes } from "./posix-path";
import { pythonRepr } from "./python-json";

interface FileError extends Error {
  errno?: number;
  winerror?: number;
  path?: string | Buffer;
  code?: string;
}

export function filesystemErrorMessage(error: unknown): string {
  const value = error as FileError;
  const path =
    value.path === undefined
      ? ""
      : `: ${pythonRepr(Buffer.isBuffer(value.path) ? decodePosixBytes(value.path) : value.path)}`;
  if (value.winerror !== undefined) {
    const message = windowsBinding()
      .windowsErrorMessage(value.winerror)
      .toString("utf16le")
      .replace(/[.\x00-\x20]+$/u, "");
    return `[WinError ${value.winerror}] ${message || `Windows Error 0x${value.winerror.toString(16)}`}${path}`;
  }
  if (value.errno !== undefined) {
    const errno = Math.abs(value.errno);
    const native =
      process.platform === "win32" ? windowsBinding() : unixBinding();
    const message = decodePosixBytes(native.errnoMessage(errno));
    return `[Errno ${errno}] ${message}${path}`;
  }
  return value.message;
}
