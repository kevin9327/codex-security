import { unixBinding, windowsBinding } from "../native";
import { widePath } from "../../../native/windows-files.mjs";
import { decodePosixBytes } from "./posix-path";

export function environment(name: string): string | undefined {
  const windows = process.platform === "win32";
  const value = windows
    ? windowsBinding().windowsEnvironment(widePath(name))
    : unixBinding().environment(Buffer.from(name));
  return value === null
    ? undefined
    : windows
      ? value.toString("utf16le")
      : decodePosixBytes(value);
}
