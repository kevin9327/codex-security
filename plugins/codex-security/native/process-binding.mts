import { createRequire } from "node:module";
import { binaryPath } from "./binding.mjs";

/** OS strings are raw POSIX bytes or UTF-16LE buffers, without NUL terminators. */
export interface ProcessRequest {
  program: Buffer;
  args: Buffer[];
  cwd?: Buffer | null;
  /** Absent/null inherits stdin; an empty buffer sends EOF. */
  input?: Buffer | null;
  environment?: { name: Buffer; value: Buffer | null }[];
}

export interface ProcessResult {
  /** Native spawn error (errno or Windows error), or zero after a successful spawn. */
  error: number;
  /** Python returncode: exit status, negative POSIX signal, or null on spawn failure. */
  returnCode: number | null;
  stdout: Buffer;
  stderr: Buffer;
}

export function loadProcessBinding(): {
  rawProcess(request: ProcessRequest): ProcessResult;
} {
  return createRequire(import.meta.url)(binaryPath) as {
    rawProcess(request: ProcessRequest): ProcessResult;
  };
}
