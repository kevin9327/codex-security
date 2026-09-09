import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readlinkSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, posix } from "node:path";
import { getSystemErrorName } from "node:util";
import letter from "@unicode/unicode-15.0.0/General_Category/Letter/regex.js";
import { unixBinding, windowsBinding } from "../native";
import {
  readDescriptor,
  type SyscallResult,
} from "../../../native/binding.mjs";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsJoin,
  windowsParts,
} from "../../../native/windows-files.mjs";
import { fileInfo } from "./helper-files";
import { filesystemErrorMessage } from "./file-errors";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { parsedPath } from "./resolve-security-md";
import { resolvedPath } from "./resolve-path";
import { appendPath, relativePath } from "./rank-selection";
import { ContractError } from "./scan-contract-errors";
import {
  streamMatchesPayload,
  windowsScanLocalFiles,
  type ScanLocalReader,
  type ScanRootIdentity,
} from "./windows-scan-files";

export type { ScanLocalReader, ScanRootIdentity } from "./windows-scan-files";
const windows = process.platform === "win32";
const parts = (path: string) =>
  path.split("/").filter((part) => part !== "" && part !== ".");
const osError = (error: unknown) => {
  const value = error as { errno?: number; winerror?: number };
  return value.errno !== undefined || value.winerror !== undefined;
};
const errorCode = (error: unknown) => (error as { code?: string }).code;
const regular = (mode: number) => (mode & 0xf000) === 0x8000;
const symbolicLink = (mode: number) => (mode & 0xf000) === 0xa000;
const sameIdentity = (left: ScanRootIdentity, right: ScanRootIdentity) =>
  left[0] === right[0] && left[1] === right[1];
const identity = (metadata: { dev: bigint; ino: bigint }): ScanRootIdentity => [
  metadata.dev,
  metadata.ino,
];

function syscall(result: SyscallResult, path?: string): number {
  if (!result.errno) return result.value;
  const error = {
    errno: result.errno,
    code: getSystemErrorName(-result.errno),
    path,
  };
  throw Object.assign(new Error(filesystemErrorMessage(error)), error);
}
function normcase(path: string): string {
  if (!windows) return path;
  const result = windowsBinding().windowsInvariantLowercase(
    widePath(path.replaceAll("/", "\\")),
  );
  if (result.error) {
    const error = { winerror: result.error };
    throw Object.assign(new Error(filesystemErrorMessage(error)), error);
  }
  return pathText(result.value);
}
function absolute(path: string): string {
  path = parsedPath(path);
  if (!windows)
    return path.startsWith("/")
      ? path
      : appendPath(
          decodePosixBytes(realpathSync.native(".", { encoding: "buffer" })),
          path,
        );
  const [drive, root] = windowsParts(path);
  if (drive && root) return path;
  const cwd = pathText(
    windowsFileSystem(windowsBinding()).absolute(widePath(drive || ".")),
  );
  return parsedPath(windowsJoin(cwd, path));
}

export { absolute as absoluteScanPath, normcase as scanPathNormcase };

export function requireSafeRelativePath(
  value: string,
  context: string,
  allowDot = false,
): string {
  const components = parts(value);
  const normalized = components.join("/") || ".";
  const first = Array.from(value).slice(0, 2);
  if (
    /^[\p{White_Space}\u001c-\u001f]*$/u.test(value) ||
    (normalized === "." && !allowDot) ||
    (first[1] === ":" && letter.test(first[0]!)) ||
    /[\\\x00-\x1f\ud800-\udfff]/u.test(value) ||
    value.startsWith("/") ||
    components.includes("..")
  )
    throw new ContractError(
      `${context}: expected a safe repository-relative POSIX path`,
    );
  return normalized;
}
export function requirePortableRelativePath(
  value: string,
  context: string,
  allowDot = false,
): string {
  const normalized = requireSafeRelativePath(value, context, allowDot);
  const unsafe =
    /[<>:"|?*\x00-\x1f]|[ .]$|^(?:con|prn|aux|nul|con[iİı]n\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/iu;
  if (
    value
      .split("/")
      .some((part) => part !== "" && part !== "." && unsafe.test(part))
  )
    throw new ContractError(
      `${context}: expected a safe scan-relative POSIX path`,
    );
  return normalized;
}
export function requireScanDirectory(scanDir: string): string {
  scanDir = absolute(scanDir);
  let directory: boolean;
  try {
    directory = windows
      ? windowsFileSystem(windowsBinding())
          .stat(widePath(scanDir), false)
          .isDirectory()
      : lstatSync(encodePosixPath(scanDir)).isDirectory();
  } catch (error) {
    if (!osError(error)) throw error;
    throw new ContractError(
      "scan directory: expected an existing non-symlink directory",
    );
  }
  if (!directory)
    throw new ContractError(
      "scan directory: expected an existing non-symlink directory",
    );
  let resolved: string;
  try {
    resolved = resolvedPath(scanDir);
  } catch (error) {
    if (!osError(error)) throw error;
    throw new ContractError(
      "scan directory: expected an existing non-symlink directory",
    );
  }
  if (normcase(resolved) !== normcase(scanDir))
    throw new ContractError(
      "scan directory: expected a canonical non-symlink directory",
    );
  return resolved;
}

export function validateScanLocalOutputPath(
  scanDir: string,
  path: string,
  relative: string,
): void {
  path = parsedPath(path);
  let parent: string;
  try {
    parent = resolvedPath(dirname(path));
    if (relativePath(parent, scanDir) === undefined) throw new Error("outside");
  } catch {
    throw new ContractError(
      `${relative}: expected a path inside the scan directory`,
    );
  }
  if (
    normcase(parent) !== normcase(dirname(path)) ||
    fileInfo(path, false)?.isSymbolicLink()
  )
    throw new ContractError(
      `${relative}: expected a non-symlink path inside the scan directory`,
    );
  const info = fileInfo(path);
  if (info !== undefined && !info.isFile())
    throw new ContractError(`${relative}: expected a regular file`);
}

function openVerifiedRoot(
  scanDir: string,
  expected?: ScanRootIdentity,
): number {
  scanDir = absolute(scanDir);
  let observed: ScanRootIdentity, descriptor: number;
  try {
    observed = identity(lstatSync(encodePosixPath(scanDir), { bigint: true }));
    if (expected !== undefined && !sameIdentity(observed, expected))
      throw new ContractError(
        "scan directory: changed after artifact restoration setup",
      );
    const canonical = requireScanDirectory(scanDir);
    descriptor = openSync(
      encodePosixPath(canonical),
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
  } catch (error) {
    if (!osError(error)) throw error;
    throw new ContractError(
      "scan directory: expected an existing non-symlink directory",
    );
  }
  const opened = identity(fstatSync(descriptor, { bigint: true }));
  if (
    !sameIdentity(opened, observed) ||
    (expected !== undefined && !sameIdentity(opened, expected))
  ) {
    closeSync(descriptor);
    throw new ContractError(
      "scan directory: changed while it was being opened",
    );
  }
  return descriptor;
}
function openParent(
  root: number,
  components: readonly string[],
  create: boolean,
): number {
  const native = unixBinding();
  let descriptor = syscall(native.duplicate(root));
  try {
    for (const part of components) {
      if (create) {
        const result = native.makeDirectoryAt(
          descriptor,
          encodePosixPath(part),
          0o700,
        );
        if (result.errno && getSystemErrorName(-result.errno) !== "EEXIST")
          syscall(result, part);
      }
      const next = syscall(
        native.openAt(
          descriptor,
          encodePosixPath(part),
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
          0,
        ),
        part,
      );
      closeSync(descriptor);
      descriptor = next;
    }
    return descriptor;
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}
function descriptorReader(descriptor: number): ScanLocalReader {
  return {
    read: (buffer) =>
      readDescriptor(descriptor, buffer, 0, buffer.length, null),
    size: () => fstatSync(descriptor, { bigint: true }).size,
    identity: () => identity(fstatSync(descriptor, { bigint: true })),
    close: () => closeSync(descriptor),
  };
}

export function scanRootIdentity(scanDir: string): [string, ScanRootIdentity] {
  scanDir = requireScanDirectory(scanDir);
  if (windows)
    return windowsScanLocalFiles(windowsBinding()).rootIdentity(scanDir);
  const descriptor = openVerifiedRoot(scanDir);
  try {
    return [scanDir, identity(fstatSync(descriptor, { bigint: true }))];
  } finally {
    closeSync(descriptor);
  }
}

export function openScanLocalFile(
  scanDir: string,
  relative: string,
  context: string,
): ScanLocalReader {
  scanDir = requireScanDirectory(scanDir);
  relative = requirePortableRelativePath(relative, context);
  if (windows) {
    try {
      return windowsScanLocalFiles(windowsBinding()).openRead(
        scanDir,
        relative,
        context,
      );
    } catch (error) {
      if (!osError(error)) throw error;
      throw new ContractError((error as Error).message);
    }
  }
  const native = unixBinding();
  let root: number | undefined,
    parent: number | undefined,
    descriptor: number | undefined;
  try {
    root = openVerifiedRoot(scanDir);
    const components = parts(relative);
    try {
      parent = openParent(root, components.slice(0, -1), false);
      descriptor = syscall(
        native.openAt(
          parent,
          encodePosixPath(components.at(-1)!),
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
          0,
        ),
        components.at(-1),
      );
    } catch (error) {
      if (!osError(error)) throw error;
      if (errorCode(error) === "ELOOP") {
        try {
          let link: Buffer;
          if (parent === undefined)
            link = readlinkSync(encodePosixPath(components.at(-1)!), {
              encoding: "buffer",
            });
          else {
            const result = native.readLinkAt(
              parent,
              encodePosixPath(components.at(-1)!),
            );
            syscall({ value: 0, errno: result.errno });
            link = result.value;
          }
          const path = decodePosixBytes(link);
          const target = path.startsWith("/")
            ? path
            : appendPath(
                appendPath(scanDir, components.slice(0, -1).join("/")),
                path,
              );
          if (relativePath(resolvedPath(target, false), scanDir) === undefined)
            throw new Error("outside");
        } catch {
          throw new ContractError(
            `${context}: expected a file inside the scan directory`,
          );
        }
        throw new ContractError(
          `${context}: expected a regular non-symlink file`,
        );
      }
      throw new ContractError(
        `${context}: expected a file inside the scan directory`,
      );
    }
    if (!fstatSync(descriptor).isFile())
      throw new ContractError(
        `${context}: expected a regular non-symlink file`,
      );
    const result = descriptorReader(descriptor);
    descriptor = undefined;
    return result;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (parent !== undefined) closeSync(parent);
    if (root !== undefined) closeSync(root);
  }
}

export function readScanLocalBytes(
  scanDir: string,
  relative: string,
  context: string,
): Buffer {
  const file = openScanLocalFile(scanDir, relative, context),
    chunks: Buffer[] = [];
  try {
    for (;;) {
      const chunk = Buffer.alloc(64 * 1024),
        count = file.read(chunk);
      if (count === 0) return Buffer.concat(chunks);
      chunks.push(chunk.subarray(0, count));
    }
  } finally {
    file.close();
  }
}
export function sha256ScanLocalFile(
  scanDir: string,
  relative: string,
  context: string,
): string {
  const file = openScanLocalFile(scanDir, relative, context),
    hash = createHash("sha256"),
    buffer = Buffer.alloc(1024 * 1024);
  try {
    for (;;) {
      const count = file.read(buffer);
      if (!count) return hash.digest("hex");
      hash.update(buffer.subarray(0, count));
    }
  } finally {
    file.close();
  }
}

export function writeScanLocalBytes(
  scanDir: string,
  relative: string,
  payload: Buffer,
  options: {
    externalName?: boolean;
    expectedRootIdentity?: ScanRootIdentity;
  } = {},
): void {
  scanDir = requireScanDirectory(scanDir);
  if (options.externalName) {
    if (["", ".", ".."].includes(relative) || /[/\0]/u.test(relative))
      throw new ContractError(
        "external output path: expected a safe file name",
      );
  } else
    relative = requirePortableRelativePath(relative, "scan-local output path");
  if (windows) {
    try {
      windowsScanLocalFiles(windowsBinding()).atomicWrite(
        scanDir,
        relative,
        payload,
        options.expectedRootIdentity,
      );
    } catch (error) {
      if (!osError(error)) throw error;
      throw new ContractError(`${relative}: ${(error as Error).message}`);
    }
    return;
  }
  const native = unixBinding();
  let root: number | undefined,
    parent: number | undefined,
    temporary: string | undefined;
  try {
    root = openVerifiedRoot(scanDir, options.expectedRootIdentity);
    const components = parts(relative),
      leaf = components.at(-1)!;
    try {
      parent = openParent(root, components.slice(0, -1), true);
    } catch (error) {
      if (!osError(error)) throw error;
      throw new ContractError(
        `${relative}: expected a path inside the scan directory`,
      );
    }
    const metadata = native.statAt(parent, encodePosixPath(leaf));
    if (!metadata.errno) {
      if (!regular(metadata.mode))
        throw new ContractError(
          `${relative}: expected a regular non-symlink file`,
        );
      const opened = native.openAt(
        parent,
        encodePosixPath(leaf),
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        0,
      );
      if (opened.errno) {
        if (
          !["ENOENT", "EACCES", "EPERM"].includes(
            getSystemErrorName(-opened.errno),
          )
        )
          syscall(opened, leaf);
      } else {
        let descriptor = opened.value;
        try {
          const current = fstatSync(descriptor, { bigint: true });
          if (!current.isFile())
            throw new ContractError(
              `${relative}: expected a regular non-symlink file`,
            );
          if (
            !sameIdentity(identity(current), [
              BigInt(metadata.device),
              BigInt(metadata.inode),
            ])
          )
            throw new ContractError(
              `${relative}: changed while it was being opened`,
            );
          if (
            options.expectedRootIdentity !== undefined &&
            current.size === BigInt(payload.length)
          ) {
            const reader = descriptorReader(descriptor);
            descriptor = -1;
            try {
              try {
                if (streamMatchesPayload(reader, payload)) return;
              } finally {
                reader.close();
              }
            } catch (error) {
              if (!osError(error)) throw error;
            }
          }
        } finally {
          if (descriptor >= 0) closeSync(descriptor);
        }
      }
    } else if (getSystemErrorName(-metadata.errno) !== "ENOENT")
      syscall({ value: 0, errno: metadata.errno }, leaf);
    temporary = `.${posix.basename(relative)}.${randomBytes(8).toString("hex")}.tmp`;
    const descriptor = syscall(
      native.openAt(
        parent,
        encodePosixPath(temporary),
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
        0o600,
      ),
      temporary,
    );
    try {
      writeFileSync(descriptor, payload);
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    syscall(
      native.renameAt(
        parent,
        encodePosixPath(temporary),
        parent,
        encodePosixPath(leaf),
      ),
      temporary,
    );
    temporary = undefined;
  } finally {
    if (temporary !== undefined && parent !== undefined) {
      const result = native.unlinkAt(parent, encodePosixPath(temporary));
      if (result.errno && getSystemErrorName(-result.errno) !== "ENOENT")
        syscall(result, temporary);
    }
    if (parent !== undefined) closeSync(parent);
    if (root !== undefined) closeSync(root);
  }
}

export function removeScanLocalFileIfExists(
  scanDir: string,
  relative: string,
): void {
  scanDir = requireScanDirectory(scanDir);
  relative = requirePortableRelativePath(relative, "scan-local cleanup path");
  if (windows) {
    try {
      windowsScanLocalFiles(windowsBinding()).unlinkIfExists(scanDir, relative);
    } catch (error) {
      if (!osError(error)) throw error;
      throw new ContractError(`${relative}: ${(error as Error).message}`);
    }
    return;
  }
  const native = unixBinding();
  let root: number | undefined, parent: number | undefined;
  try {
    root = openVerifiedRoot(scanDir);
    const components = parts(relative),
      leaf = components.at(-1)!;
    parent = openParent(root, components.slice(0, -1), false);
    const metadata = native.statAt(parent, encodePosixPath(leaf));
    if (metadata.errno) {
      if (getSystemErrorName(-metadata.errno) === "ENOENT") return;
      syscall({ value: 0, errno: metadata.errno }, leaf);
    }
    if (!regular(metadata.mode) && !symbolicLink(metadata.mode))
      throw new ContractError(
        `${relative}: expected a regular file or symlink`,
      );
    syscall(native.unlinkAt(parent, encodePosixPath(leaf)), leaf);
  } finally {
    if (parent !== undefined) closeSync(parent);
    if (root !== undefined) closeSync(root);
  }
}
