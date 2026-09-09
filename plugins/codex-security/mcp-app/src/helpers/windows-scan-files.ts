import { randomBytes } from "node:crypto";
import { win32 } from "node:path";
import type {
  WindowsBinding,
  WindowsHandle,
} from "../../../native/windows-binding.mjs";
import { windowsFlags as flags } from "../../../native/windows-flags.mjs";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsParts,
} from "../../../native/windows-files.mjs";
import { pythonRepr } from "./python-json";

export type ScanRootIdentity = readonly [bigint, bigint];
export interface ScanLocalReader {
  read(buffer: Buffer): number;
  size(): bigint;
  close(): void;
}

export class WindowsScanLocalFileError extends Error {
  constructor(
    readonly errno: number,
    readonly detail: string,
    readonly filename?: string,
  ) {
    super(
      `[Errno ${errno}] ${detail}${filename === undefined ? "" : `: ${pythonRepr(filename)}`}`,
    );
  }
}
const invalid = (path: string, reason: string) =>
  new WindowsScanLocalFileError(22, reason, path);

export function windowsScanPathParts(relative: string): string[] {
  const parts = relative
    .split("/")
    .filter((part) => part !== "" && part !== ".");
  if (
    !relative ||
    parts.length === 0 ||
    relative.startsWith("/") ||
    parts.includes("..") ||
    /[\\\0]/u.test(relative)
  )
    throw invalid(relative, "expected a safe scan-relative POSIX path");
  for (const part of parts) {
    if (/[<>:"|?*\x00-\x1f]/u.test(part) || /[ .]$/u.test(part))
      throw invalid(relative, "path contains a Windows-unsafe component");
    if (
      /^(?:AUX|CON|CONIN\$|CONOUT\$|NUL|PRN|COM[1-9¹²³]|LPT[1-9¹²³])$/u.test(
        part.split(".", 1)[0]!.toUpperCase(),
      )
    )
      throw invalid(relative, "path contains a reserved Windows device name");
  }
  return parts;
}

export function streamMatchesPayload(
  stream: Pick<ScanLocalReader, "read">,
  payload: Buffer,
): boolean {
  let offset = 0;
  while (offset < payload.length) {
    const chunk = Buffer.alloc(Math.min(64 * 1024, payload.length - offset));
    const count = stream.read(chunk);
    if (
      !count ||
      !chunk.subarray(0, count).equals(payload.subarray(offset, offset + count))
    )
      return false;
    offset += count;
  }
  return stream.read(Buffer.alloc(1)) === 0;
}

/** Keep each ancestor fixed, then operate on the verified leaf handle. */
export function windowsScanLocalFiles(native: WindowsBinding) {
  const files = windowsFileSystem(native);
  const extended = (path: string) =>
    path.startsWith("\\\\?\\")
      ? path
      : path.startsWith("\\\\")
        ? `\\\\?\\UNC\\${path.slice(2)}`
        : `\\\\?\\${path}`;
  function check(error: number, operation: string, path?: string): void {
    if (!error) return;
    const detail = pathText(native.windowsErrorMessage(error)).trim();
    throw new WindowsScanLocalFileError(
      error,
      `${operation}${path === undefined ? "" : ` for ${path}`}: ${detail}`,
      path ?? "",
    );
  }
  const close = (handle: WindowsHandle) => check(handle.close(), "CloseHandle");
  function renamePath(path: string): Buffer {
    const value = extended(path);
    const characters = Array.from(value);
    const invalid = characters.findIndex((character) =>
      /[\ud800-\udfff]/u.test(character),
    );
    if (invalid !== -1)
      throw new TypeError(
        `'utf-16-le' codec can't encode character ${pythonRepr(characters[invalid])} in position ${invalid}: surrogates not allowed`,
      );
    return widePath(value);
  }
  function normalized(path: string): string {
    if (path.startsWith("\\\\?\\UNC\\")) path = `\\\\${path.slice(8)}`;
    else if (path.startsWith("\\\\?\\")) path = path.slice(4);
    const [drive, root, tail] = windowsParts(path.replaceAll("/", "\\"));
    const parts: string[] = [];
    for (const part of tail.split("\\")) {
      if (!part || part === ".") continue;
      if (part === ".." && parts.length && parts.at(-1) !== "..") parts.pop();
      else if (part !== ".." || !root) parts.push(part);
    }
    const result = native.windowsInvariantLowercase(
      widePath(drive + root + parts.join("\\") || "."),
    );
    check(result.error, "LCMapStringEx");
    return pathText(result.value);
  }
  function open(
    path: string,
    access: number,
    share: number,
    disposition: number,
    attributes: number,
    missing = false,
  ): WindowsHandle | undefined {
    const result = native.openWindowsFile(
      widePath(extended(path)),
      access,
      share,
      disposition,
      attributes,
    );
    if (missing && (result.error === 2 || result.error === 3)) return undefined;
    check(result.error, "CreateFileW", path);
    return result.handle!;
  }
  function attributes(handle: WindowsHandle): number {
    const result = handle.attributes();
    check(result.error, "GetFileInformationByHandleEx");
    return result.attributes;
  }
  function verifyPath(
    handle: WindowsHandle,
    path: string,
    openedName = false,
  ): void {
    const result = handle.finalPath(openedName ? flags.FILE_NAME_OPENED : 0);
    check(result.error, "GetFinalPathNameByHandleW");
    if (normalized(pathText(result.path)) !== normalized(path))
      throw invalid(
        path,
        "opened file resolved outside its verified scan path",
      );
  }
  function verifyRegular(handle: WindowsHandle, path: string): void {
    const value = attributes(handle);
    if (value & flags.FILE_ATTRIBUTE_REPARSE_POINT)
      throw invalid(path, "scan-local files must not be reparse points");
    if (value & flags.FILE_ATTRIBUTE_DIRECTORY || handle.fileType().value !== 1)
      throw invalid(path, "expected a regular scan-local file");
    verifyPath(handle, path);
  }
  function openDirectory(
    path: string,
    missing = false,
  ): WindowsHandle | undefined {
    const handle = open(
      path,
      flags.FILE_READ_ATTRIBUTES,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE,
      flags.OPEN_EXISTING,
      flags.FILE_FLAG_BACKUP_SEMANTICS | flags.FILE_FLAG_OPEN_REPARSE_POINT,
      missing,
    );
    if (handle !== undefined) {
      try {
        const value = attributes(handle);
        if (value & flags.FILE_ATTRIBUTE_REPARSE_POINT)
          throw invalid(
            path,
            "scan-local directories must not be reparse points",
          );
        if (!(value & flags.FILE_ATTRIBUTE_DIRECTORY))
          throw invalid(path, "expected a scan-local directory");
        verifyPath(handle, path);
      } catch (error) {
        close(handle);
        throw error;
      }
    }
    return handle;
  }
  function identity(path: string): ScanRootIdentity {
    const handle = open(
      path,
      flags.FILE_READ_ATTRIBUTES,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE,
      flags.OPEN_EXISTING,
      flags.FILE_FLAG_BACKUP_SEMANTICS | flags.FILE_FLAG_OPEN_REPARSE_POINT,
    )!;
    try {
      const result = handle.identity();
      check(result.error, "GetFileInformationByHandleEx");
      return [
        BigInt(result.volume),
        result.fileId.readBigUInt64LE(0) |
          (result.fileId.readBigUInt64LE(8) << 64n),
      ];
    } finally {
      close(handle);
    }
  }
  const sameIdentity = (left: ScanRootIdentity, right: ScanRootIdentity) =>
    left[0] === right[0] && left[1] === right[1];
  function lockedParent<T>(
    scanDir: string,
    relative: string,
    create: boolean,
    expected: ScanRootIdentity | undefined,
    action: (parent: string, leaf: string) => T,
  ): T {
    const parts = windowsScanPathParts(relative);
    let absolute: string, root: string, observed: ScanRootIdentity;
    try {
      absolute = pathText(files.absolute(widePath(scanDir)));
      observed = identity(absolute);
      root = pathText(files.realpath(widePath(absolute)));
    } catch (error) {
      if (
        error instanceof WindowsScanLocalFileError ||
        (error as { winerror?: number }).winerror !== undefined
      )
        throw invalid(scanDir, "expected an existing scan directory");
      throw error;
    }
    if (normalized(absolute) !== normalized(root))
      throw invalid(
        scanDir,
        "scan directory must be canonical and non-reparse",
      );
    if (expected !== undefined && !sameIdentity(observed, expected))
      throw invalid(
        scanDir,
        "scan directory changed after artifact restoration setup",
      );
    const ancestors = [root];
    for (
      let parent = win32.dirname(root);
      parent !== ancestors.at(-1);
      parent = win32.dirname(parent)
    )
      ancestors.push(parent);
    const handles: WindowsHandle[] = [];
    try {
      for (const ancestor of ancestors.reverse())
        handles.push(openDirectory(ancestor)!);
      const current = identity(root);
      if (
        !sameIdentity(current, observed) ||
        (expected !== undefined && !sameIdentity(current, expected))
      )
        throw invalid(
          scanDir,
          "scan directory changed while it was being opened",
        );
      let parent = root;
      for (const part of parts.slice(0, -1)) {
        parent = win32.join(parent, part);
        let handle = openDirectory(parent, create);
        if (handle === undefined) {
          const error = native.createWindowsDirectory(
            widePath(extended(parent)),
          );
          if (error !== 80 && error !== 183)
            check(error, "CreateDirectoryW", parent);
          handle = openDirectory(parent)!;
        }
        handles.push(handle);
      }
      return action(parent, parts.at(-1)!);
    } finally {
      for (const handle of handles.reverse()) close(handle);
    }
  }
  function reader(handle: WindowsHandle): ScanLocalReader {
    return {
      read(buffer) {
        const result = handle.read(buffer, 0, buffer.length);
        check(result.error, "ReadFile");
        return result.value;
      },
      size() {
        const result = handle.size();
        check(result.error, "GetFileSizeEx");
        return BigInt(result.value);
      },
      close: () => close(handle),
    };
  }
  function openRead(
    scanDir: string,
    relative: string,
    context: string,
  ): ScanLocalReader {
    try {
      return lockedParent(
        scanDir,
        relative,
        false,
        undefined,
        (parent, leaf) => {
          const path = win32.join(parent, leaf);
          const handle = open(
            path,
            flags.GENERIC_READ | flags.FILE_READ_ATTRIBUTES,
            flags.FILE_SHARE_READ,
            flags.OPEN_EXISTING,
            flags.FILE_FLAG_OPEN_REPARSE_POINT,
          )!;
          try {
            verifyRegular(handle, path);
            return reader(handle);
          } catch (error) {
            close(handle);
            throw error;
          }
        },
      );
    } catch (error) {
      if (error instanceof WindowsScanLocalFileError)
        throw new WindowsScanLocalFileError(
          error.errno,
          `${context}: ${error.detail}`,
          error.filename,
        );
      throw error;
    }
  }
  function validateOutput(path: string): void {
    const handle = open(
      path,
      flags.FILE_READ_ATTRIBUTES,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE,
      flags.OPEN_EXISTING,
      flags.FILE_FLAG_OPEN_REPARSE_POINT | flags.FILE_FLAG_BACKUP_SEMANTICS,
      true,
    );
    if (handle === undefined) return;
    try {
      verifyRegular(handle, path);
    } finally {
      close(handle);
    }
  }
  function existingMatches(path: string, payload: Buffer): boolean {
    let handle: WindowsHandle | undefined;
    try {
      handle = open(
        path,
        flags.GENERIC_READ | flags.FILE_READ_ATTRIBUTES,
        flags.FILE_SHARE_READ,
        flags.OPEN_EXISTING,
        flags.FILE_FLAG_OPEN_REPARSE_POINT | flags.FILE_FLAG_BACKUP_SEMANTICS,
        true,
      );
    } catch (error) {
      if (
        error instanceof WindowsScanLocalFileError &&
        [5, 32, 33].includes(error.errno)
      )
        return false;
      throw error;
    }
    if (handle === undefined) return false;
    try {
      verifyRegular(handle, path);
      const stream = reader(handle);
      try {
        return (
          stream.size() === BigInt(payload.length) &&
          streamMatchesPayload(stream, payload)
        );
      } catch (error) {
        if (error instanceof WindowsScanLocalFileError) return false;
        throw error;
      }
    } finally {
      close(handle);
    }
  }
  function atomicWrite(
    scanDir: string,
    relative: string,
    payload: Buffer,
    expected?: ScanRootIdentity,
  ): void {
    lockedParent(scanDir, relative, true, expected, (parent, leaf) => {
      const destination = win32.join(parent, leaf);
      validateOutput(destination);
      if (expected !== undefined && existingMatches(destination, payload))
        return;
      let handle: WindowsHandle | undefined, temporary: string | undefined;
      for (let attempt = 0; attempt < 16; attempt++) {
        temporary = win32.join(
          parent,
          `.${leaf}.${randomBytes(8).toString("hex")}.tmp`,
        );
        try {
          handle = open(
            temporary,
            flags.GENERIC_WRITE | flags.DELETE | flags.FILE_READ_ATTRIBUTES,
            0,
            flags.CREATE_NEW,
            flags.FILE_ATTRIBUTE_NORMAL,
          );
        } catch (error) {
          if (
            error instanceof WindowsScanLocalFileError &&
            [80, 183].includes(error.errno)
          )
            continue;
          throw error;
        }
        break;
      }
      if (handle === undefined || temporary === undefined)
        throw new WindowsScanLocalFileError(
          17,
          "could not allocate a unique temp file",
        );
      try {
        try {
          verifyRegular(handle, temporary);
          let offset = 0;
          while (offset < payload.length) {
            const result = handle.write(
              payload,
              offset,
              Math.min(1024 * 1024, payload.length - offset),
            );
            check(result.error, "WriteFile");
            if (!result.value)
              throw new WindowsScanLocalFileError(
                5,
                "WriteFile made no progress",
              );
            offset += result.value;
          }
          check(handle.flush(), "FlushFileBuffers");
          check(
            handle.rename(renamePath(destination), true),
            "SetFileInformationByHandle(FileRenameInfo)",
          );
          verifyRegular(handle, destination);
        } catch (error) {
          // Delete the exact opened temporary/output file, including after rename.
          handle.setDisposition(true);
          throw error;
        }
      } finally {
        close(handle);
      }
    });
  }
  function unlinkIfExists(scanDir: string, relative: string): void {
    lockedParent(scanDir, relative, false, undefined, (parent, leaf) => {
      const path = win32.join(parent, leaf);
      const handle = open(
        path,
        flags.DELETE | flags.FILE_READ_ATTRIBUTES,
        flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE,
        flags.OPEN_EXISTING,
        flags.FILE_FLAG_OPEN_REPARSE_POINT | flags.FILE_FLAG_BACKUP_SEMANTICS,
        true,
      );
      if (handle === undefined) return;
      try {
        const value = attributes(handle);
        const reparse = (value & flags.FILE_ATTRIBUTE_REPARSE_POINT) !== 0;
        if (value & flags.FILE_ATTRIBUTE_DIRECTORY && !reparse)
          throw invalid(
            path,
            "scan-local cleanup target must not be a directory",
          );
        verifyPath(handle, path, reparse);
        check(
          handle.setDisposition(true),
          "SetFileInformationByHandle(FileDispositionInfo)",
        );
      } finally {
        close(handle);
      }
    });
  }
  return {
    openRead,
    atomicWrite,
    unlinkIfExists,
    rootIdentity(scanDir: string): [string, ScanRootIdentity] {
      return lockedParent(scanDir, ".identity", false, undefined, (parent) => [
        parent,
        identity(parent),
      ]);
    },
  };
}
