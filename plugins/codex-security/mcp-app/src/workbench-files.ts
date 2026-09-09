import { createHash } from "node:crypto";
import { lstatSync, type Stats } from "node:fs";
import { basename, dirname, posix, sep, win32 } from "node:path";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { unixBinding, windowsBinding } from "./native";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { fileInfo, readFile } from "./helpers/helper-files";
import {
  decodePosixBytes,
  encodePosixPath,
  SymlinkLoopError,
} from "./helpers/posix-path";
import { JsonSyntaxError, object, pythonRepr } from "./helpers/python-json";
import { fullPatternMatch } from "./helpers/python-regex";
import { appendPath, relativePath } from "./helpers/rank-selection";
import { compare } from "./helpers/rank-worklists";
import { parsedPath } from "./helpers/resolve-security-md";
import { resolvedPath } from "./helpers/resolve-path";
import { JsonValueError, loadsJson } from "./helpers/scan-contract-json";
import { ContractError } from "./helpers/scan-contract-errors";
import {
  absoluteScanPath,
  openScanLocalFile as openContractFile,
  scanPathNormcase,
  type ScanLocalReader,
} from "./helpers/scan-local-files";
import {
  decodePythonUtf8,
  encodeUtf8,
  UnicodeDecodeError,
} from "./helpers/utf8";
import { WorkbenchValidationError } from "./workbench-validation";

const PATCH_PREVIEW_BYTES = 16_000;
const FINDING_LOCATION_PATH_BYTES = 2048;
const FINDING_ARTIFACT_DIRECTORIES_LIMIT = 80;
const FINDING_ARTIFACTS_LIMIT = 40;
const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const osError = (error: unknown) => {
  const value = error as { errno?: number; winerror?: number };
  return value.errno !== undefined || value.winerror !== undefined;
};
function checkedPath(path: string, nulMessage: string): void {
  if (!windows && /[\ud800-\udc7f\udd00-\udfff]/u.test(path)) {
    const characters = Array.from(path);
    const first = characters.findIndex((character) =>
      /[\ud800-\udc7f\udd00-\udfff]/u.test(character),
    );
    // Filesystem surrogateescape consumes valid byte escapes before the first
    // unencodable character; the strict encoder supplies the remaining error.
    const text = characters
      .map((character, index) =>
        index < first && /[\udc80-\udcff]/u.test(character) ? "x" : character,
      )
      .join("");
    try {
      encodeUtf8(text);
    } catch (error) {
      throw new JsonValueError((error as Error).message);
    }
  }
  if (path.includes("\0")) throw new JsonValueError(nulMessage);
}
const metadata = (path: string) => {
  checkedPath(path, "stat: embedded null character in path");
  return windows
    ? windowsFiles().stat(widePath(path), false)
    : lstatSync(encodePosixPath(path));
};
const canonicalError = () =>
  new WorkbenchValidationError(
    "Scan directory must be an existing canonical non-symlink directory.",
  );

function resolveArtifactPath(path: string): string {
  if (windows && path.includes("\0")) {
    path = win32.normalize(path);
    if (path.includes("\0"))
      throw new Error("_getfinalpathname: embedded null character in path");
  }
  const invalid = windows ? null : /[\0\ud800-\udc7f\udd00-\udfff]/u.exec(path);
  if (invalid !== null) {
    // Path.resolve can fail on an earlier component before encoding this one.
    const separator = path.lastIndexOf(sep, invalid.index);
    if (separator > 0)
      resolvedPath(path.slice(0, separator), true, {
        preserveRelativeErrors: true,
      });
    checkedPath(path, "stat: embedded null character in path");
  }
  return resolvedPath(path, true, { preserveRelativeErrors: true });
}

export function requireCanonicalScanDirectory(scanDir: string): string {
  scanDir = absoluteScanPath(scanDir);
  let info: ReturnType<typeof metadata>, resolved: string;
  try {
    info = metadata(scanDir);
    resolved = resolvedPath(scanDir, true, { preserveRelativeErrors: true });
  } catch (error) {
    if (osError(error)) throw canonicalError();
    throw error;
  }
  if (
    !info.isDirectory() ||
    scanPathNormcase(resolved) !== scanPathNormcase(scanDir)
  )
    throw canonicalError();
  if (!windows) {
    if (info.mode & 0o077)
      throw new WorkbenchValidationError(
        "Scan directory must not be accessible to other users (chmod 700).",
      );
    const uid = process.geteuid?.();
    if (uid !== undefined && (info as Stats).uid !== uid)
      throw new WorkbenchValidationError(
        "Scan directory must be owned by the current user.",
      );
    for (
      let child = scanDir, parent = dirname(child);
      parent !== child;
      child = parent, parent = dirname(parent)
    ) {
      let parentInfo: Stats;
      try {
        parentInfo = lstatSync(encodePosixPath(parent));
      } catch (error) {
        if (osError(error))
          throw new WorkbenchValidationError(
            "Scan output parent could not be inspected.",
          );
        throw error;
      }
      if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink())
        throw new WorkbenchValidationError(
          "Scan output parent must be a non-symlink directory.",
        );
      if (uid !== undefined && parentInfo.uid !== 0 && parentInfo.uid !== uid)
        throw new WorkbenchValidationError(
          "Scan output parent must have a trusted owner.",
        );
      if (parentInfo.mode & 0o022 && !(parentInfo.mode & 0o1000))
        throw new WorkbenchValidationError(
          "Scan output parent must not be group- or world-writable without the sticky bit.",
        );
    }
  }
  return scanDir;
}

export function availableArtifactPath(
  scanDir: string,
  candidate: string,
): string | null {
  candidate = parsedPath(candidate);
  let resolved: string;
  try {
    const root = requireCanonicalScanDirectory(scanDir);
    resolved = resolveArtifactPath(candidate);
    if (relativePath(resolved, root) === undefined) return null;
  } catch (error) {
    if (
      (error as NodeJS.ErrnoException).code === "ENOENT" ||
      error instanceof SymlinkLoopError ||
      error instanceof WorkbenchValidationError ||
      error instanceof JsonValueError
    )
      return null;
    throw error;
  }
  if (
    candidate.includes("\0") ||
    scanPathNormcase(resolved) !== scanPathNormcase(candidate) ||
    !fileInfo(candidate)?.isFile()
  )
    return null;
  return resolved;
}

export function artifactPath(
  scanDir: string,
  fileName: string,
  required: boolean,
): string | null {
  scanDir = requireCanonicalScanDirectory(scanDir);
  const candidate = appendPath(scanDir, fileName);
  let resolved: string;
  try {
    resolved = resolveArtifactPath(candidate);
    if (relativePath(resolved, resolvedPath(scanDir, false)) === undefined)
      throw new JsonValueError("outside scan directory");
  } catch (error) {
    const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
    if (
      !missing &&
      !(error instanceof SymlinkLoopError) &&
      !(error instanceof JsonValueError)
    )
      throw error;
    if (!required && missing) return null;
    throw new WorkbenchValidationError(
      `${fileName}: expected a regular file inside the scan directory.`,
    );
  }
  if (
    candidate.includes("\0") ||
    scanPathNormcase(resolved) !== scanPathNormcase(candidate) ||
    !fileInfo(candidate)?.isFile()
  )
    throw new WorkbenchValidationError(
      `${fileName}: expected a regular non-symlink file.`,
    );
  return resolved;
}

export function rejectNonFiniteJson(value: string): never {
  throw new JsonValueError(
    `non-finite JSON number ${pythonRepr(value)} is not supported`,
  );
}

export function readJsonObject(path: string): Record<string, unknown> {
  path = parsedPath(path);
  const name = path === "." ? "" : basename(path);
  let payload: unknown;
  try {
    checkedPath(path, "embedded null byte");
    const bytes = windows
      ? windowsFiles().readFileCrt(widePath(path))
      : readFile(path);
    payload = loadsJson(decodePythonUtf8(bytes).replace(/\r\n?/gu, "\n"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EISDIR")
      Object.assign(error as Error, { path });
    if (
      osError(error) ||
      error instanceof JsonSyntaxError ||
      error instanceof JsonValueError ||
      error instanceof UnicodeDecodeError
    )
      throw new WorkbenchValidationError(
        `${name}: invalid JSON: ${filesystemErrorMessage(error)}`,
      );
    throw error;
  }
  if (!object(payload))
    throw new WorkbenchValidationError(`${name}: expected a JSON object.`);
  return payload;
}

export function openScanLocalFile(
  scanDir: string,
  relative: string,
): ScanLocalReader {
  const parts = relative
    .split("/")
    .filter((part) => part !== "" && part !== ".");
  if (relative.startsWith("/") || !parts.length || parts.includes(".."))
    throw new WorkbenchValidationError(
      "Patch path must identify a scan-local regular file.",
    );
  scanDir = requireCanonicalScanDirectory(scanDir);
  try {
    return openContractFile(scanDir, parts.join("/"), "Patch path");
  } catch (error) {
    if (error instanceof ContractError || osError(error))
      throw new WorkbenchValidationError(
        "Patch path must identify a scan-local regular file.",
      );
    throw error;
  }
}

export function scanLocalRegularFile(
  scanDir: string,
  relative: string,
): boolean {
  if (encodeUtf8(relative).length > FINDING_LOCATION_PATH_BYTES) return false;
  let file: ScanLocalReader;
  try {
    file = openContractFile(scanDir, relative, `finding artifact ${relative}`);
  } catch (error) {
    if (error instanceof ContractError || osError(error)) return false;
    throw error;
  }
  file.close();
  return true;
}

export interface PatchPreviewStats {
  additions: bigint;
  deletions: bigint;
  fileCount: bigint;
  previewTruncated: boolean;
}

export function patchArtifactPreview(
  scanDir: string,
  relative: string | null,
  expectedDigest: string | null,
): [string | null, PatchPreviewStats | null] {
  if (relative === null || expectedDigest === null) return [null, null];
  const digest = createHash("sha256"),
    preview = Buffer.alloc(PATCH_PREVIEW_BYTES + 1);
  let previewLength = 0,
    additions = 0n,
    deletions = 0n,
    fileCount = 0n,
    oldHeaders = 0n,
    newHeaders = 0n;
  const prefix: number[] = [];
  let counted = false;
  const countLine = () => {
    const start = Buffer.from(prefix).toString("latin1");
    if (start.startsWith("diff --git ")) fileCount++;
    else if (start.startsWith("+++ ")) newHeaders++;
    else if (start.startsWith("--- ")) oldHeaders++;
    else if (start.startsWith("+")) additions++;
    else if (start.startsWith("-")) deletions++;
    counted = true;
  };
  try {
    const file = openScanLocalFile(scanDir, relative),
      buffer = Buffer.alloc(64 * 1024);
    try {
      for (;;) {
        const count = file.read(buffer);
        if (!count) break;
        const chunk = buffer.subarray(0, count);
        digest.update(chunk);
        previewLength += chunk.copy(
          preview,
          previewLength,
          0,
          Math.max(0, preview.length - previewLength),
        );
        for (let start = 0; start < chunk.length; ) {
          const newline = chunk.indexOf(10, start);
          const end = newline < 0 ? chunk.length : newline + 1;
          if (!counted) {
            prefix.push(
              ...chunk.subarray(
                start,
                Math.min(end, start + 11 - prefix.length),
              ),
            );
            if (prefix.length === 11 || newline >= 0) countLine();
          }
          if (newline >= 0) {
            prefix.length = 0;
            counted = false;
          }
          start = end;
        }
      }
      if (prefix.length && !counted) countLine();
    } finally {
      file.close();
    }
  } catch (error) {
    if (error instanceof WorkbenchValidationError) return [null, null];
    throw error;
  }
  if (`sha256:${digest.digest("hex")}` !== expectedDigest) return [null, null];
  const previewTruncated = previewLength > PATCH_PREVIEW_BYTES;
  let text = preview
    .subarray(0, Math.min(previewLength, PATCH_PREVIEW_BYTES))
    .toString("utf8");
  if (previewTruncated) text += "\n... patch preview truncated ...";
  return [
    text,
    {
      additions,
      deletions,
      fileCount:
        fileCount || (oldHeaders < newHeaders ? oldHeaders : newHeaders),
      previewTruncated,
    },
  ];
}

function directoryEntries(
  path: string,
): { name: string; directory: boolean }[] | null {
  if (windows) {
    try {
      return windowsFiles()
        .entriesWithTypes(widePath(path))
        .map((entry) => ({
          name: entry.name.toString("utf16le"),
          directory: entry.isDirectory(),
        }));
    } catch (error) {
      if (osError(error)) return null;
      throw error;
    }
  }
  const entries = unixBinding().directoryEntries(encodePosixPath(path), true);
  if (entries.errno) return null;
  return entries.value.map((entry) => {
    const name = decodePosixBytes(entry.name);
    let directory = entry.errno === 0 && entry.isDirectory;
    if (entry.isSymbolicLink) {
      try {
        directory = fileInfo(appendPath(path, name))?.isDirectory() ?? false;
      } catch (error) {
        if (!osError(error)) throw error;
      }
    }
    return { name, directory };
  });
}

export function findingArtifactPaths(
  scanDir: string,
  details: Record<string, unknown>,
): string[] {
  scanDir = parsedPath(scanDir);
  const writeup = details["writeup"];
  if (!object(writeup)) return [];
  const report = writeup["reportPath"];
  if (
    typeof report !== "string" ||
    !fullPatternMatch(
      String.raw`^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$`,
      report,
    )
  )
    return [];
  const artifacts: string[] = [];
  if (scanLocalRegularFile(scanDir, report)) artifacts.push(report);
  const pocRoot = appendPath(scanDir, `${posix.dirname(report)}/poc`);
  try {
    if (!metadata(pocRoot).isDirectory()) return artifacts;
  } catch (error) {
    if (osError(error)) return artifacts;
    throw error;
  }
  const pending = [pocRoot];
  let directoriesSeen = 0;
  while (pending.length) {
    const current = pending.pop()!,
      entries = directoryEntries(current);
    if (entries === null) continue;
    if (++directoriesSeen > FINDING_ARTIFACT_DIRECTORIES_LIMIT) break;
    const directories = entries
      .filter((entry) => entry.directory)
      .map((entry) => entry.name)
      .sort(compare)
      .filter(
        (name) => !fileInfo(appendPath(current, name), false)?.isSymbolicLink(),
      );
    const files = entries
      .filter((entry) => !entry.directory)
      .map((entry) => entry.name)
      .sort(compare);
    for (const name of files) {
      const candidate = appendPath(current, name);
      const relative =
        scanDir === "." ? candidate : relativePath(candidate, scanDir);
      if (relative === undefined) continue;
      const portable = windows ? relative.replaceAll("\\", "/") : relative;
      if (!scanLocalRegularFile(scanDir, portable)) continue;
      artifacts.push(portable);
      if (artifacts.length >= FINDING_ARTIFACTS_LIMIT) return artifacts;
    }
    for (const name of directories.reverse())
      pending.push(appendPath(current, name));
  }
  return artifacts;
}
