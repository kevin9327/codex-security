import { randomUUID } from "node:crypto";
import {
  closeSync,
  linkSync,
  openSync,
  renameSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { basename, dirname } from "node:path";
import { readDescriptor } from "../../native/binding.mjs";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { encodePosixPath } from "./helpers/posix-path";
import { pythonRepr } from "./helpers/python-json";
import { appendPath, pathKey } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { copyFileWithMetadata } from "./workbench-copy";
import { pathExists } from "./workbench-deep-files";
import { WorkbenchValidationError } from "./workbench-validation";

const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const osError = (error: unknown) =>
  (error as { errno?: number }).errno !== undefined ||
  (error as { winerror?: number }).winerror !== undefined;

function pathCall(
  path: string,
  operation: () => void,
  destination?: string,
): void {
  try {
    operation();
  } catch (error) {
    if (!osError(error)) throw error;
    const value = error as Error & { path?: string; dest?: string };
    value.path = path;
    value.dest = destination;
    value.message =
      filesystemErrorMessage(value) +
      (destination === undefined ? "" : ` -> ${pythonRepr(destination)}`);
    throw error;
  }
}

function windowsStatus(error: number): void {
  if (error) throw Object.assign(new Error(), { winerror: error });
}

export function replacePublicationFile(
  source: string,
  destination: string,
): void {
  pathCall(
    source,
    () => {
      if (windows)
        windowsStatus(
          windowsBinding().replaceWindowsPath(
            widePath(source),
            widePath(destination),
          ),
        );
      else renameSync(encodePosixPath(source), encodePosixPath(destination));
    },
    destination,
  );
}

export type StagedFilePromotion = readonly [
  staged: string,
  output: string,
  backup: string | null,
];

export function promoteStagedFile(
  stagedPath: string,
  outputPath: string,
  uuid: () => string = randomUUID,
): StagedFilePromotion {
  const staged = parsedPath(stagedPath),
    output = parsedPath(outputPath);
  if (pathKey(staged) === pathKey(output))
    throw new WorkbenchValidationError(
      "A staged Deep Scan artifact must not be its published output path.",
    );
  const backup = pathExists(output)
    ? appendPath(dirname(output), `.${basename(output)}.${uuid()}.backup`)
    : null;
  if (backup !== null) replacePublicationFile(output, backup);
  try {
    replacePublicationFile(staged, output);
  } catch (error) {
    if (backup !== null) replacePublicationFile(backup, output);
    throw error;
  }
  return [staged, output, backup];
}

export function rollbackStagedFile([
  staged,
  output,
  backup,
]: StagedFilePromotion): void {
  if (pathExists(output)) replacePublicationFile(output, staged);
  if (backup !== null) replacePublicationFile(backup, output);
}

export function finishStagedFile(promotion: StagedFilePromotion): void {
  const backup = promotion[2];
  if (backup !== null) unlinkPublicationFile(backup);
}

export function unlinkPublicationFile(path: string): void {
  try {
    pathCall(path, () => {
      if (windows)
        windowsStatus(windowsBinding().unlinkWindowsPath(widePath(path)));
      else unlinkSync(encodePosixPath(path));
    });
  } catch (error) {
    const value = error as NodeJS.ErrnoException & { winerror?: number };
    if (value.code !== "ENOENT" && ![2, 3].includes(value.winerror ?? 0))
      throw error;
  }
}

export function createPublicationCopy(
  source: string,
  destination: string,
  sourceIsPath = false,
  destinationIsPath = false,
): void {
  if (sourceIsPath) source = parsedPath(source);
  if (destinationIsPath) destination = parsedPath(destination);
  try {
    if (windows)
      windowsStatus(
        windowsBinding().createWindowsHardLink(
          widePath(source),
          widePath(destination),
        ),
      );
    else linkSync(encodePosixPath(source), encodePosixPath(destination));
  } catch (error) {
    if (!osError(error)) throw error;
    copyFileWithMetadata(source, destination, sourceIsPath, destinationIsPath);
  }
}

function openRead(path: string) {
  if (windows) {
    const opened = windowsBinding().openWindowsReadFile(widePath(path));
    if (opened.errno) throw Object.assign(new Error(), { errno: opened.errno });
    const file = opened.file!;
    return {
      read(buffer: Buffer): number {
        const result = file.read(buffer);
        if (result.errno)
          throw Object.assign(new Error(), { errno: result.errno });
        return result.value;
      },
      close(): void {
        const errno = file.close();
        if (errno) throw Object.assign(new Error(), { errno });
      },
    };
  }
  const descriptor = openSync(encodePosixPath(path), "r");
  return {
    read: (buffer: Buffer) =>
      readDescriptor(descriptor, buffer, 0, buffer.length, null),
    close: () => closeSync(descriptor),
  };
}

function readChunk(file: ReturnType<typeof openRead>, buffer: Buffer): Buffer {
  let length = 0;
  while (length < buffer.length) {
    const count = file.read(buffer.subarray(length));
    if (!count) break;
    length += count;
  }
  return buffer.subarray(0, length);
}

export function publicationMatchesSnapshot(
  publication: string,
  snapshot: string,
): boolean {
  publication = parsedPath(publication);
  snapshot = parsedPath(snapshot);
  const stat = (path: string) =>
    windows
      ? windowsFiles().stat(widePath(path))
      : statSync(encodePosixPath(path), { bigint: true });
  try {
    if (windows) {
      if (windowsFiles().sameFile(widePath(publication), widePath(snapshot)))
        return true;
    } else {
      const first = statSync(encodePosixPath(publication), { bigint: true });
      const second = statSync(encodePosixPath(snapshot), { bigint: true });
      if (first.dev === second.dev && first.ino === second.ino) return true;
    }
    if (stat(publication).size !== stat(snapshot).size) return false;
    const published = openRead(publication);
    try {
      const source = openRead(snapshot);
      try {
        const publishedBuffer = Buffer.alloc(1024 * 1024),
          sourceBuffer = Buffer.alloc(1024 * 1024);
        for (;;) {
          const publishedChunk = readChunk(published, publishedBuffer);
          const sourceChunk = readChunk(source, sourceBuffer);
          if (!publishedChunk.equals(sourceChunk)) return false;
          if (!publishedChunk.length) return true;
        }
      } finally {
        source.close();
      }
    } finally {
      published.close();
    }
  } catch (error) {
    if (!osError(error)) throw error;
    return false;
  }
}
