import { randomInt } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  lchmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, posix } from "node:path";
import { getSystemErrorName } from "node:util";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsJoin,
} from "../../native/windows-files.mjs";
import { unixBinding, windowsBinding } from "./native";
import { environment } from "./helpers/environment";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { decodePosixBytes, encodePosixPath } from "./helpers/posix-path";
import { pythonRepr } from "./helpers/python-json";
import { temporaryNameAttempts } from "./helpers/temporary-name-attempts";

const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const append = (parent: string, name: string) =>
  windows
    ? windowsJoin(parent, name)
    : `${parent}${parent.endsWith("/") ? "" : "/"}${name}`;
type Failure = NodeJS.ErrnoException & { winerror?: number };
const osError = (error: unknown) =>
  (error as Failure).errno !== undefined ||
  (error as Failure).winerror !== undefined;
const errno = (error: unknown) => Math.abs((error as Failure).errno ?? 0);
// The exception classes used by tempfile follow CPython's Windows errno map.
const missing = (error: unknown) =>
  errno(error) === 2 ||
  (error as Failure).code === "ENOENT" ||
  [2, 3, 15, 18, 53, 67, 161, 206].includes((error as Failure).winerror ?? 0);
const exists = (error: unknown) =>
  errno(error) === 17 ||
  (error as Failure).code === "EEXIST" ||
  [80, 183].includes((error as Failure).winerror ?? 0);
function permission(error: unknown): boolean {
  const winerror = (error as Failure).winerror ?? 0;
  return (
    [1, 13].includes(errno(error)) ||
    ["EACCES", "EPERM"].includes((error as Failure).code ?? "") ||
    (winerror >= 19 && winerror <= 36) ||
    [5, 16, 65, 82, 83, 108, 132, 158, 167].includes(winerror)
  );
}
function failure(error: unknown): Error {
  return Object.assign(new Error(filesystemErrorMessage(error)), error);
}
function checkedErrno(error: number, path?: string): void {
  if (error !== 0)
    throw failure({
      errno: error,
      code: getSystemErrorName(-error),
      ...(path === undefined ? {} : { path }),
    });
}
function checkedWindows(error: number, path?: string): void {
  if (error !== 0)
    throw failure({ winerror: error, ...(path === undefined ? {} : { path }) });
}
function pathCall<T>(path: string, operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (!osError(error)) throw error;
    if ((error as Failure).path !== undefined) (error as Failure).path = path;
    throw failure(error);
  }
}
function absolute(path: string): string {
  if (windows) {
    const result = windowsBinding().windowsAbsolutePath(widePath(path));
    checkedWindows(result.error);
    return pathText(result.value);
  }
  if (!path.startsWith("/"))
    path = append(
      decodePosixBytes(realpathSync.native(".", { encoding: "buffer" })),
      path,
    );
  const normalized = posix.normalize(path).replace(/\/+$/u, "") || "/";
  return (
    (path.startsWith("//") && !path.startsWith("///") ? "/" : "") + normalized
  );
}
function stat(path: string, follow = true) {
  return windows
    ? windowsFiles().stat(widePath(path), follow)
    : pathCall(path, () =>
        (follow ? statSync : lstatSync)(encodePosixPath(path)),
      );
}
function isDirectory(path: string): boolean {
  try {
    return stat(path).isDirectory();
  } catch (error) {
    if (!osError(error)) throw error;
    return false;
  }
}
function isJunction(path: string): boolean {
  if (!windows) return false;
  try {
    return windowsFiles().stat(widePath(path), false).reparseTag === 0xa0000003;
  } catch (error) {
    if (!osError(error)) throw error;
    return false;
  }
}
function unlink(path: string): void {
  if (windows) {
    // The existing handle primitive also removes directories; os.unlink does not.
    const info = stat(path, false);
    if (info.isDirectory() && !isJunction(path)) checkedWindows(5, path);
    windowsFiles().unlink(widePath(path));
  } else pathCall(path, () => unlinkSync(encodePosixPath(path)));
}
function mkdir(path: string): void {
  if (windows) {
    const result = windowsBinding().createWindowsPrivateDirectory(
      widePath(path),
    );
    checkedWindows(result.error, result.path === null ? undefined : path);
  } else
    pathCall(path, () => mkdirSync(encodePosixPath(path), { mode: 0o700 }));
}
function exclusiveFile(path: string, mode: number, readWrite = false) {
  if (windows) {
    const result = windowsBinding().openWindowsExclusiveFile(
      widePath(path),
      mode,
      readWrite,
    );
    checkedErrno(result.errno, path);
    const file = result.file!;
    return {
      write(buffer: Buffer): number {
        const result = file.write(buffer);
        checkedErrno(result.errno);
        return result.value;
      },
      close: () => checkedErrno(file.close()),
    };
  }
  let descriptor: number;
  for (;;) {
    try {
      descriptor = pathCall(path, () =>
        openSync(
          encodePosixPath(path),
          readWrite
            ? constants.O_RDWR |
                constants.O_CREAT |
                constants.O_EXCL |
                constants.O_NOFOLLOW
            : "wx",
          mode,
        ),
      );
      break;
    } catch (error) {
      if ((error as Failure).code !== "EINTR") throw error;
    }
  }
  return {
    write(buffer: Buffer): number {
      for (;;) {
        try {
          return writeSync(descriptor, buffer);
        } catch (error) {
          if ((error as Failure).code !== "EINTR") throw failure(error);
        }
      }
    },
    close: () => {
      try {
        closeSync(descriptor);
      } catch (error) {
        throw failure(error);
      }
    },
  };
}
export function writeExclusiveFile(
  path: string,
  chunks: Iterable<Buffer>,
): void {
  const file = exclusiveFile(path, 0o666);
  try {
    for (const chunk of chunks) {
      let offset = 0;
      while (offset < chunk.length)
        offset += file.write(chunk.subarray(offset));
    }
  } finally {
    file.close();
  }
}
const randomName = () =>
  Array.from(
    { length: 8 },
    () => "abcdefghijklmnopqrstuvwxyz0123456789_"[randomInt(37)],
  ).join("");
let temporaryParent: string | undefined;
export function temporaryDirectoryParent(): string {
  if (temporaryParent !== undefined) return temporaryParent;
  const candidates = ["TMPDIR", "TEMP", "TMP"].flatMap(
    (name) => environment(name) || [],
  );
  if (windows) {
    const home =
      environment("USERPROFILE") ??
      (environment("HOMEPATH") === undefined
        ? undefined
        : windowsJoin(
            environment("HOMEDRIVE") ?? "",
            environment("HOMEPATH")!,
          ));
    candidates.push(
      `${home ?? "~"}\\AppData\\Local\\Temp`,
      `${environment("SYSTEMROOT") ?? "%SYSTEMROOT%"}\\Temp`,
      "c:\\temp",
      "c:\\tmp",
      "\\temp",
      "\\tmp",
    );
  } else candidates.push("/tmp", "/var/tmp", "/usr/tmp");
  try {
    candidates.push(absolute("."));
  } catch (error) {
    if (!osError(error)) throw error;
    candidates.push(".");
  }
  for (let directory of candidates) {
    if (directory !== ".") directory = absolute(directory);
    // CPython tests up to 100 names before trying the next candidate directory.
    for (let attempt = 0; attempt < 100; attempt++) {
      const path = append(directory, randomName());
      try {
        const file = exclusiveFile(path, 0o600, true);
        try {
          try {
            file.write(Buffer.from("blat"));
          } finally {
            file.close();
          }
        } finally {
          unlink(path);
        }
        temporaryParent = directory;
        return directory;
      } catch (error) {
        if (
          exists(error) ||
          (permission(error) && windows && isDirectory(directory))
        )
          continue;
        if (!osError(error)) throw error;
        break;
      }
    }
  }
  throw Object.assign(
    new Error(
      `[Errno 2] No usable temporary directory found in [${candidates.map(pythonRepr).join(", ")}]`,
    ),
    { errno: 2, code: "ENOENT" },
  );
}
function makeTemporaryDirectory(prefix: string): string {
  const parent = temporaryDirectoryParent();
  // tempfile.mkdtemp's platform TMP_MAX, eight-character names, and mode 0700.
  for (let attempt = 0; attempt < temporaryNameAttempts; attempt++) {
    const path = append(parent, prefix + randomName());
    try {
      mkdir(path);
    } catch (error) {
      if (
        exists(error) ||
        (permission(error) && windows && isDirectory(parent))
      )
        continue;
      throw error;
    }
    return absolute(path);
  }
  throw Object.assign(
    new Error("[Errno 17] No usable temporary directory name found"),
    { errno: 17, code: "EEXIST" },
  );
}
function resetPermissions(path: string): void {
  if (process.platform === "darwin") {
    checkedErrno(
      unixBinding().clearFileFlags(encodePosixPath(path), false),
      path,
    );
    pathCall(path, () => lchmodSync(encodePosixPath(path), 0o700));
  } else if (windows) windowsFiles().chmod(widePath(path), 0o700);
  else if (!stat(path, false).isSymbolicLink())
    pathCall(path, () => chmodSync(encodePosixPath(path), 0o700));
}
function removeTree(root: string, repeated = false): void {
  function onError(path: string, error: unknown): void {
    if (missing(error)) return;
    if (!permission(error) || (repeated && path === root)) throw failure(error);
    try {
      if (path !== root) resetPermissions(dirname(path));
      resetPermissions(path);
      try {
        unlink(path);
      } catch (error) {
        if ((error as Failure).code === "EISDIR") removeTree(path);
        else if (permission(error)) {
          if (!isDirectory(path) || isJunction(path)) throw error;
          removeTree(path, path === root);
        } else throw error;
      }
    } catch (error) {
      if (!missing(error)) throw failure(error);
    }
  }
  function attempt(path: string, operation: () => void): void {
    try {
      operation();
    } catch (error) {
      if (!osError(error)) throw error;
      onError(path, error);
    }
  }
  function visit(path: string): void {
    let entries: { path: string; directory: boolean }[];
    try {
      entries = windowsFiles()
        .entriesWithTypes(widePath(path))
        .map((entry) => {
          const child = append(path, pathText(entry.name));
          return {
            path: child,
            directory:
              entry.isDirectory() &&
              !entry.isSymbolicLink() &&
              !isJunction(child),
          };
        });
    } catch (error) {
      if (!osError(error)) throw error;
      onError(path, error);
      return;
    }
    const directories = entries.filter((entry) => entry.directory);
    const files = entries.filter((entry) => !entry.directory);
    for (const entry of directories) visit(entry.path);
    for (const entry of directories)
      attempt(entry.path, () => windowsFiles().unlink(widePath(entry.path)));
    for (const entry of files) attempt(entry.path, () => unlink(entry.path));
  }
  try {
    if (stat(root, false).isSymbolicLink() || isJunction(root))
      throw new Error("Cannot call rmtree on a symbolic link");
  } catch (error) {
    if (!osError(error)) throw error;
    onError(root, error);
    return;
  }
  if (windows) {
    visit(root);
    attempt(root, () => windowsFiles().unlink(widePath(root)));
    return;
  }
  // Python's Unix walker removes files immediately and schedules directories
  // on a stack. A failed file-error handler is attributed to that directory.
  const pending = [{ path: root, remove: false }];
  while (pending.length) {
    const { path, remove } = pending.pop()!;
    try {
      if (remove) {
        pathCall(path, () => rmdirSync(encodePosixPath(path)));
        continue;
      }
      if (stat(path, false).isSymbolicLink())
        throw new Error("Cannot call rmtree on a symbolic link");
      const entries = unixBinding().directoryEntries(
        encodePosixPath(path),
        true,
      );
      checkedErrno(entries.errno, path);
      pending.push({ path, remove: true });
      for (const entry of entries.value) {
        const child = append(path, decodePosixBytes(entry.name));
        if (entry.errno === 0 && entry.isDirectory && !entry.isSymbolicLink)
          pending.push({ path: child, remove: false });
        else attempt(child, () => unlink(child));
      }
    } catch (error) {
      if (!osError(error)) throw error;
      (error as Failure).path = path;
      onError(path, failure(error));
    }
  }
}
export function withTemporaryDirectory<T>(
  prefix: string,
  operation: (path: string) => T,
): T {
  const path = makeTemporaryDirectory(prefix);
  try {
    return operation(path);
  } finally {
    removeTree(path);
  }
}
