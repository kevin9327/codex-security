import {
  closeSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readlinkSync,
  statSync,
  symlinkSync,
  writeSync,
  type BigIntStats,
} from "node:fs";
import { constants } from "node:os";
import { basename, dirname, parse, posix } from "node:path";
import { getSystemErrorName } from "node:util";
import {
  readDescriptor,
  type CopyStatMetadata,
} from "../../native/binding.mjs";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsJoin,
  windowsParts,
} from "../../native/windows-files.mjs";
import { windowsFlags as win } from "../../native/windows-flags.mjs";
import { unixBinding, windowsBinding } from "./native";
import { decodeFilename, gitBytes, gitOutput } from "./workbench-git";
import {
  gitWorktreeContext,
  TargetInspectionError,
} from "./workbench-git-snapshot";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { writeFile } from "./helpers/helper-files";
import { encodePosixPath } from "./helpers/posix-path";
import { pythonRepr } from "./helpers/python-json";
import { appendPath, nulFields, pathKey } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { encodeUtf8 } from "./helpers/utf8";

const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const stringJoin = (parent: string, name: string) =>
  windows
    ? windowsJoin(parent, name)
    : `${parent}${parent.endsWith("/") ? "" : "/"}${name}`;
function relativeTo(path: string, root: string): string | undefined {
  const parts = (value: string) => {
    value = parsedPath(value);
    const anchor = windows
      ? windowsParts(value).slice(0, 2).join("")
      : value.startsWith("//")
        ? "//"
        : parse(value).root;
    const names = value
      .slice(anchor.length)
      .split(windows ? /[/\\]/u : /\//u)
      .filter((name) => name !== "" && name !== ".");
    return [anchor, ...names];
  };
  const parent = parts(root),
    target = parts(path);
  return parent.every(
    (part, index) => pathKey(part) === pathKey(target[index] ?? ""),
  ) && parent.length <= target.length
    ? target.slice(parent.length).join("/")
    : undefined;
}
const osError = (error: unknown) =>
  (error as { errno?: number }).errno !== undefined ||
  (error as { winerror?: number }).winerror !== undefined;
const missing = (error: unknown) =>
  (error as NodeJS.ErrnoException).code === "ENOENT";
function pathCall<T>(
  path: string,
  operation: () => T,
  destination?: string,
): T {
  try {
    return operation();
  } catch (error) {
    // Node's error.path decodes Buffer filenames lossily, even for raw-path calls.
    const value = error as NodeJS.ErrnoException & { dest?: string };
    if (value.path !== undefined) value.path = path;
    if (value.dest !== undefined) value.dest = destination;
    throw error;
  }
}
const stat = (path: string, follow = true) =>
  windows
    ? windowsFiles().stat(widePath(path), follow)
    : pathCall(path, () =>
        (follow ? statSync : lstatSync)(encodePosixPath(path), {
          bigint: true,
        }),
      );
const readlink = (path: string) =>
  windows
    ? pathText(windowsFiles().readlink(widePath(path)))
    : decodeFilename(
        pathCall(path, () =>
          readlinkSync(encodePosixPath(path), { encoding: "buffer" }),
        ),
      );

function isDirectory(path: string): boolean {
  try {
    return stat(path).isDirectory();
  } catch (error) {
    if (!osError(error)) throw error;
    return false;
  }
}
function isLink(path: string): boolean {
  try {
    return stat(path, false).isSymbolicLink();
  } catch (error) {
    if (!osError(error)) throw error;
    return false;
  }
}

function copyError(error: unknown): Error {
  const value = error as NodeJS.ErrnoException & { dest?: string | Buffer };
  const destination = value.dest;
  const message =
    filesystemErrorMessage(error) +
    (destination === undefined
      ? ""
      : ` -> ${pythonRepr(Buffer.isBuffer(destination) ? decodeFilename(destination) : destination)}`);
  return Object.assign(new Error(message), value, { message });
}
function errno(error: number, path?: string): never {
  throw copyError({ errno: error, code: getSystemErrorName(-error), path });
}
function winerror(error: number, path?: string, dest?: string): never {
  throw copyError({ winerror: error, path, dest });
}

function mkdir(path: string): void {
  if (windows) windowsFiles().mkdir(widePath(path), false);
  else pathCall(path, () => mkdirSync(encodePosixPath(path)));
}
// pathlib.mkdir(parents=True, exist_ok=True), including the original error path.
function mkdirParents(path: string): void {
  try {
    mkdir(path);
  } catch (error) {
    if (missing(error) && dirname(path) !== path) {
      mkdirParents(dirname(path));
      mkdirParents(path);
    } else if (!osError(error) || !isDirectory(path)) throw error;
  }
}
// copytree uses os.makedirs(exist_ok=False), unlike the Git copy's Path.mkdir.
function mkdirTree(path: string): void {
  const parent = dirname(path);
  let exists = true;
  try {
    stat(parent);
  } catch (error) {
    if (!osError(error)) throw error;
    exists = false;
  }
  if (parent !== path && !exists) {
    try {
      mkdirTree(parent);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
  mkdir(path);
}

interface CopySource {
  path: string;
  kind: "path" | "entry";
  link?: boolean;
  cachedStat?: ReturnType<typeof stat>;
  cachedCopyStat?: CopyStatMetadata;
}
const sourceRepr = (source: CopySource) =>
  source.kind === "entry"
    ? `<DirEntry ${pythonRepr(basename(source.path))}>`
    : `${windows ? "WindowsPath" : "PosixPath"}(${pythonRepr(windows ? source.path.replaceAll("\\", "/") : source.path)})`;
const sourceLink = (source: CopySource) =>
  source.kind === "entry" ? source.link! : isLink(source.path);

function sourceStat(source: CopySource) {
  if (source.kind !== "entry") return stat(source.path);
  if (!source.cachedStat) {
    source.cachedStat = stat(source.path);
    if (windows) {
      const result = windowsBinding().readCopyStat(widePath(source.path), true);
      if (result.error) winerror(result.error, source.path);
      source.cachedCopyStat = result.metadata!;
    } else {
      const info = source.cachedStat as BigIntStats;
      let flags = 0;
      if (process.platform === "darwin") {
        const result = unixBinding().readCopyStat(
          encodePosixPath(source.path),
          true,
        );
        if (result.errno) errno(result.errno, source.path);
        flags = result.metadata!.flags;
      }
      source.cachedCopyStat = {
        mode: Number(info.mode & 0o7777n),
        atimeNs: info.atimeNs,
        mtimeNs: info.mtimeNs,
        flags,
      };
    }
  }
  return source.cachedStat;
}

function copyStat(
  source: CopySource,
  destination: string,
  followSymlinks = true,
): void {
  const follow = followSymlinks || !(sourceLink(source) && isLink(destination));
  const native = windows ? windowsBinding() : unixBinding();
  let metadata = source.cachedCopyStat;
  if (!metadata || !follow) {
    const result = native.readCopyStat(
      windows ? widePath(source.path) : encodePosixPath(source.path),
      follow,
    );
    if ("error" in result && result.error) winerror(result.error, source.path);
    if ("errno" in result && result.errno) errno(result.errno, source.path);
    metadata = result.metadata!;
  }
  if (windows) {
    if (follow) {
      const result = windowsBinding().setWindowsTimes(
        widePath(destination),
        metadata.atimeNs,
        metadata.mtimeNs,
      );
      if (result.error)
        winerror(
          result.error,
          result.path === null ? undefined : pathText(result.path),
        );
      if (isLink(destination))
        destination = pathText(windowsFiles().realpath(widePath(destination)));
    }
    windowsFiles().chmod(widePath(destination), metadata.mode);
  } else {
    const result = unixBinding().copyStat(
      encodePosixPath(source.path),
      encodePosixPath(destination),
      follow,
      metadata,
    );
    if (result.errno)
      errno(
        result.errno,
        result.path === null ? undefined : decodeFilename(result.path),
      );
  }
}

let unprivilegedSymlinks = true;
function windowsTargetIsDirectory(path: string): boolean {
  const opened = windowsBinding().openWindowsFile(
    widePath(path),
    0,
    win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE,
    win.OPEN_EXISTING,
    win.FILE_FLAG_BACKUP_SEMANTICS | win.FILE_FLAG_OPEN_REPARSE_POINT,
  );
  if (opened.error) return false;
  try {
    // _check_dirW reads the link's own attributes, including dangling directory links.
    const result = opened.handle!.attributes();
    return (
      !result.error && (result.attributes & win.FILE_ATTRIBUTE_DIRECTORY) !== 0
    );
  } finally {
    opened.handle!.close();
  }
}
function symlink(target: string, destination: string): void {
  if (!windows) {
    pathCall(
      target,
      () => symlinkSync(encodePosixPath(target), encodePosixPath(destination)),
      destination,
    );
    return;
  }
  // CPython infers a directory target relative to the new link, with MAX_PATH buffers.
  const parent = destination.slice(
    0,
    Math.max(destination.lastIndexOf("/"), destination.lastIndexOf("\\"), 0),
  );
  const resolved = /^[\\/]|^.:/u.test(target)
    ? target
    : `${parent}${parent ? "\\" : ""}${target}`;
  const directory =
    destination.length < 260 &&
    resolved.length < 260 &&
    windowsTargetIsDirectory(resolved);
  let flags =
    (directory ? win.SYMBOLIC_LINK_FLAG_DIRECTORY : 0) |
    (unprivilegedSymlinks
      ? win.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
      : 0);
  let error = windowsBinding().createWindowsSymlink(
    widePath(target),
    widePath(destination),
    flags,
  );
  if (error === 87 && unprivilegedSymlinks) {
    flags &= ~win.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    error = windowsBinding().createWindowsSymlink(
      widePath(target),
      widePath(destination),
      flags,
    );
    if (error !== 87) unprivilegedSymlinks = false;
  }
  if (error) winerror(error, target, destination);
}

type TreeFailure =
  | [sourceRepr: string, destinationRepr: string, message: string]
  | string;
class CopyTreeError extends Error {
  constructor(readonly failures: TreeFailure[]) {
    super(
      `[${failures.map((failure) => (typeof failure === "string" ? pythonRepr(failure) : `(${failure[0]}, ${failure[1]}, ${pythonRepr(failure[2])})`)).join(", ")}]`,
    );
  }
}
class SameFileError extends Error {}
class SpecialFileError extends Error {}

function copyBytes(source: string, destination: string): void {
  if (windows) {
    const result = windowsBinding().copyFileCrt(
      widePath(source),
      widePath(destination),
    );
    if (result.errno)
      errno(
        result.errno,
        result.path === null ? undefined : pathText(result.path),
      );
    return;
  }
  const input = pathCall(source, () => openSync(encodePosixPath(source), "r"));
  try {
    if (fstatSync(input).isDirectory()) errno(constants.errno.EISDIR, source);
    const output = pathCall(destination, () =>
      openSync(encodePosixPath(destination), "w"),
    );
    try {
      const bytes = Buffer.alloc(64 * 1024);
      for (;;) {
        const count = readDescriptor(input, bytes, 0, bytes.length, null);
        if (!count) break;
        for (let offset = 0; offset < count; ) {
          try {
            offset += writeSync(output, bytes, offset, count - offset);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EINTR") throw error;
          }
        }
      }
    } finally {
      closeSync(output);
    }
  } finally {
    closeSync(input);
  }
}

function copy2(
  source: CopySource,
  destination: string,
  followSymlinks = true,
  destinationIsPath = false,
): void {
  if (isDirectory(destination)) {
    destination = appendPath(destination, basename(source.path));
    destinationIsPath = false;
  }
  if (windows) {
    const error = windowsBinding().copyFile2(
      widePath(source.path),
      widePath(destination),
      win.COPY_FILE_ALLOW_DECRYPTED_DESTINATION |
        (followSymlinks ? 0 : win.COPY_FILE_COPY_SYMLINK),
    );
    if (!error) return;
    if (error !== 5 && !(error === 1314 && !followSymlinks)) winerror(error);
  }
  let same = false;
  try {
    if (windows) {
      sourceStat(source);
      same = windowsFiles().sameFile(
        widePath(source.path),
        widePath(destination),
      );
    } else {
      const first = sourceStat(source) as BigIntStats,
        second = stat(destination) as BigIntStats;
      same = first.dev === second.dev && first.ino === second.ino;
    }
  } catch (error) {
    if (!osError(error)) throw error;
  }
  if (same) {
    const message = `${sourceRepr(source)} and ${destinationIsPath ? sourceRepr({ path: destination, kind: "path" }) : pythonRepr(destination)} are the same file`;
    // shutil._copytree extends Error.args[0]; SameFileError supplies a string.
    throw new SameFileError(message);
  }
  for (const path of [source, { path: destination, kind: "path" } as const]) {
    let info;
    try {
      info = sourceStat(path);
    } catch (error) {
      if (!osError(error)) throw error;
    }
    if (info && (Number(info.mode) & 0o170000) === 0o010000)
      throw new SpecialFileError(`\`${path.path}\` is a named pipe`);
  }
  if (!followSymlinks && sourceLink(source))
    symlink(readlink(source.path), destination);
  else copyBytes(source.path, destination);
  copyStat(source, destination, followSymlinks);
}

function copyTree(
  source: CopySource,
  destination: string,
  excluded: readonly string[],
  root: string,
): void {
  const entries = windows
    ? windowsFiles()
        .entriesWithTypes(widePath(source.path))
        .map((entry) => ({
          name: pathText(entry.name),
          directory: entry.isDirectory(),
          link: entry.isSymbolicLink(),
          errno: 0,
        }))
    : (() => {
        const result = unixBinding().directoryEntries(
          encodePosixPath(source.path),
          true,
        );
        if (result.errno) errno(result.errno, source.path);
        return result.value.map((entry) => ({
          name: decodeFilename(entry.name),
          directory: entry.isDirectory,
          link: entry.isSymbolicLink,
          errno: entry.errno,
        }));
      })();
  const relative = relativeTo(source.path, root) || ".";
  const ignored = excluded
    .filter((path) => pathKey(posix.dirname(path)) === pathKey(relative))
    .map((path) => posix.basename(path));
  mkdirTree(destination);
  const failures: TreeFailure[] = [];
  for (const entry of entries) {
    if (ignored.includes(entry.name)) continue;
    const from = stringJoin(source.path, entry.name),
      to = stringJoin(destination, entry.name);
    const child: CopySource = { path: from, kind: "entry", link: entry.link };
    try {
      if (entry.errno) errno(entry.errno, from);
      if (entry.link) {
        symlink(readlink(from), to);
        copyStat(child, to, false);
      } else if (entry.directory) copyTree(child, to, excluded, root);
      else copy2(child, to);
    } catch (error) {
      if (error instanceof CopyTreeError) {
        for (const failure of error.failures) failures.push(failure);
      } else if (error instanceof SameFileError) {
        for (const character of error.message) failures.push(character);
      } else if (osError(error) || error instanceof SpecialFileError)
        failures.push([
          pythonRepr(from),
          pythonRepr(to),
          copyError(error).message,
        ]);
      else throw error;
    }
  }
  try {
    copyStat(source, destination);
  } catch (error) {
    if (!osError(error)) throw error;
    if ((error as { winerror?: number }).winerror === undefined)
      failures.push([
        sourceRepr(source),
        source.kind === "path"
          ? sourceRepr({ path: destination, kind: "path" })
          : pythonRepr(destination),
        copyError(error).message,
      ]);
  }
  if (failures.length) throw new CopyTreeError(failures);
}

/** Copy a directory with the workbench's lexical exclusions and copytree metadata. */
export function copyDirectoryExcluding(
  source: string,
  destination: string,
  excluded: readonly string[],
): void {
  source = parsedPath(source);
  destination = parsedPath(destination);
  const relative = excluded.flatMap((path) => {
    const value = relativeTo(path, source);
    return value === undefined ? [] : [value || "."];
  });
  try {
    copyTree({ path: source, kind: "path" }, destination, relative, source);
  } catch (error) {
    throw osError(error) ? copyError(error) : error;
  }
}

function writeGitPointer(path: string, gitDir: string): void {
  const text = `gitdir: ${gitDir}\n`;
  // Path.write_text opens the destination before strict UTF-8 encoding.
  pathCall(path, () =>
    writeFile(
      path,
      (function* () {
        yield encodeUtf8(windows ? text.replaceAll("\n", "\r\n") : text);
      })(),
    ),
  );
}

/** Copy Git's tracked and untracked selection, retaining nested repository links. */
export function copyGitWorktreeFiles(
  source: string,
  destination: string,
  excluded: readonly string[],
): string {
  destination = parsedPath(destination);
  const [repository, pathspec] = gitWorktreeContext(parsedPath(source));
  const listed = gitBytes(repository, [
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
    "-z",
    "--",
    pathspec,
  ]);
  if (listed === null)
    throw new TargetInspectionError(
      "Could not inspect files in the selected Git working tree.",
    );
  const relative = excluded.flatMap((path) => {
    const value = relativeTo(path, repository);
    return value === undefined ? [] : [pathKey(value || ".")];
  });
  try {
    mkdir(destination);
    for (const rawPath of nulFields(listed)
      .filter((path) => path.length)
      .sort(Buffer.compare)) {
      const path = parsedPath(decodeFilename(rawPath)),
        key = pathKey(path.replaceAll(windows ? "\\" : "/", "/"));
      if (
        relative.some(
          (excludedPath) =>
            excludedPath === "." ||
            key === excludedPath ||
            key.startsWith(excludedPath + "/"),
        )
      )
        continue;
      const from = appendPath(repository, path),
        to = appendPath(destination, path);
      let metadata;
      try {
        metadata = stat(from, false);
      } catch (error) {
        if (missing(error)) continue;
        throw error;
      }
      mkdirParents(dirname(to));
      if (metadata.isSymbolicLink()) symlink(readlink(from), to);
      else if (metadata.isFile())
        copy2({ path: from, kind: "path" }, to, false, true);
      else if (metadata.isDirectory()) {
        const gitDir = gitOutput(from, ["rev-parse", "--absolute-git-dir"]);
        if (gitDir === null)
          throw new TargetInspectionError(
            `Could not inspect nested Git working tree: ${path}`,
          );
        copyGitWorktreeFiles(from, to, excluded);
        writeGitPointer(appendPath(to, ".git"), gitDir);
      } else
        throw new TargetInspectionError(
          `Unsupported Git working-tree file type: ${path}`,
        );
    }
    const target =
      pathspec === "." ? destination : appendPath(destination, pathspec);
    mkdirParents(target);
    return target;
  } catch (error) {
    throw osError(error) ? copyError(error) : error;
  }
}
