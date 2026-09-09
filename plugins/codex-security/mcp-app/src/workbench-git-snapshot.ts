import { lstatSync, statSync } from "node:fs";
import { sep } from "node:path";
import { unixBinding, windowsBinding } from "./native";
import { decodeFilename, gitBytes, gitOutput } from "./workbench-git";
import {
  widePath,
  windowsFileSystem,
  windowsJoin,
} from "../../native/windows-files.mjs";
import { decodePosixBytes, encodePosixPath } from "./helpers/posix-path";
import { compare } from "./helpers/rank-worklists";
import { resolvedPath } from "./helpers/resolve-path";
import { parsedPath } from "./helpers/resolve-security-md";

const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const joinPath = (left: string, right: string) =>
  parsedPath(
    windows
      ? windowsJoin(left, right)
      : right.startsWith("/")
        ? right
        : `${left}/${right}`,
  );
const pathParts = (path: string) =>
  parsedPath(path)
    .split(sep)
    .filter((part) => part !== "" && part !== ".");
const equalPath = (left: string, right: string) =>
  windows ? left.toLowerCase() === right.toLowerCase() : left === right;

// Path.relative_to is lexical; inventory scope aliases are checked with sameFile below.
function windowsWorktreeRelativePath(
  path: string,
  root: string,
): string | undefined {
  const parts = (value: string) => value.replace(/\\+$/u, "").split("\\");
  const parent = parts(root);
  const target = parts(path);
  return parent.every(
    (part, index) => part.toLowerCase() === target[index]?.toLowerCase(),
  )
    ? target.slice(parent.length).join("\\")
    : undefined;
}

export function gitWorktreeContext(target: string): [string, string] {
  const root = gitOutput(target, ["rev-parse", "--show-toplevel"]);
  if (root === null)
    throw new Error("Could not inspect the selected Git working tree.");
  const repository = resolvedPath(root, false);
  const selected = resolvedPath(target, false);
  const relative = windows
    ? windowsWorktreeRelativePath(selected, repository)
    : selected === repository
      ? ""
      : selected.startsWith(repository.replace(/\/$/u, "") + "/")
        ? selected.slice(repository.replace(/\/$/u, "").length + 1)
        : undefined;
  if (relative === undefined)
    throw new Error("Scan target must stay inside its Git working tree.");
  return [repository, relative.split(sep).join("/") || "."];
}

function sameFile(left: string, right: string): boolean {
  if (windows) return windowsFiles().sameFile(widePath(left), widePath(right));
  const first = statSync(encodePosixPath(left), { bigint: true });
  const second = statSync(encodePosixPath(right), { bigint: true });
  return first.dev === second.dev && first.ino === second.ino;
}

// Path.rglob("*") suppresses enumeration errors and does not descend into symlinks.
function* descendants(directory: string): Iterable<string> {
  const pending = [directory];
  while (pending.length) {
    const parent = pending.pop()!;
    let entries: { name: string; directory: boolean }[];
    if (windows) {
      try {
        entries = windowsFiles()
          .entriesWithTypes(widePath(parent))
          .map((entry) => ({
            name: entry.name.toString("utf16le"),
            directory: entry.isDirectory() && !entry.isSymbolicLink(),
          }));
      } catch (error) {
        if ((error as { winerror?: number }).winerror !== undefined) continue;
        throw error;
      }
    } else {
      const result = unixBinding().directoryEntries(
        encodePosixPath(parent),
        true,
      );
      if (result.errno) continue;
      entries = result.value.map((entry) => ({
        name: decodePosixBytes(entry.name),
        directory:
          entry.errno === 0 && entry.isDirectory && !entry.isSymbolicLink,
      }));
    }
    for (const entry of entries) yield joinPath(parent, entry.name);
    for (let index = entries.length - 1; index >= 0; index--) {
      const entry = entries[index]!;
      if (entry.directory) pending.push(joinPath(parent, entry.name));
    }
  }
}

/** Enumerate tracked and nonignored working-tree paths within a filesystem scope. */
export function gitDirectorySnapshotPaths(target: string): string[] | null {
  if (gitOutput(target, ["rev-parse", "--show-toplevel"]) === null) return null;
  const [repository, pathspec] = gitWorktreeContext(target);
  const scope = joinPath(repository, pathspec);
  const depth = pathParts(pathspec).length;
  const matchingPrefixes = new Map<string, boolean>();
  const args: string[] = [];
  let inventoryPathspec = pathspec;
  if (depth) {
    if (
      Array.from(pathspec).some(
        (character) =>
          character.codePointAt(0)! > 127 &&
          character.toLowerCase() !== character.toUpperCase(),
      )
    ) {
      // Git's icase pathspecs do not cover Unicode case aliases.
      inventoryPathspec = ".";
    } else {
      args.push("--no-literal-pathspecs");
      inventoryPathspec = `:(icase,literal)${pathspec}`;
    }
  }
  const listed = gitBytes(repository, [
    ...args,
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
    "-z",
    "--",
    inventoryPathspec,
  ]);
  if (listed === null)
    throw new Error(
      "Could not inspect files in the selected Git working tree.",
    );
  const paths: string[] = [];
  let offset = 0;
  for (let end = 0; end <= listed.length; end++) {
    if (end !== listed.length && listed[end] !== 0) continue;
    const raw = listed.subarray(offset, end);
    offset = end + 1;
    if (!raw.length) continue;
    const relative = parsedPath(decodeFilename(raw));
    let path = joinPath(repository, relative);
    if (depth) {
      const parts = pathParts(relative);
      if (parts.length <= depth) continue;
      const prefix = joinPath(repository, parts.slice(0, depth).join(sep));
      if (!matchingPrefixes.has(prefix)) {
        try {
          matchingPrefixes.set(prefix, sameFile(prefix, scope));
        } catch (error) {
          if (
            !["ENOENT", "ENOTDIR"].includes(
              (error as NodeJS.ErrnoException).code ?? "",
            )
          )
            throw error;
          matchingPrefixes.set(prefix, false);
        }
      }
      if (!matchingPrefixes.get(prefix)) continue;
      path = joinPath(scope, parts.slice(depth).join(sep));
    }
    let directory: boolean;
    try {
      directory = windows
        ? windowsFiles().stat(widePath(path), false).isDirectory()
        : lstatSync(encodePosixPath(path)).isDirectory();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    paths.push(path);
    if (!directory) continue;
    const nestedRoot = gitOutput(path, ["rev-parse", "--show-toplevel"]);
    if (
      nestedRoot !== null &&
      equalPath(resolvedPath(nestedRoot, false), resolvedPath(path, false))
    ) {
      const nested = gitDirectorySnapshotPaths(path);
      if (nested !== null) {
        for (const child of nested) paths.push(child);
        continue;
      }
    }
    for (const nested of descendants(path)) {
      const relativeParts = pathParts(nested.slice(path.length));
      if (!relativeParts.includes(".git")) paths.push(nested);
    }
  }
  return [...new Set(paths)].sort(compare);
}
