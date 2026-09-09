import { getSystemErrorName } from "node:util";
import { processBinding } from "../native";
import { decodeFilename } from "../workbench-git";
import { windowsJoin } from "../../../native/windows-files.mjs";
import { encodePosixPath } from "./posix-path";
import { compare } from "./rank-worklists";
import { parsedPath } from "./resolve-security-md";

const excludedDirectories = new Set([
  ".cache",
  ".circleci",
  ".devcontainer",
  ".git",
  ".github",
  ".idea",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".tox",
  ".venv",
  ".vscode",
  "__pycache__",
  "bench",
  "benchmark",
  "bintest",
  "build",
  "build_config",
  "build_configs",
  "build-tools",
  "build_tools",
  "ci",
  "coverage",
  "deps",
  "dev",
  "dist",
  "doc",
  "docs",
  "example",
  "examples",
  "external",
  "extern",
  "fixture",
  "fixtures",
  "generated",
  "node_modules",
  "sample",
  "samples",
  "target",
  "test",
  "tests",
  "testing",
  "third-party",
  "third_party",
  "tmp",
  "vendor",
]);
const excludedFilenames = new Set([
  ".DS_Store",
  "CHANGELOG",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "Dockerfile",
  "Gemfile",
  "Gemfile.lock",
  "LICENSE",
  "LICENSE.md",
  "Makefile",
  "NEWS",
  "NEWS.md",
  "NOTICE",
  "README",
  "README.md",
  "README.rst",
  "Rakefile",
  "SECURITY.md",
  "TODO",
  "TODO.md",
  "docker-compose.yml",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);
export function pathIsExcluded(path: string): boolean {
  const parts = parsedPath(path).split(
    process.platform === "win32" ? /[/\\]/u : /\//u,
  );
  const name = parts.at(-1)!;
  return (
    parts.some((part) => excludedDirectories.has(part)) ||
    excludedFilenames.has(name) ||
    name.endsWith(".min.js") ||
    name.endsWith(".map")
  );
}

export function appendPath(directory: string, path: string): string {
  return parsedPath(
    process.platform === "win32"
      ? windowsJoin(directory, path)
      : path.startsWith("/")
        ? path
        : `${directory}/${path}`,
  );
}

/** These worklist commands intentionally inherit the caller's Git environment. */
export function bareCommand(program: string, args: string[], cwd?: string) {
  const encode = (value: string) =>
    process.platform === "win32"
      ? Buffer.from(value, "utf16le")
      : encodePosixPath(value);
  const result = processBinding().rawProcess({
    program: encode(program),
    args: args.map(encode),
    ...(cwd === undefined ? {} : { cwd: encode(cwd) }),
  });
  if (result.error) {
    const code =
      process.platform === "win32"
        ? `Windows error ${result.error}`
        : getSystemErrorName(-result.error);
    throw Object.assign(new Error(`could not start ${program}: ${code}`), {
      code,
    });
  }
  return result;
}

export class GitSelectionError extends Error {}
export function selectedGit(repository: string, args: string[]): Buffer {
  const result = bareCommand("git", ["-C", repository, ...args]);
  if (result.returnCode !== 0)
    throw new GitSelectionError(
      result.stderr.toString("utf8").trim() ||
        `Git exited with status ${result.returnCode}`,
    );
  return result.stdout;
}
export function nulFields(bytes: Buffer): Buffer[] {
  const fields: Buffer[] = [];
  let start = 0;
  for (let end = bytes.indexOf(0); end !== -1; end = bytes.indexOf(0, start)) {
    fields.push(bytes.subarray(start, end));
    start = end + 1;
  }
  if (start < bytes.length) fields.push(bytes.subarray(start));
  return fields;
}
export type ChangedPath = [path: string, status: string];
export type DiffMode = "revisions" | "local-patch";

export function pathKey(path: string): string {
  return process.platform === "win32" ? path.toLowerCase() : path;
}
function comparePaths(left: string, right: string): number {
  const separator = process.platform === "win32" ? /[/\\]/u : /\//u;
  const a = pathKey(left).split(separator),
    b = pathKey(right).split(separator);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    const order = compare(a[index]!, b[index]!);
    if (order) return order;
  }
  return a.length - b.length;
}

export function runGitChangedPaths(
  repository: string,
  args: string[],
): ChangedPath[] {
  const fields = nulFields(
    selectedGit(repository, [
      "diff",
      "--name-status",
      "-z",
      "--diff-filter=ACMRD",
      ...args,
    ]),
  );
  const changed: ChangedPath[] = [];
  for (let index = 0; index < fields.length; ) {
    const status = String.fromCharCode(fields[index++]![0]!);
    if (status === "C" || status === "R") index++;
    changed.push([
      appendPath(repository, decodeFilename(fields[index++]!)),
      status,
    ]);
  }
  return changed;
}
export function gitChangedPaths(
  repository: string,
  base: string,
  head: string,
  mode: DiffMode,
): ChangedPath[] {
  if (mode === "revisions")
    return runGitChangedPaths(repository, [`${base}..${head}`]);
  const unstaged = runGitChangedPaths(repository, [base]);
  const staged = runGitChangedPaths(repository, ["--cached", base]);
  const untracked = selectedGit(repository, [
    "ls-files",
    "--others",
    "--exclude-standard",
    "-z",
  ]);
  const combined = new Map<string, ChangedPath>();
  const add = ([path, status]: ChangedPath) => {
    const key = pathKey(path);
    combined.set(key, [combined.get(key)?.[0] ?? path, status]);
  };
  for (const changed of [...staged, ...unstaged]) add(changed);
  for (const path of nulFields(untracked))
    if (path.length) add([appendPath(repository, decodeFilename(path)), "A"]);
  return [...combined.values()].sort(([a], [b]) => comparePaths(a, b));
}
