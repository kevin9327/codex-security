import { randomBytes } from "node:crypto";
import {
  closeSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, extname, isAbsolute, join } from "node:path";
import {
  widePath,
  windowsFileSystem,
  windowsParts,
} from "../../../native/windows-files.mjs";
import { windowsBinding } from "../native";
import { decodeFilename, gitBlobBytes } from "../workbench-git";
import { exists, fileInfo as metadata, mkdir } from "./helper-files";
import { encodePosixPath, SymlinkLoopError } from "./posix-path";
import {
  DEFAULT_PREVIEW_BYTES,
  TEXT_CODE_EXTENSIONS,
  isBinarySample,
  previewFor,
} from "./rank-preview";
import {
  appendPath,
  bareCommand,
  gitChangedPaths,
  GitSelectionError,
  nulFields,
  pathIsExcluded,
  pathKey,
  relativePath,
  selectedGit,
  windowsStreamComponent,
  type ChangedPath,
  type DiffMode,
} from "./rank-selection";
import {
  ArgumentError,
  argumentsFor,
  print,
  worklistPath,
} from "./rank-worklists";
import { resolvedPath } from "./resolve-path";
import { HomeExpansionError } from "./resolve-security-md";

const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
export class InventoryError extends Error {}

export function resolveRepository(
  value: string,
  posixHome = process.env["HOME"],
): string {
  let repository: string;
  try {
    repository = resolvedPath(worklistPath(value, posixHome));
  } catch (error) {
    if (
      error instanceof HomeExpansionError ||
      error instanceof SymlinkLoopError
    )
      throw error;
    throw new InventoryError(`--repo: cannot resolve repository: ${value}`, {
      cause: error,
    });
  }
  if (!metadata(repository)?.isDirectory())
    throw new InventoryError(`--repo: expected a directory: ${repository}`);
  return repository;
}
export function resolveScope(
  repository: string,
  value: string,
  posixHome = process.env["HOME"],
): string {
  if (!value || value.includes("\0"))
    throw new InventoryError("--scope: expected a non-empty file or directory");
  const requested = worklistPath(value, posixHome);
  const stream = windowsStreamComponent(requested);
  if (stream !== undefined)
    throw new InventoryError(
      `--scope: NTFS alternate data streams are not supported: ${stream}`,
    );
  let resolved: string;
  try {
    resolved = resolvedPath(appendPath(repository, requested));
  } catch (error) {
    if (error instanceof SymlinkLoopError) throw error;
    throw new InventoryError(`--scope: path does not exist: ${value}`, {
      cause: error,
    });
  }
  const relative = relativePath(resolved, repository);
  if (relative === undefined)
    throw new InventoryError(
      `--scope: path must remain inside --repo: ${value}`,
    );
  const info = metadata(resolved);
  if (!info?.isDirectory() && !info?.isFile())
    throw new InventoryError(`--scope: expected a file or directory: ${value}`);
  const absolute = windows
    ? windowsParts(requested).slice(0, 2).every(Boolean)
    : isAbsolute(requested);
  return absolute ? relative || "." : value;
}
export function resolveOutput(
  value: string,
  posixHome = process.env["HOME"],
): string {
  if (!value || value.includes("\0"))
    throw new InventoryError("--out: expected an inventory file path");
  const requested = worklistPath(value, posixHome);
  if (metadata(requested, false)?.isSymbolicLink())
    throw new InventoryError("--out: refusing to replace a symbolic link");
  let output: string;
  try {
    output = resolvedPath(requested, false);
  } catch (error) {
    if (error instanceof SymlinkLoopError) throw error;
    throw new InventoryError(`--out: cannot resolve inventory path: ${value}`, {
      cause: error,
    });
  }
  if (exists(output) && !metadata(output)?.isFile())
    throw new InventoryError(`--out: expected a regular file path: ${output}`);
  return output;
}

export function generateInScopeFiles(
  repository: string,
  scope: string,
  output: string,
): number {
  let result;
  try {
    result = bareCommand(
      "rg",
      [
        "--files",
        "--hidden",
        "--path-separator",
        "/",
        "--glob",
        "!.git/**",
        "--",
        scope,
      ],
      repository,
    );
  } catch (error) {
    throw new InventoryError(
      `could not run ripgrep: ${(error as Error).message}`,
      { cause: error },
    );
  }
  if (result.returnCode !== 0 && result.returnCode !== 1) {
    const detail = result.stderr.toString("utf8").trim();
    throw new InventoryError(
      `ripgrep exited with status ${result.returnCode}${detail ? `: ${detail}` : ""}`,
    );
  }
  const contents = [result.stdout];
  if (exists(appendPath(repository, ".git"))) {
    let tracked;
    try {
      tracked = bareCommand(
        "git",
        [
          "ls-files",
          "--cached",
          "--ignored",
          "--exclude-standard",
          "-z",
          "--",
          scope,
        ],
        repository,
      );
    } catch {
      /* Git's tracked-ignore supplement is optional. */
    }
    if (tracked?.returnCode === 0) {
      const prefix = scope === "." || scope.startsWith("./") ? "./" : "";
      for (const path of nulFields(tracked.stdout)) {
        const candidate = appendPath(repository, decodeFilename(path));
        if (
          path.length &&
          metadata(candidate)?.isFile() &&
          !metadata(candidate, false)?.isSymbolicLink()
        )
          contents.push(
            Buffer.concat([Buffer.from(prefix), path, Buffer.from("\n")]),
          );
      }
    }
  }
  const bytes = Buffer.concat(contents),
    rows: Buffer[] = [];
  let start = 0;
  for (
    let end = bytes.indexOf(10);
    end !== -1;
    end = bytes.indexOf(10, start)
  ) {
    rows.push(bytes.subarray(start, end + 1));
    start = end + 1;
  }
  if (start < bytes.length) rows.push(bytes.subarray(start));
  return writeInventory(output, rows.sort(Buffer.compare));
}

export function committedChangedPaths(
  repository: string,
  base: string,
  head: string,
): ChangedPath[] {
  const fields = nulFields(
    selectedGit(repository, [
      "diff",
      "--raw",
      "-z",
      "--diff-filter=ACMRD",
      `${base}..${head}`,
    ]),
  );
  const changed: ChangedPath[] = [];
  for (let index = 0; index < fields.length; ) {
    const metadata = fields[index++]!.toString("ascii").trim().split(/\s+/u);
    const status = metadata.at(-1)![0]!;
    if (status === "C" || status === "R") index++;
    const path = decodeFilename(fields[index++]!);
    const mode = status === "D" ? metadata[0]!.slice(1) : metadata[1];
    if (mode !== "120000") changed.push([appendPath(repository, path), status]);
  }
  return changed;
}
export function generateDiffInScopeFiles(
  repository: string,
  base: string,
  head: string,
  mode: DiffMode,
  output: string,
): number {
  const rows = new Map<string, Buffer>();
  try {
    const changed =
      mode === "revisions"
        ? committedChangedPaths(repository, base, head)
        : gitChangedPaths(repository, base, head, mode);
    const eligible = changed.filter(
      ([path]) =>
        !pathIsExcluded(relativePath(path, repository)!) &&
        TEXT_CODE_EXTENSIONS.has(extname(path).toLowerCase()),
    );
    const revisionPaths = eligible
      .filter(([, status]) => mode === "revisions" && status !== "D")
      .map(([path]) => relativePath(path, repository)!);
    const blobs = gitBlobBytes(
      repository,
      revisionPaths.map((path) => `${head}:${path}`),
    );
    const revisionBlobs = new Map(
      revisionPaths.map((path, index) => [pathKey(path), blobs[index]]),
    );
    for (const [path, status] of eligible) {
      const relative = relativePath(path, repository)!;
      if (status !== "D") {
        if (mode === "revisions") {
          const contents = revisionBlobs.get(pathKey(relative));
          if (contents == null)
            throw new InventoryError(
              `could not read committed diff blob: ${head}:${relative}`,
            );
          if (isBinarySample(contents)) continue;
        } else if (
          metadata(path, false)?.isSymbolicLink() ||
          !metadata(path)?.isFile() ||
          previewFor(path, DEFAULT_PREVIEW_BYTES)[1]
        )
          continue;
      }
      if (/[\n\r]/u.test(relative))
        throw new InventoryError(
          "Git changes contain a path that cannot fit in the file inventory",
        );
      if (/[\ud800-\udfff]/u.test(relative))
        throw new Error("UTF-8 cannot encode an unpaired surrogate");
      rows.set(relative, Buffer.from(`${relative}\n`));
    }
  } catch (error) {
    if (
      error instanceof GitSelectionError ||
      (error && typeof error === "object" && "code" in error)
    )
      throw new InventoryError(
        `could not resolve the selected Git changes: ${(error as Error).message}`,
        { cause: error },
      );
    throw error;
  }
  return writeInventory(output, [...rows.values()].sort(Buffer.compare));
}

export function writeInventory(output: string, rows: Buffer[]): number {
  mkdir(dirname(output));
  const temporary = join(
    dirname(output),
    `.${basename(output)}.${randomBytes(6).toString("base64url")}.tmp`,
  );
  let created = false;
  try {
    if (windows) {
      function* contents() {
        created = true;
        yield* rows;
      }
      windowsFiles().writeFile(widePath(temporary), contents(), true);
      windowsFiles().rename(widePath(temporary), widePath(output));
    } else {
      const descriptor = openSync(encodePosixPath(temporary), "wx", 0o600);
      created = true;
      try {
        for (const row of rows) writeFileSync(descriptor, row);
      } finally {
        closeSync(descriptor);
      }
      renameSync(encodePosixPath(temporary), encodePosixPath(output));
    }
  } finally {
    if (created)
      try {
        if (windows) windowsFiles().unlink(widePath(temporary));
        else unlinkSync(encodePosixPath(temporary));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
  }
  return rows.length;
}
export interface InventoryOptions {
  repo: string;
  scope: string;
  out: string;
  diffBase?: string;
  diffHead?: string;
  diffMode?: DiffMode;
}
export function prepareInventory(
  options: InventoryOptions,
  posixHome = process.env["HOME"],
): number {
  const repository = resolveRepository(options.repo, posixHome);
  const scope = resolveScope(repository, options.scope, posixHome);
  const output = resolveOutput(options.out, posixHome);
  if (options.diffBase === undefined)
    return generateInScopeFiles(repository, scope, output);
  if (scope !== "." && scope !== "./")
    throw new InventoryError(
      "--scope: diff scans must use the repository root",
    );
  return generateDiffInScopeFiles(
    repository,
    options.diffBase,
    options.diffHead ?? "HEAD",
    options.diffMode ?? "revisions",
    output,
  );
}
export function generateInScopeFilesCommand(
  args: string[],
  posixHome = process.env["HOME"],
): number {
  const usage =
    "usage: launch_codex_security_mcp[.cmd] --helper generate-in-scope-files [-h] --repo REPO --scope SCOPE --out OUT [--diff-base DIFF_BASE] [--diff-head DIFF_HEAD] [--diff-mode {revisions,local-patch}]";
  try {
    const values = argumentsFor(args, ["repo", "scope", "out"], [], {
      "diff-base": undefined,
      "diff-head": undefined,
      "diff-mode": ["revisions", "local-patch"],
    });
    if (values.help) {
      print(
        `${usage}\n\nGenerate the shared, deterministically ordered security-scan file inventory.\n\noptions:\n  -h, --help  show this help message and exit\n  --repo REPO  Repository root.\n  --scope SCOPE  File or directory within the repository.\n  --out OUT  Destination for the file inventory.\n  --diff-base DIFF_BASE  Authoritative Git base for a changed-file inventory.\n  --diff-head DIFF_HEAD  Authoritative Git head revision (default: HEAD).\n  --diff-mode {revisions,local-patch}  Use committed revisions or the current staged and unstaged patch (default: revisions).`,
      );
      return 0;
    }
    const mode = (values["diff-mode"] ?? "revisions") as DiffMode;
    const count = prepareInventory(
      {
        repo: values.repo as string,
        scope: values.scope as string,
        out: values.out as string,
        diffBase: values["diff-base"] as string | undefined,
        diffHead: values["diff-head"] as string | undefined,
        diffMode: mode,
      },
      posixHome,
    );
    print(`Recorded ${count} in-scope files.`);
    return 0;
  } catch (error) {
    if (error instanceof ArgumentError) print(usage, true);
    print(
      `generate_in_scope_files: ${error instanceof ArgumentError ? "error: " : ""}${(error as Error).message}`,
      true,
    );
    return error instanceof HomeExpansionError ||
      error instanceof SymlinkLoopError
      ? 1
      : 2;
  }
}
