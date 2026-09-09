import { basename, dirname, extname } from "node:path";
import { decodeFilename, gitBlobBytes } from "../workbench-git";
import {
  descendants,
  gitDirectorySnapshotPaths,
} from "../workbench-git-snapshot";
import { exists, fileInfo } from "./helper-files";
import {
  DEFAULT_PREVIEW_BYTES,
  TEXT_CODE_EXTENSIONS,
  previewFor,
  previewForBytes,
} from "./rank-preview";
import {
  appendPath,
  bareCommand,
  excludedFilenames,
  gitChangedPaths,
  nulFields,
  pathIsExcluded,
  pathKey,
  relativePath,
  windowsStreamComponent,
  type DiffMode,
} from "./rank-selection";
import {
  ArgumentError,
  argumentsFor,
  compare,
  loadScopesFile,
  print,
  worklistPath,
  writeRankRows,
  type RankRow,
} from "./rank-worklists";
import { resolvedPath } from "./resolve-path";
import { parsedPath } from "./resolve-security-md";

const directPreviewReadBytes = 64 * 1024;
type Command =
  | "make-repo-rank-input"
  | "make-repo-scope-input"
  | "make-diff-rank-input";
const filesystemError = (error: unknown) =>
  error instanceof Error &&
  ("code" in error || "errno" in error || "winerror" in error);

export function resolveRankScope(
  repository: string,
  scope: string,
  expandUser: boolean,
  rejectSymlinks: boolean,
  posixHome = process.env["HOME"],
): string {
  const requested = expandUser
    ? worklistPath(scope, posixHome)
    : parsedPath(scope);
  const stream = windowsStreamComponent(requested);
  if (stream !== undefined)
    throw new Error(
      `Scope must not use an NTFS alternate data stream: ${stream}`,
    );
  const path = appendPath(repository, requested);
  if (rejectSymlinks) {
    const relative = relativePath(path, repository);
    const outside = () => new Error(`Scope must be inside repo: ${path}`);
    if (relative === undefined) throw outside();
    let ancestor = repository;
    for (const part of relative.split("/").filter(Boolean)) {
      if (part === "..") {
        if (pathKey(ancestor) === pathKey(repository)) throw outside();
        ancestor = dirname(ancestor);
        continue;
      }
      ancestor = appendPath(ancestor, part);
      let info;
      try {
        info = fileInfo(ancestor, false);
      } catch (error) {
        if (!filesystemError(error)) throw error;
      }
      if (!info) throw new Error(`Scope path not found: ${ancestor}`);
      if (
        info.isSymbolicLink() ||
        ("reparseTag" in info && info.reparseTag & 0x20000000)
      )
        throw new Error(
          `Requested scope must not contain symbolic links: ${ancestor}`,
        );
    }
  }
  const resolved = resolvedPath(path, false);
  if (relativePath(resolved, repository) === undefined)
    throw new Error(`Scope must be inside repo: ${resolved}`);
  const info = fileInfo(resolved);
  if (!info?.isDirectory() && !info?.isFile())
    throw new Error(`Scope path not found: ${resolved}`);
  return resolved;
}

export function repoRankRows(
  repository: string,
  scopes: string[],
  explicit: boolean,
  area: string,
  previewBytes: number,
  posixHome = process.env["HOME"],
): RankRow[] {
  const resolvedScopes = scopes.map((scope) =>
    resolveRankScope(repository, scope, !explicit, false, posixHome),
  );
  const directFiles = new Set(
    resolvedScopes
      .filter((scope) => explicit && fileInfo(scope)?.isFile())
      .map(pathKey),
  );
  const rows = new Map<string, RankRow>();
  for (const scope of resolvedScopes) {
    const label = area || relativePath(scope, repository) || ".";
    const file = fileInfo(scope)?.isFile();
    for (const path of file ? [scope] : descendants(scope)) {
      try {
        if (
          fileInfo(path, false)?.isSymbolicLink() ||
          !fileInfo(path)?.isFile()
        )
          continue;
        if (relativePath(resolvedPath(path), repository) === undefined)
          continue;
      } catch (error) {
        if (filesystemError(error)) continue;
        throw error;
      }
      const relative = relativePath(path, repository)!;
      const directlyRequested = directFiles.has(pathKey(path));
      const excludedPath = explicit
        ? relativePath(path, file ? dirname(scope) : scope)!
        : relative;
      const sourceLike = TEXT_CODE_EXTENSIONS.has(extname(path).toLowerCase());
      if (!directlyRequested && (pathIsExcluded(excludedPath) || !sourceLike))
        continue;
      let preview = "";
      if (
        !directlyRequested ||
        sourceLike ||
        excludedFilenames.has(basename(path))
      ) {
        const result = previewFor(
          path,
          previewBytes,
          directlyRequested ? directPreviewReadBytes : undefined,
        );
        if (result[1] && !directlyRequested) continue;
        preview = result[0];
      }
      if (!rows.has(relative))
        rows.set(relative, { path: relative, area: label, preview });
    }
  }
  return [...rows.values()].sort((a, b) => compare(a.path, b.path));
}

function* ancestors(path: string): Iterable<string> {
  while (true) {
    yield path;
    const parent = dirname(path);
    if (parent === path) return;
    path = parent;
  }
}

function scopedFiles(repository: string, scope: string): Iterable<string> {
  const paths = gitDirectorySnapshotPaths(scope);
  if (paths !== null) return paths;
  let result;
  try {
    result = bareCommand(
      "rg",
      [
        "--files",
        "--hidden",
        "--no-require-git",
        "--null",
        "--glob",
        "!.git/**",
        "--",
        relativePath(scope, repository) || ".",
      ],
      repository,
    );
  } catch (error) {
    if (!filesystemError(error)) throw error;
    const ignoreNames = new Set([".gitignore", ".ignore", ".rgignore"]);
    let hasRules =
      [...ancestors(repository)].some((path) =>
        exists(appendPath(path, ".git")),
      ) ||
      [...ancestors(scope)].some(
        (path) =>
          relativePath(path, repository) !== undefined &&
          [...ignoreNames].some((name) =>
            fileInfo(appendPath(path, name))?.isFile(),
          ),
      );
    if (!hasRules)
      for (const path of descendants(scope)) {
        if (fileInfo(path)?.isFile() && ignoreNames.has(basename(path))) {
          hasRules = true;
          break;
        }
      }
    if (hasRules)
      throw new Error(
        "Could not safely enumerate ignored scoped files without Git or ripgrep.",
        { cause: error },
      );
    return descendants(scope);
  }
  if (result.returnCode !== 0 && result.returnCode !== 1)
    throw new Error(
      `Could not enumerate scoped repository files: ${result.stderr.toString("utf8").trim()}`,
    );
  return nulFields(result.stdout)
    .filter((path) => path.length)
    .map((path) => appendPath(repository, decodeFilename(path)));
}

export function repoScopeRows(
  repository: string,
  scopes: string[],
  posixHome = process.env["HOME"],
): { path: string }[] {
  const rows = new Set<string>();
  for (const scope of scopes) {
    const selected = resolveRankScope(
      repository,
      scope,
      false,
      true,
      posixHome,
    );
    for (const path of fileInfo(selected)?.isFile()
      ? [selected]
      : scopedFiles(repository, selected)) {
      let relative: string | undefined;
      try {
        if (
          fileInfo(path, false)?.isSymbolicLink() ||
          !fileInfo(path)?.isFile()
        )
          continue;
        relative = relativePath(resolvedPath(path), repository);
      } catch (error) {
        if (filesystemError(error)) continue;
        throw error;
      }
      if (relative !== undefined && !relative.split("/").includes(".git"))
        rows.add(relative);
    }
  }
  return [...rows].sort(compare).map((path) => ({ path }));
}

export function diffRankRows(
  repository: string,
  base: string,
  head: string,
  mode: DiffMode,
  area: string,
  previewBytes: number,
): RankRow[] {
  const changed = gitChangedPaths(repository, base, head, mode).filter(
    ([path]) =>
      !pathIsExcluded(relativePath(path, repository)!) &&
      TEXT_CODE_EXTENSIONS.has(extname(path).toLowerCase()),
  );
  const revisionPaths = changed
    .filter(([, status]) => mode === "revisions" && status !== "D")
    .map(([path]) => relativePath(path, repository)!);
  const blobs = gitBlobBytes(
    repository,
    revisionPaths.map((path) => `${head}:${path}`),
  );
  const revisionBlobs = new Map(
    revisionPaths.map((path, index) => [pathKey(path), blobs[index]]),
  );
  const rows: RankRow[] = [];
  for (const [path, status] of changed) {
    const relative = relativePath(path, repository)!;
    let preview = "";
    if (status !== "D") {
      if (mode === "revisions") {
        const content = revisionBlobs.get(pathKey(relative));
        if (content == null)
          throw new Error(
            `Unable to read committed diff blob: ${head}:${relative}`,
          );
        const result = previewForBytes(relative, content, previewBytes);
        if (result[1]) continue;
        preview = result[0];
      } else if (
        !fileInfo(path, false)?.isSymbolicLink() &&
        fileInfo(path)?.isFile()
      ) {
        let inside = false;
        try {
          inside = relativePath(resolvedPath(path), repository) !== undefined;
        } catch (error) {
          if (!filesystemError(error)) throw error;
        }
        if (inside) {
          const result = previewFor(path, previewBytes);
          if (result[1]) continue;
          preview = result[0];
        }
      }
    }
    rows.push({ path: relative, area, preview });
  }
  return rows.sort((a, b) => compare(a.path, b.path));
}

export function generateRankInputCommand(
  command: Command,
  args: string[],
  posixHome = process.env["HOME"],
): number {
  const scoped = command === "make-repo-scope-input";
  const diff = command === "make-diff-rank-input";
  const required = [
    "repo",
    ...(scoped ? ["scopes-file"] : diff ? ["base"] : []),
    "out",
  ];
  const optional = scoped
    ? {}
    : diff
      ? { mode: ["revisions", "local-patch"], head: undefined, area: undefined }
      : { scope: undefined, "scopes-file": undefined, area: undefined };
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] ${required.map((name) => `--${name} ${name.replaceAll("-", "_").toUpperCase()}`).join(" ")}${scoped ? "" : " [--area AREA] [--preview-bytes PREVIEW_BYTES]"}${diff ? " [--mode {revisions,local-patch}] [--head HEAD]" : scoped ? "" : " [--scope SCOPE] [--scopes-file SCOPES_FILE]"}`;
  try {
    const values = argumentsFor(
      args,
      required,
      scoped ? [] : ["preview-bytes"],
      optional,
    );
    if (values["help"]) {
      print(
        `${usage}\n\nCodex Security scan worklist helper.\n\n${scoped ? "List every explicitly scoped file without ranking or reading its contents." : diff ? "Create rank_input.jsonl from Git changed source-like files." : "Create rank_input.jsonl for subagent-based file ranking."}\n\noptions:\n  -h, --help  show this help message and exit\n  --repo REPO  Repository root.\n  --out OUT  Output ${scoped ? "scoped-source-input.jsonl" : "rank_input.jsonl"} path.${diff ? "\n  --base BASE  Git diff base revision.\n  --mode {revisions,local-patch}  Committed revisions or staged plus unstaged local patch (default: revisions).\n  --head HEAD  Git diff head revision (default: HEAD)." : `\n  --scopes-file SCOPES_FILE  JSON array of repository-relative files and directories to scan together.${scoped ? "" : "\n  --scope SCOPE  Path within the repository to scan (default: .)."}`}${scoped ? "" : `\n  --area AREA  Area label (default: ${diff ? "diff" : "scope"}).\n  --preview-bytes PREVIEW_BYTES  Maximum UTF-8 bytes in each preview (default: ${DEFAULT_PREVIEW_BYTES}).`}`,
      );
      return 0;
    }
    const path = (name: string) =>
      worklistPath(values[name] as string, posixHome);
    const repository = resolvedPath(path("repo"), false);
    if (!fileInfo(repository)?.isDirectory())
      throw new Error(`Repo path not found: ${repository}`);
    const previewBytes = Number(
      values["preview-bytes"] ?? DEFAULT_PREVIEW_BYTES,
    );
    const rows = scoped
      ? repoScopeRows(
          repository,
          loadScopesFile(path("scopes-file")),
          posixHome,
        )
      : diff
        ? diffRankRows(
            repository,
            values["base"] as string,
            (values["head"] ?? "HEAD") as string,
            (values["mode"] ?? "revisions") as DiffMode,
            (values["area"] ?? "diff") as string,
            previewBytes,
          )
        : repoRankRows(
            repository,
            values["scopes-file"] === undefined
              ? [(values["scope"] ?? ".") as string]
              : loadScopesFile(path("scopes-file")),
            values["scopes-file"] !== undefined,
            (values["area"] ?? "") as string,
            previewBytes,
            posixHome,
          );
    const output = path("out");
    writeRankRows(output, rows);
    print(
      `Wrote ${rows.length} ${scoped ? "scoped paths" : "rows"} to ${output}`,
    );
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    print(
      error instanceof ArgumentError
        ? `${usage}\n${command}: error: ${message}`
        : message,
      true,
    );
    return error instanceof ArgumentError ? 2 : 1;
  }
}
