import { gitBytes } from "../workbench-git";
import { cleanWorktreeContentDigest } from "../workbench-git-snapshot";
import { pythonRepr } from "./python-json";
import { appendPath, relativePath } from "./rank-selection";
import { resolvedPath } from "./resolve-path";
import { parsedPath } from "./resolve-security-md";

export const CONTEXT_LINES = 3;
export const MAX_BYTES = 16_000;
export const MAX_LINES = 60;

export interface ExcerptScan {
  target_revision: unknown;
  target_snapshot_digest: unknown;
}
type Location = Record<string, unknown>;
const stringValue = (value: unknown): string =>
  typeof value === "string" ? value : pythonRepr(value);
const integer = (value: unknown): bigint | null =>
  typeof value === "bigint"
    ? value
    : typeof value === "boolean" ||
        (typeof value === "number" && Number.isInteger(value))
      ? BigInt(value)
      : null;

/** Read the sealed revision, keeping the original worktree-snapshot eligibility. */
export function scannedSourceText(
  scan: ExcerptScan,
  target: string,
  path: string,
): string | null {
  if (safeSourcePath(target, path) === null) return null;
  const revision = scan.target_revision;
  if (revision === "unversioned") return null;
  if (
    scan.target_snapshot_digest !== null &&
    scan.target_snapshot_digest !== cleanWorktreeContentDigest()
  )
    return null;
  const content = gitBytes(target, [
    "cat-file",
    "blob",
    `${stringValue(revision)}:${path}`,
  ]);
  return content === null ? null : content.toString("utf8");
}

export function safeSourcePath(
  target: string,
  relative: string,
): string | null {
  if (relative.includes("\\") || relative.startsWith("/")) return null;
  const parts = relative
    .split("/")
    .filter((part) => part !== "" && part !== ".");
  if (parts.includes("..")) return null;
  try {
    const root = parsedPath(target);
    const joined = appendPath(root, parts.join("/") || ".");
    // pathlib.resolve raises ValueError for an embedded NUL, including in a missing path.
    if (joined.includes("\0")) return null;
    const path = resolvedPath(joined, false);
    return relativePath(path, root) === undefined ? null : path;
  } catch {
    return null;
  }
}

export function findingSourceExcerpt(
  scan: ExcerptScan,
  target: string | null,
  locations: readonly Location[],
): string | null {
  if (target === null || locations.length === 0) return null;
  const location =
    locations.find((candidate) =>
      stringValue(candidate["role"] ?? "")
        .toLowerCase()
        .includes("root_control"),
    ) ?? locations[0]!;
  const path = location["path"],
    startLine = integer(location["startLine"]);
  if (typeof path !== "string" || startLine === null) return null;
  const source = scannedSourceText(scan, target, path);
  if (!source || source.includes("\0")) return null;
  const lines = source.split(/\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/u);
  if (lines.at(-1) === "") lines.pop();
  if (startLine < 1n || startLine > BigInt(lines.length)) return null;
  const lastAffected = integer(location["endLine"]) ?? startLine;
  const start = Number(startLine);
  const excerptStart = Math.max(1, start - CONTEXT_LINES);
  const excerptEnd = Math.min(
    lines.length,
    Math.max(start, Number(lastAffected)) + CONTEXT_LINES,
    excerptStart + MAX_LINES - 1,
  );
  const width = String(excerptEnd).length;
  const excerpt: string[] = [];
  for (let line = excerptStart; line <= excerptEnd; line++)
    excerpt.push(`${String(line).padStart(width)}  ${lines[line - 1]}`);
  const encoded = Buffer.from(excerpt.join("\n"));
  let end = Math.min(encoded.length, MAX_BYTES);
  // The source is valid decoded text; only the final cut can split a UTF-8 sequence.
  while (end < encoded.length && (encoded[end]! & 0xc0) === 0x80) end--;
  return encoded.subarray(0, end).toString("utf8");
}
