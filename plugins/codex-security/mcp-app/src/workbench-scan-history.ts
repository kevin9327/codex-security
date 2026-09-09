import { isIP } from "node:net";
import { sep } from "node:path";
import type { Connection, Parameter } from "../../native/sqlite.mjs";
import {
  pathText,
  widePath,
  windowsFileSystem,
} from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { environment } from "./helpers/environment";
import { object, parseJson } from "./helpers/python-json";
import { compare } from "./helpers/rank-worklists";
import { resolvedPath } from "./helpers/resolve-path";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { lowercase } from "./helpers/unicode-case";
import { casefold } from "./workbench-dashboard";
import { gitOutput } from "./workbench-git";

export interface ScanQuery {
  query?: string;
  targetId?: string;
  status?: string;
  mode?: string;
  repository?: string;
  scanRoot?: string;
  offset: bigint;
  limit?: bigint;
}
type RepositoryOrigin = readonly [host: string, path: string];
const latest = (left: string, right: string) =>
  compare(left, right) < 0 ? right : left;
const trim = (value: string) =>
  value.replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );
const expand = (value: string) =>
  resolvedPath(expandHome(parsedPath(value), environment("HOME")), false);

/** Keep the workbench's existing URL and SCP origin equivalence, without IDNA rewriting. */
export function repositoryOrigin(target: string): RepositoryOrigin | null {
  const remote = gitOutput(target, ["remote", "get-url", "origin"]);
  if (remote === null) return null;
  let host: string, path: string;
  if (remote.includes("://")) {
    // urllib.parse.urlsplit strips leading C0/space and embedded tab/newline bytes.
    const source = remote
      .replace(/^[\x00-\x20]+/u, "")
      .replace(/[\t\r\n]/gu, "");
    const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):/u.exec(source);
    const scheme = schemeMatch?.[1]?.toLowerCase();
    if (scheme !== "https" && scheme !== "ssh") return null;
    const rest = source.slice(schemeMatch![0].length);
    if (!rest.startsWith("//")) return null;
    const authorityEnd = rest.slice(2).search(/[/?#]/u);
    const authority =
      authorityEnd === -1 ? rest.slice(2) : rest.slice(2, authorityEnd + 2);
    let remainder = authorityEnd === -1 ? "" : rest.slice(authorityEnd + 2);
    const fragment = remainder.indexOf("#");
    if (fragment !== -1) {
      if (remainder.slice(fragment + 1)) return null;
      remainder = remainder.slice(0, fragment);
    }
    const query = remainder.indexOf("?");
    if (query !== -1) {
      if (remainder.slice(query + 1)) return null;
      remainder = remainder.slice(0, query);
    }
    const normalizedAuthority = authority
      .replace(/[@:#?]/gu, "")
      .normalize("NFKC");
    if (/[/?#@:]/u.test(normalizedAuthority)) return null;
    const hostInfo = authority.slice(authority.lastIndexOf("@") + 1);
    let port = "";
    const bracket = hostInfo.indexOf("[");
    if (authority.includes("[") !== authority.includes("]")) return null;
    if (bracket !== -1) {
      if (bracket !== 0) return null;
      const close = hostInfo.indexOf("]", 1);
      host = hostInfo.slice(1, close);
      const suffix = hostInfo.slice(close + 1);
      if (suffix && !suffix.startsWith(":")) return null;
      port = suffix.slice(1);
    } else {
      const colon = hostInfo.indexOf(":");
      host = colon === -1 ? hostInfo : hostInfo.slice(0, colon);
      port = colon === -1 ? "" : hostInfo.slice(colon + 1);
    }
    if (authority.includes("[")) {
      if (host.startsWith("v")) {
        if (!/^v[0-9a-fA-F]+\.[\s\S]+$/u.test(host)) return null;
      } else {
        const [address, scope, ...extra] = host.split("%");
        if (extra.length || scope === "" || isIP(address!) !== 6) return null;
      }
    }
    if (!host) return null;
    if (port) {
      if (!/^[0-9]+$/u.test(port)) return null;
      const number = BigInt(port);
      if (number > 65535n) return null;
      if (number !== (scheme === "https" ? 443n : 22n)) host += `:${number}`;
    }
    path = remainder;
  } else {
    const colon = remote.indexOf(":");
    if (colon === -1) return null;
    const authority = remote.slice(0, colon);
    path = remote.slice(colon + 1);
    if (/[?#]/u.test(path)) return null;
    host = authority.slice(authority.lastIndexOf("@") + 1);
  }
  path = path.replace(/^\/+|\/+$/gu, "");
  if (path.endsWith(".git")) path = path.slice(0, -4);
  return host && path ? [lowercase(host), path] : null;
}

function windowsPathKey(value: string): string {
  const native = windowsBinding();
  const resolved = windowsFileSystem(native).realpath(widePath(value), false);
  const result = native.windowsInvariantLowercase(
    widePath(pathText(resolved).replaceAll("/", "\\")),
  );
  if (result.error)
    throw Object.assign(new Error("Could not normalize Windows path"), {
      winerror: result.error,
    });
  return pathText(result.value);
}
function relatedTargets(connection: Connection, repository: string): string[] {
  const requested = connection
    .prepare(
      "SELECT COALESCE((SELECT id FROM security_targets WHERE current_path = ?), '') AS target_id",
    )
    .get([repository])!
    .get("target_id");
  const common = gitOutput(repository, [
    "rev-parse",
    "--path-format=absolute",
    "--git-common-dir",
  ]);
  const origin = repositoryOrigin(repository);
  return connection
    .prepare("SELECT id, current_path FROM security_targets")
    .all()
    .flatMap((target) => {
      const id = target.get("id") as string;
      if (id === requested) return [id];
      const path = target.get("current_path") as string;
      const targetPath = resolvedPath(path, false);
      if (
        process.platform === "win32"
          ? lowercase(targetPath) === lowercase(repository)
          : targetPath === repository
      )
        return [id];
      const targetCommon = gitOutput(path, [
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
      ]);
      if (targetCommon !== null && common !== null) {
        const left = resolvedPath(targetCommon, false),
          right = resolvedPath(common, false);
        if (
          process.platform === "win32"
            ? lowercase(left) === lowercase(right)
            : left === right
        )
          return [id];
      }
      const targetOrigin = repositoryOrigin(path);
      return targetOrigin !== null &&
        origin !== null &&
        targetOrigin[0] === origin[0] &&
        targetOrigin[1] === origin[1]
        ? [id]
        : [];
    });
}

export function listScans(connection: Connection, args?: ScanQuery) {
  const windows = process.platform === "win32";
  if (windows)
    connection.function("codex_security_path_key", 1, false, (value) =>
      windowsPathKey(value as string),
    );
  const clauses: string[] = [],
    values: Parameter[] = [];
  if (args?.repository) {
    const repository = expand(args.repository);
    const related = relatedTargets(connection, repository);
    const matches = ["scans.target_path = ?"];
    values.push(repository);
    if (related.length) {
      matches.push(`scans.target_id IN (${related.map(() => "?").join(", ")})`);
      values.push(...related);
    }
    clauses.push(`(${matches.join(" OR ")})`);
  }
  if (args?.scanRoot) {
    let root = expand(args.scanRoot);
    if (windows) root = windowsPathKey(root);
    const prefix = root.replace(windows ? /\\+$/u : /\/+$/u, "") + sep;
    const column = windows
      ? "codex_security_path_key(scans.scan_dir)"
      : "scans.scan_dir";
    clauses.push(`(${column} = ? OR substr(${column}, 1, ?) = ?)`);
    values.push(root, BigInt(Array.from(prefix).length), prefix);
  }
  if (args?.targetId) {
    clauses.push("scans.target_id = ?");
    values.push(args.targetId);
  }
  if (args?.mode) {
    clauses.push("scans.mode = ?");
    values.push(args.mode);
  }
  if (args?.status) {
    if (args.status === "canceled")
      clauses.push("scans.canceled_at IS NOT NULL");
    else {
      clauses.push("scans.status = ? AND scans.canceled_at IS NULL");
      values.push(args.status);
    }
  }
  const query = args?.query ? casefold(trim(args.query)) : "";
  if (query) {
    clauses.push(
      "(instr(lower(scans.target_path), ?) > 0 OR instr(lower(COALESCE(scans.target_summary, '')), ?) > 0 OR instr(lower(scans.scope), ?) > 0 OR instr(lower(scans.mode), ?) > 0)",
    );
    values.push(query, query, query, query);
  }
  const paginated =
    args !== undefined && (args.limit !== undefined || args.offset !== 0n);
  const requestedLimit = args?.limit || 20n;
  const limit = paginated
    ? requestedLimit < 20n
      ? requestedLimit
      : 20n
    : undefined;
  if (limit !== undefined) {
    // Preserve sqlite3's diagnostic when the requested offset cannot be bound.
    if (
      args!.offset < -9223372036854775808n ||
      args!.offset > 9223372036854775807n
    )
      throw new Error("Python int too large to convert to SQLite INTEGER");
    values.push(limit + 1n, args!.offset);
  }
  const rows = connection
    .prepare(
      `
    SELECT scans.*, progress.reportable_findings_count, progress.scope_file_count,
        progress.review_items_completed, progress.review_items_total,
        progress.updated_at AS progress_updated_at,
        (SELECT COUNT(*) FROM finding_occurrences AS occurrences WHERE occurrences.scan_id = scans.id) AS finding_count
    FROM scans JOIN scan_progress AS progress ON progress.scan_id = scans.id
    ${clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""}
    ORDER BY CASE WHEN scans.status = 'running' AND scans.canceled_at IS NULL THEN 0 ELSE 1 END,
        MAX(scans.updated_at, progress.updated_at) DESC, scans.started_at DESC, scans.id
    ${paginated ? "LIMIT ? OFFSET ?" : ""}
  `,
    )
    .all(values);
  const scans = rows
    .slice(0, limit === undefined ? undefined : Number(limit))
    .map((record) => {
      const row = record.toObject();
      const stored =
        row["cost_json"] === null
          ? null
          : parseJson(row["cost_json"] as string, false, BigInt, (value) => {
              throw new Error(`invalid JSON number ${value}`);
            });
      const cost = !object(stored)
        ? {}
        : !("usage" in stored)
          ? { cost: stored }
          : {
              usage: stored["usage"],
              ...(object(stored["cost"]) ? { cost: stored["cost"] } : {}),
            };
      return {
        completedAt: row["completed_at"],
        continuationThreadId: row["continuation_thread_id"],
        ...cost,
        findingCount: row["finding_count"],
        handoffStatus: row["handoff_status"],
        mode: row["mode"],
        model: row["model"],
        parentScanId: row["parent_scan_id"],
        progress: {
          candidates: { reportable: row["reportable_findings_count"] },
          coverage: {
            closedRows: row["review_items_completed"],
            filesTotal: row["scope_file_count"],
            worklistRows: row["review_items_total"],
          },
          phase: row["phase"],
          status: row["canceled_at"] ? "canceled" : row["status"],
          updatedAt: row["progress_updated_at"],
        },
        recipeAvailable: row["recipe_json"] !== null,
        reasoningEffort: row["reasoning_effort"],
        scanDir: row["scan_dir"],
        scanId: row["id"] as string,
        scope: row["scope"],
        startedAt: row["started_at"],
        targetId: row["target_id"] as string,
        targetPath: row["target_path"],
        targetRevision: row["target_revision"],
        targetSummary: row["target_summary"],
        updatedAt: latest(
          row["updated_at"] as string,
          row["progress_updated_at"] as string,
        ),
        ...(row["completion_warnings_json"] !== "[]"
          ? {
              warnings: parseJson(row["completion_warnings_json"] as string),
            }
          : {}),
      };
    });
  return {
    scans,
    ...(limit === undefined
      ? {}
      : {
          limit,
          nextOffset: rows.length > limit ? args!.offset + limit : null,
          offset: args!.offset,
        }),
  };
}
