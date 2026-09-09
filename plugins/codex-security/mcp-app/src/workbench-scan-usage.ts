import decimalDigit from "@unicode/unicode-15.0.0/General_Category/Decimal_Number/regex.js";
import { accessSync, closeSync, constants, openSync, readSync } from "node:fs";
import { isAbsolute } from "node:path";
import { Connection, type Row, type SqlValue } from "../../native/sqlite.mjs";
import {
  widePath,
  windowsFileSystem,
  windowsParts,
} from "../../native/windows-files.mjs";
import { sqliteBinding, unixBinding, windowsBinding } from "./native";
import { environment } from "./helpers/environment";
import { hasText } from "./helpers/finding-root-cause";
import { fileInfo } from "./helpers/helper-files";
import {
  decodePosixBytes,
  encodePosixPath,
  SymlinkLoopError,
} from "./helpers/posix-path";
import { preflightInteger } from "./helpers/preflight-config";
import { parsePythonDateTime } from "./helpers/python-date-time";
import {
  JsonFloat,
  JsonSyntaxError,
  object,
  objectEntries,
  objectFromEntries,
  parseJson,
  pythonValueError,
  stringifyJson,
} from "./helpers/python-json";
import { appendPath, pathKey } from "./helpers/rank-selection";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { resolvedPath } from "./helpers/resolve-path";
import { fileUri } from "./helpers/snapshot-sqlite";
import { UnicodeDecodeError } from "./helpers/utf8";
import { normalizedUuid } from "./workbench-validation";

const tokenFields = {
  input_tokens: "inputTokens",
  cached_input_tokens: "cachedInputTokens",
  cache_write_input_tokens: "cacheWriteInputTokens",
  output_tokens: "outputTokens",
  reasoning_output_tokens: "reasoningOutputTokens",
  total_tokens: "totalTokens",
} as const;
const stateDatabaseName = new RegExp(
  `^state_((?:${decimalDigit.source})+)\\.sqlite$(?![\\s\\S])`,
);
type TokenUsage = Record<
  (typeof tokenFields)[keyof typeof tokenFields],
  bigint
>;
type Table = Record<string, unknown>;
interface RolloutSession {
  threadId: string;
  parentThreadId: string | null;
  path: string;
}
const osError = (error: unknown) => {
  const value = error as { errno?: number; winerror?: number };
  return value.errno !== undefined || value.winerror !== undefined;
};
const valueError = (error: unknown) =>
  error instanceof JsonSyntaxError ||
  error instanceof UnicodeDecodeError ||
  (error instanceof Error && error.name === "ValueError");
const truth = (value: unknown): boolean => {
  if (Array.isArray(value) || Buffer.isBuffer(value)) return value.length !== 0;
  if (object(value)) return Object.keys(value).length !== 0;
  if (value instanceof JsonFloat) return Number(value.source) !== 0;
  return Boolean(value);
};
const json = (value: string | Buffer) =>
  parseJson(value, false, preflightInteger);

export function measuredScanCostJson(usage: Table): string {
  return stringifyJson(
    { usage },
    { compact: true, separators: [",", ":"], allowNan: false },
  );
}

export function reconcileCompletedScanCost(
  connection: Connection,
  scan: Row,
  costJson: string,
): void {
  const stored = scan.get("cost_json"),
    existing = stored === null ? {} : json(stored as string | Buffer);
  if (object(existing) && Object.hasOwn(existing, "usage"))
    costJson = stringifyJson(
      objectFromEntries([...objectEntries(existing), ["cost", json(costJson)]]),
      { compact: true, separators: [",", ":"], allowNan: false },
    );
  connection.prepare("BEGIN IMMEDIATE").run();
  try {
    connection
      .prepare(
        "UPDATE scans SET cost_json = ? WHERE id = ? AND status = 'complete'",
      )
      .run([costJson, scan.get("id")]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
}

function emptyTokenUsage(): TokenUsage {
  return Object.fromEntries(
    Object.values(tokenFields).map((key) => [key, 0n]),
  ) as TokenUsage;
}
function addTokenUsage(target: TokenUsage, addition: TokenUsage): void {
  for (const key of Object.values(tokenFields)) target[key] += addition[key];
}
function unavailableUsage(
  reason: string,
  warnings: Set<string> = new Set(),
): Table {
  return {
    coverage: "unavailable",
    source: "codex_rollout",
    threadCount: 0,
    warnings: [...new Set([reason, ...warnings])].sort(),
  };
}

function scanRootThreadIds(
  connection: Connection,
  scan: Row,
  supplied: string | null,
): string[] {
  const candidates: SqlValue[] = [supplied];
  for (const key of ["continuation_thread_id", "deep_scan_owner_thread_id"])
    if (scan.columns.includes(key)) candidates.push(scan.get(key));
  const workspace = connection
    .prepare("SELECT thread_id FROM workspaces WHERE id = ?")
    .get([scan.get("workspace_id")]);
  if (workspace !== undefined) candidates.push(workspace.get("thread_id"));
  if (scan.get("mode") === "deep")
    for (const row of connection
      .prepare(
        `
      SELECT DISTINCT sdk_thread_id FROM deep_scan_workers
      WHERE scan_id = ? AND sdk_thread_id IS NOT NULL ORDER BY sdk_thread_id
    `,
      )
      .iterate([scan.get("id")]))
      candidates.push(row.get("sdk_thread_id"));
  return [...new Set(candidates.filter(hasText))];
}

const expandedPath = (path: string) =>
  parsedPath(expandHome(parsedPath(path), environment("HOME")));
function isFile(path: string): boolean {
  if (path.includes("\0")) return false;
  if (process.platform !== "win32") {
    try {
      encodePosixPath(path);
    } catch {
      return false;
    }
  }
  return fileInfo(path)?.isFile() ?? false;
}
function readable(path: string): boolean {
  if (process.platform === "win32") return fileInfo(path) !== undefined;
  try {
    accessSync(encodePosixPath(path), constants.R_OK);
    return true;
  } catch (error) {
    if (osError(error)) return false;
    throw error;
  }
}
function directoryNames(path: string): string[] {
  if (process.platform === "win32")
    return windowsFileSystem(windowsBinding())
      .entriesWithTypes(widePath(path))
      .map((entry) => entry.name.toString("utf16le"));
  const result = unixBinding().directoryEntries(encodePosixPath(path), false);
  if (result.errno !== 0)
    throw Object.assign(new Error(), { errno: result.errno });
  return result.value.map((item) => decodePosixBytes(item.name));
}
function codexStateDatabase(): string | null {
  const strip = (value: string | undefined) =>
    (value ?? "").replace(
      /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
      "",
    );
  const configured = strip(environment("CODEX_STATE_DB"));
  if (configured) {
    const path = expandedPath(configured);
    return isFile(path) && readable(path) ? resolvedPath(path, false) : null;
  }
  const configuredHome = strip(environment("CODEX_HOME")),
    home = configuredHome
      ? expandedPath(configuredHome)
      : appendPath(expandedPath("~"), ".codex"),
    sqliteHome = strip(environment("CODEX_SQLITE_HOME")),
    roots = [
      ...(sqliteHome ? [expandedPath(sqliteHome)] : []),
      home,
      appendPath(home, "sqlite"),
    ],
    seen = new Set<string>();
  for (const root of roots) {
    let candidates: [bigint, string][];
    try {
      const resolved = resolvedPath(root, false),
        key = pathKey(resolved);
      if (seen.has(key)) continue;
      seen.add(key);
      candidates = [];
      for (const name of directoryNames(resolved)) {
        const match = stateDatabaseName.exec(name);
        if (match === null) continue;
        const path = appendPath(resolved, name);
        if (!isFile(path) || !readable(path)) continue;
        const digits = Array.from(match[1]!, (character) => {
          const point = character.codePointAt(0)!;
          let start = point;
          while (decimalDigit.test(String.fromCodePoint(start - 1))) start--;
          return String((point - start) % 10);
        }).join("");
        candidates.push([preflightInteger(digits), path]);
      }
    } catch (error) {
      if (
        osError(error) ||
        valueError(error) ||
        error instanceof SymlinkLoopError
      )
        continue;
      throw error;
    }
    if (candidates.length) {
      let latest = candidates[0]!;
      for (const candidate of candidates)
        if (candidate[0] > latest[0]) latest = candidate;
      return resolvedPath(latest[1], false);
    }
  }
  return null;
}

function rolloutPath(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null;
  const candidate = expandedPath(value);
  if (
    process.platform === "win32"
      ? !windowsParts(candidate).slice(0, 2).every(Boolean)
      : !isAbsolute(candidate)
  )
    return null;
  try {
    const resolved = resolvedPath(candidate);
    if (!isFile(resolved)) return null;
    if (pathKey(resolved) === pathKey(candidate)) return resolved;
    if (
      process.platform === "darwin" &&
      /^\/(?:var|tmp)\//u.test(candidate) &&
      resolved === "/private" + candidate
    )
      return resolved;
  } catch (error) {
    if (!osError(error) && !(error instanceof SymlinkLoopError)) throw error;
  }
  return null;
}

function discoverRolloutSessions(
  stateDatabase: string,
  roots: string[],
  warnings: Set<string>,
): [RolloutSession[], Set<string>] {
  const database = new Connection(
    sqliteBinding(),
    fileUri(stateDatabase) + "?mode=ro",
    { uri: true },
  );
  try {
    database.raw.busyTimeout(1000);
    database.prepare("PRAGMA query_only = ON").run();
    for (const [table, required] of [
      ["threads", ["id", "rollout_path"]],
      ["thread_spawn_edges", ["parent_thread_id", "child_thread_id"]],
    ] as const) {
      const columns = new Set(
        database
          .prepare(`PRAGMA table_info(${table})`)
          .all()
          .map((row) => String(row.get("name"))),
      );
      if (required.some((key) => !columns.has(key)))
        throw pythonValueError(
          "Codex state graph does not expose the required thread columns.",
        );
    }
    const sessions: RolloutSession[] = [],
      seen = new Set<string>(),
      missing = new Set<string>();
    for (const root of roots) {
      const row = database
        .prepare("SELECT id, rollout_path FROM threads WHERE id = ?")
        .get([root]);
      if (row === undefined) {
        missing.add(root);
        warnings.add("scan_root_unavailable");
        continue;
      }
      if (!seen.has(root)) {
        const path = rolloutPath(row.get("rollout_path"));
        if (path === null) {
          missing.add(root);
          warnings.add("rollout_unavailable");
          continue;
        }
        sessions.push({ threadId: root, parentThreadId: null, path });
        seen.add(root);
      }
      for (const descendant of database
        .prepare(
          `
        WITH RECURSIVE descendants(depth, parent_thread_id, child_thread_id, ancestry, cycle) AS (
          SELECT 1, edges.parent_thread_id, edges.child_thread_id,
            '|' || edges.parent_thread_id || '|' || edges.child_thread_id || '|',
            edges.parent_thread_id = edges.child_thread_id
          FROM thread_spawn_edges AS edges WHERE edges.parent_thread_id = ?
          UNION ALL
          SELECT descendants.depth + 1, edges.parent_thread_id, edges.child_thread_id,
            descendants.ancestry || edges.child_thread_id || '|',
            instr(descendants.ancestry, '|' || edges.child_thread_id || '|') > 0
          FROM thread_spawn_edges AS edges
          JOIN descendants ON edges.parent_thread_id = descendants.child_thread_id
          WHERE descendants.cycle = 0
        )
        SELECT descendants.depth, descendants.parent_thread_id, descendants.child_thread_id,
          descendants.cycle, threads.rollout_path
        FROM descendants LEFT JOIN threads ON threads.id = descendants.child_thread_id
        ORDER BY descendants.depth, descendants.child_thread_id
      `,
        )
        .iterate([root])) {
        const child = descendant.get("child_thread_id"),
          parent = descendant.get("parent_thread_id");
        if (typeof child !== "string" || typeof parent !== "string") {
          warnings.add("thread_lineage_incomplete");
          continue;
        }
        if (truth(descendant.get("cycle"))) {
          missing.add(child);
          warnings.add("thread_lineage_cycle");
          continue;
        }
        if (seen.has(child)) continue;
        const path = rolloutPath(descendant.get("rollout_path"));
        if (path === null) {
          missing.add(child);
          warnings.add("rollout_unavailable");
          continue;
        }
        sessions.push({ threadId: child, parentThreadId: parent, path });
        seen.add(child);
      }
    }
    return [sessions, missing];
  } finally {
    database.close();
  }
}

function timestamp(value: unknown): bigint | null {
  if (typeof value !== "string" || !value) return null;
  let parsed;
  try {
    parsed = parsePythonDateTime(
      value.endsWith("Z") ? value.slice(0, -1) + "+00:00" : value,
    );
  } catch (error) {
    if (valueError(error)) return null;
    throw error;
  }
  if (!parsed.aware) return null;
  if (
    parsed.microseconds < -62135596800000000n ||
    parsed.microseconds > 253402300799999999n
  )
    throw Object.assign(new RangeError("date value out of range"), {
      name: "OverflowError",
    });
  return parsed.microseconds;
}
function sessionParentThreadId(payload: Table): string | null {
  const source = payload["source"];
  if (object(source)) {
    const agent = source["subagent"];
    if (object(agent)) {
      const spawn = agent["thread_spawn"];
      if (
        object(spawn) &&
        typeof spawn["parent_thread_id"] === "string" &&
        spawn["parent_thread_id"]
      )
        return spawn["parent_thread_id"];
    }
  }
  for (const key of ["parent_thread_id", "forked_from_id"])
    if (typeof payload[key] === "string" && payload[key]) return payload[key];
  return null;
}
function uuid7Order(value: string): bigint | null {
  const normalized = normalizedUuid(value);
  if (
    normalized === null ||
    normalized[14] !== "7" ||
    !/[89ab]/u.test(normalized[19]!)
  )
    return null;
  return BigInt("0x" + normalized.replaceAll("-", ""));
}
function isOwnedTaskStart(
  threadId: string,
  event: Table,
  payload: Table,
): boolean {
  if (event["type"] !== "event_msg" || payload["type"] !== "task_started")
    return false;
  const turnId = payload["turn_id"];
  if (typeof turnId !== "string" || !turnId) return false;
  const thread = uuid7Order(threadId),
    turn = uuid7Order(turnId);
  return thread === null || (turn !== null && turn >= thread);
}
function tokenSnapshot(payload: Table): TokenUsage | null {
  const info = payload["info"];
  if (!object(info) || !object(info["total_token_usage"])) return null;
  const usage = info["total_token_usage"],
    legacy = usage["cache_write_tokens"],
    input = usage["input_tokens"],
    cached = usage["cached_input_tokens"] ?? 0n;
  let written = Object.hasOwn(usage, "cache_write_input_tokens")
    ? usage["cache_write_input_tokens"]
    : Object.hasOwn(usage, "cache_write_tokens")
      ? legacy
      : 0n;
  const zero =
    written === 0n ||
    written === false ||
    (written instanceof JsonFloat && Number(written.source) === 0);
  if (
    zero &&
    typeof legacy === "bigint" &&
    legacy > 0n &&
    typeof input === "bigint" &&
    typeof cached === "bigint" &&
    cached + legacy <= input
  )
    written = legacy;
  const result = emptyTokenUsage();
  for (const [source, destination] of Object.entries(tokenFields)) {
    const value =
      source === "cache_write_input_tokens"
        ? written
        : Object.hasOwn(usage, source)
          ? usage[source]
          : 0n;
    if (typeof value !== "bigint" || value < 0n) return null;
    if (
      ["input_tokens", "output_tokens", "total_tokens"].includes(source) &&
      !Object.hasOwn(usage, source)
    )
      return null;
    result[destination as keyof TokenUsage] = value;
  }
  if (
    result.cachedInputTokens + result.cacheWriteInputTokens >
    result.inputTokens
  )
    return null;
  result.totalTokens = result.inputTokens + result.outputTokens;
  return result;
}

function* binaryLines(path: string): Generator<Buffer> {
  const descriptor =
    process.platform === "win32"
      ? undefined
      : openSync(encodePosixPath(path), "r");
  const file =
    descriptor === undefined
      ? windowsFileSystem(windowsBinding()).openRead(widePath(path))
      : {
          read: (buffer: Buffer) => readSync(descriptor, buffer),
          close: () => closeSync(descriptor),
        };
  let pending = Buffer.alloc(0);
  try {
    for (;;) {
      const buffer = Buffer.alloc(8192),
        count = file.read(buffer);
      if (!count) {
        if (pending.length) yield pending;
        return;
      }
      let start = 0;
      for (
        let end = buffer.indexOf(10);
        end >= 0 && end < count;
        end = buffer.indexOf(10, start)
      ) {
        yield Buffer.concat([pending, buffer.subarray(start, end + 1)]);
        pending = Buffer.alloc(0);
        start = end + 1;
      }
      pending = Buffer.concat([pending, buffer.subarray(start, count)]);
    }
  } finally {
    file.close();
  }
}
function readRolloutUsage(
  session: RolloutSession,
  startedAt: bigint,
  completedAt: bigint | null,
): [TokenUsage, Set<string>] {
  const total = emptyTokenUsage(),
    warnings = new Set<string>();
  let previous = emptyTokenUsage(),
    boundary = false,
    lineNumber = 0;
  for (const raw of binaryLines(session.path)) {
    lineNumber++;
    if (raw.at(-1) !== 10) {
      warnings.add("rollout_record_incomplete");
      continue;
    }
    let event;
    try {
      event = json(raw);
    } catch (error) {
      if (!valueError(error)) throw error;
      if (lineNumber === 1)
        throw pythonValueError("The rollout session metadata is unreadable.");
      if (boundary) warnings.add("rollout_record_invalid");
      continue;
    }
    if (!object(event)) {
      if (boundary) warnings.add("rollout_record_invalid");
      continue;
    }
    const payload = event["payload"];
    if (lineNumber === 1) {
      if (event["type"] !== "session_meta" || !object(payload)) {
        warnings.add("thread_identity_mismatch");
        return [total, warnings];
      }
      const id = truth(payload["id"]) ? payload["id"] : payload["session_id"];
      if (id !== session.threadId) {
        warnings.add("thread_identity_mismatch");
        return [total, warnings];
      }
      const parent = sessionParentThreadId(payload);
      if (
        session.parentThreadId !== null &&
        parent !== session.parentThreadId
      ) {
        warnings.add("thread_identity_mismatch");
        return [total, warnings];
      }
      boundary =
        session.parentThreadId === null &&
        !parent &&
        !truth(payload["forked_from_id"]);
      continue;
    }
    if (!object(payload)) continue;
    if (!boundary) {
      if (isOwnedTaskStart(session.threadId, event, payload)) {
        const started = timestamp(event["timestamp"]);
        if (started === null) {
          warnings.add("thread_ownership_unavailable");
          return [total, warnings];
        }
        if (
          started < startedAt ||
          (completedAt !== null && started > completedAt)
        ) {
          warnings.add("thread_outside_scan_window");
          return [total, warnings];
        }
        boundary = true;
      } else if (
        event["type"] === "event_msg" &&
        payload["type"] === "token_count"
      ) {
        const inherited = tokenSnapshot(payload);
        if (inherited !== null) previous = inherited;
      }
      continue;
    }
    if (event["type"] !== "event_msg" || payload["type"] !== "token_count")
      continue;
    const current = timestamp(event["timestamp"]),
      snapshot = tokenSnapshot(payload);
    if (current === null || snapshot === null) {
      warnings.add("token_record_invalid");
      continue;
    }
    const delta = emptyTokenUsage();
    for (const key of Object.values(tokenFields))
      delta[key] =
        snapshot[key] >= previous[key]
          ? snapshot[key] - previous[key]
          : snapshot[key];
    previous = snapshot;
    if (
      current < startedAt ||
      (completedAt !== null && current > completedAt) ||
      delta.totalTokens <= 0n
    )
      continue;
    addTokenUsage(total, delta);
  }
  if (!boundary) warnings.add("thread_ownership_unavailable");
  return [total, warnings];
}

export function collectScanUsage(
  connection: Connection,
  scan: Row,
  threadId: string | null = null,
  completedAt: string | null = null,
): Table {
  const roots = scanRootThreadIds(connection, scan, threadId);
  if (!roots.length) return unavailableUsage("scan_thread_unavailable");
  const database = codexStateDatabase();
  if (database === null) return unavailableUsage("codex_state_unavailable");
  const started = timestamp(scan.get("started_at")),
    stopped = timestamp(completedAt || scan.get("completed_at"));
  if (started === null) return unavailableUsage("scan_window_unavailable");
  const warnings = new Set<string>();
  let sessions: RolloutSession[], missing: Set<string>;
  try {
    [sessions, missing] = discoverRolloutSessions(database, roots, warnings);
  } catch (error) {
    if (
      osError(error) ||
      valueError(error) ||
      (error as { sqliteErrorCode?: number }).sqliteErrorCode !== undefined
    )
      return unavailableUsage("codex_state_unavailable");
    throw error;
  }
  if (!sessions.length)
    return unavailableUsage("scan_thread_unavailable", warnings);
  const total = emptyTokenUsage(),
    accepted = new Set<string>(),
    excluded = new Set<string>();
  let observed = 0;
  for (const session of sessions) {
    if (
      session.parentThreadId !== null &&
      excluded.has(session.parentThreadId)
    ) {
      excluded.add(session.threadId);
      continue;
    }
    if (
      session.parentThreadId !== null &&
      !accepted.has(session.parentThreadId)
    ) {
      missing.add(session.threadId);
      warnings.add("thread_lineage_incomplete");
      continue;
    }
    let usage: TokenUsage, currentWarnings: Set<string>;
    try {
      [usage, currentWarnings] = readRolloutUsage(session, started, stopped);
    } catch (error) {
      if (!osError(error) && !valueError(error)) throw error;
      missing.add(session.threadId);
      warnings.add("rollout_unavailable");
      continue;
    }
    if (currentWarnings.has("thread_outside_scan_window")) {
      excluded.add(session.threadId);
      continue;
    }
    for (const warning of currentWarnings) warnings.add(warning);
    if (
      currentWarnings.has("thread_identity_mismatch") ||
      currentWarnings.has("thread_ownership_unavailable")
    ) {
      missing.add(session.threadId);
      continue;
    }
    accepted.add(session.threadId);
    observed++;
    addTokenUsage(total, usage);
  }
  if (!observed) return unavailableUsage("scan_thread_unavailable", warnings);
  return {
    coverage: missing.size || warnings.size ? "partial" : "complete",
    source: "codex_rollout",
    ...total,
    threadCount: observed,
    ...(missing.size ? { missingThreadCount: missing.size } : {}),
    ...(warnings.size ? { warnings: [...warnings].sort() } : {}),
  };
}
