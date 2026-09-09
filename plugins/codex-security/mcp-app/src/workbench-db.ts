import { createHash } from "node:crypto";
import { dirname, parse, sep } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { Connection, type SqliteBinding } from "../../native/sqlite.mjs";
import { windowsJoin } from "../../native/windows-files.mjs";
import { chmod, mkdir } from "./helpers/helper-files";
import { environment } from "./helpers/environment";
import { resolvedPath } from "./helpers/resolve-path";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { MIGRATIONS } from "./workbench-migrations";
import { applyMigrations as applySchemaMigrations } from "./workbench-schema";

const windows = process.platform === "win32";
const joinPath = (left: string, right: string) =>
  parsedPath(windows ? windowsJoin(left, right) : `${left}/${right}`);

export function stateDir(): string {
  const configured = environment("CODEX_SECURITY_STATE_DIR");
  const home = environment("HOME");
  const expanded = (value: string) => expandHome(parsedPath(value), home);
  if (configured) return resolvedPath(expanded(configured), false);
  const codexHome = expanded(environment("CODEX_HOME") ?? "~/.codex");
  return resolvedPath(
    joinPath(codexHome, ["state", "plugins", "codex-security"].join(sep)),
    false,
  );
}

export function databasePath(): string {
  return joinPath(stateDir(), "workbench.sqlite3");
}

export function stableTargetId(target: string): string {
  const source = `local-workspace\0${parsedPath(target)}`;
  // str.encode() is strict here: a filesystem surrogate must not become U+FFFD.
  const characters = Array.from(source);
  const surrogate = (character: string) =>
    character.length === 1 && character >= "\ud800" && character <= "\udfff";
  const start = characters.findIndex(surrogate);
  if (start !== -1) {
    let end = start + 1;
    while (end < characters.length && surrogate(characters[end]!)) end++;
    const location =
      end === start + 1
        ? `character '\\u${characters[start]!.charCodeAt(0).toString(16)}' in position ${start}`
        : `characters in position ${start}-${end - 1}`;
    throw new Error(
      `'utf-8' codec can't encode ${location}: surrogates not allowed`,
    );
  }
  return `target_sha256_${createHash("sha256").update(source).digest("hex")}`;
}

export function ensureSecurityTarget(
  connection: Connection,
  targetPath: string,
  now: () => string,
): string {
  const existing = connection
    .prepare("SELECT id FROM security_targets WHERE current_path = ?")
    .get([targetPath]);
  if (existing !== undefined) return String(existing.get("id"));
  const targetId = stableTargetId(targetPath);
  const timestamp = now();
  const path = parsedPath(targetPath);
  connection
    .prepare(
      `INSERT OR IGNORE INTO security_targets (
            id, current_path, display_name, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?)`,
    )
    .run([
      targetId,
      targetPath,
      path === "." ? "" : parse(path).base,
      timestamp,
      timestamp,
    ]);
  return targetId;
}

export function backfillSecurityTargets(
  connection: Connection,
  now: () => string,
): void {
  const rows = connection
    .prepare(
      `SELECT target_path FROM workspaces WHERE target_path IS NOT NULL
        UNION SELECT target_path FROM scans`,
    )
    .all();
  for (const row of rows) {
    const targetPath = row.get("target_path") as string;
    const targetId = ensureSecurityTarget(connection, targetPath, now);
    connection
      .prepare(
        "UPDATE workspaces SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
      )
      .run([targetId, targetPath]);
    connection
      .prepare(
        "UPDATE scans SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
      )
      .run([targetId, targetPath]);
  }
}

export function applyMigrations(
  native: SqliteBinding,
  connection: Connection,
  now: () => string,
): void {
  applySchemaMigrations(native, connection, MIGRATIONS, now, (current) =>
    backfillSecurityTargets(current, now),
  );
}

export async function connect(
  native: SqliteBinding,
  now: () => string,
): Promise<Connection> {
  const path = databasePath();
  mkdir(dirname(path));
  for (let attempt = 0; attempt < 5; attempt++) {
    const connection = new Connection(native, path);
    try {
      connection.prepare("PRAGMA foreign_keys = ON").run();
      connection.prepare("PRAGMA busy_timeout = 5000").run();
      applyMigrations(native, connection, now);
      connection.prepare("PRAGMA journal_mode = WAL").run();
      chmod(path, 0o600);
      return connection;
    } catch (error) {
      connection.close();
      // Match sqlite3.OperationalError; constraint and callback failures are not retried.
      const code = (error as { sqliteErrorCode?: number }).sqliteErrorCode;
      if (
        code === undefined ||
        ![1, 3, 4, 5, 6, 8, 9, 10, 13, 14, 15, 16, 17].includes(code)
      )
        throw error;
      if (
        attempt === 4 ||
        !/locked|busy/u.test((error as Error).message.toLowerCase())
      )
        throw error;
      await sleep(50 * 2 ** attempt);
    }
  }
  throw new Error("SQLite retry loop exhausted unexpectedly.");
}
