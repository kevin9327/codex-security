import {
  completeStatement,
  type Connection,
  type SqliteBinding,
} from "../../native/sqlite.mjs";
import { MIGRATIONS, type MigrationRecord } from "./workbench-migrations";

export function sqlStatements(native: SqliteBinding, script: string): string[] {
  const lines = script.split(/\r\n|[\n\r\v\f\u001c-\u001e\u0085\u2028\u2029]/u);
  if (lines.at(-1) === "") lines.pop();
  const statements: string[] = [];
  let buffer = "";
  for (const line of lines) {
    buffer = `${buffer}\n${line}`.replace(
      /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
      "",
    );
    if (completeStatement(native, buffer)) {
      statements.push(buffer);
      buffer = "";
    }
  }
  if (buffer) throw new Error("Incomplete SQLite migration statement.");
  return statements;
}

function columnNames(connection: Connection, table: string): Set<string> {
  return new Set(
    connection
      .prepare(`PRAGMA table_info(${table})`)
      .all()
      .map((row) => row.get("name") as string),
  );
}

export function addColumnIfMissing(
  connection: Connection,
  table: string,
  column: string,
  definition: string,
): void {
  if (!columnNames(connection, table).has(column))
    connection
      .prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
      .run();
}

export function repairThreadScopedWorkspacesMigration(
  connection: Connection,
): void {
  addColumnIfMissing(connection, "workspaces", "thread_id", "TEXT");
  connection
    .prepare(
      "CREATE INDEX IF NOT EXISTS workspaces_by_thread_and_updated_at " +
        "ON workspaces(thread_id, updated_at DESC)",
    )
    .run();
}

export function repairDeepScanMigration(
  native: SqliteBinding,
  connection: Connection,
  migrations: readonly MigrationRecord[] = MIGRATIONS,
): void {
  const scanColumns = columnNames(connection, "scans");
  const ownerColumnMissing = !scanColumns.has("deep_scan_owner_thread_id");
  const expectedObjects = [
    "scans_one_running_deep_per_owner_target",
    "deep_scan_runs",
    "deep_scan_workers",
    "deep_scan_workers_completion_sequence",
    "deep_scan_workers_by_scan_status",
    "deep_scan_dedup_inputs",
  ];
  const existingObjects = new Set(
    connection
      .prepare(
        "SELECT name FROM sqlite_master WHERE name LIKE 'deep_scan_%' " +
          "OR name = 'scans_one_running_deep_per_owner_target'",
      )
      .all()
      .map((row) => row.get("name")),
  );
  if (
    !ownerColumnMissing &&
    expectedObjects.every((name) => existingObjects.has(name))
  )
    return;
  if (ownerColumnMissing)
    addColumnIfMissing(
      connection,
      "scans",
      "deep_scan_owner_thread_id",
      "TEXT",
    );
  const [, , migrationSql] = migrations.find(([version]) => version === 11)!;
  for (let statement of sqlStatements(native, migrationSql)) {
    if (statement.startsWith("ALTER TABLE scans")) continue;
    if (statement.startsWith("UPDATE scans") && !ownerColumnMissing) continue;
    for (const prefix of [
      "CREATE UNIQUE INDEX ",
      "CREATE INDEX ",
      "CREATE TABLE ",
    ]) {
      if (statement.startsWith(prefix)) {
        statement = statement.replace(prefix, `${prefix}IF NOT EXISTS `);
        break;
      }
    }
    connection.prepare(statement).run();
    if (
      statement.startsWith("UPDATE scans") &&
      scanColumns.has("continuation_thread_id")
    )
      connection
        .prepare(
          "UPDATE scans SET deep_scan_owner_thread_id = continuation_thread_id " +
            "WHERE mode = 'deep' AND status = 'running' " +
            "AND continuation_thread_id IS NOT NULL",
        )
        .run();
  }
}

export function repairDeepScanFailureCounterMigration(
  connection: Connection,
): void {
  const thresholdMissing = !columnNames(connection, "deep_scan_runs").has(
    "stop_after_consecutive_errors",
  );
  addColumnIfMissing(
    connection,
    "deep_scan_runs",
    "stop_after_consecutive_errors",
    "INTEGER NOT NULL DEFAULT 1 CHECK (stop_after_consecutive_errors >= 1)",
  );
  if (thresholdMissing)
    connection
      .prepare(
        "UPDATE deep_scan_runs SET stop_after_consecutive_errors = stop_after_no_new",
      )
      .run();
  addColumnIfMissing(
    connection,
    "deep_scan_runs",
    "consecutive_errors",
    "INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_errors >= 0)",
  );
}

export function repairStableTargetsMigration(
  native: SqliteBinding,
  connection: Connection,
  migrations: readonly MigrationRecord[] = MIGRATIONS,
): boolean {
  const workspaceColumns = columnNames(connection, "workspaces");
  const scanColumns = columnNames(connection, "scans");
  const existingObjects = new Set(
    connection
      .prepare(
        "SELECT name FROM sqlite_master WHERE name IN ('security_targets', 'scans_by_target')",
      )
      .all()
      .map((row) => row.get("name")),
  );
  if (
    workspaceColumns.has("target_id") &&
    scanColumns.has("target_id") &&
    existingObjects.has("security_targets") &&
    existingObjects.has("scans_by_target")
  )
    return false;
  const [, , migrationSql] = migrations.find(([version]) => version === 16)!;
  for (let statement of sqlStatements(native, migrationSql)) {
    if (statement.startsWith("ALTER TABLE workspaces")) {
      addColumnIfMissing(
        connection,
        "workspaces",
        "target_id",
        "TEXT REFERENCES security_targets(id)",
      );
      continue;
    }
    if (statement.startsWith("ALTER TABLE scans")) {
      addColumnIfMissing(
        connection,
        "scans",
        "target_id",
        "TEXT REFERENCES security_targets(id)",
      );
      continue;
    }
    statement = statement.replace(
      "CREATE TABLE ",
      "CREATE TABLE IF NOT EXISTS ",
    );
    statement = statement.replace(
      "CREATE INDEX ",
      "CREATE INDEX IF NOT EXISTS ",
    );
    connection.prepare(statement).run();
  }
  connection
    .prepare(
      `
        UPDATE scans
        SET target_id = NULL
        WHERE target_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM security_targets WHERE security_targets.id = scans.target_id
            )
        `,
    )
    .run();
  return true;
}
