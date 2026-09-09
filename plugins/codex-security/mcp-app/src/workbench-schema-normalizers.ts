import type {
  Connection,
  SqliteBinding,
  SqlValue,
} from "../../native/sqlite.mjs";
import { MIGRATIONS, type MigrationRecord } from "./workbench-migrations";
import { addColumnIfMissing, sqlStatements } from "./workbench-schema-repairs";

const preReleaseHistoryError =
  "The Codex Security database has an unsupported pre-release migration history.";
const executionHistoryError =
  "The Codex Security database has an unsupported execution-profile migration history.";

function columns(connection: Connection, table: string): Set<SqlValue> {
  return new Set(
    connection
      .prepare(`PRAGMA table_info(${table})`)
      .all()
      .map((row) => row.get("name")),
  );
}

function migrationName(
  connection: Connection,
  version: bigint,
): SqlValue | undefined {
  return connection
    .prepare("SELECT name FROM schema_migrations WHERE version = ?")
    .get([version])
    ?.get("name");
}

export function normalizeMirrorLineageMigrations(connection: Connection): void {
  const mirrorNames = new Map([
    [29n, "freeze stopped scan source digests"],
    [30n, "separate deep scan publication failures"],
  ]);
  const migrations = new Map(
    connection
      .prepare(
        "SELECT version, name FROM schema_migrations WHERE version BETWEEN 29 AND 32",
      )
      .all()
      .map((row) => [row.get("version"), row.get("name")]),
  );
  if (
    ![...mirrorNames].some(
      ([version, name]) => migrations.get(version) === name,
    )
  )
    return;
  if (
    migrations.size !== mirrorNames.size ||
    [...mirrorNames].some(([version, name]) => migrations.get(version) !== name)
  )
    throw new Error(
      "The Codex Security database has an unsupported mirror migration history.",
    );
  for (const [oldVersion, newVersion] of [
    [30n, 32n],
    [29n, 31n],
  ] as const)
    connection
      .prepare(
        "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
      )
      .run([newVersion, oldVersion, mirrorNames.get(oldVersion)!]);
}

export function normalizePreReleaseExecutionProfileMigrations(
  connection: Connection,
  timestamp: string,
): void {
  const scanColumns = columns(connection, "scans");
  const workspaceColumns = columns(connection, "workspaces");
  const legacyColumns = ["execution_model", "reasoning_effort"];
  const renamedColumns = ["legacy_execution_model", "legacy_reasoning_effort"];
  const executionMigrations = new Map(
    connection
      .prepare(
        "SELECT version, name FROM schema_migrations WHERE version IN (11, 12, 25)",
      )
      .all()
      .map((row) => [row.get("version"), row.get("name")]),
  );
  const supportedExecutionMigrations = new Map([
    [11n, ["deep scan orchestration state", "scan execution profiles"]],
    [
      12n,
      [
        "scan continuation threads",
        "scan execution profiles",
        "dynamic scan execution profiles",
      ],
    ],
  ]);
  const modelMigrationName = "persist scan model settings";
  if (executionMigrations.get(25n) === "dynamic scan execution profiles") {
    connection
      .prepare(
        "UPDATE schema_migrations SET name = ? WHERE version = 25 AND name = ?",
      )
      .run([modelMigrationName, "dynamic scan execution profiles"]);
    executionMigrations.set(25n, modelMigrationName);
  }
  const hasLegacyProfileHistory =
    executionMigrations.get(11n) === "scan execution profiles" ||
    executionMigrations.get(12n) === "scan execution profiles" ||
    executionMigrations.get(12n) === "dynamic scan execution profiles";
  const hasLegacyProfileColumns =
    scanColumns.has("execution_model") ||
    workspaceColumns.has("execution_model") ||
    workspaceColumns.has("reasoning_effort");
  if (!(hasLegacyProfileHistory || hasLegacyProfileColumns)) return;

  if (
    [...supportedExecutionMigrations].some(([version, names]) => {
      const name = executionMigrations.get(version);
      return name != null && !names.includes(name as string);
    })
  )
    throw new Error(executionHistoryError);
  if (
    hasLegacyProfileColumns &&
    !(
      legacyColumns.every(
        (column) => scanColumns.has(column) && workspaceColumns.has(column),
      ) &&
      !renamedColumns.some(
        (column) => scanColumns.has(column) || workspaceColumns.has(column),
      )
    )
  )
    throw new Error(executionHistoryError);
  if (hasLegacyProfileHistory && !hasLegacyProfileColumns)
    throw new Error(executionHistoryError);
  if (
    executionMigrations.get(25n) != null &&
    executionMigrations.get(25n) !== modelMigrationName
  )
    throw new Error(executionHistoryError);

  // Retain historical values and constraints outside the independent settings namespace.
  for (const table of ["workspaces", "scans"]) {
    connection
      .prepare(
        `ALTER TABLE ${table} RENAME COLUMN execution_model TO legacy_execution_model`,
      )
      .run();
    connection
      .prepare(
        `ALTER TABLE ${table} RENAME COLUMN reasoning_effort TO legacy_reasoning_effort`,
      )
      .run();
  }
  addColumnIfMissing(connection, "scans", "model", "TEXT");
  addColumnIfMissing(connection, "scans", "reasoning_effort", "TEXT");
  connection
    .prepare(
      `
        UPDATE scans
        SET model = COALESCE(model, legacy_execution_model),
            reasoning_effort = COALESCE(reasoning_effort, legacy_reasoning_effort)
        `,
    )
    .run();
  for (const [version, name] of [
    [11n, "scan execution profiles"],
    [12n, "scan execution profiles"],
    [12n, "dynamic scan execution profiles"],
  ] as const)
    connection
      .prepare("DELETE FROM schema_migrations WHERE version = ? AND name = ?")
      .run([version, name]);
  if (executionMigrations.get(25n) == null)
    connection
      .prepare(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
      )
      .run([25n, modelMigrationName, timestamp]);
}

export function normalizePreReleaseMigrations(
  native: SqliteBinding,
  connection: Connection,
  timestamp: string,
  migrations: readonly MigrationRecord[] = MIGRATIONS,
): void {
  normalizeMirrorLineageMigrations(connection);
  connection
    .prepare(
      "UPDATE schema_migrations SET version = 40 WHERE version = 33 AND name = ?",
    )
    .run(["index finding identity and comparison history"]);

  if (migrationName(connection, 25n) === "persist scan completion warnings") {
    if (
      connection
        .prepare("SELECT 1 FROM schema_migrations WHERE version = 26")
        .get() !== undefined
    )
      throw new Error(preReleaseHistoryError);
    connection
      .prepare(
        "UPDATE schema_migrations SET version = 26 WHERE version = 25 AND name = ?",
      )
      .run(["persist scan completion warnings"]);
  }

  if (migrationName(connection, 12n) === "phase-specific scan progress") {
    if (migrationName(connection, 20n) !== undefined)
      throw new Error(preReleaseHistoryError);
    connection
      .prepare(
        "UPDATE schema_migrations SET version = 20 WHERE version = 12 AND name = ?",
      )
      .run(["phase-specific scan progress"]);
  }

  normalizePreReleaseExecutionProfileMigrations(connection, timestamp);

  if (migrationName(connection, 13n) === "current scan preflight state") {
    if (migrationName(connection, 21n) !== undefined)
      throw new Error(preReleaseHistoryError);
    connection
      .prepare(
        "UPDATE schema_migrations SET version = 21 WHERE version = 13 AND name = ?",
      )
      .run(["current scan preflight state"]);
  }

  if (migrationName(connection, 18n) === "scan target summaries") {
    connection
      .prepare(
        "UPDATE scans SET handoff_claimed_at = NULL, handoff_claim_token = NULL " +
          "WHERE handoff_status = 'delivered'",
      )
      .run();
    connection
      .prepare(
        "UPDATE schema_migrations SET name = ? WHERE version = 18 AND name = ?",
      )
      .run(["clear legacy delivered handoff claims", "scan target summaries"]);
  }

  const setupPreferencesMigration = migrationName(connection, 19n);
  if (
    setupPreferencesMigration === "structured scan guidance context" ||
    setupPreferencesMigration === "idempotent scan lifecycle requests"
  ) {
    const [, , migrationSql] = migrations.find(([version]) => version === 19)!;
    for (const statement of sqlStatements(native, migrationSql))
      connection
        .prepare(
          statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS "),
        )
        .run();
    connection
      .prepare(
        "UPDATE schema_migrations SET name = ? WHERE version = 19 AND name = ?",
      )
      .run(["persist setup workspace preference", setupPreferencesMigration]);
  }

  const phaseProgressMigration = migrationName(connection, 20n);
  if (
    phaseProgressMigration === "retain superseded scan lifecycle requests" ||
    phaseProgressMigration === "threat model publication receipts"
  ) {
    addColumnIfMissing(
      connection,
      "scan_progress",
      "phase_items_total",
      "INTEGER NOT NULL DEFAULT 0 CHECK (phase_items_total >= 0)",
    );
    addColumnIfMissing(
      connection,
      "scan_progress",
      "phase_items_completed",
      "INTEGER NOT NULL DEFAULT 0 CHECK (phase_items_completed >= 0 AND phase_items_completed <= phase_items_total)",
    );
    addColumnIfMissing(
      connection,
      "scan_progress",
      "phase_progress_unit",
      "TEXT CHECK (phase_progress_unit IS NULL OR phase_progress_unit IN (" +
        "'checks', 'threat_surfaces', 'review_receipts', 'candidate_findings', " +
        "'validated_findings', 'report_artifacts'))",
    );
    connection
      .prepare(
        "UPDATE schema_migrations SET name = ? WHERE version = 20 AND name = ?",
      )
      .run(["phase-specific scan progress", phaseProgressMigration]);
  }

  const preflightProgressMigration = migrationName(connection, 21n);
  if (
    preflightProgressMigration === "scan progress projection and activity" ||
    preflightProgressMigration === "deep coordinator manifest receipts"
  ) {
    addColumnIfMissing(
      connection,
      "scan_progress",
      "preflight_issues_json",
      "TEXT NOT NULL DEFAULT '[]'",
    );
    addColumnIfMissing(
      connection,
      "scan_progress",
      "preflight_checks_total",
      "INTEGER NOT NULL DEFAULT 0 CHECK (preflight_checks_total >= 0)",
    );
    addColumnIfMissing(
      connection,
      "scan_progress",
      "preflight_checks_completed",
      "INTEGER NOT NULL DEFAULT 0 CHECK (preflight_checks_completed >= 0 AND preflight_checks_completed <= preflight_checks_total)",
    );
    connection
      .prepare(
        "UPDATE schema_migrations SET name = ? WHERE version = 21 AND name = ?",
      )
      .run(["current scan preflight state", preflightProgressMigration]);
  }

  if (migrationName(connection, 22n) === "dynamic scan execution profiles") {
    addColumnIfMissing(connection, "scans", "recipe_json", "TEXT");
    addColumnIfMissing(
      connection,
      "scans",
      "parent_scan_id",
      "TEXT REFERENCES scans(id) ON DELETE SET NULL",
    );
    connection
      .prepare(
        "UPDATE schema_migrations SET name = ? WHERE version = 22 AND name = ?",
      )
      .run([
        "replayable scan launch recipes",
        "dynamic scan execution profiles",
      ]);
  }

  if (migrationName(connection, 2n) !== "finding management schema") return;
  const legacyVersions = new Map(
    connection
      .prepare(
        "SELECT version, name FROM schema_migrations WHERE version BETWEEN 2 AND 5",
      )
      .all()
      .map((row) => [row.get("version"), row.get("name")]),
  );
  const expected = new Map<SqlValue, string>([
    [2n, "finding management schema"],
    [3n, "scan handoff delivery claims"],
    [4n, "finding remediation action claims"],
    [5n, "scan target snapshot digests"],
  ]);
  for (const [version, name] of legacyVersions)
    if (expected.get(version) !== name) throw new Error(preReleaseHistoryError);

  connection
    .prepare("DELETE FROM schema_migrations WHERE version = 5 AND name = ?")
    .run([expected.get(5n)!]);
  for (const [oldVersion, newVersion] of [
    [4n, 5n],
    [3n, 4n],
    [2n, 3n],
  ] as const)
    connection
      .prepare(
        "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
      )
      .run([newVersion, oldVersion, expected.get(oldVersion)!]);
  addColumnIfMissing(
    connection,
    "workspaces",
    "capability_preflight_json",
    "TEXT",
  );
  addColumnIfMissing(connection, "scans", "target_snapshot_digest", "TEXT");
  connection
    .prepare(
      "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
    )
    .run([2n, "persist capability preflight summaries", timestamp]);
}
