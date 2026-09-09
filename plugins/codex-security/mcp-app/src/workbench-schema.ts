import type {
  Connection,
  Parameter,
  SqliteBinding,
  SqlValue,
} from "../../native/sqlite.mjs";
import type { MigrationRecord } from "./workbench-migrations";
import { normalizePreReleaseMigrations } from "./workbench-schema-normalizers";
import {
  addColumnIfMissing,
  repairDeepScanFailureCounterMigration,
  repairDeepScanMigration,
  repairStableTargetsMigration,
  repairThreadScopedWorkspacesMigration,
  sqlStatements,
} from "./workbench-schema-repairs";
import {
  JsonFloat,
  object,
  objectEntries,
  objectFromEntries,
  parseJson,
  parseJsonBytes,
  pythonRepr,
  stringifyJson,
} from "./helpers/python-json";

// Retain the original JSON mapping operations: missing fields must not become SQL NULL.
function typeName(value: unknown): string {
  if (value === null) return "NoneType";
  if (Array.isArray(value)) return "list";
  if (value instanceof JsonFloat || typeof value === "number") return "float";
  if (typeof value === "bigint") return "int";
  if (typeof value === "boolean") return "bool";
  return typeof value === "string" ? "str" : "dict";
}
function get(value: unknown, key: string, fallback: unknown = null): unknown {
  if (!object(value))
    throw new TypeError(`'${typeName(value)}' object has no attribute 'get'`);
  return Object.hasOwn(value, key) ? value[key] : fallback;
}
function item(value: unknown, key: string): unknown {
  if (object(value)) {
    if (!Object.hasOwn(value, key)) throw new Error(pythonRepr(key));
    return value[key];
  }
  if (Array.isArray(value))
    throw new TypeError("list indices must be integers or slices, not str");
  if (typeof value === "string")
    throw new TypeError("string indices must be integers, not 'str'");
  throw new TypeError(`'${typeName(value)}' object is not subscriptable`);
}
function contains(value: unknown, key: string): boolean {
  if (object(value)) return Object.hasOwn(value, key);
  if (Array.isArray(value)) return value.includes(key);
  if (typeof value === "string") return value.includes(key);
  throw new TypeError(`argument of type '${typeName(value)}' is not iterable`);
}
function storedJson(value: SqlValue): unknown {
  if (typeof value === "string") return parseJson(value);
  if (Buffer.isBuffer(value)) return parseJsonBytes(value);
  throw new TypeError(
    `the JSON object must be str, bytes or bytearray, not ${typeName(value)}`,
  );
}
function parameters(values: unknown[]): Parameter[] {
  // The native binder still rejects nonscalar parameters inside the DML transaction.
  return values.map((value) =>
    value instanceof JsonFloat ? Number(value.source) : value,
  ) as Parameter[];
}

export function migrateFindingWorkflowReviewColumns(
  connection: Connection,
): void {
  for (const row of connection
    .prepare(
      "SELECT workflow_id, review_key, prompt_digest FROM finding_workflow_reviews",
    )
    .all()) {
    const binding = storedJson(row.get("prompt_digest"));
    const source = item(binding, "source");
    const scope = item(binding, "scope");
    connection
      .prepare(
        `UPDATE finding_workflow_reviews SET review_contract_version = ?, codex_version = ?,
            source_repository_path = ?, source_revision = ?, source_refs_digest = ?,
            source_content_digest = ?, scope_repository_id = ?, scope_all_repositories = ?,
            model = ?, effort = ?, settings_digest = ?, prompt_digest = ?, contract_digest = ?
            WHERE workflow_id = ? AND review_key = ?`,
      )
      .run(
        parameters([
          item(binding, "version"),
          item(binding, "codexVersion"),
          item(source, "repository"),
          item(source, "revision"),
          item(source, "refsDigest"),
          item(source, "content"),
          get(scope, "repositoryId"),
          get(scope, "allRepositories"),
          item(binding, "model"),
          item(binding, "effort"),
          get(binding, "settingsDigest"),
          item(binding, "promptDigest"),
          item(binding, "contractDigest"),
          row.get("workflow_id"),
          row.get("review_key"),
        ]),
      );
  }
}

export function migrateFindingWorkflowColumns(connection: Connection): void {
  // Backfill renamed columns in place so checkpoint foreign keys and rows survive.
  for (const row of connection
    .prepare("SELECT id, results_json FROM finding_workflows")
    .all()) {
    const state = storedJson(row.get("results_json"));
    const scope = get(state, "scope", objectFromEntries([]));
    const stages = item(state, "stages");
    if (!object(stages))
      throw new TypeError(
        `'${typeName(stages)}' object has no attribute 'items'`,
      );
    const resultEntries: [string, unknown][] = [];
    for (const [stage, value] of objectEntries(stages))
      if (contains(value, "result"))
        resultEntries.push([stage, item(value, "result")]);
    const results = objectFromEntries(resultEntries);
    if (contains(item(stages, "dedupe"), "pendingWrite"))
      results["dedupePendingWrite"] = item(
        item(stages, "dedupe"),
        "pendingWrite",
      );
    connection
      .prepare(
        `UPDATE finding_workflows SET
            repository_path = ?, scan_request_digest = ?, scan_id = ?, scan_dir = ?,
            artifact_digest = ?, destination = ?, scope_repository_id = ?, scope_all_repositories = ?,
            scan_status = ?, scan_error = ?, publish_status = ?, publish_error = ?,
            dedupe_status = ?, dedupe_error = ?, results_json = ? WHERE id = ?`,
      )
      .run(
        parameters([
          get(state, "repositoryPath"),
          get(state, "scanRequestDigest"),
          get(state, "scanId"),
          get(state, "scanDir"),
          get(state, "artifactDigest"),
          get(state, "destination"),
          get(scope, "repositoryId"),
          get(scope, "allRepositories"),
          item(item(stages, "scan"), "status"),
          get(item(stages, "scan"), "error"),
          item(item(stages, "publish"), "status"),
          get(item(stages, "publish"), "error"),
          item(item(stages, "dedupe"), "status"),
          get(item(stages, "dedupe"), "error"),
          stringifyJson(results, { compact: true, allowNan: false }),
          row.get("id"),
        ]),
      );
  }
}

export function applyMigrations(
  native: SqliteBinding,
  connection: Connection,
  migrations: readonly MigrationRecord[],
  now: () => string,
  backfillSecurityTargets: (connection: Connection) => void,
): void {
  connection.commit();
  connection.prepare("BEGIN IMMEDIATE").run();
  try {
    connection
      .prepare(
        `
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            `,
      )
      .run();
    normalizePreReleaseMigrations(native, connection, now());
    const applied = new Set(
      connection
        .prepare("SELECT version FROM schema_migrations")
        .all()
        .map((row) => row.get("version")),
    );
    let shouldBackfillTargets = false;
    for (const [version, name, sql] of migrations) {
      if (applied.has(BigInt(version))) {
        if (version === 2)
          addColumnIfMissing(
            connection,
            "workspaces",
            "capability_preflight_json",
            "TEXT",
          );
        else if (version === 6)
          repairThreadScopedWorkspacesMigration(connection);
        else if (version === 11) repairDeepScanMigration(native, connection);
        else if (version === 12)
          addColumnIfMissing(
            connection,
            "scans",
            "continuation_thread_id",
            "TEXT",
          );
        else if (version === 13)
          addColumnIfMissing(
            connection,
            "scan_progress",
            "scope_file_count",
            "INTEGER CHECK (scope_file_count >= 0)",
          );
        else if (version === 16)
          shouldBackfillTargets = repairStableTargetsMigration(
            native,
            connection,
          );
        else if (version === 26)
          addColumnIfMissing(
            connection,
            "scans",
            "completion_warnings_json",
            "TEXT NOT NULL DEFAULT '[]'",
          );
        else if (version === 28)
          addColumnIfMissing(
            connection,
            "deep_scan_runs",
            "max_time_hours",
            "REAL NOT NULL DEFAULT 96",
          );
        else if (version === 31)
          addColumnIfMissing(
            connection,
            "scans",
            "retained_source_digests_json",
            "TEXT",
          );
        else if (version === 32)
          addColumnIfMissing(
            connection,
            "deep_scan_runs",
            "publication_error_message",
            "TEXT",
          );
        continue;
      }
      if (version === 6) repairThreadScopedWorkspacesMigration(connection);
      else if (version === 16)
        shouldBackfillTargets = repairStableTargetsMigration(
          native,
          connection,
        );
      else {
        for (const statement of sqlStatements(native, sql))
          connection.prepare(statement).run();
        if (version === 38) migrateFindingWorkflowColumns(connection);
        else if (version === 39)
          migrateFindingWorkflowReviewColumns(connection);
      }
      connection
        .prepare(
          "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
        )
        .run([version, name, now()]);
    }
    if (applied.has(27n)) repairDeepScanFailureCounterMigration(connection);
    if (shouldBackfillTargets) backfillSecurityTargets(connection);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
}
