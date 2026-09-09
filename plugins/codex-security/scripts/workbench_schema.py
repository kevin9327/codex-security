"""SQLite schema history for the Codex Security workbench."""

import argparse
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

MIGRATIONS = tuple(
    (record["version"], record["name"], "\n".join(record["sqlLines"]))
    for record in json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "workbench-migrations.json").read_text(
            encoding="utf-8"
        )
    )
)


def migrate_finding_workflow_review_columns(connection: sqlite3.Connection) -> None:
    for row in connection.execute(
        "SELECT workflow_id, review_key, prompt_digest FROM finding_workflow_reviews"
    ).fetchall():
        binding = json.loads(row["prompt_digest"])
        source = binding["source"]
        scope = binding["scope"]
        connection.execute(
            """UPDATE finding_workflow_reviews SET review_contract_version = ?, codex_version = ?,
            source_repository_path = ?, source_revision = ?, source_refs_digest = ?,
            source_content_digest = ?, scope_repository_id = ?, scope_all_repositories = ?,
            model = ?, effort = ?, settings_digest = ?, prompt_digest = ?, contract_digest = ?
            WHERE workflow_id = ? AND review_key = ?""",
            (
                binding["version"],
                binding["codexVersion"],
                source["repository"],
                source["revision"],
                source["refsDigest"],
                source["content"],
                scope.get("repositoryId"),
                scope.get("allRepositories"),
                binding["model"],
                binding["effort"],
                binding.get("settingsDigest"),
                binding["promptDigest"],
                binding["contractDigest"],
                row["workflow_id"],
                row["review_key"],
            ),
        )


def migrate_finding_workflow_columns(connection: sqlite3.Connection) -> None:
    # Rename/backfill in place so existing checkpoint foreign keys and rows survive.
    for row in connection.execute("SELECT id, results_json FROM finding_workflows").fetchall():
        state = json.loads(row["results_json"])
        scope = state.get("scope", {})
        stages = state["stages"]
        results = {stage: value["result"] for stage, value in stages.items() if "result" in value}
        if "pendingWrite" in stages["dedupe"]:
            results["dedupePendingWrite"] = stages["dedupe"]["pendingWrite"]
        connection.execute(
            """UPDATE finding_workflows SET
            repository_path = ?, scan_request_digest = ?, scan_id = ?, scan_dir = ?,
            artifact_digest = ?, destination = ?, scope_repository_id = ?, scope_all_repositories = ?,
            scan_status = ?, scan_error = ?, publish_status = ?, publish_error = ?,
            dedupe_status = ?, dedupe_error = ?, results_json = ? WHERE id = ?""",
            (
                state.get("repositoryPath"),
                state.get("scanRequestDigest"),
                state.get("scanId"),
                state.get("scanDir"),
                state.get("artifactDigest"),
                state.get("destination"),
                scope.get("repositoryId"),
                scope.get("allRepositories"),
                stages["scan"]["status"],
                stages["scan"].get("error"),
                stages["publish"]["status"],
                stages["publish"].get("error"),
                stages["dedupe"]["status"],
                stages["dedupe"].get("error"),
                json.dumps(results, allow_nan=False),
                row["id"],
            ),
        )


def apply_migrations(
    connection: sqlite3.Connection,
    migrations: tuple[tuple[int, str, str], ...],
    now: Callable[[], str],
    backfill_security_targets: Callable[[sqlite3.Connection], None],
) -> None:
    connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        normalize_pre_release_migrations(connection, now())
        applied = {
            row["version"] for row in connection.execute("SELECT version FROM schema_migrations")
        }
        should_backfill_targets = False
        for version, name, sql in migrations:
            if version in applied:
                if version == 2:
                    add_column_if_missing(
                        connection, "workspaces", "capability_preflight_json", "TEXT"
                    )
                elif version == 6:
                    repair_thread_scoped_workspaces_migration(connection)
                elif version == 11:
                    repair_deep_scan_migration(connection)
                elif version == 12:
                    add_column_if_missing(connection, "scans", "continuation_thread_id", "TEXT")
                elif version == 13:
                    add_column_if_missing(
                        connection,
                        "scan_progress",
                        "scope_file_count",
                        "INTEGER CHECK (scope_file_count >= 0)",
                    )
                elif version == 16:
                    should_backfill_targets = repair_stable_targets_migration(connection)
                elif version == 26:
                    add_column_if_missing(
                        connection,
                        "scans",
                        "completion_warnings_json",
                        "TEXT NOT NULL DEFAULT '[]'",
                    )
                elif version == 28:
                    add_column_if_missing(
                        connection,
                        "deep_scan_runs",
                        "max_time_hours",
                        "REAL NOT NULL DEFAULT 96",
                    )
                elif version == 31:
                    add_column_if_missing(
                        connection,
                        "scans",
                        "retained_source_digests_json",
                        "TEXT",
                    )
                elif version == 32:
                    add_column_if_missing(
                        connection,
                        "deep_scan_runs",
                        "publication_error_message",
                        "TEXT",
                    )
                continue
            if version == 6:
                repair_thread_scoped_workspaces_migration(connection)
            elif version == 16:
                should_backfill_targets = repair_stable_targets_migration(connection)
            else:
                for statement in sql_statements(sql):
                    connection.execute(statement)
                if version == 38:
                    migrate_finding_workflow_columns(connection)
                elif version == 39:
                    migrate_finding_workflow_review_columns(connection)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, now()),
            )
        if 27 in applied:
            repair_deep_scan_failure_counter_migration(connection)
        if should_backfill_targets:
            backfill_security_targets(connection)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def normalize_pre_release_execution_profile_migrations(
    connection: sqlite3.Connection, timestamp: str
) -> None:
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    workspace_columns = {row["name"] for row in connection.execute("PRAGMA table_info(workspaces)")}
    legacy_columns = {"execution_model", "reasoning_effort"}
    renamed_columns = {
        "legacy_execution_model",
        "legacy_reasoning_effort",
    }
    execution_migrations = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 12, 25)"
        )
    }
    supported_execution_migrations = {
        11: {"deep scan orchestration state", "scan execution profiles"},
        12: {
            "scan continuation threads",
            "scan execution profiles",
            "dynamic scan execution profiles",
        },
    }
    model_migration_name = "persist scan model settings"
    if execution_migrations.get(25) == "dynamic scan execution profiles":
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 25 AND name = ?",
            (model_migration_name, "dynamic scan execution profiles"),
        )
        execution_migrations[25] = model_migration_name
    has_legacy_profile_history = any(
        execution_migrations.get(version) in legacy_names
        for version, legacy_names in (
            (11, {"scan execution profiles"}),
            (12, {"scan execution profiles", "dynamic scan execution profiles"}),
        )
    )
    has_legacy_profile_columns = any(
        column in columns
        for column, columns in (
            ("execution_model", scan_columns),
            ("execution_model", workspace_columns),
            ("reasoning_effort", workspace_columns),
        )
    )
    if not (has_legacy_profile_history or has_legacy_profile_columns):
        return

    if any(
        execution_migrations.get(version) not in ({None} | supported_names)
        for version, supported_names in supported_execution_migrations.items()
    ):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    if has_legacy_profile_columns and not (
        legacy_columns <= scan_columns
        and legacy_columns <= workspace_columns
        and not renamed_columns.intersection(scan_columns | workspace_columns)
    ):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )
    if has_legacy_profile_history and not has_legacy_profile_columns:
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    if execution_migrations.get(25) not in (None, model_migration_name):
        raise SystemExit(
            "The Codex Security database has an unsupported execution-profile migration history."
        )

    # Keep the historical values and constraints for recovery while moving
    # them out of the namespace used by the current independent scan settings.
    for table in ("workspaces", "scans"):
        connection.execute(
            f"ALTER TABLE {table} RENAME COLUMN execution_model TO legacy_execution_model"
        )
        connection.execute(
            f"ALTER TABLE {table} RENAME COLUMN reasoning_effort TO legacy_reasoning_effort"
        )
    add_column_if_missing(connection, "scans", "model", "TEXT")
    add_column_if_missing(connection, "scans", "reasoning_effort", "TEXT")
    connection.execute(
        """
        UPDATE scans
        SET model = COALESCE(model, legacy_execution_model),
            reasoning_effort = COALESCE(reasoning_effort, legacy_reasoning_effort)
        """
    )
    for version, name in (
        (11, "scan execution profiles"),
        (12, "scan execution profiles"),
        (12, "dynamic scan execution profiles"),
    ):
        connection.execute(
            "DELETE FROM schema_migrations WHERE version = ? AND name = ?",
            (version, name),
        )
    if execution_migrations.get(25) is None:
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (25, model_migration_name, timestamp),
        )


def normalize_pre_release_migrations(connection: sqlite3.Connection, timestamp: str) -> None:
    normalize_mirror_lineage_migrations(connection)
    connection.execute(
        "UPDATE schema_migrations SET version = 40 WHERE version = 33 AND name = ?",
        ("index finding identity and comparison history",),
    )

    completion_warning_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 25"
    ).fetchone()
    if (
        completion_warning_migration is not None
        and completion_warning_migration["name"] == "persist scan completion warnings"
    ):
        if (
            connection.execute("SELECT 1 FROM schema_migrations WHERE version = 26").fetchone()
            is not None
        ):
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )
        connection.execute(
            "UPDATE schema_migrations SET version = 26 WHERE version = 25 AND name = ?",
            ("persist scan completion warnings",),
        )

    phase_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 12"
    ).fetchone()
    if (
        phase_progress_migration is not None
        and phase_progress_migration["name"] == "phase-specific scan progress"
    ):
        target_migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 20"
        ).fetchone()
        if target_migration is not None:
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )
        connection.execute(
            "UPDATE schema_migrations SET version = 20 WHERE version = 12 AND name = ?",
            ("phase-specific scan progress",),
        )

    normalize_pre_release_execution_profile_migrations(connection, timestamp)

    preflight_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 13"
    ).fetchone()
    if (
        preflight_progress_migration is not None
        and preflight_progress_migration["name"] == "current scan preflight state"
    ):
        target_migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 21"
        ).fetchone()
        if target_migration is not None:
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )
        connection.execute(
            "UPDATE schema_migrations SET version = 21 WHERE version = 13 AND name = ?",
            ("current scan preflight state",),
        )

    delivered_claim_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 18"
    ).fetchone()
    if (
        delivered_claim_migration is not None
        and delivered_claim_migration["name"] == "scan target summaries"
    ):
        connection.execute(
            "UPDATE scans SET handoff_claimed_at = NULL, handoff_claim_token = NULL "
            "WHERE handoff_status = 'delivered'"
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 18 AND name = ?",
            ("clear legacy delivered handoff claims", "scan target summaries"),
        )

    setup_preferences_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 19"
    ).fetchone()
    legacy_setup_preferences_migrations = {
        "structured scan guidance context",
        "idempotent scan lifecycle requests",
    }
    if (
        setup_preferences_migration is not None
        and setup_preferences_migration["name"] in legacy_setup_preferences_migrations
    ):
        migration_sql = next(sql for version, _, sql in MIGRATIONS if version == 19)
        for statement in sql_statements(migration_sql):
            connection.execute(statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 19 AND name = ?",
            ("persist setup workspace preference", setup_preferences_migration["name"]),
        )

    phase_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 20"
    ).fetchone()
    legacy_phase_progress_migrations = {
        "retain superseded scan lifecycle requests",
        "threat model publication receipts",
    }
    if (
        phase_progress_migration is not None
        and phase_progress_migration["name"] in legacy_phase_progress_migrations
    ):
        add_column_if_missing(
            connection,
            "scan_progress",
            "phase_items_total",
            "INTEGER NOT NULL DEFAULT 0 CHECK (phase_items_total >= 0)",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "phase_items_completed",
            "INTEGER NOT NULL DEFAULT 0 "
            "CHECK (phase_items_completed >= 0 AND phase_items_completed <= phase_items_total)",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "phase_progress_unit",
            "TEXT CHECK (phase_progress_unit IS NULL OR phase_progress_unit IN ("
            "'checks', 'threat_surfaces', 'review_receipts', 'candidate_findings', "
            "'validated_findings', 'report_artifacts'))",
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 20 AND name = ?",
            ("phase-specific scan progress", phase_progress_migration["name"]),
        )

    preflight_progress_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 21"
    ).fetchone()
    legacy_preflight_progress_migrations = {
        "scan progress projection and activity",
        "deep coordinator manifest receipts",
    }
    if (
        preflight_progress_migration is not None
        and preflight_progress_migration["name"] in legacy_preflight_progress_migrations
    ):
        add_column_if_missing(
            connection,
            "scan_progress",
            "preflight_issues_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "preflight_checks_total",
            "INTEGER NOT NULL DEFAULT 0 CHECK (preflight_checks_total >= 0)",
        )
        add_column_if_missing(
            connection,
            "scan_progress",
            "preflight_checks_completed",
            "INTEGER NOT NULL DEFAULT 0 CHECK (preflight_checks_completed >= 0 "
            "AND preflight_checks_completed <= preflight_checks_total)",
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 21 AND name = ?",
            ("current scan preflight state", preflight_progress_migration["name"]),
        )

    scan_recipe_migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 22"
    ).fetchone()
    if (
        scan_recipe_migration is not None
        and scan_recipe_migration["name"] == "dynamic scan execution profiles"
    ):
        add_column_if_missing(connection, "scans", "recipe_json", "TEXT")
        add_column_if_missing(
            connection,
            "scans",
            "parent_scan_id",
            "TEXT REFERENCES scans(id) ON DELETE SET NULL",
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 22 AND name = ?",
            ("replayable scan launch recipes", "dynamic scan execution profiles"),
        )

    migration = connection.execute(
        "SELECT name FROM schema_migrations WHERE version = 2"
    ).fetchone()
    if migration is None or migration["name"] != "finding management schema":
        return

    legacy_versions = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version BETWEEN 2 AND 5"
        )
    }
    expected = {
        2: "finding management schema",
        3: "scan handoff delivery claims",
        4: "finding remediation action claims",
        5: "scan target snapshot digests",
    }
    for version, name in legacy_versions.items():
        if expected.get(version) != name:
            raise SystemExit(
                "The Codex Security database has an unsupported pre-release migration history."
            )

    connection.execute(
        "DELETE FROM schema_migrations WHERE version = 5 AND name = ?",
        (expected[5],),
    )
    for old_version, new_version in ((4, 5), (3, 4), (2, 3)):
        connection.execute(
            "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
            (new_version, old_version, expected[old_version]),
        )
    add_column_if_missing(connection, "workspaces", "capability_preflight_json", "TEXT")
    add_column_if_missing(connection, "scans", "target_snapshot_digest", "TEXT")
    connection.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
        (2, "persist capability preflight summaries", timestamp),
    )


def normalize_mirror_lineage_migrations(connection: sqlite3.Connection) -> None:
    mirror_names = {
        29: "freeze stopped scan source digests",
        30: "separate deep scan publication failures",
    }
    migrations = {
        row["version"]: row["name"]
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version BETWEEN 29 AND 32"
        )
    }
    if not any(migrations.get(version) == name for version, name in mirror_names.items()):
        return
    if migrations != mirror_names:
        raise SystemExit("The Codex Security database has an unsupported mirror migration history.")
    for old_version, new_version in ((30, 32), (29, 31)):
        connection.execute(
            "UPDATE schema_migrations SET version = ? WHERE version = ? AND name = ?",
            (new_version, old_version, mirror_names[old_version]),
        )


def repair_deep_scan_migration(connection: sqlite3.Connection) -> None:
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    owner_column_missing = "deep_scan_owner_thread_id" not in scan_columns
    expected_objects = {
        "scans_one_running_deep_per_owner_target",
        "deep_scan_runs",
        "deep_scan_workers",
        "deep_scan_workers_completion_sequence",
        "deep_scan_workers_by_scan_status",
        "deep_scan_dedup_inputs",
    }
    existing_objects = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'deep_scan_%' "
            "OR name = 'scans_one_running_deep_per_owner_target'"
        )
    }
    if not owner_column_missing and expected_objects <= existing_objects:
        return

    if owner_column_missing:
        add_column_if_missing(connection, "scans", "deep_scan_owner_thread_id", "TEXT")
    migration_sql = next(sql for version, _, sql in MIGRATIONS if version == 11)
    for statement in sql_statements(migration_sql):
        if statement.startswith("ALTER TABLE scans"):
            continue
        if statement.startswith("UPDATE scans") and not owner_column_missing:
            continue
        for prefix in ("CREATE UNIQUE INDEX ", "CREATE INDEX ", "CREATE TABLE "):
            if statement.startswith(prefix):
                statement = statement.replace(prefix, f"{prefix}IF NOT EXISTS ", 1)
                break
        connection.execute(statement)
        if statement.startswith("UPDATE scans") and "continuation_thread_id" in scan_columns:
            connection.execute(
                "UPDATE scans SET deep_scan_owner_thread_id = continuation_thread_id "
                "WHERE mode = 'deep' AND status = 'running' "
                "AND continuation_thread_id IS NOT NULL"
            )


def repair_deep_scan_failure_counter_migration(connection: sqlite3.Connection) -> None:
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")}
    threshold_missing = "stop_after_consecutive_errors" not in columns
    add_column_if_missing(
        connection,
        "deep_scan_runs",
        "stop_after_consecutive_errors",
        "INTEGER NOT NULL DEFAULT 1 CHECK (stop_after_consecutive_errors >= 1)",
    )
    if threshold_missing:
        connection.execute(
            "UPDATE deep_scan_runs SET stop_after_consecutive_errors = stop_after_no_new"
        )
    add_column_if_missing(
        connection,
        "deep_scan_runs",
        "consecutive_errors",
        "INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_errors >= 0)",
    )


def repair_thread_scoped_workspaces_migration(connection: sqlite3.Connection) -> None:
    add_column_if_missing(connection, "workspaces", "thread_id", "TEXT")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS workspaces_by_thread_and_updated_at "
        "ON workspaces(thread_id, updated_at DESC)"
    )


def repair_stable_targets_migration(connection: sqlite3.Connection) -> bool:
    workspace_columns = {row["name"] for row in connection.execute("PRAGMA table_info(workspaces)")}
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    existing_objects = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE name IN ('security_targets', 'scans_by_target')"
        )
    }
    if (
        "target_id" in workspace_columns
        and "target_id" in scan_columns
        and existing_objects == {"security_targets", "scans_by_target"}
    ):
        return False

    migration_sql = next(sql for version, _, sql in MIGRATIONS if version == 16)
    for statement in sql_statements(migration_sql):
        if statement.startswith("ALTER TABLE workspaces"):
            add_column_if_missing(
                connection,
                "workspaces",
                "target_id",
                "TEXT REFERENCES security_targets(id)",
            )
            continue
        if statement.startswith("ALTER TABLE scans"):
            add_column_if_missing(
                connection,
                "scans",
                "target_id",
                "TEXT REFERENCES security_targets(id)",
            )
            continue
        statement = statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
        statement = statement.replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1)
        connection.execute(statement)
    connection.execute(
        """
        UPDATE scans
        SET target_id = NULL
        WHERE target_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM security_targets WHERE security_targets.id = scans.target_id
            )
        """
    )
    return True


def add_column_if_missing(
    connection: sqlite3.Connection, table: str, column: str, definition: str
) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def sql_statements(script: str) -> list[str]:
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines():
        buffer = f"{buffer}\n{line}".strip()
        if sqlite3.complete_statement(buffer):
            statements.append(buffer)
            buffer = ""
    if buffer:
        raise ValueError("Incomplete SQLite migration statement.")
    return statements


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
