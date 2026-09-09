import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Connection } from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import { sqlStatements } from "../../../../plugins/codex-security/mcp-app/src/workbench-schema-repairs";
import {
  filesystemIdentity,
  requireScanTargetIdentity,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import { validateLocation } from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-validation";
import { ContractError } from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-contract-errors";
import { stringifyJson } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

type History = "profiles" | "history" | "public";
export type Request =
  | { operation: "identity"; target: string }
  | { operation: "locations"; locations: (Record<string, unknown> | null)[] }
  | {
      operation: "setup";
      history: History;
      database: string;
      repository?: string;
      profileMigration?: string;
      followUpMigration?: string;
    }
  | {
      operation: "inspect";
      history: History;
      database: string;
      scanId?: string;
    };
function run(request: Request): unknown {
  if (request.operation === "identity") {
    const metadata = filesystemIdentity(request.target),
      scan = {
        target_path: request.target,
        target_device: metadata.dev + 1n,
        target_inode: metadata.ino,
      };
    assert.equal(requireScanTargetIdentity(scan), request.target);
    scan.target_inode += 1n;
    assert.throws(() => requireScanTargetIdentity(scan), TargetInspectionError);
    return null;
  }
  if (request.operation === "locations")
    return request.locations.map((location) => {
      if (location === null) return false;
      try {
        validateLocation(
          {
            path: location["path"],
            startLine: location["start_line"],
            endLine: location["end_line"],
            role: location["role"],
          },
          "candidate.locations[0]",
        );
        return true;
      } catch (error) {
        if (!(error instanceof ContractError)) throw error;
        return false;
      }
    });
  const native = sqliteBinding(),
    connection = new Connection(native, request.database);
  try {
    if (request.operation === "setup") {
      connection
        .prepare(
          "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)",
        )
        .run();
      const timestamp =
        request.history === "profiles"
          ? "2026-07-09T00:00:00Z"
          : "2026-07-30T00:00:00Z";
      for (const [version, name, sql] of MIGRATIONS) {
        if (version > (request.history === "public" ? 24 : 10)) break;
        for (const statement of sqlStatements(native, sql))
          connection.prepare(statement).run();
        connection
          .prepare("INSERT INTO schema_migrations VALUES (?, ?, ?)")
          .run([version, name, timestamp]);
      }
      if (request.history !== "public") {
        for (const table of ["workspaces", "scans"]) {
          connection
            .prepare(
              `ALTER TABLE ${table} ADD COLUMN execution_model TEXT${request.history === "profiles" ? " CHECK (execution_model IS NULL OR length(execution_model) BETWEEN 1 AND 128)" : ""}`,
            )
            .run();
          connection
            .prepare(
              `ALTER TABLE ${table} ADD COLUMN reasoning_effort TEXT${request.history === "profiles" ? " CHECK ((reasoning_effort IS NULL OR length(reasoning_effort) BETWEEN 1 AND 64) AND ((execution_model IS NULL) = (reasoning_effort IS NULL)))" : ""}`,
            )
            .run();
        }
        if (request.history === "history") {
          const followUp = MIGRATIONS.find(
            ([, name]) => name === request.followUpMigration,
          )!;
          for (const statement of sqlStatements(native, followUp[2]))
            connection.prepare(statement).run();
        }
        connection
          .prepare("INSERT INTO schema_migrations VALUES (?, ?, ?)")
          .run([
            11,
            request.profileMigration ?? "scan execution profiles",
            timestamp,
          ]);
        connection
          .prepare("INSERT INTO schema_migrations VALUES (?, ?, ?)")
          .run([
            12,
            request.followUpMigration ?? "dynamic scan execution profiles",
            timestamp,
          ]);
      }
      connection
        .prepare(
          "ALTER TABLE scans ADD COLUMN completion_warnings_json TEXT NOT NULL DEFAULT '[]'",
        )
        .run();
      connection
        .prepare("INSERT INTO schema_migrations VALUES (?, ?, ?)")
        .run([25, "persist scan completion warnings", timestamp]);
      if (request.history === "profiles") {
        connection
          .prepare(
            "INSERT INTO workspaces (id, target_path, thread_id, execution_model, reasoning_effort, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
          )
          .run([
            "legacy-workspace",
            request.repository!,
            "legacy-thread",
            "gpt-workspace",
            "medium",
            timestamp,
            timestamp,
          ]);
        connection
          .prepare(
            "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at, execution_model, reasoning_effort) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .run([
            "legacy-scan",
            "legacy-workspace",
            request.repository!,
            "legacy-revision",
            ".",
            "standard",
            join(request.repository!, "legacy-scan"),
            "complete",
            "reporting",
            timestamp,
            timestamp,
            timestamp,
            "gpt-legacy",
            "high",
          ]);
        connection
          .prepare("UPDATE scans SET completion_warnings_json = ? WHERE id = ?")
          .run(['["legacy warning"]', "legacy-scan"]);
      } else if (request.history === "public") {
        connection
          .prepare(
            "INSERT INTO workspaces (id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?)",
          )
          .run(["legacy-workspace", request.repository!, timestamp, timestamp]);
        connection
          .prepare(
            "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at, completion_warnings_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .run([
            "legacy-scan",
            "legacy-workspace",
            request.repository!,
            "legacy-revision",
            ".",
            "standard",
            join(request.repository!, "legacy-scan"),
            "complete",
            "reporting",
            timestamp,
            timestamp,
            timestamp,
            '["existing warning"]',
          ]);
      }
      connection.commit();
      return null;
    }
    const columns = new Set(
      connection
        .prepare("PRAGMA table_info(scans)")
        .all()
        .map((row) => row.get("name")),
    );
    const versions =
      request.history === "profiles"
        ? "11,12,25,26"
        : request.history === "public"
          ? "25,26"
          : "11,12,20,25,26";
    const migrations = Object.fromEntries(
      connection
        .prepare(
          `SELECT version, name FROM schema_migrations WHERE version IN (${versions})`,
        )
        .all()
        .map((row) => [String(row.get("version")), row.get("name")]),
    );
    const deepScanTables =
      connection
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'deep_scan_runs'",
        )
        .get() !== undefined;
    if (request.history === "history")
      return {
        migrations,
        legacyColumnsRenamed: columns.has("legacy_execution_model"),
        deepScanTables,
      };
    const warnings = JSON.parse(
      connection
        .prepare("SELECT completion_warnings_json FROM scans WHERE id = ?")
        .get(["legacy-scan"])!
        .get(0) as string,
    ) as unknown;
    if (request.history === "public")
      return {
        columns: [...columns]
          .filter((name) =>
            ["model", "reasoning_effort", "completion_warnings_json"].includes(
              name as string,
            ),
          )
          .sort(),
        migrations,
        warnings,
      };
    const profile = (id: string) =>
      connection
        .prepare(
          "SELECT legacy_execution_model, legacy_reasoning_effort, model, reasoning_effort FROM scans WHERE id = ?",
        )
        .get([id])!
        .toObject();
    const previous = profile("legacy-scan"),
      workspaceProfile = connection
        .prepare(
          "SELECT legacy_execution_model, legacy_reasoning_effort FROM workspaces WHERE id = ?",
        )
        .get(["legacy-workspace"])!
        .toObject();
    connection
      .prepare(
        "UPDATE scans SET model = ?, reasoning_effort = NULL WHERE id = ?",
      )
      .run(["gpt-current", request.scanId!]);
    connection
      .prepare("UPDATE scans SET reasoning_effort = ? WHERE id = ?")
      .run(["high", request.scanId!]);
    return {
      columns: [...columns]
        .filter((name) =>
          [
            "deep_scan_owner_thread_id",
            "continuation_thread_id",
            "model",
            "reasoning_effort",
            "completion_warnings_json",
            "legacy_execution_model",
            "legacy_reasoning_effort",
          ].includes(name as string),
        )
        .sort(),
      migrations,
      profile: previous,
      workspaceProfile,
      warnings,
      currentProfile: profile(request.scanId!),
      deepScanTables,
    };
  } finally {
    connection.close();
  }
}
process.stdout.write(
  stringifyJson(run(JSON.parse(readFileSync(0, "utf8")) as Request)),
);
