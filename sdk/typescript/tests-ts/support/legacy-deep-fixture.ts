import assert from "node:assert/strict";
import fs from "node:fs";
import { dirname, join } from "node:path";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  sqliteBinding,
  windowsBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import { applyMigrations } from "../../../../plugins/codex-security/mcp-app/src/workbench-schema";
import { beginDeepScanForScan } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-start";
import { recoverCandidateLedgerPublication } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-coordinator";
import { createPublicationCopy } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-publication";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import {
  buildReportMarkdown,
  type ReportManifest,
  type ReportCoverage,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/report-projection";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface OwnershipProbe {
  storedToken: string | null;
  suppliedToken: string | null;
  mutation?: "rotate" | "withdraw";
}
export type Request =
  | { operation: "ownership"; probe: OwnershipProbe }
  | { operation: "copy"; source: string; destination: string }
  | { operation: "recover"; root: string }
  | { operation: "migration"; recorded: boolean }
  | { operation: "report"; pluginRoot: string; reason: string }
  | {
      operation: "sql";
      database: string;
      statement: string;
      parameters: string[];
    };

const scanId = "11111111-1111-4111-8111-111111111111",
  workspaceId = "44444444-4444-4444-8444-444444444444";
function database<T>(
  path: string,
  operation: (connection: Connection) => T,
): T {
  const connection = new Connection(sqliteBinding(), path);
  try {
    return operation(connection);
  } finally {
    connection.close();
  }
}
function run(request: Request): unknown {
  switch (request.operation) {
    case "sql":
      return database(request.database, (connection) => {
        connection.prepare(request.statement).run(request.parameters);
        connection.commit();
        return null;
      });
    case "report": {
      const read = (name: string) =>
        parseJson(
          fs.readFileSync(
            join(request.pluginRoot, "examples/completed-scan", name),
          ),
        );
      const manifest = read("scan-manifest.json") as ReportManifest,
        coverage = read("coverage.json") as ReportCoverage;
      coverage.completeness = "partial";
      coverage["deferred"] = [
        { id: "candidate-example", reason: request.reason },
      ];
      return buildReportMarkdown(manifest, { findings: [] }, coverage);
    }
    case "copy": {
      let calls = 0;
      if (process.platform === "win32") {
        const native = windowsBinding(),
          link = native.createWindowsHardLink;
        native.createWindowsHardLink = () => {
          calls++;
          return 50;
        };
        try {
          createPublicationCopy(request.source, request.destination);
        } finally {
          native.createWindowsHardLink = link;
        }
      } else {
        const link = fs.linkSync;
        fs.linkSync = () => {
          calls++;
          throw Object.assign(new Error("hardlinks are unavailable"), {
            code: "ENOTSUP",
            errno: -95,
          });
        };
        try {
          createPublicationCopy(request.source, request.destination);
        } finally {
          fs.linkSync = link;
        }
      }
      assert.equal(calls, 1);
      return null;
    }
    case "recover":
      return database(":memory:", (connection) => {
        const scanDir = join(request.root, "scan"),
          ledger = join(
            scanDir,
            "artifacts/02_discovery/candidate_ledger.jsonl",
          );
        const snapshot = join(
            request.root,
            "worker/canonical/candidate_ledger.jsonl",
          ),
          backup = join(
            dirname(ledger),
            ".candidate_ledger.jsonl.fixture.backup",
          );
        fs.mkdirSync(dirname(ledger), { recursive: true });
        fs.mkdirSync(dirname(snapshot), { recursive: true });
        fs.writeFileSync(ledger, "old ledger\n");
        fs.copyFileSync(ledger, backup);
        fs.writeFileSync(snapshot, "new ledger\n");
        fs.copyFileSync(snapshot, ledger);
        connection.exec(
          "CREATE TABLE scans (id TEXT PRIMARY KEY, scan_dir TEXT); CREATE TABLE deep_scan_workers (scan_id TEXT, kind TEXT, status TEXT, artifact_dir TEXT, updated_at TEXT)",
        );
        connection
          .prepare("INSERT INTO scans VALUES (?, ?)")
          .run([scanId, scanDir]);
        connection
          .prepare("INSERT INTO deep_scan_workers VALUES (?, ?, ?, ?, ?)")
          .run([scanId, "dedup", "running", dirname(dirname(snapshot)), "now"]);
        recoverCandidateLedgerPublication(connection, scanId);
        return {
          ledger: fs.readFileSync(ledger, "utf8"),
          backup: fs.existsSync(backup),
        };
      });
    case "migration":
      return database(":memory:", (connection) => {
        const timestamp = "2026-07-01T00:00:00Z";
        const migrate = (migrations: typeof MIGRATIONS) =>
          applyMigrations(
            sqliteBinding(),
            connection,
            migrations,
            () => timestamp,
            () => {},
          );
        migrate(MIGRATIONS.filter(([version]) => version < 28));
        connection
          .prepare(
            "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
          )
          .run(["legacy-workspace", timestamp, timestamp]);
        connection
          .prepare(
            "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, '/legacy/target', 'legacy-revision', '.', 'deep', '/legacy/scan', 'running', 'discovery', ?, ?, ?)",
          )
          .run([
            "legacy-scan",
            "legacy-workspace",
            timestamp,
            timestamp,
            timestamp,
          ]);
        connection
          .prepare(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at) VALUES (?, 1, 'legacy-workflow', 'running', 'discovery', 1, 0, 3, 10, ?, ?)",
          )
          .run(["legacy-scan", timestamp, timestamp]);
        if (request.recorded)
          connection
            .prepare(
              "INSERT INTO schema_migrations (version, name, applied_at) VALUES (28, ?, ?)",
            )
            .run(["persist deep scan discovery time limit", timestamp]);
        connection.commit();
        migrate(MIGRATIONS);
        const defaultHours = connection
          .prepare("SELECT max_time_hours FROM deep_scan_runs")
          .get()!
          .get(0);
        connection
          .prepare("UPDATE deep_scan_runs SET max_time_hours = 2.5")
          .run();
        connection.commit();
        migrate(MIGRATIONS);
        return {
          default: defaultHours,
          configured: connection
            .prepare("SELECT max_time_hours FROM deep_scan_runs")
            .get()!
            .get(0),
          migration: connection
            .prepare("SELECT name FROM schema_migrations WHERE version = 28")
            .get()!
            .get(0),
        };
      });
    case "ownership":
      return database(":memory:", (connection) => {
        for (const [, , sql] of MIGRATIONS) connection.exec(sql);
        const insert = (table: string, row: Record<string, Parameter>) =>
          connection
            .prepare(
              `INSERT INTO ${table} (${Object.keys(row).join(",")}) VALUES (${Object.keys(
                row,
              )
                .map(() => "?")
                .join(",")})`,
            )
            .run(Object.values(row));
        insert("workspaces", {
          id: workspaceId,
          thread_id: null,
          created_at: "before",
          updated_at: "before",
        });
        insert("scans", {
          id: scanId,
          workspace_id: workspaceId,
          target_path: "/target",
          target_revision: "revision",
          scope: ".",
          mode: "deep",
          scan_dir: "/scan",
          status: "running",
          phase: "discovery",
          recipe_json: "{}",
          handoff_status: "delivered",
          handoff_claim_token: request.probe.storedToken,
          deep_scan_owner_thread_id: null,
          started_at: "before",
          created_at: "before",
          updated_at: "before",
        });
        insert("deep_scan_runs", {
          scan_id: scanId,
          schema_version: 1n,
          workflow_version: "fixture",
          status: "running",
          phase: "discovery",
          workers: 1n,
          subagents: 0n,
          stop_after_no_new: 3n,
          max_discovery_runs: 10n,
          created_at: "before",
          updated_at: "before",
        });
        connection.commit();
        if (request.probe.mutation === "rotate")
          connection.exec(
            "CREATE TRIGGER rotate_claim BEFORE UPDATE OF thread_id ON workspaces BEGIN UPDATE scans SET handoff_claim_token = '33333333-3333-4333-8333-333333333333' WHERE workspace_id = NEW.id; END",
          );
        if (request.probe.mutation === "withdraw")
          connection.exec(
            "CREATE TRIGGER withdraw_handoff BEFORE UPDATE OF thread_id ON workspaces BEGIN UPDATE scans SET handoff_status = 'pending' WHERE workspace_id = NEW.id; END",
          );
        let result: unknown = null,
          accepted = false,
          error: string | null = null;
        try {
          result = beginDeepScanForScan(
            {
              now: () => "after",
              uuid: () => {
                throw new Error("unexpected UUID allocation");
              },
              stdin: () => {
                throw new Error("unexpected stdin read");
              },
            },
            connection,
            scanId,
            "requesting-thread",
            {
              scanId,
              threadId: "requesting-thread",
              targetPath: null,
              scope: ".",
              userContext: null,
              scanRoot: null,
              claimToken: request.probe.suppliedToken,
              model: null,
              reasoningEffort: null,
              availableParallelism: null,
              workflowVersion: null,
            },
          );
          accepted = true;
        } catch (failure) {
          if (!(failure instanceof WorkbenchValidationError)) throw failure;
          error = failure.message;
        }
        const scan = connection
            .prepare("SELECT * FROM scans WHERE id = ?")
            .get([scanId])!,
          workspace = connection
            .prepare("SELECT * FROM workspaces WHERE id = ?")
            .get([workspaceId])!;
        return {
          accepted,
          error,
          result,
          scanOwner: scan.get("deep_scan_owner_thread_id"),
          workspaceOwner: workspace.get("thread_id"),
          scanUpdatedAt: scan.get("updated_at"),
          workspaceUpdatedAt: workspace.get("updated_at"),
          storedToken: scan.get("handoff_claim_token"),
          handoffStatus: scan.get("handoff_status"),
        };
      });
  }
}
process.stdout.write(
  stringifyJson(run(JSON.parse(fs.readFileSync(0, "utf8")) as Request)),
);
