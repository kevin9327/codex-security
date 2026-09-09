import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameters,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { applyMigrations } from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import {
  listGlobalFindings,
  listRepositories,
  type NavigationQuery,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-navigation";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { runWorkbench } from "../../src/runtime.js";
import {
  requireScan,
  requireWorkspace,
  resolveScanId,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-records";

export type Operation =
  | { sql: string; parameters?: Parameters }
  | {
      command: "list-global-findings" | "list-repositories";
      options?: NavigationQuery;
    }
  | { snapshot: true }
  | { lookup: "scan" | "workspace" | "resolve"; id: string }
  | { sdk: string[]; pluginRoot: string; stateDir: string; input?: string };
export interface Request {
  initialize?: boolean;
  operations: Operation[];
}
async function main() {
  const request = parseJson(readFileSync(0, "utf8")) as Request;
  const native = sqliteBinding();
  const connection = new Connection(native, process.argv[2] ?? ":memory:");
  connection.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;");
  const results: unknown[] = [];
  try {
    if (request.initialize)
      applyMigrations(native, connection, () => "2026-01-01T00:00:00+00:00");
    for (const operation of request.operations) {
      try {
        let value: unknown = null;
        if ("sql" in operation) {
          connection.prepare(operation.sql).run(operation.parameters ?? []);
        } else if ("snapshot" in operation) {
          value = Object.fromEntries(
            [
              "security_targets",
              "workspaces",
              "scans",
              "scan_progress",
              "findings",
              "finding_occurrences",
              "finding_locations",
              "finding_triage",
              "scan_comparisons",
              "scan_comparison_matches",
            ].map((table) => [
              table,
              connection
                .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
                .all()
                .map((row) => row.toObject()),
            ]),
          );
        } else if ("lookup" in operation) {
          value =
            operation.lookup === "resolve"
              ? resolveScanId(connection, operation.id)
              : (operation.lookup === "scan" ? requireScan : requireWorkspace)(
                  connection,
                  operation.id,
                ).toObject();
        } else if ("sdk" in operation) {
          value = await runWorkbench(
            {
              pluginRoot: operation.pluginRoot,
              environment: {
                ...process.env,
                CODEX_SECURITY_STATE_DIR: operation.stateDir,
                PYTHON: "missing-navigation-python",
                PATH: "",
              },
              failureMessage: "Navigation failed",
            },
            operation.sdk,
            operation.input,
          );
        } else {
          value =
            operation.command === "list-global-findings"
              ? listGlobalFindings(
                  connection,
                  operation.options ?? { offset: 0n },
                )
              : listRepositories(connection, operation.options);
        }
        results.push({ value, inTransaction: connection.inTransaction });
      } catch (error) {
        results.push({
          error: (error as Error).message,
          kind: (error as Error).constructor.name,
          inTransaction: connection.inTransaction,
        });
      }
    }
  } finally {
    connection.close();
  }
  process.stdout.write(stringifyJson(results));
}
void main();
