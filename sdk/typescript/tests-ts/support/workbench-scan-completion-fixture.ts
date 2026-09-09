import { readFileSync } from "node:fs";
import {
  Connection,
  Row,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as budget from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-budget";
import * as completion from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-completion";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export const scanId = "11111111-1111-4111-8111-111111111111";
export const workspaceId = "22222222-2222-4222-8222-222222222222";
export interface Action {
  operation:
    | "complete"
    | "completeLocked"
    | "completeBudget"
    | "setLimit"
    | "sql"
    | "commit"
    | "rollback";
  reportFault?: { remaining: number; kind: "io" | "value" | "type" };
  prepareOnly?: boolean;
  maxCostUsd?: number;
  message?: string | null;
  id?: string;
  costJson?: string | null;
  claimToken?: string | null;
  threadId?: string | null;
  now?: string;
  nowSql?: string;
  failNow?: number;
  nowError?: "value" | "type" | "exit" | "runtime";
  sql?: string;
  parameters?: Parameter[];
  beforeBeginSql?: string;
}
export interface Request {
  environment: Record<string, string>;
  workspace?: Record<string, Parameter>;
  scan?: Record<string, Parameter>;
  progress?: Record<string, Parameter> | null;
  records?: Record<string, Record<string, Parameter>[]>;
  setupSql?: string[];
  actions: Action[];
}
export interface Outcome {
  reportCalls?: string | null;
  result?: unknown;
  error?: string;
  systemExit?: boolean;
  inTransaction: boolean;
  events: unknown[][];
}
export interface Response {
  outcomes: Outcome[];
  snapshot: Record<string, Record<string, unknown>[]>;
  node: string;
}
function output(value: unknown): unknown {
  if (value instanceof Row) return output(value.toObject());
  if (Buffer.isBuffer(value)) return { bytes: value.toString("hex") };
  if (typeof value === "number") return new JsonFloat(String(value));
  if (Array.isArray(value)) return value.map(output);
  if (
    value !== null &&
    typeof value === "object" &&
    !(value instanceof JsonFloat)
  )
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, output(item)]),
    );
  return value;
}
function input(value: unknown): unknown {
  if (value instanceof JsonFloat) return Number(value.source);
  if (Array.isArray(value)) return value.map(input);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, input(item)]),
    );
  return value;
}
const tables = [
  "workspaces",
  "scans",
  "scan_progress",
  "scan_artifacts",
  "findings",
  "finding_occurrences",
  "finding_locations",
  "finding_triage",
  "finding_remediation_attempts",
  "deep_scan_runs",
  "deep_scan_workers",
  "scan_comparisons",
  "scan_comparison_matches",
];
function execute(request: Request): Response {
  for (const [key, value] of Object.entries(request.environment))
    process.env[key] = value;
  const connection = new Connection(sqliteBinding(), ":memory:");
  const insert = (table: string, values: Record<string, Parameter>) =>
    connection
      .prepare(
        `INSERT INTO ${table} (${Object.keys(values).join(", ")}) VALUES (${Object.keys(
          values,
        )
          .map(() => "?")
          .join(", ")})`,
      )
      .run(Object.values(values));
  try {
    for (const [, , sql] of MIGRATIONS) connection.exec(sql);
    insert("workspaces", {
      id: workspaceId,
      thread_id: "owner",
      active_scan_id: scanId,
      created_at: "created",
      updated_at: "workspace-updated",
      ...request.workspace,
    });
    insert("scans", {
      id: scanId,
      workspace_id: workspaceId,
      target_path: "/target",
      target_revision: "unversioned",
      target_id: "target:synthetic",
      target_snapshot_digest: `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`,
      scope: ".",
      mode: "standard",
      scan_dir: "/scan",
      status: "running",
      phase: "discovery",
      handoff_status: "delivered",
      started_at: "2026-01-01T00:00:00Z",
      created_at: "created",
      updated_at: "scan-updated",
      ...request.scan,
    });
    if (request.progress !== null)
      insert("scan_progress", {
        scan_id: scanId,
        updated_at: "progress-updated",
        ...request.progress,
      });
    for (const [table, rows] of Object.entries(request.records ?? {}))
      for (const row of rows) insert(table, row);
    connection.commit();
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    connection.commit();
    const outcomes = request.actions.map((action): Outcome => {
      const globals = globalThis as unknown as {
        finalizationReportFault?: {
          remaining: number;
          calls: number;
          kind: string;
        };
      };
      if (action.reportFault)
        globals.finalizationReportFault = { ...action.reportFault, calls: 0 };
      const events: unknown[][] = [],
        raw = connection.raw,
        prepare = raw.prepare,
        exec = raw.exec;
      let beforeBegin = action.beforeBeginSql,
        clocks = 0;
      raw.prepare = (sql) => {
        if (beforeBegin && sql.trim() === "BEGIN IMMEDIATE") {
          const pending = beforeBegin;
          beforeBegin = undefined;
          events.push(["before-begin", pending, connection.inTransaction]);
          exec.call(raw, pending);
        }
        events.push([
          "query",
          sql.trim().replace(/\s+/gu, " "),
          connection.inTransaction,
        ]);
        return prepare.call(raw, sql);
      };
      raw.exec = (sql) => {
        events.push(["transaction", sql, connection.inTransaction]);
        return exec.call(raw, sql);
      };
      const db = {
        now: () => {
          events.push(["now", connection.inTransaction]);
          if (action.nowSql) connection.prepare(action.nowSql).run();
          if (++clocks === Number(action.failNow)) {
            if (action.nowError === "exit")
              throw new WorkbenchValidationError("clock failed");
            if (action.nowError === "type") throw new TypeError("clock failed");
            throw Object.assign(new Error("clock failed"), {
              name: action.nowError === "value" ? "ValueError" : "Error",
            });
          }
          return action.now ?? "2026-01-02T00:00:00Z";
        },
      };
      try {
        let result: unknown = null;
        const id = action.id ?? scanId;
        switch (action.operation) {
          case "completeBudget":
            result = budget.completeBudgetExhaustedScan(db, connection, {
              scanId: id,
              costJson: action.costJson ?? null,
              message: action.message ?? null,
            });
            break;
          case "setLimit":
            result = budget.setScanCostLimit(db, connection, {
              scanId: id,
              maxCostUsd: Number(action.maxCostUsd),
            });
            break;
          case "complete":
            result = completion.completeScan(
              db,
              connection,
              {
                scanId: id,
                costJson: action.costJson ?? null,
                claimToken: action.claimToken ?? null,
                threadId: action.threadId ?? null,
              },
              action.prepareOnly ?? false,
            );
            break;
          case "completeLocked":
            result = completion.completeScanLocked(
              db,
              connection,
              id,
              action.claimToken ?? null,
              action.costJson ?? null,
              {
                prepareOnly: action.prepareOnly ?? false,
                threadId: action.threadId ?? null,
              },
            );
            break;
          case "sql":
            connection.prepare(action.sql!).run(action.parameters);
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
        }
        return {
          result: output(result),
          inTransaction: connection.inTransaction,
          reportCalls: globals.finalizationReportFault
            ? String(globals.finalizationReportFault.calls)
            : null,
          events,
        };
      } catch (error) {
        return {
          error: filesystemErrorMessage(error),
          systemExit: error instanceof WorkbenchValidationError,
          inTransaction: connection.inTransaction,
          reportCalls: globals.finalizationReportFault
            ? String(globals.finalizationReportFault.calls)
            : null,
          events,
        };
      } finally {
        delete globals.finalizationReportFault;
        raw.prepare = prepare;
        raw.exec = exec;
      }
    });
    return {
      outcomes,
      node: process.versions.node,
      snapshot: Object.fromEntries(
        tables.map((table) => [
          table,
          connection
            .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
            .all()
            .map((row) => row.toObject()),
        ]),
      ),
    };
  } finally {
    connection.close();
  }
}
process.stdout.write(
  stringifyJson(
    output(
      (input(parseJson(readFileSync(0, "utf8"))) as Request[]).map(execute),
    ),
    { compact: true, sortKeys: true },
  ),
);
