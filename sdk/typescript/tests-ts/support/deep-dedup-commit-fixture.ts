import { readFileSync } from "node:fs";
import {
  Connection,
  Row,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as owner from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-dedup-commit";
import { appendPath } from "../../../../plugins/codex-security/mcp-app/src/helpers/rank-selection";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  pythonRepr,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export const scanId = "11111111-1111-4111-8111-111111111111";
export const workspaceId = "22222222-2222-4222-8222-222222222222";
export const workerId = "33333333-3333-4333-8333-333333333333";
export const now = "2026-01-02T00:00:00Z";
export interface Action {
  operation: "dedup" | "locked" | "sql" | "query" | "commit" | "rollback";
  args?: Partial<owner.CommitDeepDedupArguments>;
  timestamp?: string;
  failNow?: number;
  nowSql?: string;
  beforeBeginSql?: string;
  sql?: string;
  parameters?: Parameter[];
}
export interface Request {
  environment?: Record<string, string>;
  workspace?: Record<string, Parameter>;
  scan?: Record<string, Parameter>;
  run?: Record<string, Parameter> | null;
  workers?: Record<string, Parameter>[];
  inputs?: Record<string, Parameter>[];
  progress?: Record<string, Parameter>;
  setupSql?: string[];
  actions: Action[];
}
export interface Outcome {
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
function execute(request: Request): Response {
  for (const [key, value] of Object.entries(request.environment ?? {}))
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
      created_at: now,
      updated_at: now,
      ...request.workspace,
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
      handoff_status: "delivered",
      started_at: "2026-01-01T00:00:00Z",
      created_at: now,
      updated_at: now,
      ...request.scan,
    });
    if (request.run !== null)
      insert("deep_scan_runs", {
        scan_id: scanId,
        schema_version: 1n,
        workflow_version: "deep-security-scan/v1",
        status: "running",
        phase: "setup",
        workers: 4n,
        subagents: 1n,
        stop_after_no_new: 3n,
        stop_after_consecutive_errors: 3n,
        max_discovery_runs: 40n,
        max_time_hours: 2,
        created_at: now,
        updated_at: now,
        ...request.run,
      });
    for (const worker of request.workers ?? [])
      insert("deep_scan_workers", {
        id: workerId,
        scan_id: scanId,
        kind: "discovery",
        status: "queued",
        prompt_path: "/prompt",
        artifact_dir: "/artifacts",
        created_at: now,
        updated_at: now,
        ...worker,
      });
    for (const row of request.inputs ?? [])
      insert("deep_scan_dedup_inputs", { scan_id: scanId, ...row });
    if (request.progress)
      insert("scan_progress", { scan_id: scanId, ...request.progress });
    connection.commit();
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    connection.commit();
    const outcomes = request.actions.map((action): Outcome => {
      const events: unknown[][] = [],
        raw = connection.raw,
        prepare = raw.prepare,
        exec = raw.exec;
      let beforeBegin = true,
        clocks = 0;
      raw.prepare = (sql) => {
        events.push([
          "query",
          sql.trim().replace(/\s+/gu, " "),
          connection.inTransaction,
        ]);
        return prepare.call(raw, sql);
      };
      raw.exec = (sql) => {
        if (beforeBegin && sql === "BEGIN IMMEDIATE") {
          beforeBegin = false;
          if (action.beforeBeginSql) {
            events.push([
              "before-begin",
              action.beforeBeginSql,
              connection.inTransaction,
            ]);
            exec.call(raw, action.beforeBeginSql);
          }
        }
        events.push(["transaction", sql, connection.inTransaction]);
        return exec.call(raw, sql);
      };
      const context: owner.DeepDedupCommitContext = {
        uuid: () => "77777777-7777-4777-8777-777777777777",
        now: () => {
          events.push(["now", connection.inTransaction]);
          if (++clocks === Number(action.failNow))
            throw new Error("clock failed");
          if (action.nowSql) connection.prepare(action.nowSql).run();
          return action.timestamp ?? now;
        },
      };
      const directory =
        (request.scan?.["scan_dir"] as string | undefined) ?? "/scan";
      const args: owner.CommitDeepDedupArguments = {
        scanId,
        workerId,
        coordinatorGeneration: null,
        candidateLedgerPath: null,
        resultManifestPath: appendPath(directory, "result.json"),
        newFindingsCount: 0n,
        ...action.args,
      };
      try {
        let result: unknown = null;
        switch (action.operation) {
          case "dedup":
            result = owner.commitDeepScanDedup(context, connection, args);
            break;
          case "locked":
            result = owner.commitDeepScanDedupLocked(
              context,
              connection,
              args,
              args.scanId,
            );
            break;
          case "sql":
            connection.prepare(action.sql!).run(action.parameters);
            break;
          case "query":
            result = connection.prepare(action.sql!).all(action.parameters);
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
          events,
        };
      } catch (error) {
        const destination = (error as { dest?: string }).dest;
        return {
          error:
            filesystemErrorMessage(error) +
            (destination === undefined ? "" : ` -> ${pythonRepr(destination)}`),
          systemExit: error instanceof WorkbenchValidationError,
          inTransaction: connection.inTransaction,
          events,
        };
      } finally {
        raw.prepare = prepare;
        raw.exec = exec;
      }
    });
    return {
      outcomes,
      snapshot: Object.fromEntries(
        [
          "workspaces",
          "scans",
          "scan_progress",
          "deep_scan_runs",
          "deep_scan_workers",
          "deep_scan_dedup_inputs",
        ].map((table) => [
          table,
          connection
            .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
            .all()
            .map((row) => row.toObject()),
        ]),
      ),
      node: process.versions.node,
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
