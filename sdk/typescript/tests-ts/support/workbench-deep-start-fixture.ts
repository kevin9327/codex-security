import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import {
  Connection,
  Row,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as deep from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-start";
import { DeepScanConfigError } from "../../../../plugins/codex-security/mcp-app/src/helpers/deep-scan-config";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export const workspaceId = "22222222-2222-4222-8222-222222222222";
export interface Action {
  operation:
    | "begin"
    | "forScan"
    | "forTarget"
    | "get"
    | "sql"
    | "query"
    | "commit"
    | "rollback";
  args?: Partial<deep.BeginDeepScanArguments>;
  now?: string;
  nowSql?: string;
  failNow?: number;
  uuids?: string[];
  failUuid?: number;
  stdin?: string;
  failStdin?: boolean;
  sql?: string;
  parameters?: Parameter[];
  beforeBeginSql?: string;
  beforeBeginReplace?: string;
  beforeBeginWrite?: { path: string; text: string };
}
export interface Request {
  environment: Record<string, string>;
  target: string;
  scanRoot: string;
  workspace?: Record<string, Parameter> | null;
  records?: Record<string, Record<string, Parameter>[]>;
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
  "security_targets",
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
  "deep_scan_dedup_inputs",
  "scan_comparisons",
  "scan_comparison_matches",
];
function execute(request: Request): Response {
  for (const [key, value] of Object.entries(request.environment))
    process.env[key] = value;
  const connection = new Connection(sqliteBinding(), ":memory:");
  let sequence = 0;
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
    if (request.workspace !== null)
      insert("workspaces", {
        id: workspaceId,
        thread_id: "owner",
        target_path: request.target,
        target_title: "target",
        default_scope: ".",
        default_mode: "standard",
        submitted: 1n,
        created_at: "created",
        updated_at: "workspace-updated",
        ...request.workspace,
      });
    for (const [table, rows] of Object.entries(request.records ?? {}))
      for (const row of rows) insert(table, row);
    connection.commit();
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    connection.commit();
    const outcomes = request.actions.map((action): Outcome => {
      const events: unknown[][] = [],
        raw = connection.raw,
        prepare = raw.prepare,
        exec = raw.exec;
      let beforeBegin = true,
        clocks = 0,
        ids = 0;
      raw.prepare = (sql) => {
        if (beforeBegin && sql.trim() === "BEGIN IMMEDIATE") {
          beforeBegin = false;
          if (action.beforeBeginSql) {
            events.push([
              "before-begin",
              action.beforeBeginSql,
              connection.inTransaction,
            ]);
            exec.call(raw, action.beforeBeginSql);
          }
          if (action.beforeBeginReplace) {
            renameSync(
              action.beforeBeginReplace,
              action.beforeBeginReplace + ".old",
            );
            mkdirSync(action.beforeBeginReplace);
          }
          if (action.beforeBeginWrite)
            writeFileSync(
              action.beforeBeginWrite.path,
              action.beforeBeginWrite.text,
            );
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
      const context = {
        now: () => {
          events.push(["now", connection.inTransaction]);
          if (action.nowSql) connection.prepare(action.nowSql).run();
          if (++clocks === Number(action.failNow))
            throw new Error("clock failed");
          return action.now ?? "2026-01-02T00:00:00Z";
        },
        uuid: () => {
          events.push(["uuid", connection.inTransaction]);
          if (++ids === Number(action.failUuid)) throw new Error("UUID failed");
          return (
            action.uuids?.[ids - 1] ??
            `${String(++sequence).padStart(8, "0")}-1111-4111-8111-111111111111`
          );
        },
        stdin: () => {
          events.push(["stdin", connection.inTransaction]);
          if (action.failStdin) throw new Error("stdin failed");
          return action.stdin ?? "";
        },
      };
      try {
        let result: unknown = null;
        const args = {
          scanId: null,
          targetPath: request.target,
          scanRoot: request.scanRoot,
          threadId: "owner",
          scope: ".",
          userContext: null,
          userContextStdin: false,
          claimToken: null,
          model: null,
          reasoningEffort: null,
          availableParallelism: 4,
          workflowVersion: "deep-security-scan/v1",
          ...action.args,
        };
        switch (action.operation) {
          case "begin":
            result = deep.beginDeepScan(context, connection, args);
            break;
          case "forScan":
            result = deep.beginDeepScanForScan(
              context,
              connection,
              args.scanId!,
              args.threadId!,
              args,
            );
            break;
          case "forTarget":
            result = deep.beginDeepScanForTarget(
              context,
              connection,
              args,
              args.threadId!,
            );
            break;
          case "get":
            result = deep.getDeepScan(context, connection, {
              scanId: args.scanId!,
              threadId: args.threadId!,
            });
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
        return {
          error: filesystemErrorMessage(error),
          systemExit:
            error instanceof WorkbenchValidationError ||
            error instanceof TargetInspectionError ||
            error instanceof DeepScanConfigError,
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
