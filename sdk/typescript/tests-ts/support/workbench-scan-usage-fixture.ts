import { readFileSync } from "node:fs";
import {
  Connection,
  Row,
  type SqlValue,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  collectScanUsage,
  measuredScanCostJson,
  reconcileCompletedScanCost,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-usage";
import { storedScanCostFields } from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-history";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  object,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface Action {
  operation:
    | "collect"
    | "reconcile"
    | "measure"
    | "stored"
    | "sql"
    | "commit"
    | "rollback";
  scan?: Record<string, unknown>;
  threadId?: string | null;
  completedAt?: string | null;
  costJson?: string;
  usage?: Record<string, unknown>;
  value?: string | null;
  sql?: string;
}
export interface Request {
  environment: Record<string, string>;
  actions: Action[];
  workspaceThread?: string | null;
  workers?: unknown[];
  scan?: Record<string, unknown>;
  setupSql?: string[];
  state?: {
    path: string;
    threads: [unknown, unknown][];
    edges?: [unknown, unknown][];
    schema?: string;
  };
}
export interface Outcome {
  value?: unknown;
  error?: string;
  inTransaction: boolean;
}
export interface Response {
  node: string;
  outcomes: Outcome[];
  rows: Record<string, unknown>[];
}
const sqlValue = (value: unknown): SqlValue =>
  value instanceof JsonFloat
    ? Number(value.source)
    : object(value) && typeof value["bytes"] === "string"
      ? Buffer.from(value["bytes"], "hex")
      : (value as SqlValue);
const requests = parseJson(readFileSync(0, "utf8")) as unknown as Request[];
const output: Response[] = requests.map((request) => {
  for (const [key, value] of Object.entries(request.environment))
    process.env[key] = value;
  if (request.state) {
    const state = new Connection(sqliteBinding(), request.state.path);
    try {
      state.raw.exec(
        request.state.schema ??
          "CREATE TABLE threads(id, rollout_path); CREATE TABLE thread_spawn_edges(parent_thread_id, child_thread_id);",
      );
      for (const row of request.state.threads)
        state
          .prepare("INSERT INTO threads VALUES (?,?)")
          .run(row.map(sqlValue));
      for (const row of request.state.edges ?? [])
        state
          .prepare("INSERT INTO thread_spawn_edges VALUES (?,?)")
          .run(row.map(sqlValue));
      state.commit();
    } finally {
      state.close();
    }
  }
  const connection = new Connection(sqliteBinding(), ":memory:");
  const fields = {
    id: "scan",
    workspace_id: "workspace",
    mode: "standard",
    status: "complete",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:10:00Z",
    cost_json: null,
    continuation_thread_id: null,
    deep_scan_owner_thread_id: null,
    ...request.scan,
  };
  try {
    connection.raw.exec(`
      CREATE TABLE scans(id TEXT, workspace_id TEXT, mode TEXT, status TEXT, started_at TEXT, completed_at TEXT, cost_json TEXT, continuation_thread_id TEXT, deep_scan_owner_thread_id TEXT);
      CREATE TABLE workspaces(id TEXT, thread_id TEXT);
      CREATE TABLE deep_scan_workers(scan_id TEXT, sdk_thread_id TEXT);
    `);
    connection
      .prepare(
        `INSERT INTO scans (${Object.keys(fields).join(",")}) VALUES (${Object.keys(
          fields,
        )
          .map(() => "?")
          .join(",")})`,
      )
      .run(Object.values(fields).map(sqlValue));
    connection
      .prepare("INSERT INTO workspaces VALUES (?,?)")
      .run([
        "workspace",
        request.workspaceThread === undefined
          ? "root"
          : request.workspaceThread,
      ]);
    for (const worker of request.workers ?? [])
      connection
        .prepare("INSERT INTO deep_scan_workers VALUES (?,?)")
        .run(["scan", sqlValue(worker)]);
    connection.commit();
    for (const sql of request.setupSql ?? []) connection.raw.exec(sql);
    const outcomes = request.actions.map((action): Outcome => {
      const row = connection.prepare("SELECT * FROM scans LIMIT 1").get()!;
      const values = {
        ...Object.fromEntries(
          row.columns.map((column) => [column, row.get(column)]),
        ),
        ...action.scan,
      };
      const scan = new Row(
        Object.keys(values),
        Object.values(values).map(sqlValue),
      );
      try {
        let value: unknown = null;
        switch (action.operation) {
          case "collect":
            value = collectScanUsage(
              connection,
              scan,
              action.threadId ?? null,
              action.completedAt ?? null,
            );
            break;
          case "reconcile":
            reconcileCompletedScanCost(connection, scan, action.costJson!);
            break;
          case "measure":
            value = measuredScanCostJson(action.usage!);
            break;
          case "stored":
            value = storedScanCostFields(action.value ?? null);
            break;
          case "sql":
            connection.prepare(action.sql!).run();
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
        }
        return { value, inTransaction: connection.inTransaction };
      } catch (error) {
        return {
          error: filesystemErrorMessage(error),
          inTransaction: connection.inTransaction,
        };
      }
    });
    return {
      node: process.versions.node,
      outcomes,
      rows: connection
        .prepare("SELECT * FROM scans ORDER BY rowid")
        .all()
        .map((row) =>
          Object.fromEntries(
            row.columns.map((column) => [column, row.get(column)]),
          ),
        ),
    };
  } finally {
    connection.close();
  }
});
function normalize(value: unknown): unknown {
  if (Buffer.isBuffer(value)) return { bytes: value.toString("hex") };
  if (Array.isArray(value)) return value.map(normalize);
  if (object(value))
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, normalize(item)]),
    );
  return value;
}
process.stdout.write(
  stringifyJson(normalize(output), { compact: true, sortKeys: true }),
);
