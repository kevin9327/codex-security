import { readFileSync } from "node:fs";
import {
  Connection,
  Row,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  processBinding,
  sqliteBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as workflows from "../../../../plugins/codex-security/mcp-app/src/workbench-finding-workflows";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import { decodeFilename } from "../../../../plugins/codex-security/mcp-app/src/workbench-git";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export type Action = (
  | { operation: "workflow"; payload: unknown }
  | { operation: "read"; id: string }
  | { operation: "save"; state: workflows.FindingWorkflowState }
  | {
      operation: "bind";
      state: workflows.FindingWorkflowState;
      binding: unknown;
    }
  | { operation: "register"; id: string; scanId: string; scanDir: string }
  | { operation: "sql" | "query"; sql: string; parameters?: Parameter[] }
  | { operation: "commit" | "rollback" }
) & {
  timestamp?: string;
  git?: { stdout?: string; stderr?: string; status?: number }[];
};
export interface Request {
  actions: Action[];
  foreignKeys?: boolean;
}
export interface Outcome {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  events: unknown[];
  inTransaction: boolean;
}
export interface Response {
  outcomes: Outcome[];
  snapshot: Record<string, unknown[]>;
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
      Object.entries(value).map(([key, child]) => [key, output(child)]),
    );
  return value;
}
function execute(request: Request): Response {
  const connection = new Connection(sqliteBinding(), ":memory:");
  try {
    for (const [, , sql] of MIGRATIONS) connection.exec(sql);
    if (request.foreignKeys !== false)
      connection.exec("PRAGMA foreign_keys = ON");
    const outcomes = request.actions.map((action): Outcome => {
      const events: unknown[] = [],
        raw = connection.raw,
        prepare = raw.prepare,
        exec = raw.exec,
        native = processBinding(),
        originalProcess = native.rawProcess;
      raw.prepare = (sql) => {
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
      let probe = 0;
      if (action.git)
        native.rawProcess = (options) => {
          events.push([
            "git",
            options.args.map((arg) =>
              process.platform === "win32"
                ? arg.toString("utf16le")
                : decodeFilename(arg),
            ),
          ]);
          const reply = action.git![probe++];
          if (!reply) throw new Error("Unexpected Git probe");
          return {
            error: 0,
            returnCode: Number(reply.status ?? 0),
            stdout: Buffer.from(reply.stdout ?? "", "base64"),
            stderr: Buffer.from(reply.stderr ?? "", "base64"),
          };
        };
      try {
        let value: unknown = null;
        const timestamp = action.timestamp ?? "2026-08-01T00:00:00Z";
        switch (action.operation) {
          case "workflow":
            value = workflows.findingWorkflow(
              connection,
              action.payload,
              timestamp,
            );
            break;
          case "read":
            value = workflows.readFindingWorkflow(connection, action.id);
            break;
          case "save":
            workflows.saveFindingWorkflow(connection, action.state, timestamp);
            break;
          case "bind":
            workflows.bindFindingWorkflow(action.state, action.binding);
            value = action.state;
            break;
          case "register":
            workflows.registerWorkflowScan(
              connection,
              action.id,
              action.scanId,
              action.scanDir,
              timestamp,
            );
            break;
          case "sql":
            connection
              .prepare(action.sql)
              .run(
                action.parameters?.map((parameter) =>
                  parameter instanceof JsonFloat
                    ? Number(parameter.source)
                    : parameter,
                ),
              );
            break;
          case "query":
            value = connection
              .prepare(action.sql)
              .all(
                action.parameters?.map((parameter) =>
                  parameter instanceof JsonFloat
                    ? Number(parameter.source)
                    : parameter,
                ),
              );
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
        }
        return {
          value: output(value),
          inTransaction: connection.inTransaction,
          events,
        };
      } catch (error) {
        return {
          error: filesystemErrorMessage(error),
          systemExit:
            error instanceof WorkbenchValidationError ||
            error instanceof TargetInspectionError,
          inTransaction: connection.inTransaction,
          events,
        };
      } finally {
        raw.prepare = prepare;
        raw.exec = exec;
        native.rawProcess = originalProcess;
      }
    });
    return {
      outcomes,
      node: process.versions.node,
      snapshot: Object.fromEntries(
        [
          "finding_workflows",
          "finding_workflow_reviews",
          "workspaces",
          "scans",
        ].map((table) => [
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
    output((parseJson(readFileSync(0, "utf8")) as Request[]).map(execute)),
    { compact: true, sortKeys: true },
  ),
);
