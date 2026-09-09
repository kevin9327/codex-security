import { readFileSync } from "node:fs";
import {
  Connection,
  Row,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  registerCliScan,
  type CliRegistrationArguments,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-cli-registration";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";

export const SCAN = "11111111-1111-4111-8111-111111111111";
export const WORKSPACE = "22222222-2222-4222-8222-222222222222";
type Phase = "now" | "uuid" | "stdin";
interface Hook {
  phase: Phase;
  call?: number;
  sql?: string;
  error?: string;
  systemExit?: boolean;
}
export type Action =
  | {
      operation: "register";
      args: CliRegistrationArguments;
      stdin?: string;
      ids?: [string, string];
      times?: string[];
      hooks?: Hook[];
    }
  | { operation: "sql" | "query"; sql: string; parameters?: Parameter[] }
  | { operation: "commit" | "rollback" };
export interface Request {
  records?: Record<string, Record<string, Parameter>[]>;
  setupSql?: string[];
  actions: Action[];
}
export interface Outcome {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  events: unknown[];
  inTransaction: boolean;
}
export interface Response {
  node: string;
  outcomes: Outcome[];
  snapshot: Record<string, Record<string, unknown>[]>;
}
const parameter = (value: Parameter): Parameter =>
  value instanceof JsonFloat ? Number(value.source) : value;
function output(value: unknown): unknown {
  if (value instanceof Row) return output(value.toObject());
  if (Buffer.isBuffer(value)) return { $bytes: value.toString("hex") };
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
    connection.exec("PRAGMA foreign_keys=ON");
    connection.exec("CREATE TABLE synthetic_audit(value TEXT)");
    for (const [table, rows] of Object.entries(request.records ?? {}))
      for (const row of rows) {
        const keys = Object.keys(row);
        connection
          .prepare(
            `INSERT INTO ${table} (${keys.join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`,
          )
          .run(Object.values(row).map(parameter));
      }
    connection.commit();
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    const outcomes = request.actions.map((action): Outcome => {
      const events: unknown[] = [],
        raw = connection.raw,
        prepare = raw.prepare,
        exec = raw.exec;
      raw.prepare = (sql) => {
        events.push([
          "query",
          sql.trim().replace(/\s+/gu, " "),
          connection.inTransaction,
        ]);
        const statement = prepare.call(raw, sql);
        if (/^(BEGIN|COMMIT|ROLLBACK)\b/iu.test(sql)) {
          const step = statement.step;
          let traced = false;
          statement.step = () => {
            if (!traced) {
              events.push(["transaction", sql, connection.inTransaction]);
              traced = true;
            }
            return step.call(statement);
          };
        }
        return statement;
      };
      raw.exec = (sql) => {
        events.push(["transaction", sql, connection.inTransaction]);
        return exec.call(raw, sql);
      };
      try {
        let value: unknown = null;
        if (action.operation === "register") {
          const calls = { now: 0, uuid: 0, stdin: 0 };
          const hook = (phase: Phase): number => {
            const call = ++calls[phase];
            events.push([phase, call, connection.inTransaction]);
            for (const configured of action.hooks ?? []) {
              if (
                configured.phase !== phase ||
                Number(configured.call ?? 1) !== call
              )
                continue;
              if (configured.sql) connection.prepare(configured.sql).run();
              if (configured.error)
                throw configured.systemExit
                  ? new WorkbenchValidationError(configured.error)
                  : new Error(configured.error);
            }
            return call;
          };
          value = registerCliScan(
            {
              now: () => {
                const call = hook("now");
                return (
                  action.times?.[call - 1] ?? "2026-08-15T12:00:00.123456Z"
                );
              },
              uuid: () => (action.ids ?? [SCAN, WORKSPACE])[hook("uuid") - 1]!,
              stdin: () => {
                hook("stdin");
                return action.stdin ?? "";
              },
            },
            connection,
            action.args,
          );
        } else if (action.operation === "sql")
          connection
            .prepare(action.sql)
            .run((action.parameters ?? []).map(parameter));
        else if (action.operation === "query")
          value = connection
            .prepare(action.sql)
            .all((action.parameters ?? []).map(parameter));
        else if (action.operation === "commit") connection.commit();
        else connection.rollback();
        return {
          value: output(value),
          events,
          inTransaction: connection.inTransaction,
        };
      } catch (error) {
        return {
          error: filesystemErrorMessage(error),
          systemExit:
            error instanceof WorkbenchValidationError ||
            error instanceof TargetInspectionError,
          events,
          inTransaction: connection.inTransaction,
        };
      } finally {
        raw.prepare = prepare;
        raw.exec = exec;
      }
    });
    const snapshot = Object.fromEntries(
      connection
        .prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .all()
        .map((row) => {
          const name = row.get("name") as string;
          return [
            name,
            connection
              .prepare(`SELECT * FROM ${name} ORDER BY rowid`)
              .all()
              .map((row) => output(row)),
          ];
        }),
    ) as Response["snapshot"];
    return { node: process.versions.node, outcomes, snapshot };
  } finally {
    connection.close();
  }
}
const requests = parseJson(readFileSync(0, "utf8")) as unknown as Request[];
process.stdout.write(stringifyJson(requests.map(execute)));
