import { readFileSync } from "node:fs";
import {
  Connection,
  Row,
  type Parameter,
  type SqlValue,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as remediation from "../../../../plugins/codex-security/mcp-app/src/workbench-remediation";
import { requireScan } from "../../../../plugins/codex-security/mcp-app/src/workbench-records";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export const SCAN = "11111111-1111-4111-8111-111111111111";
export const WORKSPACE = "22222222-2222-4222-8222-222222222222";
export const REQUEST = "33333333-3333-4333-8333-333333333333";
export const TOKEN = "44444444-4444-4444-8444-444444444444";
export const OCCURRENCE = "synthetic-occurrence";
export const NOW = 1786795200123456n;
type Values = Record<string, Parameter>;
export type Action = (
  | {
      operation: "available";
      command: string;
      occurrenceId?: string | null;
      scanError?: string;
      scanSql?: string;
    }
  | { operation: "lease"; values?: Values; blobs?: Record<string, string> }
  | { operation: "transition"; current: string; requested: string }
  | {
      operation: "pending";
      current: string;
      requested: string;
      pending: string | null;
    }
  | {
      operation: "cancel";
      args?: Partial<remediation.CancelRemediationArguments>;
    }
  | { operation: "sql"; sql: string; parameters?: Parameter[] }
  | { operation: "commit" | "rollback" }
) & { now?: bigint; nowError?: string; nowSql?: string };
export interface Request {
  scan?: Values;
  occurrences?: Values[];
  attempts?: Values[];
  setupSql?: string[];
  actions: Action[];
}
export interface Outcome {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  inTransaction: boolean;
  events: unknown[];
}
export interface Response {
  outcomes: Outcome[];
  snapshot: Record<string, Record<string, unknown>[]>;
  node: string;
}
const parameter = (value: Parameter): Parameter =>
  value instanceof JsonFloat ? Number(value.source) : value;
function output(value: unknown): unknown {
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
  const insert = (table: string, values: Values) =>
    connection
      .prepare(
        `INSERT INTO ${table} (${Object.keys(values).join(", ")}) VALUES (${Object.keys(
          values,
        )
          .map(() => "?")
          .join(", ")})`,
      )
      .run(Object.values(values).map(parameter));
  try {
    for (const [, , sql] of MIGRATIONS) connection.exec(sql);
    insert("workspaces", {
      id: WORKSPACE,
      created_at: "created",
      updated_at: "updated",
    });
    insert("scans", {
      id: SCAN,
      workspace_id: WORKSPACE,
      target_path: "/target",
      target_revision: "revision",
      scope: ".",
      mode: "standard",
      scan_dir: "/scan",
      status: "complete",
      phase: "reporting",
      started_at: "started",
      created_at: "created",
      updated_at: "updated",
      ...request.scan,
    });
    for (const [index, occurrence] of (request.occurrences ?? [{}]).entries()) {
      const finding = `synthetic-finding-${index}`;
      insert("findings", {
        id: finding,
        fingerprint: finding,
        rule_id: "synthetic-rule",
        identity_anchor: "anchor",
        created_at: "created",
        updated_at: "updated",
      });
      insert("finding_occurrences", {
        id: index ? `${OCCURRENCE}-${index}` : OCCURRENCE,
        finding_id: finding,
        scan_id: SCAN,
        title: "Synthetic finding",
        summary: "Synthetic summary",
        severity: "high",
        confidence: "high",
        remediation: "Synthetic remediation",
        created_at: "created",
        ...occurrence,
      });
    }
    for (const attempt of request.attempts ?? [])
      insert("finding_remediation_attempts", {
        request_id: REQUEST,
        occurrence_id: OCCURRENCE,
        state: "requested",
        version: 1n,
        base_revision: "revision",
        pending_action: "generate",
        pending_action_claim_token: TOKEN,
        pending_action_claimed_at: "2026-08-15T12:00:00Z",
        created_at: "created",
        updated_at: "updated",
        ...attempt,
      });
    connection.commit();
    connection.exec("PRAGMA foreign_keys = ON");
    connection.exec("CREATE TABLE synthetic_audit(value TEXT)");
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
      const now = () => {
        events.push(["now", connection.inTransaction]);
        if (action.nowSql) connection.prepare(action.nowSql).run();
        if (action.nowError) throw new Error(action.nowError);
        return action.now ?? NOW;
      };
      try {
        let value: unknown = null;
        switch (action.operation) {
          case "available":
            remediation.requireRemediationAvailable(
              connection,
              action.command,
              action.occurrenceId === undefined
                ? OCCURRENCE
                : action.occurrenceId,
              (db, id) => {
                events.push(["scan", id, connection.inTransaction]);
                if (action.scanSql) db.prepare(action.scanSql).run();
                if (action.scanError) throw new Error(action.scanError);
                return requireScan(db, id);
              },
            );
            break;
          case "lease": {
            const values: Values = {
              pending_action_claim_token: TOKEN,
              pending_action_delivered_at: null,
              pending_action_claimed_at: "2026-08-15T12:00:00Z",
              ...action.values,
            };
            for (const [key, hex] of Object.entries(action.blobs ?? {}))
              values[key] = Buffer.from(hex, "hex");
            value = remediation.remediationClaimIsActive(
              new Row(
                Object.keys(values),
                Object.values(values).map(parameter) as SqlValue[],
              ),
              now,
            );
            break;
          }
          case "transition":
            remediation.requireRemediationTransition(
              action.current,
              action.requested,
            );
            break;
          case "pending":
            remediation.requireRemediationPendingAction(
              new Row(
                ["state", "pending_action"],
                [action.current, action.pending],
              ),
              action.requested,
            );
            break;
          case "cancel":
            value = remediation.cancelFindingRemediationRequest(
              connection,
              {
                occurrenceId: OCCURRENCE,
                requestId: REQUEST,
                actionToken: TOKEN,
                ...action.args,
              },
              now,
            );
            break;
          case "sql":
            connection
              .prepare(action.sql)
              .run(action.parameters?.map(parameter));
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
        }
        return { value, events, inTransaction: connection.inTransaction };
      } catch (error) {
        return {
          error: filesystemErrorMessage(error),
          systemExit: error instanceof WorkbenchValidationError,
          events,
          inTransaction: connection.inTransaction,
        };
      } finally {
        raw.prepare = prepare;
        raw.exec = exec;
      }
    });
    return {
      node: process.versions.node,
      outcomes,
      snapshot: Object.fromEntries(
        [
          "scans",
          "finding_occurrences",
          "finding_remediation_attempts",
          "synthetic_audit",
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
