import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as remediation from "../../../../plugins/codex-security/mcp-app/src/workbench-remediation-requests";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import { scanTargetIdentity } from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import { timestamp } from "../../../../plugins/codex-security/mcp-app/src/helpers/utc-timestamp";
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
type Phase = "now" | "microseconds" | "stale" | "patch" | "checkout" | "render";
export type Action = (
  | { operation: "open"; occurrenceId?: string }
  | {
      operation: "request" | "action" | "claim" | "deliver" | "release";
      args?: Partial<remediation.RemediationActionArguments>;
    }
  | { operation: "sql"; sql: string; parameters?: Parameter[] }
  | { operation: "commit" | "rollback" }
) & {
  now?: bigint;
  hooks?: Partial<
    Record<Phase, { sql?: string; error?: string; systemExit?: boolean }>
  >;
};
export interface Request {
  targetPath: string;
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
      target_path: request.targetPath,
      target_inode: scanTargetIdentity(request.targetPath, {
        headRevision: "unversioned",
      })[3],
      target_revision: "unversioned",
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
        base_revision: "unversioned",
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
      const hook = (phase: Phase) => {
        const configured = action.hooks?.[phase];
        if (configured?.sql) connection.prepare(configured.sql).run();
        if (configured?.error)
          throw configured.systemExit
            ? new WorkbenchValidationError(configured.error)
            : new Error(configured.error);
      };
      const context: remediation.WorkbenchRemediationRequestContext = {
        now() {
          events.push(["now", connection.inTransaction]);
          hook("now");
          return timestamp(action.now ?? NOW).replace("+00:00", "Z");
        },
        nowMicroseconds() {
          events.push(["microseconds", connection.inTransaction]);
          hook("microseconds");
          return action.now ?? NOW;
        },
        staleClaimBefore(...seconds: [] | [bigint]) {
          events.push(["stale", seconds, connection.inTransaction]);
          hook("stale");
          return timestamp(
            (action.now ?? NOW) - (seconds[0] ?? 120n) * 1_000_000n,
          ).replace("+00:00", "Z");
        },
        scanContext(db, id) {
          events.push(["render", id, db.inTransaction]);
          hook("render");
          return {
            scanId: id,
            attempts: db
              .prepare(
                "SELECT request_id, state, version, pending_action FROM finding_remediation_attempts ORDER BY rowid",
              )
              .all()
              .map((row) => row.toObject()),
          };
        },
        requireMatchingPatchDigest(scan, path, digest) {
          events.push([
            "patch",
            scan.get("id"),
            path,
            digest,
            connection.inTransaction,
          ]);
          hook("patch");
        },
        requireRemediationCheckoutUnchanged(scan, current, options) {
          events.push([
            "checkout",
            scan.get("id"),
            current.get("request_id"),
            options,
            connection.inTransaction,
          ]);
          hook("checkout");
        },
      };
      try {
        let value: unknown = null;
        switch (action.operation) {
          case "open":
            remediation.requireFindingOpen(
              connection,
              action.occurrenceId ?? OCCURRENCE,
            );
            break;
          case "sql":
            connection
              .prepare(action.sql)
              .run((action.parameters ?? []).map(parameter));
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
          default: {
            const args = {
              occurrenceId: OCCURRENCE,
              requestId: REQUEST,
              actionToken: TOKEN,
              action: "apply",
              expectedVersion: 1n,
              ...action.args,
            };
            switch (action.operation) {
              case "request":
                value = remediation.requestFindingRemediation(
                  context,
                  connection,
                  args,
                );
                break;
              case "action":
                value = remediation.requestFindingRemediationAction(
                  context,
                  connection,
                  args,
                );
                break;
              case "claim":
                value = remediation.claimFindingRemediationResend(
                  context,
                  connection,
                  args,
                );
                break;
              case "deliver":
                value = remediation.markFindingRemediationDelivered(
                  context,
                  connection,
                  args,
                );
                break;
              case "release":
                value = remediation.releaseFindingRemediationClaim(
                  context,
                  connection,
                  args,
                );
                break;
            }
          }
        }
        return { value, events, inTransaction: connection.inTransaction };
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
    return {
      node: process.versions.node,
      outcomes,
      snapshot: Object.fromEntries(
        [
          "scans",
          "finding_occurrences",
          "finding_triage",
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
