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
import * as results from "../../../../plugins/codex-security/mcp-app/src/workbench-results";
import * as findingResults from "../../../../plugins/codex-security/mcp-app/src/workbench-finding-results";
import { scanTargetIdentity } from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import {
  findingOccurrenceConditions,
  findingOccurrenceRows,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-history";
import { requireScan } from "../../../../plugins/codex-security/mcp-app/src/workbench-records";
import {
  requireOccurrence,
  WorkbenchValidationError,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodeFilename } from "../../../../plugins/codex-security/mcp-app/src/workbench-git";

export const scanId = "11111111-1111-4111-8111-111111111111";
export const workspaceId = "22222222-2222-4222-8222-222222222222";
export type Callback =
  | "backfill"
  | "artifact"
  | "finding"
  | "remediation"
  | "recovery";
export interface Action {
  operation:
    | "scan"
    | "context"
    | "workspace"
    | "list"
    | "conditions"
    | "rows"
    | "kinds"
    | "paths"
    | "contract"
    | "coverage"
    | "triage"
    | "updated"
    | "finding"
    | "remediation"
    | "availability"
    | "details"
    | "sql"
    | "query"
    | "commit"
    | "rollback";
  id?: string;
  occurrenceId?: string | null;
  options?: {
    resultScanId?: string | null;
    resultScan?: Record<string, unknown> | null;
    threadId?: string | null;
  };
  query?: string | null;
  severity?: string | null;
  status?: string | null;
  limit?: bigint;
  offset?: bigint;
  row?: Record<string, Parameter>;
  sql?: string;
  parameters?: Parameter[];
  fail?: Callback;
  callbackSql?: Partial<Record<Callback, string>>;
  artifacts?: Record<string, string | null>;
  remediation?: [boolean, string | null];
  recovery?: boolean;
  git?: { stdout?: string; stderr?: string; status?: number }[];
  value?: unknown;
  valueBytes?: string;
  related?: Record<string, unknown>[];
}
export interface Request {
  targetIdentityPath?: string;
  workspace?: Record<string, Parameter>;
  scan?: Record<string, Parameter>;
  progress?: Record<string, Parameter> | null;
  records?: Record<string, Record<string, Parameter>[]>;
  setupSql?: string[];
  actions: Action[];
}
export interface Outcome {
  result?: unknown;
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
      user_context: "workspace context",
      ...request.workspace,
    });
    const identity =
      request.targetIdentityPath === undefined
        ? undefined
        : scanTargetIdentity(request.targetIdentityPath, {
            headRevision: "revision",
          });
    insert("scans", {
      id: scanId,
      workspace_id: workspaceId,
      target_path: "/target",
      target_revision: "revision",
      scope: ".",
      mode: "standard",
      scan_dir: "/scan",
      status: "running",
      phase: "discovery",
      started_at: "started",
      created_at: "created",
      updated_at: "scan-updated",
      user_context: "scan context",
      ...(identity === undefined
        ? {}
        : {
            target_path: request.targetIdentityPath,
            target_device: identity[2],
            target_inode: identity[3],
          }),
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
        return prepare.call(raw, sql);
      };
      raw.exec = (sql) => {
        events.push(["transaction", sql, connection.inTransaction]);
        return exec.call(raw, sql);
      };
      const native = processBinding(),
        process = native.rawProcess;
      let probe = 0;
      if (action.git)
        native.rawProcess = (options) => {
          events.push([
            "git",
            options.args.map((arg) =>
              globalThis.process.platform === "win32"
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
      const callback = (name: Callback, args: unknown[]) => {
        events.push([name, ...args, connection.inTransaction]);
        const sql = action.callbackSql?.[name];
        if (sql) connection.prepare(sql).run();
        if (action.fail === name)
          throw new WorkbenchValidationError(`${name} failed`);
      };
      const callbacks: results.ResultCallbacks = {
        backfillFindingDetails: (_db, scan) =>
          callback("backfill", [scan.get("id")]),
        availableArtifactPath: (directory, candidate) => {
          callback("artifact", [directory, candidate]);
          return action.artifacts?.[candidate] ?? null;
        },
        findingResult: (_db, scan, occurrence, related) => {
          callback("finding", [
            scan.get("id"),
            occurrence.get("id"),
            occurrence.columns,
            related,
          ]);
          return { ...occurrence.toObject(), scanId: scan.get("id"), related };
        },
        remediationAvailability: (scan) => {
          callback("remediation", [scan.get("id")]);
          return action.remediation ?? [false, "not available"];
        },
        scanResultsRecoveryNeeded: (_db, scan) => {
          callback("recovery", [scan.get("id")]);
          return action.recovery ?? false;
        },
      };
      const id = action.id ?? scanId;
      const scan = () =>
        action.row
          ? new Row(
              Object.keys(action.row),
              Object.values(action.row) as Row["values"],
            )
          : requireScan(connection, id);
      try {
        let result: unknown = null;
        switch (action.operation) {
          case "details":
            result = findingResults.readFindingDetails(
              action.valueBytes === undefined
                ? action.value
                : Buffer.from(action.valueBytes, "base64"),
            );
            break;
          case "availability":
            result = findingResults.remediationAvailability(scan());
            break;
          case "remediation":
            result = findingResults.findingRemediationResult(
              connection,
              action.occurrenceId ?? "unknown",
            );
            break;
          case "finding":
            result = findingResults.findingResult(
              connection,
              scan(),
              requireOccurrence(connection, action.occurrenceId ?? "unknown"),
              action.related ?? [],
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
          case "workspace":
            result = results.workspaceState(
              connection,
              action.id ?? workspaceId,
              callbacks,
              action.options,
            );
            break;
          case "context":
            result = results.scanContext(
              connection,
              id,
              callbacks,
              action.occurrenceId,
            );
            break;
          case "scan":
            result = results.scanResult(
              connection,
              scan(),
              callbacks,
              action.occurrenceId,
            );
            break;
          case "list":
            result = results.listFindings(
              connection,
              {
                ...action,
                scanId: id,
                limit: action.limit ?? 20n,
                offset: action.offset ?? 0n,
              },
              callbacks,
            );
            break;
          case "rows":
            result = findingOccurrenceRows(connection, id, {
              ...action,
              limit: action.limit ?? 20n,
              offset: action.offset ?? 0n,
            });
            break;
          case "conditions":
            result = findingOccurrenceConditions(id, action);
            break;
          case "kinds":
            result = results.expectedTargetKinds(scan());
            break;
          case "paths":
            result = results.requestedScanPaths(scan());
            break;
          case "contract":
            result = results.scanContract(scan());
            break;
          case "coverage":
            result = results.expectedCoverageMode(scan());
            break;
          case "triage":
            result = results.findingTriageResult(
              connection,
              action.occurrenceId ?? "unknown",
            );
            break;
          case "updated":
            result = results.findingManagementUpdatedAt(connection, id);
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
            error instanceof TargetInspectionError,
          inTransaction: connection.inTransaction,
          events,
        };
      } finally {
        raw.prepare = prepare;
        raw.exec = exec;
        native.rawProcess = process;
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
