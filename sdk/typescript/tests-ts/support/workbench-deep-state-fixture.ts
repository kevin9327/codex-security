import { readFileSync } from "node:fs";
import {
  Connection,
  Row,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as deep from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-state";
import * as terminal from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-terminal";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import {
  windowsFileSystem,
  widePath,
} from "../../../../plugins/codex-security/native/windows-files.mjs";
import { WindowsScanModel } from "./windows-scan-model";

export const scanId = "11111111-1111-4111-8111-111111111111";
export const workspaceId = "22222222-2222-4222-8222-222222222222";
export const workerId = "33333333-3333-4333-8333-333333333333";
export interface Action {
  operation:
    | "state"
    | "result"
    | "progress"
    | "run"
    | "worker"
    | "owned"
    | "running"
    | "ready"
    | "ensure"
    | "existing"
    | "terminal"
    | "transition"
    | "bounded"
    | "error"
    | "sql"
    | "commit"
    | "rollback"
    | "clearPublicationFailure"
    | "failFromParent"
    | "cancelFromParent"
    | "cancelWorkers"
    | "windowsSize"
    | "others";
  id?: string;
  threadId?: string;
  target?: string;
  scope?: string;
  revision?: string;
  digest?: string;
  device?: bigint | string;
  inode?: bigint | string;
  current?: string;
  requested?: string;
  message?: string;
  timestamp?: string;
  nowError?: boolean;
  maximum?: number;
  original?: Parameter;
  publication?: Parameter;
  sql?: string;
  parameters?: Parameter[];
  config?: deep.DeepScanRunConfig;
  disposition?: string | null;
  canonical?: Record<string, string>;
  canonicalError?: boolean;
  canonicalSql?: string;
  deadline?: boolean;
  deadlineError?: boolean;
  deadlineSql?: string;
  row?: Record<string, Parameter>;
  windowsError?: number;
  windowsDirectory?: boolean;
  windowsType?: number;
}
export interface Request {
  workspace?: Record<string, Parameter>;
  scan?: Record<string, Parameter>;
  run?: Record<string, Parameter> | null;
  workers?: Record<string, Parameter>[];
  inputs?: Record<string, Parameter>[];
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
function materialize(value: unknown): unknown {
  if (value instanceof Row) return materialize(value.toObject());
  if (typeof value === "number") return new JsonFloat(String(value));
  if (Array.isArray(value)) return value.map(materialize);
  if (
    value !== null &&
    typeof value === "object" &&
    !(value instanceof JsonFloat)
  )
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, materialize(item)]),
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
      updated_at: "updated",
      ...request.workspace,
    });
    insert("scans", {
      id: scanId,
      workspace_id: workspaceId,
      target_path: "/target",
      target_revision: "revision",
      target_snapshot_digest: "digest",
      target_device: 10n,
      target_inode: 20n,
      scope: ".",
      mode: "deep",
      scan_dir: "/scan",
      status: "running",
      phase: "discovery",
      handoff_status: "delivered",
      started_at: "started",
      created_at: "created",
      updated_at: "updated",
      ...request.scan,
    });
    if (request.run !== null)
      insert("deep_scan_runs", {
        scan_id: scanId,
        schema_version: 1n,
        workflow_version: "deep-security-scan/v1",
        status: "running",
        phase: "discovery",
        workers: 4n,
        subagents: 1n,
        stop_after_no_new: 3n,
        stop_after_consecutive_errors: 3n,
        max_discovery_runs: 40n,
        max_time_hours: 2,
        created_at: "created",
        updated_at: "updated",
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
        created_at: "created",
        updated_at: "updated",
        ...worker,
      });
    for (const input of request.inputs ?? [])
      insert("deep_scan_dedup_inputs", { scan_id: scanId, ...input });
    connection.commit();
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    connection.commit();
    const outcomes = request.actions.map((action): Outcome => {
      const events: unknown[] = [],
        raw = connection.raw,
        originalPrepare = raw.prepare,
        originalExec = raw.exec;
      raw.prepare = (sql) => {
        events.push([
          "query",
          sql.trim().replace(/\s+/gu, " "),
          connection.inTransaction,
        ]);
        return originalPrepare.call(raw, sql);
      };
      raw.exec = (sql) => {
        events.push(["transaction", sql, connection.inTransaction]);
        return originalExec.call(raw, sql);
      };
      const callbacks: deep.DeepScanStateCallbacks = {
        canonicalDiscoveryArtifacts: () => {
          events.push(["canonical", connection.inTransaction]);
          if (action.canonicalSql)
            connection.prepare(action.canonicalSql).run();
          if (action.canonicalError)
            throw new WorkbenchValidationError("canonical failed");
          return action.canonical ?? { candidateLedgerPath: "/ledger" };
        },
        deepScanDeadlineReached: () => {
          events.push(["deadline", connection.inTransaction]);
          if (action.deadlineSql) connection.prepare(action.deadlineSql).run();
          if (action.deadlineError) throw new Error("deadline failed");
          return action.deadline ?? false;
        },
      };
      const id = action.id ?? scanId;
      const scan = () =>
        action.row
          ? new Row(
              Object.keys(action.row),
              Object.values(action.row) as Row["values"],
            )
          : connection.prepare("SELECT * FROM scans WHERE id = ?").get([id])!;
      try {
        let result: unknown = null;
        switch (action.operation) {
          case "sql":
            connection.prepare(action.sql!).run(action.parameters);
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
          case "clearPublicationFailure":
            terminal.clearDeepScanPublicationFailure(connection, id, () => {
              events.push(["now", connection.inTransaction]);
              if (action.nowError) throw new Error("clock failed");
              return action.timestamp ?? "timestamp";
            });
            break;
          case "failFromParent":
            terminal.failFromParentScan(
              connection,
              id,
              action.message ?? null,
              action.timestamp ?? "timestamp",
            );
            break;
          case "cancelFromParent":
            terminal.cancelFromParentScan(
              connection,
              id,
              action.timestamp ?? "timestamp",
            );
            break;
          case "cancelWorkers":
            terminal.cancelActiveWorkers(
              connection,
              id,
              action.timestamp ?? "timestamp",
            );
            break;
          case "bounded":
            result = deep.boundedErrorText(
              action.message!,
              Number(action.maximum),
            );
            break;
          case "error":
            result = deep.deepScanError(
              new Row(["error_message", "publication_error_message"], [
                action.original ?? null,
                action.publication ?? null,
              ] as Row["values"]),
            );
            break;
          case "transition":
            deep.requireWorkerTransition(action.current!, action.requested!);
            break;
          case "run":
            result = deep.requireDeepScanRun(connection, id);
            break;
          case "worker":
            result = deep.requireDeepScanWorker(
              connection,
              action.id ?? workerId,
            );
            break;
          case "owned":
            result = deep.requireOwnedScan(
              connection,
              id,
              action.threadId ?? "owner",
            );
            break;
          case "running":
            result = deep.requireRunningDeepScan(connection, id);
            break;
          case "ready":
            deep.requireDeepScanReadyForParentCompletion(connection, scan());
            break;
          case "state":
            result = deep.deepScanState(connection, id, callbacks);
            break;
          case "result":
            result = deep.deepScanResult(
              connection,
              id,
              callbacks,
              action.disposition,
            );
            break;
          case "others":
            result = deep.otherRunningDeepScans(connection, id);
            break;
          case "progress":
            result = deep.independentReviewProgress(connection, id);
            break;
          case "ensure":
            result = deep.ensureDeepScanRun(
              connection,
              scan(),
              action.config ?? {
                workers: 4n,
                subagents: 1n,
                stopAfterNoNew: 3n,
                stopAfterConsecutiveErrors: 3n,
                maxDiscoveryRuns: 40n,
                maxTimeHours: 2,
              },
              "new-workflow",
              "timestamp",
            );
            break;
          case "existing":
            result =
              deep.existingDeepScanForTarget(
                connection,
                action.threadId ?? "owner",
                action.target ?? "/target",
                action.scope ?? ".",
              ) ?? null;
            break;
          case "terminal":
            result =
              deep.terminalDeepScanForTargetSnapshot(
                connection,
                action.threadId ?? "next-owner",
                action.target ?? "/target",
                action.scope ?? ".",
                action.revision ?? "revision",
                action.digest ?? "digest",
                action.device ?? 10n,
                action.inode ?? 20n,
              ) ?? null;
            break;
          case "windowsSize": {
            const model = new WindowsScanModel();
            model.add(
              "C:\\work\\ledger",
              action.windowsDirectory ?? false,
              Buffer.from(action.message ?? ""),
            );
            const native = model.native,
              open = native.openWindowsFile;
            if (action.windowsError || action.windowsType !== undefined)
              native.openWindowsFile = (...args) => {
                const opened = open(...args);
                if (opened.handle) {
                  opened.handle.size = () => ({
                    error: Number(action.windowsError ?? 0),
                    value: "0",
                  });
                  if (action.windowsType !== undefined)
                    opened.handle.fileType = () => ({
                      error: 0,
                      value: Number(action.windowsType),
                    });
                }
                return opened;
              };
            try {
              const info = windowsFileSystem(native).stat(
                widePath("C:\\work\\ledger"),
              );
              result = { size: info.size, file: info.isFile() };
            } finally {
              events.push(...model.events, [
                "closed",
                model.held.every((item) => item.closed),
              ]);
            }
            break;
          }
        }
        return {
          result: materialize(result),
          inTransaction: connection.inTransaction,
          events,
        };
      } catch (error) {
        return {
          error:
            action.operation === "windowsSize"
              ? (error as Error).message
              : filesystemErrorMessage(error),
          systemExit: error instanceof WorkbenchValidationError,
          inTransaction: connection.inTransaction,
          events,
        };
      } finally {
        raw.prepare = originalPrepare;
        raw.exec = originalExec;
      }
    });
    return {
      outcomes,
      snapshot: Object.fromEntries(
        [
          "workspaces",
          "scans",
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
    materialize(
      (input(parseJson(readFileSync(0, "utf8"))) as Request[]).map(execute),
    ),
    { compact: true, sortKeys: true },
  ),
);
