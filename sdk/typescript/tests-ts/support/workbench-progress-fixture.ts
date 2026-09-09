import fs from "node:fs";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import * as progress from "../../../../plugins/codex-security/mcp-app/src/workbench-progress";
import { requireCurrentCoordinator } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-lease";

const scanId = "12345678-1234-5678-90ab-123456789abc";
const workspaceId = "33333333-3333-4333-8333-333333333333";
type Callback = "stdin" | "now" | "scan" | "workspace" | "context";
export interface Action {
  operation:
    | "progress"
    | "context"
    | "update"
    | "issues"
    | "issueText"
    | "length"
    | "reportable"
    | "lease"
    | "commit"
    | "rollback";
  args?: Record<string, unknown>;
  value?: unknown;
  maximum?: number;
  label?: string;
  stdin?: string;
  failAt?: Callback;
  writeAt?: Callback;
  afterReadSql?: string;
  beginExisting?: boolean;
}
export interface Request {
  scan?: Record<string, unknown>;
  workspace?: Record<string, unknown>;
  progress?: Record<string, unknown>;
  coordinator?: Record<string, unknown>;
  setupSql?: string[];
  actions: Action[];
}
export interface Snapshot {
  scans: Record<string, unknown>[];
  progress: Record<string, unknown>[];
  workspaces: Record<string, unknown>[];
  coordinators: Record<string, unknown>[];
  audit: Record<string, unknown>[];
}
export interface Outcome {
  result?: unknown;
  error?: string;
  kind?: string;
  events: { event: string; inTransaction: boolean; id?: string }[];
  inTransaction: boolean;
  snapshot: Snapshot;
}
export interface Response {
  outcomes: Outcome[];
  snapshot: Snapshot;
  node: string;
}

const schema = `
CREATE TABLE workspaces (id TEXT PRIMARY KEY, thread_id TEXT, user_context TEXT, updated_at TEXT);
CREATE TABLE scans (
  id TEXT PRIMARY KEY, workspace_id TEXT, status TEXT, canceled_at TEXT, mode TEXT,
  phase TEXT, handoff_status TEXT, handoff_claim_token TEXT, continuation_thread_id TEXT,
  user_context TEXT, model TEXT, reasoning_effort TEXT, updated_at TEXT
);
CREATE TABLE scan_progress (
  scan_id TEXT PRIMARY KEY,
  review_items_total INTEGER NOT NULL CHECK (review_items_total >= 0),
  review_items_completed INTEGER NOT NULL CHECK (review_items_completed >= 0 AND review_items_completed <= review_items_total),
  reportable_findings_count INTEGER NOT NULL CHECK (reportable_findings_count >= 0),
  deep_review_pass INTEGER CHECK (deep_review_pass IS NULL OR deep_review_pass >= 1),
  phase_items_total INTEGER NOT NULL CHECK (phase_items_total >= 0),
  phase_items_completed INTEGER NOT NULL CHECK (phase_items_completed >= 0 AND phase_items_completed <= phase_items_total),
  phase_progress_unit TEXT CHECK (phase_progress_unit IS NULL OR phase_progress_unit IN ('checks', 'threat_surfaces', 'review_receipts', 'candidate_findings', 'validated_findings', 'report_artifacts')),
  preflight_issues_json TEXT NOT NULL,
  preflight_checks_total INTEGER NOT NULL CHECK (preflight_checks_total >= 0),
  preflight_checks_completed INTEGER NOT NULL CHECK (preflight_checks_completed >= 0 AND preflight_checks_completed <= preflight_checks_total),
  updated_at TEXT
);
CREATE TABLE deep_scan_runs (scan_id TEXT PRIMARY KEY, status TEXT, coordinator_generation INTEGER);
CREATE TABLE audit (event TEXT);
`;

function run(request: Request): Response {
  const connection = new Connection(sqliteBinding(), ":memory:");
  const all = (table: string) =>
    connection
      .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
      .all()
      .map((row) => row.toObject());
  const snapshot = (): Snapshot => ({
    scans: all("scans"),
    progress: all("scan_progress"),
    workspaces: all("workspaces"),
    coordinators: all("deep_scan_runs"),
    audit: all("audit"),
  });
  const insert = (table: string, values: Record<string, unknown>) =>
    connection
      .prepare(
        `INSERT INTO ${table} (${Object.keys(values).join(", ")}) VALUES (${Object.keys(
          values,
        )
          .map(() => "?")
          .join(", ")})`,
      )
      .run(Object.values(values) as Parameter[]);
  try {
    connection.exec(schema);
    insert("workspaces", {
      id: workspaceId,
      thread_id: "workspace-thread",
      user_context: "saved",
      updated_at: "original",
      ...request.workspace,
    });
    insert("scans", {
      id: scanId,
      workspace_id: workspaceId,
      status: "running",
      canceled_at: null,
      mode: "standard",
      phase: "preflight",
      handoff_status: "delivered",
      handoff_claim_token: null,
      continuation_thread_id: null,
      user_context: "scan context",
      model: "original-model",
      reasoning_effort: "original-effort",
      updated_at: "original",
      ...request.scan,
    });
    insert("scan_progress", {
      scan_id: scanId,
      review_items_total: 0n,
      review_items_completed: 0n,
      reportable_findings_count: 8n,
      deep_review_pass: null,
      phase_items_total: 0n,
      phase_items_completed: 0n,
      phase_progress_unit: null,
      preflight_issues_json: "[]",
      preflight_checks_total: 0n,
      preflight_checks_completed: 0n,
      updated_at: "original",
      ...request.progress,
    });
    if (request.coordinator)
      insert("deep_scan_runs", {
        scan_id: scanId,
        status: "running",
        coordinator_generation: 1n,
        ...request.coordinator,
      });
    connection.commit();
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    let events: Outcome["events"] = [];
    const execute = connection.raw.exec.bind(connection.raw);
    connection.raw.exec = (sql) => {
      if (/^(?:BEGIN|COMMIT|ROLLBACK)\b/iu.test(sql))
        events.push({
          event: sql.trim().toUpperCase(),
          inTransaction: connection.inTransaction,
        });
      execute(sql);
    };
    const outcomes = request.actions.map((action): Outcome => {
      events = [];
      if (action.beginExisting) {
        connection.exec("BEGIN");
        connection.prepare("INSERT INTO audit VALUES ('existing')").run();
      }
      const callback = (event: Callback, id?: string) => {
        events.push({
          event,
          inTransaction: connection.inTransaction,
          ...(id === undefined ? {} : { id }),
        });
        if (action.writeAt === event)
          connection.prepare("INSERT INTO audit VALUES (?)").run([event]);
        if (action.failAt === event) throw new Error(`${event} failed`);
      };
      const callbacks = {
        now: () => {
          callback("now");
          return "2026-01-02T00:00:00Z";
        },
        readStdin: () => {
          callback("stdin");
          return action.stdin ?? " input context ";
        },
        requireScan: (c: Connection, id: string) => {
          callback("scan", id);
          const row = c.prepare("SELECT * FROM scans WHERE id = ?").get([id]);
          if (row === undefined) throw new Error("scan not found");
          if (action.afterReadSql) c.prepare(action.afterReadSql).run();
          return row;
        },
        requireWorkspace: (c: Connection, id: string) => {
          callback("workspace", id);
          const row = c
            .prepare("SELECT * FROM workspaces WHERE id = ?")
            .get([id]);
          if (row === undefined) throw new Error("workspace not found");
          return row;
        },
        scanContext: (_c: Connection, id: string) => {
          callback("context", id);
          return {
            scanId: id,
            ...snapshot(),
            inTransaction: connection.inTransaction,
          };
        },
      };
      const args = {
        scanId,
        workspaceId,
        threadId: null,
        claimToken: null,
        userContext: " replacement ",
        userContextStdin: false,
        model: null,
        reasoningEffort: null,
        preflightIssuesJson: null,
        preflightIssuesJsonStdin: false,
        coordinatorGeneration: null,
        deepReviewPass: null,
        phase: null,
        phaseItemsTotal: null,
        phaseItemsCompleted: null,
        phaseProgressUnit: null,
        reviewItemsTotal: null,
        reviewItemsCompleted: null,
        reportableFindingsCount: null,
        command: "update-progress",
        ...action.args,
      } as progress.ContextArguments &
        progress.ProgressArguments & { command: string };
      const invoke = () => {
        switch (action.operation) {
          case "context":
            return progress.updateContext(connection, args, callbacks);
          case "progress":
            return progress.updateProgress(connection, args, callbacks);
          case "update":
            return progress.update(connection, args, callbacks);
          case "issues":
            return progress.preflightIssuesJson(action.value as string | null);
          case "issueText":
            return progress.preflightIssueText(
              action.value,
              Number(action.maximum),
              action.label ?? "test",
            );
          case "length":
            return progress.javascriptStringLength(action.value as string);
          case "reportable":
            return progress.reportableCount(
              action.args!["currentPhase"] as string,
              args.phase,
              args.reportableFindingsCount,
            );
          case "lease":
            return requireCurrentCoordinator(
              connection.prepare("SELECT * FROM deep_scan_runs").get()!,
              args,
            );
          case "commit":
            return connection.commit();
          case "rollback":
            return connection.rollback();
        }
      };
      let result: Pick<Outcome, "result" | "error" | "kind">;
      try {
        result = { result: invoke() ?? null };
      } catch (error) {
        result = {
          error: (error as Error).message,
          kind:
            typeof (error as { sqliteErrorCode?: number }).sqliteErrorCode ===
            "number"
              ? "SqliteError"
              : (error as Error).constructor.name,
        };
      }
      return {
        ...result,
        events: [...events],
        inTransaction: connection.inTransaction,
        snapshot: snapshot(),
      };
    });
    return { outcomes, snapshot: snapshot(), node: process.versions.node };
  } finally {
    connection.close();
  }
}

process.stdout.write(
  stringifyJson((parseJson(fs.readFileSync(0, "utf8")) as Request[]).map(run)),
);
