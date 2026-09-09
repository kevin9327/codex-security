import fs from "node:fs";
import { Connection } from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { stringifyJson } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import * as handoff from "../../../../plugins/codex-security/mcp-app/src/workbench-handoff";

export const SCAN_ID = "12345678-1234-5678-90ab-123456789abc";
export const FIRST_TOKEN = "11111111-1111-4111-8111-111111111111";
export const SECOND_TOKEN = "22222222-2222-4222-8222-222222222222";
const timestamp = "2026-01-02T00:00:00Z";
const staleBefore = "2026-01-01T23:00:00Z";
type Callback = "now" | "scan" | "stale" | "workspace" | "state";
export interface Action {
  operation:
    | "claim"
    | "release"
    | "attach"
    | "deliver"
    | "current"
    | "token"
    | "thread"
    | "commit"
    | "rollback";
  scanId?: string;
  claimToken?: string | null;
  threadId?: string | null;
  owningThreadId?: string | null;
  takeOverStale?: boolean;
  now?: string;
  staleBefore?: string;
  failAt?: Callback;
  writeAt?: Callback;
  afterReadSql?: string;
  beginExisting?: boolean;
}
export interface Request {
  scan?: Record<string, string | null>;
  workspaceThread?: string | null;
  setupSql?: string[];
  actions: Action[];
  database?: string;
  initialize?: boolean;
}
export interface Snapshot {
  scans: Record<string, unknown>[];
  progress: Record<string, unknown>[];
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
CREATE TABLE workspaces (id TEXT PRIMARY KEY, thread_id TEXT);
CREATE TABLE scans (
  id TEXT PRIMARY KEY, workspace_id TEXT, mode TEXT, handoff_status TEXT,
  handoff_claim_token TEXT, handoff_claimed_at TEXT, continuation_thread_id TEXT,
  deep_scan_owner_thread_id TEXT, updated_at TEXT
);
CREATE TABLE scan_progress (
  scan_id TEXT PRIMARY KEY, phase_items_total INTEGER, phase_items_completed INTEGER,
  phase_progress_unit TEXT, preflight_checks_total INTEGER,
  preflight_checks_completed INTEGER, updated_at TEXT
);
CREATE TABLE audit (event TEXT);
`;

function run(request: Request): Response {
  const connection = new Connection(
    sqliteBinding(),
    request.database ?? ":memory:",
  );
  const snapshot = (): Snapshot => ({
    scans: connection
      .prepare("SELECT * FROM scans ORDER BY id")
      .all()
      .map((row) => row.toObject()),
    progress: connection
      .prepare("SELECT * FROM scan_progress ORDER BY scan_id")
      .all()
      .map((row) => row.toObject()),
    audit: connection
      .prepare("SELECT * FROM audit ORDER BY rowid")
      .all()
      .map((row) => row.toObject()),
  });
  try {
    if (request.initialize !== false) {
      connection.exec(schema);
      connection
        .prepare("INSERT INTO workspaces VALUES (?, ?)")
        .run([
          "workspace",
          request.workspaceThread === undefined
            ? "workspace-thread"
            : request.workspaceThread,
        ]);
      const scan = {
        id: SCAN_ID,
        workspace_id: "workspace",
        mode: "standard",
        handoff_status: "pending",
        handoff_claim_token: null,
        handoff_claimed_at: null,
        continuation_thread_id: null,
        deep_scan_owner_thread_id: null,
        updated_at: "original",
        ...request.scan,
      };
      connection
        .prepare(
          `INSERT INTO scans (${Object.keys(scan).join(", ")}) VALUES (${Object.keys(
            scan,
          )
            .map(() => "?")
            .join(", ")})`,
        )
        .run(Object.values(scan));
      connection
        .prepare(
          "INSERT INTO scan_progress VALUES (?, 9, 4, 'files', 7, 3, 'original')",
        )
        .run([SCAN_ID]);
      connection.commit();
      for (const sql of request.setupSql ?? []) connection.exec(sql);
    }
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
          return action.now ?? timestamp;
        },
        requireScan: (c: Connection, id: string) => {
          callback("scan", id);
          const row = c.prepare("SELECT * FROM scans WHERE id = ?").get([id]);
          if (row === undefined) throw new Error("scan not found");
          if (action.afterReadSql) c.prepare(action.afterReadSql).run();
          return row;
        },
        staleClaimBefore: () => {
          callback("stale");
          return action.staleBefore ?? staleBefore;
        },
        requireWorkspace: (c: Connection, id: string) => {
          callback("workspace", id);
          const row = c
            .prepare("SELECT * FROM workspaces WHERE id = ?")
            .get([id]);
          if (row === undefined) throw new Error("workspace not found");
          return row;
        },
        workspaceState: (_c: Connection, id: string) => {
          callback("state", id);
          return {
            workspaceId: id,
            ...snapshot(),
            inTransaction: connection.inTransaction,
          };
        },
      };
      const args = {
        scanId: action.scanId ?? SCAN_ID,
        claimToken:
          action.claimToken === undefined ? FIRST_TOKEN : action.claimToken,
        threadId: action.threadId ?? null,
        takeOverStale: action.takeOverStale ?? false,
      };
      const invoke = () => {
        switch (action.operation) {
          case "claim":
            return handoff.claimHandoffDelivery(
              connection,
              { ...args, claimToken: args.claimToken! },
              callbacks,
            );
          case "release":
            return handoff.releaseHandoffDelivery(
              connection,
              { ...args, claimToken: args.claimToken! },
              callbacks,
            );
          case "attach":
            return handoff.attachScanContinuationThread(
              connection,
              { ...args, claimToken: args.claimToken! },
              callbacks,
            );
          case "deliver":
            return handoff.markHandoffDelivered(
              connection,
              { ...args, claimToken: args.claimToken! },
              callbacks,
            );
          case "current":
            return handoff.requireCurrentContinuation(
              connection
                .prepare("SELECT * FROM scans WHERE id = ?")
                .get([SCAN_ID])!,
              args.claimToken,
              { errorMessage: "continuation rejected" },
            );
          case "token":
            return handoff.requireHandoffClaimToken(args.claimToken!);
          case "thread":
            return handoff.validateHandoffDeliveryThread(
              action.owningThreadId ?? null,
              args.threadId!,
              args.claimToken!,
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
  stringifyJson((JSON.parse(fs.readFileSync(0, "utf8")) as Request[]).map(run)),
);
