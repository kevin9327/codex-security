import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  processBinding,
  sqliteBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import { applyMigrations } from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import { decodeFilename } from "../../../../plugins/codex-security/mcp-app/src/workbench-git";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import * as setup from "../../../../plugins/codex-security/mcp-app/src/workbench-setup";
import {
  requireUuid,
  WorkbenchValidationError,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export type Action = (
  | { kind: "sql" | "query"; sql: string; parameters?: Parameter[] }
  | { kind: "commitDb" | "rollbackDb" }
  | {
      kind: "target" | "inspectTarget" | "review" | "scannable";
      target: string;
    }
  | { kind: "scope"; scope: string; mode: string; target: string }
  | { kind: "commit"; target: string; revision: string; label: string }
  | { kind: "diff" | "inspect"; args: setup.SetupArguments }
  | { kind: "root"; target: string; scanRoot: string | null }
  | { kind: "summary"; target: setup.DiffTarget }
  | { kind: "create"; args: setup.CreateWorkspaceArguments }
  | { kind: "save"; args: setup.WorkspaceArguments & setup.SetupArguments }
) & {
  git?: { stdout?: string; stderr?: string; status?: number }[];
  stdin?: string;
  stdinError?: boolean;
  stateError?: boolean;
  afterReadSql?: string;
};
export interface Request {
  actions: Action[];
  migrate?: boolean;
}
export interface Response {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  inTransaction: boolean;
  events: unknown[];
}
const native = sqliteBinding();
const connection = new Connection(native, ":memory:");
const request = parseJson(readFileSync(0, "utf8")) as unknown as Request;
try {
  connection.exec("PRAGMA foreign_keys = ON");
  if (request.migrate !== false)
    applyMigrations(native, connection, () => "2026-01-01T00:00:00Z");
  const responses = request.actions.map((action): Response => {
    const events: unknown[] = [];
    const processNative = processBinding(),
      original = processNative.rawProcess;
    let probe = 0;
    if (action.git)
      processNative.rawProcess = (options) => {
        events.push([
          "git",
          options.args.map((arg) =>
            process.platform === "win32"
              ? arg.toString("utf16le")
              : decodeFilename(arg),
          ),
        ]);
        const output = action.git![probe++];
        if (!output) throw new Error("Unexpected Git probe");
        return {
          error: 0,
          returnCode: Number(output.status ?? 0),
          stdout: Buffer.from(output.stdout ?? "", "base64"),
          stderr: Buffer.from(output.stderr ?? "", "base64"),
        };
      };
    const callbacks = {
      now: () => {
        events.push(["now", connection.inTransaction]);
        return "2026-01-02T03:04:05Z";
      },
      readStdin: () => {
        events.push(["stdin", connection.inTransaction]);
        if (action.stdinError) throw new Error("stdin failed");
        return action.stdin ?? "";
      },
      workspaceState: (database: Connection, id: string) => {
        events.push(["state", id, database.inTransaction]);
        if (action.stateError) throw new Error("state failed");
        return database
          .prepare("SELECT * FROM workspaces WHERE id = ?")
          .get([id])!
          .toObject();
      },
      requireWorkspace: (database: Connection, id: string) => {
        events.push(["require", id, database.inTransaction]);
        const uuid = requireUuid(id, "workspace-id");
        const row = database
          .prepare("SELECT * FROM workspaces WHERE id = ?")
          .get([uuid]);
        if (row === undefined)
          throw new WorkbenchValidationError(
            "Codex Security workspace not found. Reopen it to continue.",
          );
        if (action.afterReadSql) {
          database.prepare(action.afterReadSql).run();
          database.commit();
        }
        return row;
      },
    };
    try {
      let value: unknown = null;
      switch (action.kind) {
        case "sql":
          connection.prepare(action.sql).run(action.parameters);
          break;
        case "query":
          value = connection
            .prepare(action.sql)
            .all(action.parameters)
            .map((row) => row.toObject());
          break;
        case "commitDb":
          connection.commit();
          break;
        case "rollbackDb":
          connection.rollback();
          break;
        case "target":
          value = setup.requireTarget(action.target);
          break;
        case "inspectTarget":
          value = setup.inspectTarget(action.target);
          break;
        case "review":
          value = setup.requireReviewChangesTarget(action.target);
          break;
        case "scannable":
          setup.requireScannableTarget(action.target);
          break;
        case "scope":
          value = setup.requireScope(action.scope, action.mode, action.target);
          break;
        case "commit":
          value = setup.resolveGitCommit(
            action.target,
            action.revision,
            action.label,
          );
          break;
        case "diff": {
          const args = action.args;
          value = setup.requireDiffTarget(
            args.targetPath,
            args.diffTargetKind,
            args.diffBaseRevision,
            args.diffHeadRevision,
            args.diffContentDigest,
          );
          break;
        }
        case "inspect":
          value = setup.inspectSetup(action.args);
          break;
        case "root":
          value = setup.scanTargetRoot(action.scanRoot, action.target);
          break;
        case "summary":
          value = setup.diffTargetSummary(action.target);
          break;
        case "create":
          value = setup.createWorkspace(connection, action.args, callbacks);
          break;
        case "save":
          value = setup.saveWorkspace(connection, action.args, callbacks);
          break;
      }
      return { value, inTransaction: connection.inTransaction, events };
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
      processNative.rawProcess = original;
    }
  });
  process.stdout.write(stringifyJson(responses));
} finally {
  connection.close();
}
