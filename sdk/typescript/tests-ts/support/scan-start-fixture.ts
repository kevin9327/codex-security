import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { applyMigrations } from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import { getScanFeedback } from "../../../../plugins/codex-security/mcp-app/src/workbench-feedback";
import {
  getScanRecipe,
  parseScanRecipe,
  setScanThread,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-recipes";
import {
  archiveScan,
  compactTimestamp,
  insertRunningScan,
  safeSegment,
  scanDiffIdentity,
  storedDiffTarget,
  type RunningScan,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-start";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { resolvedPath } from "../../../../plugins/codex-security/mcp-app/src/helpers/resolve-path";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  widePath,
  pathText,
  windowsFileSystem,
} from "../../../../plugins/codex-security/native/windows-files.mjs";
import type { WindowsBinding } from "../../../../plugins/codex-security/native/windows-binding.mjs";

export type Action =
  | { kind: "parseRecipe"; value: string; repository: string }
  | { kind: "getRecipe"; scanId: string }
  | {
      kind: "setThread";
      scanId: string;
      threadId: string;
      now?: string;
      nowSql?: string;
      failNow?: string;
    }
  | { kind: "windowsMkdir"; errors: number[]; recursive?: boolean }
  | { kind: "sql"; sql: string; parameters?: Parameter[] }
  | { kind: "query"; sql: string; parameters?: Parameter[] }
  | { kind: "commit" | "rollback" }
  | { kind: "feedback"; scanId: string }
  | {
      kind: "archive";
      scanDir: string;
      archivedScanDir: string | null;
      archiveExisting: boolean;
      timestamp?: string;
    }
  | {
      kind: "insert";
      workspaceId: string;
      options: Omit<RunningScan, "workspace">;
    }
  | { kind: "safe"; values: string[] }
  | { kind: "timestamp" }
  | { kind: "diff"; value: Readonly<Record<string, string>> | null }
  | { kind: "stored"; scanId: string };
export interface Request {
  actions: Action[];
  migrate?: boolean;
}
const request = parseJson(readFileSync(0, "utf8")) as unknown as Request;
const native = sqliteBinding(),
  connection = new Connection(native, ":memory:");
try {
  connection.exec("PRAGMA foreign_keys = ON");
  if (request.migrate !== false)
    applyMigrations(native, connection, () => "2026-01-01T00:00:00+00:00");
  const results = request.actions.map((action) => {
    try {
      let value: unknown = null;
      switch (action.kind) {
        case "parseRecipe":
          value = parseScanRecipe(action.value, action.repository);
          break;
        case "getRecipe":
          value = getScanRecipe(connection, action);
          break;
        case "setThread":
          value = setScanThread(connection, action, () => {
            if (action.nowSql) connection.prepare(action.nowSql).run();
            if (action.failNow) throw new Error(action.failNow);
            return action.now ?? "2026-08-15T12:00:00.123456Z";
          });
          break;
        case "windowsMkdir": {
          const calls: { path: string; recursive: boolean }[] = [],
            errors = action.errors.map(Number);
          const files = windowsFileSystem({
            windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
            createWindowsDirectory: (path: Buffer) => {
              calls.push({ path: pathText(path), recursive: false });
              return errors.shift() ?? 0;
            },
            createWindowsDirectories: (path: Buffer) => {
              calls.push({ path: pathText(path), recursive: true });
              return errors.shift() ?? 0;
            },
          } as unknown as WindowsBinding);
          let error: number | null = null;
          try {
            files.mkdir(widePath("C:\\parent\\child"), action.recursive);
          } catch (failure) {
            error = (failure as { winerror: number }).winerror;
          }
          value = { calls, error };
          break;
        }
        case "sql":
          connection.prepare(action.sql).run(action.parameters);
          break;
        case "query":
          value = connection
            .prepare(action.sql)
            .all(action.parameters)
            .map((row) => row.toObject());
          break;
        case "commit":
          connection.commit();
          break;
        case "rollback":
          connection.rollback();
          break;
        case "feedback":
          value = getScanFeedback(
            connection,
            connection
              .prepare("SELECT * FROM scans WHERE id = ?")
              .get([action.scanId])!,
          );
          break;
        case "archive":
          archiveScan(
            connection,
            action,
            action.scanDir,
            action.timestamp ?? "after",
            (path) => resolvedPath(path),
          );
          break;
        case "insert":
          value = insertRunningScan(connection, {
            ...action.options,
            workspace: connection
              .prepare("SELECT * FROM workspaces WHERE id = ?")
              .get([action.workspaceId])!,
          });
          break;
        case "safe":
          value = action.values.map(safeSegment);
          break;
        case "timestamp":
          value = compactTimestamp();
          break;
        case "diff":
          value = scanDiffIdentity(action.value);
          break;
        case "stored":
          value = storedDiffTarget(
            connection
              .prepare("SELECT * FROM scans WHERE id = ?")
              .get([action.scanId])!,
          );
          break;
      }
      return { value, inTransaction: connection.inTransaction };
    } catch (error) {
      return {
        error: filesystemErrorMessage(error),
        kind: (error as Error).constructor.name,
        inTransaction: connection.inTransaction,
      };
    }
  });
  process.stdout.write(stringifyJson(results));
} finally {
  connection.close();
}
