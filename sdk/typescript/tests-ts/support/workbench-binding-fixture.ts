import { readFileSync, readdirSync } from "node:fs";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as binding from "../../../../plugins/codex-security/mcp-app/src/workbench-binding";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export type Action =
  | { operation: "binding"; pluginRoot: string; completedAt?: string }
  | { operation: "verify"; manifest: Record<string, unknown> }
  | { operation: "digest"; scanDir: string; relative: string }
  | {
      operation: "published";
      scanDir: string;
      manifest: Record<string, unknown>;
    }
  | { operation: "recorded"; scanDir: string }
  | { operation: "pin"; id?: string; digest: string }
  | { operation: "sql"; sql: string; parameters?: Parameter[] }
  | { operation: "commit" | "rollback" };
export interface Request {
  scan?: Record<string, Parameter>;
  setupSql?: string[];
  actions: Action[];
}
export interface Outcome {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  inTransaction: boolean;
  events: unknown[];
  descriptors: bigint | null;
}
export interface Response {
  outcomes: Outcome[];
  scans: Record<string, unknown>[];
  node: string;
}
const scanId = "11111111-1111-4111-8111-111111111111",
  workspaceId = "22222222-2222-4222-8222-222222222222";
const descriptors = () =>
  process.platform === "linux" ? readdirSync("/proc/self/fd").length : null;
function execute(request: Request): Response {
  const connection = new Connection(sqliteBinding(), ":memory:");
  try {
    for (const [, , sql] of MIGRATIONS) connection.exec(sql);
    connection
      .prepare(
        "INSERT INTO workspaces(id,created_at,updated_at) VALUES (?, 'created', 'updated')",
      )
      .run([workspaceId]);
    const scan: Record<string, Parameter> = {
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
      updated_at: "updated",
      ...request.scan,
    };
    connection
      .prepare(
        `INSERT INTO scans(${Object.keys(scan).join(", ")}) VALUES (${Object.keys(
          scan,
        )
          .map(() => "?")
          .join(", ")})`,
      )
      .run(
        Object.values(scan).map((value) =>
          value instanceof JsonFloat ? Number(value.source) : value,
        ),
      );
    connection.commit();
    connection.exec("PRAGMA foreign_keys = ON");
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    const outcomes = request.actions.map((action): Outcome => {
      const before = descriptors(),
        events: unknown[] = [],
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
      const row = () =>
        connection.prepare("SELECT * FROM scans WHERE id = ?").get([scanId])!;
      const delta = () => {
        const after = descriptors();
        return before === null || after === null
          ? null
          : BigInt(after - before);
      };
      try {
        let value: unknown = null;
        switch (action.operation) {
          case "binding":
            value = binding.workbenchCompletionBinding(
              row(),
              action.completedAt ?? "completed",
              action.pluginRoot,
            );
            break;
          case "verify":
            binding.verifyManifestBinding(row(), action.manifest);
            break;
          case "digest":
            value = binding.scanLocalFileDigest(
              action.scanDir,
              action.relative,
            );
            break;
          case "published":
            value = binding.publishedManifestDigest(
              action.scanDir,
              action.manifest,
            );
            break;
          case "recorded":
            binding.requireRecordedManifestDigest(row(), action.scanDir);
            break;
          case "pin":
            binding.pinLegacyManifestDigest(
              connection,
              action.id ?? scanId,
              action.digest,
            );
            break;
          case "sql":
            connection.prepare(action.sql).run(action.parameters);
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
        }
        return {
          value,
          inTransaction: connection.inTransaction,
          events,
          descriptors: delta(),
        };
      } catch (error) {
        return {
          error: filesystemErrorMessage(error),
          systemExit: error instanceof WorkbenchValidationError,
          inTransaction: connection.inTransaction,
          events,
          descriptors: delta(),
        };
      } finally {
        raw.prepare = prepare;
        raw.exec = exec;
      }
    });
    return {
      outcomes,
      scans: connection
        .prepare("SELECT * FROM scans ORDER BY rowid")
        .all()
        .map((row) => row.toObject()),
      node: process.versions.node,
    };
  } finally {
    connection.close();
  }
}
process.stdout.write(
  stringifyJson(
    (parseJson(readFileSync(0, "utf8")) as Request[]).map(execute),
    { compact: true, sortKeys: true },
  ),
);
