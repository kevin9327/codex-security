import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameters,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  processBinding,
  sqliteBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import { applyMigrations } from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import {
  listScans,
  repositoryOrigin,
  type ScanQuery,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-history";
import { listRepositories } from "../../../../plugins/codex-security/mcp-app/src/workbench-navigation";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import { runWorkbench } from "../../src/runtime.js";

export type Operation =
  | { sql: string; parameters?: Parameters }
  | { query?: ScanQuery }
  | { origin: string }
  | { repositories: true }
  | { snapshot: true }
  | { sdk: string[]; state: string; plugin: string };
export interface Request {
  initialize?: boolean;
  operations: Operation[];
  git?: Record<string, { common?: string | null; origin?: string | null }>;
}
export interface Response {
  results: {
    value?: unknown;
    error?: string;
    kind?: string;
    inTransaction: boolean;
  }[];
  probes: { target: string; args: string[] }[];
}

async function main() {
  const request = parseJson(readFileSync(0, "utf8")) as Request;
  const native = sqliteBinding(),
    processes = processBinding();
  const connection = new Connection(native, process.argv[2] ?? ":memory:");
  const response: Response = { results: [], probes: [] };
  const run = processes.rawProcess;
  const decode = (value: Buffer) =>
    process.platform === "win32"
      ? value.toString("utf16le")
      : decodePosixBytes(value);
  processes.rawProcess = (command) => {
    if (decode(command.program) === "git") {
      const args = command.args.map(decode),
        index = args.indexOf("-C");
      const target = args[index + 1]!,
        options = args.slice(index + 2);
      response.probes.push({ target, args: options });
      const configured = request.git?.[target];
      if (configured !== undefined) {
        const value =
          configured[options[0] === "rev-parse" ? "common" : "origin"] ?? null;
        return {
          error: 0,
          returnCode: value === null ? 1 : 0,
          stdout: value === null ? Buffer.alloc(0) : Buffer.from(`${value}\n`),
          stderr: Buffer.alloc(0),
        };
      }
    }
    return run(command);
  };
  try {
    if (request.initialize)
      applyMigrations(native, connection, () => "2026-01-01T00:00:00+00:00");
    for (const operation of request.operations) {
      try {
        let value: unknown = null;
        if ("sql" in operation)
          connection.prepare(operation.sql).run(operation.parameters ?? []);
        else if ("origin" in operation)
          value = repositoryOrigin(operation.origin);
        else if ("repositories" in operation)
          value = listRepositories(connection);
        else if ("snapshot" in operation)
          value = Object.fromEntries(
            ["security_targets", "scans", "scan_progress"].map((table) => [
              table,
              connection
                .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
                .all()
                .map((row) => row.toObject()),
            ]),
          );
        else if ("sdk" in operation)
          value = await runWorkbench(
            {
              pluginRoot: operation.plugin,
              environment: {
                ...process.env,
                CODEX_SECURITY_STATE_DIR: operation.state,
                PYTHON: "missing-list-scans-python",
              },
            },
            operation.sdk,
          );
        else value = listScans(connection, operation.query);
        response.results.push({
          value,
          inTransaction: connection.inTransaction,
        });
      } catch (error) {
        response.results.push({
          error: (error as Error).message,
          kind: (error as Error).constructor.name,
          inTransaction: connection.inTransaction,
        });
      }
    }
  } finally {
    processes.rawProcess = run;
    connection.close();
  }
  process.stdout.write(stringifyJson(response));
}
void main();
