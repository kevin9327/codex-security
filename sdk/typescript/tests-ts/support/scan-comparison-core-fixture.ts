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
  compareScans,
  findingMatches,
  listUnmatchedScanPairs,
  requireScan,
  resolveScanId,
  saveScanComparison,
  scanCoversPath,
  ScanComparisonError,
  type PairArgs,
  type ComparisonScan,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-comparison";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";

type Table = Record<string, unknown>;
export interface Sql {
  sql: string;
  parameters?: Parameters;
}
interface Settings {
  coverage?: Record<string, Table>;
  backfill?: Record<string, Sql[]>;
  failure?: {
    callback: string;
    at?: number;
    message: string;
    domain?: boolean;
  };
}
export type Operation =
  | Sql
  | { snapshot: true }
  | { resolve: string }
  | {
      cover: {
        scan: Pick<ComparisonScan, "status" | "target_id">;
        targetId: string | null;
        path: string | null;
        coverage: Table;
      };
    }
  | ((
      | {
          compare: PairArgs & {
            includeMatchingInputs?: boolean;
            requireMatches?: boolean;
          };
        }
      | { save: PairArgs; source?: string }
      | { plan: { repository: string; force?: boolean } }
      | { linked: { occurrenceId: string; scanId: string; startedAt: string } }
    ) &
      Settings);
export interface Request {
  operations: Operation[];
  git?: Record<string, { common?: string | null; origin?: string | null }>;
}
export interface Event {
  callback: string;
  id?: string;
  inTransaction: boolean;
}
export interface Response {
  results: {
    value?: unknown;
    error?: string;
    kind?: string;
    inTransaction: boolean;
    events: Event[];
  }[];
  probes: { target: string; args: string[] }[];
}
const request = parseJson(readFileSync(0, "utf8")) as Request;
const native = sqliteBinding(),
  processes = processBinding(),
  connection = new Connection(native, process.argv[2] ?? ":memory:");
const response: Response = { results: [], probes: [] };
const original = processes.rawProcess;
const decode = (value: Buffer) =>
  process.platform === "win32"
    ? value.toString("utf16le")
    : decodePosixBytes(value);
processes.rawProcess = (command) => {
  if (decode(command.program) === "git") {
    const args = command.args.map(decode),
      at = args.indexOf("-C"),
      target = args[at + 1]!,
      options = args.slice(at + 2);
    response.probes.push({ target, args: options });
    const configured = request.git?.[target];
    if (configured !== undefined) {
      const value =
        configured[options[0] === "rev-parse" ? "common" : "origin"] ?? null;
      return {
        error: 0,
        returnCode: value === null ? 1 : 0,
        stdout: value === null ? Buffer.alloc(0) : Buffer.from(value + "\n"),
        stderr: Buffer.alloc(0),
      };
    }
  }
  return original(command);
};
try {
  connection.prepare("PRAGMA foreign_keys=ON").run();
  applyMigrations(native, connection, () => "2026-01-01T00:00:00+00:00");
  for (const operation of request.operations) {
    const events: Event[] = [],
      counts = new Map<string, number>();
    const event = (callback: string, id?: string) => {
      events.push({
        callback,
        ...(id === undefined ? {} : { id }),
        inTransaction: connection.inTransaction,
      });
      const count = (counts.get(callback) ?? 0) + 1;
      counts.set(callback, count);
      const failure = "failure" in operation ? operation.failure : undefined;
      if (failure?.callback === callback && count === Number(failure.at ?? 1))
        throw failure.domain
          ? new ScanComparisonError(failure.message)
          : new Error(failure.message);
    };
    const callbacks = {
      requireScan: (db: Connection, id: string) => {
        event("require", id);
        return requireScan(db, id);
      },
      readCoverage: (scan: ComparisonScan) => {
        event("coverage", scan.id);
        return (
          ("coverage" in operation
            ? operation.coverage?.[scan.id]
            : undefined) ?? {
            completeness: "complete",
            includePaths: ["."],
            excludePaths: [],
            explicitExclusions: [],
          }
        );
      },
      backfillFindingDetails: (db: Connection, scan: ComparisonScan) => {
        event("backfill", scan.id);
        for (const statement of ("backfill" in operation
          ? operation.backfill?.[scan.id]
          : undefined) ?? [])
          db.prepare(statement.sql).run(statement.parameters ?? []);
      },
      now: () => {
        event("now");
        return "2026-02-01T00:00:00+00:00";
      },
      readMatches: () => {
        event("input");
        return "source" in operation ? operation.source : undefined;
      },
    };
    try {
      let value: unknown = null;
      if ("sql" in operation)
        connection.prepare(operation.sql).run(operation.parameters ?? []);
      else if ("snapshot" in operation)
        value = Object.fromEntries(
          [
            "security_targets",
            "workspaces",
            "scans",
            "scan_progress",
            "findings",
            "finding_occurrences",
            "finding_locations",
            "finding_triage",
            "scan_comparisons",
            "scan_comparison_matches",
          ].map((table) => [
            table,
            connection
              .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
              .all()
              .map((row) => row.toObject()),
          ]),
        );
      else if ("resolve" in operation)
        value = resolveScanId(connection, operation.resolve);
      else if ("compare" in operation)
        value = compareScans(connection, operation.compare, callbacks);
      else if ("save" in operation)
        value = saveScanComparison(connection, operation.save, callbacks);
      else if ("plan" in operation)
        value = listUnmatchedScanPairs(connection, operation.plan, callbacks);
      else if ("linked" in operation)
        value = findingMatches(
          connection,
          operation.linked.occurrenceId,
          operation.linked.scanId,
          operation.linked.startedAt,
        );
      else
        value = scanCoversPath(
          operation.cover.scan,
          operation.cover.targetId,
          operation.cover.path,
          operation.cover.coverage,
        );
      response.results.push({
        value,
        inTransaction: connection.inTransaction,
        events,
      });
    } catch (error) {
      response.results.push({
        error: (error as Error).message,
        kind: (error as Error).constructor.name,
        inTransaction: connection.inTransaction,
        events,
      });
    }
  }
} finally {
  processes.rawProcess = original;
  connection.close();
}
process.stdout.write(stringifyJson(response));
