import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameters,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { indexFindings } from "../../../../plugins/codex-security/mcp-app/src/workbench-finding-index";
import { applyMigrations } from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import {
  findPotentialDuplicates,
  listDedupeGroups,
  listStoredFindings,
  storeDedupeGroups,
  storeFindings,
  upsertFinding,
  type ImportedEntry,
  type ImportedFinding,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-findings";
import {
  normalizedVector,
  similarity,
  vectorNorm,
} from "../../../../plugins/codex-security/mcp-app/src/finding-similarity";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export type Operation =
  | {
      type: "index";
      scanId: string;
      document: { findings?: unknown };
      timestamp: string;
    }
  | { type: "execute"; sql: string; parameters?: Parameters }
  | { type: "query"; sql: string; parameters?: Parameters }
  | {
      type: "store";
      entries: ImportedEntry[];
      repository?: string;
      timestamp?: string;
    }
  | {
      type: "upsert";
      finding: ImportedFinding;
      repository?: string;
      timestamp?: string;
    }
  | { type: "groups"; groups: string[][]; timestamp?: string }
  | { type: "list"; limit: bigint; offset: bigint }
  | { type: "duplicates"; id: string; repository?: string }
  | { type: "list-groups"; id: string }
  | { type: "sql"; sql: string; parameters?: Parameters }
  | { type: "snapshot" };
export interface Request {
  initialize?: boolean;
  captureQueries?: boolean;
  operations?: Operation[];
  numeric?: (number | bigint | JsonFloat)[][];
  dot?: { left: number[]; right: number[] }[];
  interleave?: "list" | "duplicates";
}
const request = parseJson(readFileSync(0, "utf8")) as Request;
const native = sqliteBinding();
const queries: { sql: string; parameters: Parameters }[] = [];
const filename = process.argv[2] ?? ":memory:";
let writer: Connection | undefined;
let changed = false;
class ObservedConnection extends Connection {
  override prepare(sql: string) {
    const statement = super.prepare(sql);
    const iterate = statement.iterate.bind(statement);
    statement.iterate = function* (parameters: Parameters = []) {
      queries.push({ sql, parameters });
      for (const row of iterate(parameters)) {
        if (
          !changed &&
          ((request.interleave === "list" &&
            sql.startsWith("SELECT COUNT(*)")) ||
            (request.interleave === "duplicates" &&
              sql.startsWith("SELECT embeddings.model")))
        ) {
          changed = true;
          writer = new Connection(native, filename);
          writer.exec(
            "BEGIN IMMEDIATE; UPDATE findings SET details_json='{}' WHERE id='b'; DELETE FROM finding_embeddings WHERE finding_id='b'; COMMIT;",
          );
        }
        yield row;
      }
    };
    return statement;
  }
}
function snapshot(connection: Connection) {
  return Object.fromEntries(
    [
      "findings",
      "finding_embeddings",
      "finding_repositories",
      "finding_dedupe_groups",
      "finding_dedupe_group_members",
    ].map((table) => [
      table,
      connection
        .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
        .all()
        .map((row) => row.toObject()),
    ]),
  );
}
function main() {
  if (request.dot)
    return request.dot.map(({ left, right }) =>
      similarity(left.map(Number), right.map(Number)),
    );
  if (request.numeric) {
    const bits = (value: number) => {
      const buffer = Buffer.alloc(8);
      buffer.writeDoubleBE(value);
      return buffer.toString("hex");
    };
    return request.numeric.map((vector) => {
      const values = vector.map((value) =>
        value instanceof JsonFloat ? Number(value.source) : Number(value),
      );
      const norm = vectorNorm(values);
      if (!Number.isFinite(norm) || norm === 0) return { norm: bits(norm) };
      const normalized = normalizedVector(vector);
      return {
        norm: bits(norm),
        normalized: normalized.map(bits),
        similarity: bits(similarity(normalized, normalized)),
      };
    });
  }
  const connection = new ObservedConnection(native, filename);
  connection.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;");
  try {
    if (request.initialize)
      applyMigrations(native, connection, () => "2026-01-01T00:00:00+00:00");
    const results = (request.operations ?? []).map((operation) => {
      queries.length = 0;
      try {
        let value: unknown;
        switch (operation.type) {
          case "index":
            indexFindings(
              connection,
              operation.scanId,
              operation.document,
              operation.timestamp,
            );
            value = null;
            break;
          case "execute":
            connection.prepare(operation.sql).run(operation.parameters);
            value = null;
            break;
          case "query":
            value = connection
              .prepare(operation.sql)
              .all(operation.parameters)
              .map((row) => row.toObject());
            break;
          case "store":
            value = storeFindings(
              connection,
              operation.entries,
              operation.timestamp ?? "2026-01-02T00:00:00+00:00",
              operation.repository ?? null,
            );
            break;
          case "upsert":
            value =
              connection.transaction(() =>
                upsertFinding(
                  connection,
                  operation.finding,
                  operation.timestamp ?? "2026-01-03T00:00:00+00:00",
                  operation.repository ?? null,
                ),
              ) ?? null;
            break;
          case "groups":
            value = storeDedupeGroups(
              connection,
              operation.groups,
              operation.timestamp ?? "2026-01-02T00:00:00+00:00",
            );
            break;
          case "list":
            value = listStoredFindings(
              connection,
              operation.limit,
              operation.offset,
            );
            break;
          case "duplicates":
            value = findPotentialDuplicates(
              connection,
              operation.id,
              operation.repository ?? null,
            );
            break;
          case "list-groups":
            value = listDedupeGroups(connection, operation.id);
            break;
          case "sql":
            value = connection.transaction(() =>
              connection
                .prepare(operation.sql)
                .all(operation.parameters)
                .map((row) => row.values),
            );
            break;
          case "snapshot":
            value = snapshot(connection);
            break;
        }
        return {
          value,
          inTransaction: connection.inTransaction,
          queries: request.captureQueries === false ? [] : [...queries],
        };
      } catch (error) {
        return {
          error: (error as Error).message,
          kind: (error as Error).constructor.name,
          code: (error as { sqliteErrorCode?: number }).sqliteErrorCode ?? null,
          inTransaction: connection.inTransaction,
          queries: request.captureQueries === false ? [] : [...queries],
        };
      }
    });
    return { results };
  } finally {
    writer?.close();
    connection.close();
  }
}
process.stdout.write(stringifyJson(main(), { compact: true, allowNan: false }));
