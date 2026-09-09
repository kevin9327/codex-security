import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameters,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  confirmedFindingAliases,
  findingAliases,
  findingMatches,
  findingRelations,
  knownFindingGroups,
  rowsForIds,
  savedFindingLinks,
  type FindingLink,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-finding-links";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export type Operation =
  | { sql: string; parameters?: Parameters }
  | { aliases: [string, string][] }
  | { confirmed: string[] }
  | { saved: string[] }
  | { groups: { links: FindingLink[]; scanIds: string[] } }
  | { relations: { scanId: string; ids: string[] } }
  | { matches: { occurrenceId: string; scanId: string; startedAt: string } }
  | { limit: number }
  | { rows: string[] };
export interface Response {
  results: {
    value?: unknown;
    error?: string;
    queries: number;
    inTransaction: boolean;
  }[];
}
const operations = parseJson(readFileSync(0, "utf8")) as Operation[];
const connection = new Connection(sqliteBinding(), ":memory:");
connection.exec(`
  CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT);
  CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT, UNIQUE(scan_id, finding_id));
  CREATE INDEX occurrences_by_finding ON finding_occurrences(finding_id, id);
  CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
  CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT, reason TEXT);
  CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
  CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);
`);
let queries = 0;
const prepare = connection.prepare.bind(connection);
connection.prepare = (sql) => {
  queries++;
  return prepare(sql);
};
const response: Response = { results: [] };
try {
  for (const operation of operations) {
    queries = 0;
    try {
      let value: unknown = null;
      if ("sql" in operation)
        connection.prepare(operation.sql).run(operation.parameters ?? []);
      else if ("aliases" in operation)
        value = Object.fromEntries(findingAliases(operation.aliases));
      else if ("confirmed" in operation)
        value = Object.fromEntries(
          confirmedFindingAliases(connection, operation.confirmed),
        );
      else if ("saved" in operation)
        value = savedFindingLinks(connection, new Set(operation.saved));
      else if ("groups" in operation)
        value = knownFindingGroups(
          operation.groups.links,
          new Set(operation.groups.scanIds),
        );
      else if ("relations" in operation)
        value = findingRelations(
          connection,
          operation.relations.scanId,
          operation.relations.ids,
        );
      else if ("matches" in operation)
        value = findingMatches(
          connection,
          operation.matches.occurrenceId,
          operation.matches.scanId,
          operation.matches.startedAt,
        );
      else if ("limit" in operation)
        connection.raw.limit(9, Number(operation.limit));
      else
        value = [
          ...rowsForIds(
            connection,
            "SELECT id FROM finding_occurrences WHERE id IN ({placeholders}) ORDER BY id",
            operation.rows,
          ),
        ].map((row) => row.get("id"));
      response.results.push({
        value,
        queries,
        inTransaction: connection.inTransaction,
      });
    } catch (error) {
      response.results.push({
        error: (error as Error).message,
        queries,
        inTransaction: connection.inTransaction,
      });
    }
  }
} finally {
  connection.close();
}
process.stdout.write(stringifyJson(response));
