import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  Connection,
  type Parameters,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  sqliteBinding,
  processBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  casefold,
  dashboard,
  listDedupeGroups,
  type DashboardQuery,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-dashboard";
import { timestamp } from "../../../../plugins/codex-security/mcp-app/src/helpers/workbench-read";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export const schema = `
CREATE TABLE findings(id TEXT PRIMARY KEY, details_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE finding_repositories(repository_id TEXT NOT NULL, finding_id TEXT NOT NULL REFERENCES findings(id), PRIMARY KEY(repository_id,finding_id));
CREATE TABLE finding_dedupe_groups(id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE finding_dedupe_group_members(group_id TEXT NOT NULL REFERENCES finding_dedupe_groups(id),finding_id TEXT NOT NULL REFERENCES findings(id),PRIMARY KEY(group_id,finding_id));
CREATE INDEX finding_dedupe_groups_by_finding ON finding_dedupe_group_members(finding_id,group_id);
`;
export const populated = `
INSERT INTO findings VALUES
 ('a','{"title":"Straße Σς İ ﬃ Ꭰꭰ","severity":{"level":"high"},"10":1.0,"2":9007199254740993,"evidence":{"text":"complete ✓","values":[1,null,true]}}','2026-01-01','2026-01-04'),
 ('b','{"title":"Second","severity":{"level":"low"}}','2026-01-03','2026-01-02'),
 ('c','{"title":"Third","severity":{"level":"medium"}}','2026-01-03','2026-01-02'),
 ('unlisted',NULL,'2026-01-05','2026-01-05');
INSERT INTO finding_repositories VALUES ('repo-z','a'),('repo-a','a'),('repo-b','b'),('repo-a','unlisted');
INSERT INTO finding_dedupe_groups VALUES ('10','2026-01-02'),('2','2026-01-02'),('empty','2026-01-01');
INSERT INTO finding_dedupe_group_members VALUES ('10','b'),('10','a'),('2','c'),('2','b'),('2','unlisted');
`;
export interface Request {
  action:
    | "describe"
    | "queries"
    | "casefold"
    | "casefold-all"
    | "timestamps"
    | "interleave";
  setup?: string;
  queries?: DashboardQuery[];
  findingIds?: string[];
  values?: string[];
  readOnly?: boolean;
}
const native = sqliteBinding();
const request = parseJson(readFileSync(0, "utf8")) as Request;
const filename = process.argv[2] ?? ":memory:";
function snapshot(connection: Connection) {
  return Object.fromEntries(
    [
      "findings",
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
function run(): unknown {
  if (request.action === "describe") return { schema, populated };
  if (request.action === "casefold") return request.values!.map(casefold);
  if (request.action === "timestamps")
    return {
      values: request.values!.map((value) => timestamp(BigInt(value))),
      now: timestamp(processBinding().wallClockMicroseconds()),
    };
  if (request.action === "casefold-all") {
    const digest = createHash("sha256");
    let changed = 0;
    for (let point = 0; point <= 0x10ffff; point++) {
      const original = String.fromCodePoint(point),
        folded = casefold(original);
      if (folded !== original) changed++;
      digest.update(
        `${point.toString(16)}:${Buffer.from(folded, "utf16le").toString("hex")}\n`,
      );
    }
    return { points: 0x110000, changed, sha256: digest.digest("hex") };
  }
  let connection = new Connection(native, filename);
  connection.exec("PRAGMA journal_mode=WAL");
  connection.exec(schema + (request.setup ?? ""));
  if (request.action === "interleave") {
    connection.close();
    const writer = new Connection(native, filename);
    let changed = false;
    class Reader extends Connection {
      override prepare(sql: string) {
        const statement = super.prepare(sql);
        if (sql.includes("SELECT DISTINCT repository_id AS id")) {
          const all = statement.all.bind(statement);
          statement.all = (parameters: Parameters = []) => {
            const rows = all(parameters);
            if (!changed) {
              changed = true;
              writer.exec(`BEGIN IMMEDIATE;
                UPDATE findings SET details_json='{"title":"changed"}' WHERE id='a';
                INSERT INTO findings VALUES('new','{"title":"New"}','latest','latest');
                INSERT INTO finding_repositories VALUES('repo-new','new');
                INSERT INTO finding_dedupe_groups VALUES('new-group','latest');
                INSERT INTO finding_dedupe_group_members VALUES('new-group','new');
                COMMIT;`);
            }
            return rows;
          };
        }
        return statement;
      }
    }
    connection = new Reader(native, filename, { readOnly: true });
    try {
      return request.queries!.map((query) => dashboard(connection, query));
    } finally {
      writer.close();
      connection.close();
    }
  }
  if (request.readOnly) {
    connection.close();
    connection = new Connection(native, filename, { readOnly: true });
  }
  try {
    const before = snapshot(connection);
    const results = request.queries!.map((query) => {
      try {
        return {
          value: dashboard(connection, query),
          inTransaction: connection.inTransaction,
        };
      } catch (error) {
        const code = (error as { sqliteErrorCode?: number }).sqliteErrorCode;
        return {
          error: (error as Error).message,
          ...(code === undefined ? {} : { code }),
          inTransaction: connection.inTransaction,
        };
      }
    });
    return {
      before,
      results,
      groups: (request.findingIds ?? []).map((id) =>
        listDedupeGroups(connection, id),
      ),
      after: snapshot(connection),
    };
  } finally {
    connection.close();
  }
}
process.stdout.write(stringifyJson(run(), { compact: true }));
