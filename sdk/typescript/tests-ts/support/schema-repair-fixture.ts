import { createRequire } from "node:module";
import { join } from "node:path";
import {
  Connection,
  type SqliteBinding,
  type SqlValue,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { nativeTarget } from "../../../../plugins/codex-security/native/platform.mjs";
import {
  MIGRATIONS,
  type MigrationRecord,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import {
  addColumnIfMissing,
  repairDeepScanFailureCounterMigration,
  repairDeepScanMigration,
  repairStableTargetsMigration,
  repairThreadScopedWorkspacesMigration,
  sqlStatements,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-schema-repairs";

type Operation =
  | "column"
  | "thread"
  | "deep"
  | "counter"
  | "targets"
  | "sql"
  | "commit"
  | "rollback";
interface Step {
  operation: Operation;
  sql?: string;
  migrations?: readonly MigrationRecord[];
}
interface Scenario {
  name: string;
  setup: string;
  steps: Step[];
}
export interface Snapshot {
  value: boolean | null;
  error: { code: number | null; message: string } | null;
  inTransaction: boolean;
  schema: Record<string, unknown>[];
  tables: Record<string, Record<string, unknown>[]>;
}
export interface ScenarioResult {
  name: string;
  snapshots: Snapshot[];
}
const through = (version: number) =>
  MIGRATIONS.filter(([number]) => number <= version)
    .map(([, , sql]) => sql)
    .join("\n");
const workspaces = `
INSERT INTO workspaces(id,thread_id,created_at,updated_at) VALUES
 ('workspace-a','owner-a','t','t'),('workspace-b','owner-a','t','t'),
 ('workspace-c','owner-c','t','t'),('workspace-d','owner-d','t','t'),('workspace-e','owner-e','t','t');
`;
const scans = `
INSERT INTO scans(id,workspace_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES
 ('scan-a','workspace-a','/repo','revision','.','deep','/scan-a','running','discovery','t','t','t'),
 ('scan-b','workspace-b','/repo','revision','.','deep','/scan-b','running','discovery','t','t','t'),
 ('scan-c','workspace-c','/other','revision','.','deep','/scan-c','running','discovery','t','t','t'),
 ('scan-d','workspace-d','/standard','revision','.','standard','/scan-d','running','discovery','t','t','t'),
 ('scan-e','workspace-e','/finished','revision','.','deep','/scan-e','complete','discovery','t','t','t');
`;
const continuation = `ALTER TABLE scans ADD COLUMN continuation_thread_id TEXT;
UPDATE scans SET continuation_thread_id='continuation-c' WHERE id='scan-c';`;
const targetTable = `CREATE TABLE security_targets(id TEXT PRIMARY KEY,current_path TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);`;
const partialTargets =
  through(15) +
  workspaces +
  scans +
  targetTable +
  `
ALTER TABLE workspaces ADD COLUMN target_id TEXT;
ALTER TABLE scans ADD COLUMN target_id TEXT;
INSERT INTO security_targets VALUES('kept-target','/repo','Kept','t','t');
UPDATE scans SET target_id=CASE WHEN id='scan-a' THEN 'kept-target' ELSE 'orphan' END;
UPDATE workspaces SET target_id='orphan';`;
const scenarios: Scenario[] = [
  {
    name: "column",
    setup:
      "CREATE TABLE things(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO things VALUES(41,'kept');",
    steps: [{ operation: "column" }, { operation: "column" }],
  },
  { name: "column-missing-table", setup: "", steps: [{ operation: "column" }] },
  {
    name: "thread",
    setup:
      "CREATE TABLE workspaces(id TEXT,updated_at TEXT); INSERT INTO workspaces VALUES('kept','t');",
    steps: [{ operation: "thread" }, { operation: "thread" }],
  },
  {
    name: "counter",
    setup:
      "CREATE TABLE deep_scan_runs(scan_id TEXT,stop_after_no_new INTEGER); INSERT INTO deep_scan_runs VALUES('a',2),('b',7);",
    steps: [
      { operation: "counter" },
      { operation: "commit" },
      {
        operation: "sql",
        sql: "UPDATE deep_scan_runs SET stop_after_consecutive_errors=9,consecutive_errors=3",
      },
      { operation: "commit" },
      { operation: "counter" },
    ],
  },
  {
    name: "counter-partial",
    setup:
      "CREATE TABLE deep_scan_runs(scan_id TEXT,stop_after_no_new INTEGER,stop_after_consecutive_errors INTEGER); INSERT INTO deep_scan_runs VALUES('a',2,9);",
    steps: [{ operation: "counter" }],
  },
  {
    name: "counter-error",
    setup:
      "CREATE TABLE deep_scan_runs(scan_id TEXT,stop_after_no_new INTEGER); INSERT INTO deep_scan_runs VALUES('invalid',0);",
    steps: [{ operation: "counter" }, { operation: "rollback" }],
  },
  {
    name: "deep-owners",
    setup: through(10) + workspaces + scans + continuation,
    steps: [
      { operation: "deep" },
      { operation: "commit" },
      { operation: "deep", migrations: [] },
    ],
  },
  {
    name: "deep-partial",
    setup:
      through(11) +
      workspaces +
      scans +
      continuation +
      "UPDATE scans SET deep_scan_owner_thread_id='custom-a' WHERE id='scan-a'; DROP TABLE deep_scan_dedup_inputs;",
    steps: [{ operation: "deep" }],
  },
  {
    name: "deep-rollback",
    setup: through(10) + workspaces + scans,
    steps: [
      { operation: "sql", sql: "BEGIN" },
      { operation: "deep" },
      { operation: "rollback" },
    ],
  },
  {
    name: "deep-injected",
    setup: through(10) + workspaces + scans,
    steps: [
      {
        operation: "deep",
        migrations: [
          [
            11,
            "injected",
            "ALTER TABLE scans ADD COLUMN ignored TEXT;\nUPDATE scans SET deep_scan_owner_thread_id='injected';\nCREATE TABLE deep_scan_injected(value TEXT);",
          ],
        ],
      },
    ],
  },
  {
    name: "targets",
    setup: through(15) + workspaces + scans,
    steps: [
      { operation: "targets" },
      { operation: "commit" },
      { operation: "targets", migrations: [] },
    ],
  },
  {
    name: "targets-partial",
    setup: partialTargets,
    steps: [
      { operation: "targets" },
      { operation: "commit" },
      { operation: "targets" },
    ],
  },
  {
    name: "targets-rollback",
    setup: partialTargets,
    steps: [
      { operation: "sql", sql: "BEGIN" },
      { operation: "targets" },
      { operation: "rollback" },
    ],
  },
  {
    name: "targets-injected",
    setup: through(15) + workspaces + scans,
    steps: [
      {
        operation: "targets",
        migrations: [
          [
            16,
            "injected",
            MIGRATIONS.find(([version]) => version === 16)![2] +
              "\nCREATE TABLE injected_marker(value TEXT);",
          ],
        ],
      },
    ],
  },
];
export const statementCases = [
  "",
  " \t\r\n",
  "SELECT 1;\nSELECT 2;",
  "SELECT 1; SELECT 2;",
  "\u0085\u001fSELECT 1;\u2000\n",
  "SELECT\u20281;\u2029SELECT\u00852;",
  "SELECT\r\n1;\rSELECT\v2;\fSELECT\u001c3;\u001dSELECT\u001e4;",
  "SELECT 'inside;quote'; -- trailing comment\nSELECT 2;",
  "CREATE TRIGGER t AFTER INSERT ON things BEGIN\nINSERT INTO things VALUES('semi;colon');\nUPDATE things SET value='next';\nEND;\n",
  "-- heading\nSELECT 1;\n/* closed */\nSELECT 2;",
  "SELECT 1",
  "-- only a comment\n",
  "/* open",
  "\ufeff",
  "\ufeffSELECT 1;",
  "SELECT 'x\u001fy';",
  "SELECT '\u0085';",
  "SELECT 1;\n\n",
];

const scalar = (value: SqlValue): unknown =>
  typeof value === "bigint" ? value.toString() : value;
function readRows(db: Connection, sql: string): Record<string, unknown>[] {
  return db
    .prepare(sql)
    .all()
    .map((row) =>
      Object.fromEntries(
        row.columns.map((column) => [column, scalar(row.get(column))]),
      ),
    );
}
function snapshot(
  db: Connection,
  value: boolean | void,
  error: Snapshot["error"],
): Snapshot {
  const schema = readRows(
    db,
    "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
  );
  const tables: Snapshot["tables"] = {};
  for (const { name } of readRows(
    db,
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
  ))
    tables[name as string] = readRows(
      db,
      `SELECT * FROM "${(name as string).replaceAll('"', '""')}" ORDER BY rowid`,
    );
  return {
    value: value ?? null,
    error,
    inTransaction: db.inTransaction,
    schema,
    tables,
  };
}
const command = process.argv[3];
if (command === "describe") {
  console.log(JSON.stringify({ scenarios, statementCases }));
} else {
  const native = createRequire(import.meta.url)(
    join(
      process.argv[2]!,
      "mcp",
      "native",
      nativeTarget,
      process.platform === "win32" ? "windows.node" : "unix.node",
    ),
  ) as SqliteBinding;
  if (command === "statements") {
    console.log(
      JSON.stringify(
        statementCases.map((script) => {
          try {
            return { statements: sqlStatements(native, script), error: null };
          } catch (error) {
            return { statements: null, error: (error as Error).message };
          }
        }),
      ),
    );
  } else {
    const scenario = scenarios.find(({ name }) => name === command)!;
    const db = new Connection(native, ":memory:");
    const snapshots: Snapshot[] = [];
    try {
      db.exec("PRAGMA foreign_keys=ON");
      db.exec(scenario.setup);
      snapshots.push(snapshot(db, undefined, null));
      for (const step of scenario.steps) {
        let value: boolean | void = undefined;
        let error: Snapshot["error"] = null;
        try {
          switch (step.operation) {
            case "column":
              addColumnIfMissing(db, "things", "extra", "TEXT DEFAULT 'added'");
              break;
            case "thread":
              repairThreadScopedWorkspacesMigration(db);
              break;
            case "deep":
              repairDeepScanMigration(native, db, step.migrations);
              break;
            case "counter":
              repairDeepScanFailureCounterMigration(db);
              break;
            case "targets":
              value = repairStableTargetsMigration(native, db, step.migrations);
              break;
            case "commit":
              db.commit();
              break;
            case "rollback":
              db.rollback();
              break;
            case "sql":
              db.prepare(step.sql!).run();
              break;
          }
        } catch (failure) {
          const caught = failure as Error & { sqliteErrorCode?: number };
          error = {
            code: caught.sqliteErrorCode ?? null,
            message: caught.message,
          };
        }
        snapshots.push(snapshot(db, value, error));
      }
      console.log(
        JSON.stringify({
          name: scenario.name,
          snapshots,
        } satisfies ScenarioResult),
      );
    } finally {
      db.close();
    }
  }
}
