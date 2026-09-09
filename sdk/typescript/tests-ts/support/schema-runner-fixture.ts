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
  applyMigrations,
  migrateFindingWorkflowColumns,
  migrateFindingWorkflowReviewColumns,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-schema";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

interface Step {
  operation:
    | "apply"
    | "workflow"
    | "review"
    | "sql"
    | "commit"
    | "rollback"
    | "reopen";
  migrations?: readonly MigrationRecord[];
  sql?: string;
  nowErrorAt?: number;
  backfillError?: boolean;
}
interface Scenario {
  name: string;
  setup: string;
  steps: Step[];
  file?: boolean;
}
export interface Snapshot {
  error: { code: number | null; message: string } | null;
  inTransaction: boolean;
  schema: Record<string, unknown>[];
  tables: Record<string, Record<string, unknown>[]>;
  foreignKeys: Record<string, unknown>[];
  events: string[];
}
export interface ScenarioResult {
  name: string;
  snapshots: Snapshot[];
}
const historyTable =
  "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at TEXT NOT NULL);";
const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
const through = (version: number) =>
  historyTable +
  MIGRATIONS.filter(([number]) => number <= version)
    .map(
      ([number, name, sql]) =>
        sql +
        `INSERT INTO schema_migrations VALUES(${number},${quote(name)},'original-${number}');`,
    )
    .join("\n");
const select = (...versions: number[]) =>
  MIGRATIONS.filter(([version]) => versions.includes(version));
const again: Step[] = [{ operation: "apply" }, { operation: "apply" }];
const laterError: MigrationRecord = [
  999,
  "synthetic later failure",
  "INSERT INTO synthetic_missing_table VALUES(1);",
];
const basicRows = `
INSERT INTO workspaces(id,created_at,updated_at) VALUES('workspace-a','t','t'),('workspace-b','t','t');
INSERT INTO scans(id,workspace_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES
 ('scan-a','workspace-a','/repo-a','revision','.','deep','/scan-a','running','discovery','t','t','t'),
 ('scan-b','workspace-b','/repo-b','revision','.','deep','/scan-b','running','discovery','t','t','t');
`;
const deepRows = `INSERT INTO deep_scan_runs(scan_id,schema_version,workflow_version,status,phase,workers,subagents,stop_after_no_new,max_discovery_runs,created_at,updated_at) VALUES
 ('scan-a',1,'synthetic','running','discovery',2,0,2,10,'t','t'),('scan-b',1,'synthetic','running','discovery',2,0,7,10,'t','t');`;
const complete = JSON.stringify({
  repositoryPath: "/synthetic/repository",
  scanRequestDigest: "request",
  scanId: "saved-scan",
  scanDir: "/synthetic/scan",
  artifactDigest: "artifact",
  destination: "https://synthetic.invalid",
  scope: { repositoryId: "repository" },
  stages: {
    scan: { status: "completed", result: null },
    publish: { status: "completed", result: { findingIds: [] } },
    dedupe: { status: "completed", result: { duplicateGroups: [] } },
  },
});
const pending =
  '{"stages":{"scan":{"status":"pending"},"publish":{"status":"pending"},"dedupe":{"status":"pending"}}}';
const unfinished = JSON.stringify({
  scope: { allRepositories: true },
  stages: {
    scan: { status: "failed", error: "interrupted" },
    publish: { status: "running", error: "earlier failure" },
    dedupe: {
      status: "failed",
      error: "lost acknowledgement",
      result: { duplicateGroups: [["a", "b"]] },
      pendingWrite: { groups: [["a", "b"]] },
    },
  },
});
const numeric =
  '{"stages":{"10":{"result":0},"2":{"result":[9007199254740993,1.0,-0.0,1e16,1e-7,5e-324,"café 🔐","\\u007f","\\ud800"]},"scan":{"status":true,"result":null},"dedupePendingWrite":{"result":"old"},"publish":{"status":"completed","result":{"2":1,"1":2,"__proto__":3}},"dedupe":{"status":"failed","result":{"groups":[]},"pendingWrite":{"groups":[["a","b"]]}}},"repositoryPath":7,"scope":{"allRepositories":2.0},"ignored":true}';
const duplicateKeys =
  '{"stages":{"2":{"result":"first"},"scan":{"status":"completed"},"1":{"result":1},"2":{"result":"last"},"publish":{"status":"pending"},"dedupe":{"status":"pending"},"ignored-list":[],"ignored-string":"none"}}';
const review = JSON.stringify({
  version: 1,
  codexVersion: "0.synthetic",
  source: {
    repository: "/synthetic/repository",
    revision: "revision",
    refsDigest: "refs",
    content: "content",
  },
  scope: { repositoryId: "repository" },
  model: "synthetic-model",
  effort: "high",
  promptDigest: "prompt",
  contractDigest: "contract",
});
const reviewNumeric =
  '{"version":9007199254740993,"codexVersion":2.0,"source":{"repository":"/café/🔐","revision":"revision","refsDigest":"refs","content":"content"},"scope":{"allRepositories":true},"model":"synthetic-model","effort":"high","settingsDigest":null,"promptDigest":"digest","contractDigest":"contract"}';
const insertWorkflow = (
  id: string,
  state: string,
  column = "state_json",
  blob = false,
) =>
  `INSERT INTO finding_workflows(id,${column},created_at,updated_at) VALUES(${quote(id)},${blob ? `X'${Buffer.from("\ufeff" + state, "utf16le").toString("hex")}'` : quote(state)},'created','updated');`;
const insertReview = (key: string, binding: string, column = "binding_json") =>
  `INSERT INTO finding_workflow_reviews(workflow_id,review_key,${column},result_json,created_at) VALUES('complete',${quote(key)},${quote(binding)},'{ "kept": 1 }\n','review-created');`;
const checkpointRows =
  insertWorkflow("complete", complete) +
  insertWorkflow("unfinished", unfinished) +
  insertWorkflow("pending", pending) +
  insertWorkflow("numeric", numeric) +
  insertWorkflow("duplicates", duplicateKeys) +
  insertWorkflow("blob", complete, "state_json", true) +
  insertReview("review", review) +
  insertReview("numeric", reviewNumeric) +
  insertReview(
    "nonfinite",
    reviewNumeric
      .replace("9007199254740993", "NaN")
      .replace('"codexVersion":2.0', '"codexVersion":Infinity'),
  ) +
  `
CREATE TABLE workflow_references(workflow_id TEXT REFERENCES finding_workflows(id) ON DELETE CASCADE);
INSERT INTO workflow_references VALUES('complete');`;
const partialRepairs = `
ALTER TABLE workspaces DROP COLUMN capability_preflight_json;
DROP INDEX workspaces_by_thread_and_updated_at;
ALTER TABLE workspaces DROP COLUMN thread_id;
DROP INDEX scans_one_running_deep_per_owner_target;
ALTER TABLE scans DROP COLUMN deep_scan_owner_thread_id;
DROP TABLE deep_scan_dedup_inputs;
ALTER TABLE scans DROP COLUMN continuation_thread_id;
ALTER TABLE scan_progress DROP COLUMN scope_file_count;
DROP INDEX scans_by_target;
ALTER TABLE scans DROP COLUMN completion_warnings_json;
ALTER TABLE deep_scan_runs DROP COLUMN max_time_hours;
ALTER TABLE scans DROP COLUMN retained_source_digests_json;
ALTER TABLE deep_scan_runs DROP COLUMN publication_error_message;
ALTER TABLE deep_scan_runs DROP COLUMN stop_after_consecutive_errors;
ALTER TABLE deep_scan_runs DROP COLUMN consecutive_errors;
UPDATE schema_migrations SET name='legacy counter ownership' WHERE version=27;
`;
const legacyFindingIndexes =
  through(32) +
  MIGRATIONS.find(([version]) => version === 40)![2] +
  "INSERT INTO schema_migrations VALUES(33,'index finding identity and comparison history','original-33');";
const scenarios: Scenario[] = [
  { name: "fresh", setup: "", steps: again },
  {
    name: "legacy-finding-indexes",
    setup: legacyFindingIndexes,
    steps: again,
  },
  {
    name: "legacy-finding-indexes-later-error",
    setup: legacyFindingIndexes,
    steps: [{ operation: "apply", migrations: [...MIGRATIONS, laterError] }],
  },
  {
    name: "current-severity-checkpoints",
    setup:
      through(41) +
      `INSERT INTO scan_severity_classifications VALUES('saved-scan','["finding"]','assessed','rubric','knowledge');`,
    file: true,
    steps: [
      { operation: "apply" },
      { operation: "reopen" },
      { operation: "apply" },
    ],
  },
  {
    name: "empty-sequence",
    setup: "",
    steps: [{ operation: "apply", migrations: [] }],
  },
  {
    name: "partial-recorded",
    setup: through(39) + basicRows + deepRows + partialRepairs,
    steps: again,
  },
  {
    name: "recorded-counter-with-empty-sequence",
    setup:
      through(28) +
      basicRows +
      deepRows +
      "ALTER TABLE deep_scan_runs DROP COLUMN stop_after_consecutive_errors; ALTER TABLE deep_scan_runs DROP COLUMN consecutive_errors;",
    steps: [{ operation: "apply", migrations: [] }],
  },
  {
    name: "new-special-repairs",
    setup: through(5),
    steps: [
      {
        operation: "apply",
        migrations: [[6, "injected thread", "INVALID SQL;"]],
      },
      { operation: "apply", migrations: select(6) },
    ],
  },
  {
    name: "new-target-repair",
    setup: through(15),
    steps: [
      {
        operation: "apply",
        migrations: [[16, "injected target", "INVALID SQL;"]],
      },
    ],
  },
  {
    name: "last-target-result",
    setup: through(16) + "DROP INDEX scans_by_target;",
    steps: [{ operation: "apply", migrations: [...select(16), ...select(16)] }],
  },
  {
    name: "legacy-normalization",
    setup:
      through(10) +
      "UPDATE schema_migrations SET name='finding management schema' WHERE version=2; UPDATE schema_migrations SET name='scan handoff delivery claims' WHERE version=3; UPDATE schema_migrations SET name='finding remediation action claims' WHERE version=4; UPDATE schema_migrations SET name='scan target snapshot digests' WHERE version=5;",
    steps: again,
  },
  {
    name: "later-error",
    setup: through(37) + checkpointRows,
    steps: [{ operation: "apply", migrations: [...MIGRATIONS, laterError] }],
  },
  {
    name: "backfill-error",
    setup: through(15),
    steps: [{ operation: "apply", backfillError: true }],
  },
  {
    name: "normalization-error",
    setup:
      through(30) +
      "UPDATE schema_migrations SET name='freeze stopped scan source digests' WHERE version=29;",
    steps: [{ operation: "apply" }],
  },
  {
    name: "clock-first-error",
    setup: "",
    steps: [{ operation: "apply", nowErrorAt: 1 }],
  },
  {
    name: "clock-later-error",
    setup: "",
    steps: [{ operation: "apply", nowErrorAt: 3 }],
  },
  {
    name: "initial-commit",
    setup: "CREATE TABLE preceding_work(value TEXT);",
    steps: [
      {
        operation: "sql",
        sql: "INSERT INTO preceding_work VALUES('must commit')",
      },
      { operation: "apply", migrations: [laterError] },
    ],
  },
  {
    name: "duplicate-unapplied-version",
    setup: "",
    steps: [
      {
        operation: "apply",
        migrations: [
          [41, "first", "CREATE TABLE first_table(value TEXT);"],
          [41, "second", "CREATE TABLE second_table(value TEXT);"],
        ],
      },
    ],
  },
  {
    name: "workflows",
    setup: through(37) + checkpointRows,
    file: true,
    steps: [
      { operation: "apply" },
      { operation: "reopen" },
      { operation: "apply" },
      {
        operation: "sql",
        sql: "DELETE FROM finding_workflows WHERE id='complete'",
      },
      { operation: "commit" },
    ],
  },
  {
    name: "recorded-backfill-not-replayed",
    setup:
      through(41) +
      insertWorkflow("complete", complete, "results_json") +
      insertReview("review", review, "prompt_digest"),
    steps: [{ operation: "apply" }],
  },
];
const malformedWorkflows = [
  ["syntax", "{"],
  ["root-list", "[]"],
  ["root-null", "null"],
  ["missing-stages", "{}"],
  ["scope-null", pending.replace('{"stages"', '{"scope":null,"stages"')],
  ["stages-list", '{"stages":[]}'],
  ["stage-null", '{"stages":{"extra":null}}'],
  ["stage-index", '{"stages":{"extra":"result","later":null}}'],
  [
    "missing-dedupe",
    '{"stages":{"scan":{"status":"pending"},"publish":{"status":"pending"}}}',
  ],
  [
    "missing-status",
    pending.replace('"scan":{"status":"pending"}', '"scan":{}'),
  ],
  ["null-status", pending.replace('"status":"pending"', '"status":null')],
  [
    "nonfinite-nan",
    pending.replace(
      '"dedupe":{"status":"pending"}',
      '"dedupe":{"status":"pending","result":NaN}',
    ),
  ],
  [
    "nonfinite-infinity",
    pending.replace(
      '"dedupe":{"status":"pending"}',
      '"dedupe":{"status":"pending","pendingWrite":{"n":1e999}}',
    ),
  ],
] as const;
for (const [name, state] of malformedWorkflows)
  scenarios.push({
    name: `malformed-workflow-${name}`,
    setup:
      through(37) +
      insertWorkflow("complete", complete) +
      insertWorkflow("malformed", state),
    steps: [{ operation: "apply" }],
  });
for (const [name, binding] of [
  ["syntax", "{"],
  ["root-list", "[]"],
  ["source-null", review.replace('"source":{', '"source":null,"unused":{')],
  ["scope-null", review.replace('"scope":{', '"scope":null,"unusedScope":{')],
  ["missing-version", review.replace('"version":1,', "")],
] as const)
  scenarios.push({
    name: `malformed-review-${name}`,
    setup:
      through(38) +
      insertWorkflow("complete", complete, "results_json") +
      insertReview("valid", review) +
      insertReview("invalid", binding),
    steps: [{ operation: "apply" }],
  });
scenarios.push(
  {
    name: "workflow-partial-direct",
    setup:
      through(38) +
      insertWorkflow("complete", complete, "results_json") +
      insertWorkflow("invalid", "{}", "results_json"),
    steps: [{ operation: "workflow" }, { operation: "rollback" }],
  },
  {
    name: "review-partial-direct",
    setup:
      through(39) +
      insertWorkflow("complete", complete, "results_json") +
      insertReview("valid", review, "prompt_digest") +
      insertReview("invalid", "{}", "prompt_digest"),
    steps: [{ operation: "review" }, { operation: "rollback" }],
  },
);
const jsonCases = [
  "{}",
  "[]",
  '{"2":1,"1":2,"2":3,"é":"🔐\\u007f\\ud800"}',
  "[1.0,-0.0,0.0001,1e16,1e-7,5e-324,9007199254740993]",
  '{"a":NaN}',
  '{"a":[Infinity,-Infinity]}',
  '{"a":1e999}',
  '{"s":"a  b\\n\\t","empty":{},"nested":[{"0":true,"-1":null}]}',
];
function scalar(value: SqlValue): unknown {
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "number") {
    const bytes = Buffer.alloc(8);
    bytes.writeDoubleLE(value);
    return { real: bytes.toString("hex") };
  }
  return Buffer.isBuffer(value) ? { blob: value.toString("hex") } : value;
}
function rows(connection: Connection, sql: string): Record<string, unknown>[] {
  return connection
    .prepare(sql)
    .all()
    .map((row) =>
      Object.fromEntries(
        row.columns.map((column) => [column, scalar(row.get(column))]),
      ),
    );
}
function snapshot(
  connection: Connection,
  events: string[],
  error: Snapshot["error"] = null,
): Snapshot {
  const schema = rows(
    connection,
    "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
  );
  const tables: Snapshot["tables"] = {};
  for (const { name } of rows(
    connection,
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
  ))
    tables[name as string] = rows(
      connection,
      `SELECT * FROM "${(name as string).replaceAll('"', '""')}" ORDER BY rowid`,
    );
  return {
    error,
    inTransaction: connection.inTransaction,
    schema,
    tables,
    foreignKeys: rows(connection, "PRAGMA foreign_key_check"),
    events: [...events],
  };
}
const command = process.argv[3];
if (command === "describe")
  console.log(JSON.stringify({ scenarios, jsonCases }));
else if (command === "json")
  console.log(
    JSON.stringify(
      jsonCases.map((source) => {
        const value = parseJson(source);
        const pretty = stringifyJson(value);
        try {
          return {
            pretty,
            compact: stringifyJson(value, { compact: true, allowNan: false }),
            error: null,
          };
        } catch (error) {
          return { pretty, compact: null, error: (error as Error).message };
        }
      }),
    ),
  );
else {
  const native = createRequire(import.meta.url)(
    join(
      process.argv[2]!,
      "mcp",
      "native",
      nativeTarget,
      process.platform === "win32" ? "windows.node" : "unix.node",
    ),
  ) as SqliteBinding;
  const events: string[] = [];
  let clock = 0;
  const receipt = (connection: Connection) => {
    const versions = rows(
      connection,
      "SELECT version FROM schema_migrations ORDER BY version",
    ).map((row) => row["version"]);
    const hasCounter = rows(
      connection,
      "PRAGMA table_info(deep_scan_runs)",
    ).some((row) => row["name"] === "stop_after_consecutive_errors");
    const thresholds = hasCounter
      ? rows(
          connection,
          "SELECT stop_after_consecutive_errors FROM deep_scan_runs ORDER BY scan_id",
        ).map((row) => row["stop_after_consecutive_errors"])
      : [];
    events.push(
      `backfill:${connection.inTransaction}:${versions.join(",")}:${thresholds.join(",")}`,
    );
    connection
      .prepare("CREATE TABLE IF NOT EXISTS callback_receipts(value TEXT)")
      .run();
    connection.prepare("INSERT INTO callback_receipts VALUES('called')").run();
  };
  if (command === "concurrent") {
    const connection = new Connection(native, process.argv[4]!);
    connection.exec("PRAGMA foreign_keys=ON");
    console.log("ready");
    process.stdin.once("data", () => {
      try {
        applyMigrations(
          native,
          connection,
          MIGRATIONS,
          () => {
            clock++;
            if (
              clock === 1 &&
              rows(connection, "SELECT version FROM schema_migrations")
                .length === 0
            )
              Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150);
            return "concurrent-time";
          },
          receipt,
        );
        console.log(
          JSON.stringify({ clock, snapshot: snapshot(connection, events) }),
        );
      } finally {
        connection.close();
        process.stdin.destroy();
      }
    });
  } else {
    const scenario = scenarios.find(({ name }) => name === command)!;
    const filename = scenario.file ? process.argv[4]! : ":memory:";
    let connection = new Connection(native, filename);
    try {
      connection.exec("PRAGMA foreign_keys=ON");
      connection.exec(scenario.setup);
      const snapshots = [snapshot(connection, events)];
      for (const step of scenario.steps) {
        let error: Snapshot["error"] = null;
        try {
          switch (step.operation) {
            case "apply":
              applyMigrations(
                native,
                connection,
                step.migrations ?? MIGRATIONS,
                () => {
                  clock++;
                  events.push(`now:${clock}:${connection.inTransaction}`);
                  if (clock === step.nowErrorAt)
                    throw new Error("Synthetic clock failure.");
                  return `tick-${clock}`;
                },
                (database) => {
                  if (database !== connection)
                    throw new Error("Callback received another connection.");
                  receipt(database);
                  if (step.backfillError)
                    throw new Error("Synthetic target backfill failure.");
                },
              );
              break;
            case "workflow":
              migrateFindingWorkflowColumns(connection);
              break;
            case "review":
              migrateFindingWorkflowReviewColumns(connection);
              break;
            case "sql":
              connection.prepare(step.sql!).run();
              break;
            case "commit":
              connection.commit();
              break;
            case "rollback":
              connection.rollback();
              break;
            case "reopen":
              connection.close();
              connection = new Connection(native, filename);
              connection.exec("PRAGMA foreign_keys=ON");
              break;
          }
        } catch (failure) {
          const caught = failure as Error & { sqliteErrorCode?: number };
          error = {
            code: caught.sqliteErrorCode ?? null,
            message: caught.message,
          };
        }
        snapshots.push(snapshot(connection, events, error));
      }
      console.log(
        JSON.stringify({
          name: scenario.name,
          snapshots,
        } satisfies ScenarioResult),
      );
    } finally {
      connection.close();
    }
  }
}
