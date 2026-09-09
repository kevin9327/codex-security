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
  normalizeMirrorLineageMigrations,
  normalizePreReleaseExecutionProfileMigrations,
  normalizePreReleaseMigrations,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-schema-normalizers";

export const timestamp = "2026-07-04T12:00:00Z";
type Operation =
  | "mirror"
  | "execution"
  | "general"
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
  error: { code: number | null; message: string } | null;
  inTransaction: boolean;
  schema: Record<string, unknown>[];
  tables: Record<string, Record<string, unknown>[]>;
}
export interface ScenarioResult {
  name: string;
  snapshots: Snapshot[];
}
const historyTable =
  "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at TEXT NOT NULL);";
const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
const history = (rows: readonly (readonly [number | bigint, string])[]) =>
  rows
    .map(
      ([version, name]) =>
        `INSERT INTO schema_migrations VALUES(${version},${quote(name)},'applied-${version}');`,
    )
    .join("\n");
const through = (version: number, omitted = 0) =>
  historyTable +
  MIGRATIONS.filter(([number]) => number <= version && number !== omitted)
    .map(([number, name, sql]) => sql + history([[number, name]]))
    .join("\n");
const tables = `
CREATE TABLE workspaces(id TEXT PRIMARY KEY,label TEXT);
CREATE TABLE scans(id TEXT PRIMARY KEY,handoff_status TEXT,handoff_claimed_at TEXT,handoff_claim_token TEXT);
CREATE TABLE scan_progress(scan_id TEXT PRIMARY KEY,reviewed INTEGER);
INSERT INTO workspaces VALUES('workspace','kept');
INSERT INTO scans VALUES('delivered','delivered','old-time','old-token'),('pending','pending','pending-time','pending-token');
INSERT INTO scan_progress VALUES('delivered',7);
`;
const profiles = ["workspaces", "scans"]
  .map(
    (table) => `
ALTER TABLE ${table} ADD COLUMN execution_model TEXT CHECK(execution_model IS NULL OR execution_model IN ('legacy-model','alternate'));
ALTER TABLE ${table} ADD COLUMN reasoning_effort TEXT CHECK((reasoning_effort IS NULL OR reasoning_effort IN ('medium','high')) AND ((execution_model IS NULL) = (reasoning_effort IS NULL)));
`,
  )
  .join("\n");
const legacySmall =
  tables +
  profiles +
  `
UPDATE workspaces SET execution_model='legacy-model',reasoning_effort='medium';
UPDATE scans SET execution_model='legacy-model',reasoning_effort='medium';
`;
const repeat = (operation: Operation): Step[] => [
  { operation },
  { operation: "commit" },
  { operation },
];
const general = (
  name: string,
  rows: readonly (readonly [number | bigint, string])[],
  extra = "",
  steps = repeat("general"),
): Scenario => ({
  name,
  setup: historyTable + tables + history(rows) + extra,
  steps,
});
const mirrorRows = [
  [29, "freeze stopped scan source digests"],
  [30, "separate deep scan publication failures"],
] as const;
const legacyRows = [
  [2, "finding management schema"],
  [3, "scan handoff delivery claims"],
  [4, "finding remediation action claims"],
  [5, "scan target snapshot digests"],
] as const;
const scenarios: Scenario[] = [
  {
    name: "current",
    setup: through(41),
    steps: [{ operation: "general", migrations: [] }],
  },
  general("unrelated-history", [
    [11, "background scan workers"],
    [12, "managed repositories"],
    [33, "unrelated migration"],
    [9007199254740993n, "future"],
  ]),
  general("finding-index-history", [
    [33, "index finding identity and comparison history"],
  ]),
  general(
    "finding-index-conflict",
    [
      [33, "index finding identity and comparison history"],
      [40, "occupied"],
    ],
    "",
    [{ operation: "general" }, { operation: "rollback" }],
  ),
  general(
    "finding-index-rollback",
    [[33, "index finding identity and comparison history"]],
    "",
    [
      { operation: "sql", sql: "BEGIN IMMEDIATE" },
      { operation: "general" },
      { operation: "rollback" },
    ],
  ),
  general(
    "finding-index-before-warning-error",
    [
      [33, "index finding identity and comparison history"],
      [25, "persist scan completion warnings"],
      [26, "occupied"],
    ],
    "",
    [{ operation: "general" }, { operation: "rollback" }],
  ),
  general(
    "finding-index-after-mirror-error",
    [[33, "index finding identity and comparison history"], mirrorRows[0]],
    "",
    [{ operation: "general" }],
  ),
  {
    name: "mirror",
    setup: historyTable + history(mirrorRows),
    steps: repeat("mirror"),
  },
  {
    name: "mirror-partial",
    setup: historyTable + history(mirrorRows.slice(0, 1)),
    steps: [{ operation: "mirror" }],
  },
  {
    name: "mirror-conflict",
    setup: historyTable + history([...mirrorRows, [31, "already present"]]),
    steps: [{ operation: "mirror" }],
  },
  {
    name: "mirror-rollback",
    setup: historyTable + history(mirrorRows),
    steps: [
      { operation: "sql", sql: "BEGIN IMMEDIATE" },
      { operation: "mirror" },
      { operation: "rollback" },
    ],
  },
  general(
    "mirror-before-warning-error",
    [...mirrorRows, [25, "persist scan completion warnings"], [26, "occupied"]],
    "",
    [{ operation: "general" }, { operation: "rollback" }],
  ),
];

for (const [version, name, suffix] of [
  [11, "scan execution profiles", "v11"],
  [12, "scan execution profiles", "v12-static"],
  [12, "dynamic scan execution profiles", "v12-dynamic"],
  [13, "dynamic scan execution profiles", "v13"],
  [22, "dynamic scan execution profiles", "v22"],
  [25, "dynamic scan execution profiles", "v25"],
] as const) {
  const setup =
    through(24, version) +
    history([[version, name]]) +
    profiles +
    `
INSERT INTO workspaces(id,created_at,updated_at,execution_model,reasoning_effort) VALUES
 ('workspace-a','t','t','legacy-model','medium'),('workspace-b','t','t','alternate','high'),('workspace-c','t','t',NULL,NULL);
INSERT INTO scans(id,workspace_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at,execution_model,reasoning_effort) VALUES
 ('a','workspace-a','/repo','revision','.','standard','/scan-a','complete','discovery','t','t','t','legacy-model','medium'),
 ('b','workspace-b','/repo','revision','.','standard','/scan-b','complete','discovery','t','t','t','alternate','high'),
 ('c','workspace-c','/repo','revision','.','standard','/scan-c','complete','discovery','t','t','t',NULL,NULL);
` +
    (version === 13
      ? "ALTER TABLE scans ADD COLUMN model TEXT; UPDATE scans SET model='chosen' WHERE id='b';"
      : "");
  scenarios.push({
    name: `profiles-${suffix}`,
    setup,
    steps: repeat("general"),
  });
}
scenarios.push(
  {
    name: "execution-columns-only",
    setup: historyTable + legacySmall,
    steps: repeat("execution"),
  },
  {
    name: "execution-renames-history-only",
    setup:
      historyTable +
      tables +
      history([[25, "dynamic scan execution profiles"]]),
    steps: repeat("execution"),
  },
  {
    name: "execution-stray-scan-effort",
    setup:
      historyTable +
      tables +
      history([
        [11, "unrelated"],
        [12, "unrelated"],
        [25, "unrelated"],
      ]) +
      "ALTER TABLE scans ADD COLUMN reasoning_effort TEXT;",
    steps: repeat("execution"),
  },
  {
    name: "execution-missing-columns",
    setup:
      historyTable +
      tables +
      history([
        [11, "scan execution profiles"],
        [25, "dynamic scan execution profiles"],
      ]),
    steps: [{ operation: "execution" }, { operation: "rollback" }],
  },
  {
    name: "execution-partial-columns",
    setup:
      historyTable +
      legacySmall +
      "ALTER TABLE workspaces DROP COLUMN reasoning_effort;",
    steps: [{ operation: "execution" }],
  },
  {
    name: "execution-renamed-collision",
    setup:
      historyTable +
      legacySmall +
      "ALTER TABLE scans ADD COLUMN legacy_reasoning_effort TEXT;",
    steps: [{ operation: "execution" }],
  },
  {
    name: "execution-backfill-error",
    setup:
      historyTable +
      legacySmall +
      "ALTER TABLE scans ADD COLUMN model TEXT CHECK(model != 'legacy-model');",
    steps: [{ operation: "execution" }, { operation: "rollback" }],
  },
  {
    name: "execution-rollback",
    setup: historyTable + legacySmall,
    steps: [
      { operation: "sql", sql: "BEGIN IMMEDIATE" },
      { operation: "execution" },
      { operation: "rollback" },
    ],
  },
  {
    name: "execution-constraints",
    setup: historyTable + legacySmall,
    steps: [
      { operation: "execution" },
      { operation: "commit" },
      {
        operation: "sql",
        sql: "UPDATE scans SET legacy_execution_model='invalid'",
      },
      { operation: "rollback" },
    ],
  },
);
for (const version of [11, 12, 25])
  scenarios.push({
    name: `execution-unknown-${version}`,
    setup:
      historyTable +
      legacySmall +
      history([[version, "unsupported profile history"]]),
    steps: [{ operation: "execution" }],
  });
for (const [oldVersion, newVersion, name] of [
  [25, 26, "persist scan completion warnings"],
  [12, 20, "phase-specific scan progress"],
  [13, 21, "current scan preflight state"],
] as const) {
  scenarios.push(general(`remap-${oldVersion}`, [[oldVersion, name]]));
  scenarios.push(
    general(
      `remap-conflict-${oldVersion}`,
      [
        [oldVersion, name],
        [newVersion, "occupied"],
      ],
      "",
      [{ operation: "general" }],
    ),
  );
}
scenarios.push(
  general("claims", [[18, "scan target summaries"]], "", [
    { operation: "general" },
    { operation: "commit" },
    {
      operation: "sql",
      sql: "UPDATE scans SET handoff_claimed_at='new-time',handoff_claim_token='new-token' WHERE id='delivered'",
    },
    { operation: "commit" },
    { operation: "general" },
  ]),
  general("legacy-versions", legacyRows),
  general("legacy-partial", [legacyRows[0], legacyRows[2], legacyRows[3]]),
  general("legacy-conflict", [legacyRows[0], [3, "unexpected"]], "", [
    { operation: "general" },
  ]),
  general(
    "legacy-existing-columns",
    legacyRows,
    "ALTER TABLE workspaces ADD COLUMN capability_preflight_json TEXT; UPDATE workspaces SET capability_preflight_json='kept'; ALTER TABLE scans ADD COLUMN target_snapshot_digest TEXT; UPDATE scans SET target_snapshot_digest='digest';",
  ),
  general("legacy-rollback", legacyRows, "", [
    { operation: "sql", sql: "BEGIN IMMEDIATE" },
    { operation: "general" },
    { operation: "rollback" },
  ]),
  general("recipe", [[22, "dynamic scan execution profiles"]]),
  general(
    "recipe-existing",
    [[22, "dynamic scan execution profiles"]],
    "ALTER TABLE scans ADD COLUMN recipe_json TEXT; UPDATE scans SET recipe_json='kept';",
  ),
);
for (const [index, name] of [
  "structured scan guidance context",
  "idempotent scan lifecycle requests",
].entries()) {
  scenarios.push(
    general(
      `setup-${index}`,
      [[19, name]],
      index === 0
        ? ""
        : MIGRATIONS.find(([version]) => version === 19)![2] +
            "INSERT INTO setup_preferences VALUES(1,1,'kept');",
    ),
  );
}
const injected: readonly MigrationRecord[] = [
  [
    19,
    "injected",
    "CREATE TABLE injected_settings(value TEXT);\nINSERT INTO injected_settings VALUES('kept');",
  ],
];
const failing: readonly MigrationRecord[] = [
  [
    19,
    "injected",
    "CREATE TABLE partial_settings(value TEXT);\nINSERT INTO missing_settings VALUES('failure');",
  ],
];
scenarios.push(
  general("setup-injected", [[19, "structured scan guidance context"]], "", [
    { operation: "general", migrations: injected },
    { operation: "commit" },
    { operation: "general", migrations: [] },
  ]),
  general(
    "setup-injected-error",
    [[19, "structured scan guidance context"]],
    "",
    [{ operation: "general", migrations: failing }, { operation: "rollback" }],
  ),
  general(
    "setup-injected-rollback",
    [[19, "structured scan guidance context"]],
    "",
    [
      { operation: "sql", sql: "BEGIN IMMEDIATE" },
      { operation: "general", migrations: failing },
      { operation: "rollback" },
    ],
  ),
);
for (const [index, name] of [
  "retain superseded scan lifecycle requests",
  "threat model publication receipts",
].entries()) {
  scenarios.push(
    general(
      `phase-${index}`,
      [[20, name]],
      index === 0
        ? ""
        : "ALTER TABLE scan_progress ADD COLUMN phase_items_total INTEGER; UPDATE scan_progress SET phase_items_total=3;",
    ),
  );
}
for (const [index, name] of [
  "scan progress projection and activity",
  "deep coordinator manifest receipts",
].entries()) {
  scenarios.push(
    general(
      `preflight-${index}`,
      [[21, name]],
      index === 0
        ? ""
        : "ALTER TABLE scan_progress ADD COLUMN preflight_issues_json TEXT; UPDATE scan_progress SET preflight_issues_json='[\"kept\"]';",
    ),
  );
}
scenarios.push(
  general(
    "phase-constraint-error",
    [[20, "retain superseded scan lifecycle requests"]],
    "ALTER TABLE scan_progress ADD COLUMN phase_items_total INTEGER; UPDATE scan_progress SET phase_items_total=-1;",
    [{ operation: "general" }, { operation: "rollback" }],
  ),
);
scenarios.push({
  name: "ordered-combination",
  setup:
    historyTable +
    legacySmall +
    history([
      ...mirrorRows,
      ...legacyRows,
      [11, "scan execution profiles"],
      [12, "phase-specific scan progress"],
      [13, "current scan preflight state"],
      [18, "scan target summaries"],
      [19, "structured scan guidance context"],
      [22, "dynamic scan execution profiles"],
      [25, "persist scan completion warnings"],
    ]),
  steps: repeat("general"),
});

const scalar = (value: SqlValue): unknown =>
  typeof value === "bigint" ? value.toString() : value;
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
  return { error, inTransaction: connection.inTransaction, schema, tables };
}
const command = process.argv[3];
if (command === "describe") {
  console.log(JSON.stringify({ timestamp, scenarios }));
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
  const scenario = scenarios.find(({ name }) => name === command)!;
  const connection = new Connection(native, ":memory:");
  try {
    connection.exec("PRAGMA foreign_keys=ON");
    connection.exec(scenario.setup);
    const snapshots = [snapshot(connection)];
    for (const step of scenario.steps) {
      let error: Snapshot["error"] = null;
      try {
        switch (step.operation) {
          case "mirror":
            normalizeMirrorLineageMigrations(connection);
            break;
          case "execution":
            normalizePreReleaseExecutionProfileMigrations(
              connection,
              timestamp,
            );
            break;
          case "general":
            normalizePreReleaseMigrations(
              native,
              connection,
              timestamp,
              step.migrations,
            );
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
        }
      } catch (failure) {
        const caught = failure as Error & { sqliteErrorCode?: number };
        error = {
          code: caught.sqliteErrorCode ?? null,
          message: caught.message,
        };
      }
      snapshots.push(snapshot(connection, error));
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
