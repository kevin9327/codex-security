import { once } from "node:events";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname } from "node:path";
import {
  Connection,
  type SqliteBinding,
  type SqlValue,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  processBinding,
  sqliteBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  backfillSecurityTargets,
  connect,
  databasePath,
  ensureSecurityTarget,
  stableTargetId,
  stateDir,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import { encodePosixPath } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import {
  chmod,
  mkdir,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/helper-files";

type Failure =
  | "locked"
  | "busy-name"
  | "folded-busy"
  | "constraint"
  | "missing";
export interface Request {
  action: "paths" | "identities" | "targets" | "connect" | "inspect";
  paths?: string[];
  setup?: string;
  steps?: {
    operation: "ensure" | "backfill" | "sql" | "commit" | "rollback";
    value?: string;
  }[];
  failure?: Failure;
  failures?: number;
  clockErrorAt?: number;
  clockValues?: string[];
  pending?: boolean;
  repeat?: boolean;
  databaseDirectory?: boolean;
  initialMode?: number;
  rawEnvironment?: Record<string, string | null>;
}
export interface Snapshot {
  schema: Record<string, unknown>[];
  tables: Record<string, Record<string, unknown>[]>;
  foreignKeys: Record<string, unknown>[];
  inTransaction: boolean;
}
export interface Report {
  error?: { message: string; code: string | null; sqliteCode: number | null };
  stateDir?: string;
  databasePath?: string;
  identities?: { path: string; id?: string; error?: string }[];
  steps?: {
    result: string | null;
    error: Report["error"] | null;
    snapshot: Snapshot;
  }[];
  snapshots?: Snapshot[];
  pragmas?: { foreignKeys: string; busyTimeout: string; journalMode: string };
  clock?: string[];
  opens?: number;
  closes?: number;
  activeHandles?: number;
  mode?: number;
}
const native = sqliteBinding();
const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
export const through = (version: number) =>
  "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_at TEXT NOT NULL);" +
  MIGRATIONS.filter(([number]) => number <= version)
    .map(
      ([number, name, sql]) =>
        sql +
        `INSERT INTO schema_migrations VALUES(${number},${quote(name)},'original-${number}');`,
    )
    .join("\n");
export const legacyRows = `
INSERT INTO workspaces(id,target_path,created_at,updated_at) VALUES
 ('workspace-a','/synthetic//alpha/./','t','t'),
 ('workspace-b','/synthetic/beta','t','t'),
 ('workspace-empty',NULL,'t','t');
INSERT INTO scans(id,workspace_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES
 ('scan-a','workspace-a','/synthetic/alpha','revision','.','standard','/scan-a','complete','reporting','t','t','t'),
 ('scan-b','workspace-b','/synthetic/beta','revision','.','standard','/scan-b','complete','reporting','t','t','t');
`;
export const scenarios: { name: string; request: Request }[] = [
  {
    name: "fresh",
    request: { action: "connect", repeat: true, pending: true },
  },
  {
    name: "legacy-targets",
    request: {
      action: "connect",
      setup: through(15) + legacyRows,
      repeat: true,
    },
  },
  {
    name: "existing-targets",
    request: {
      action: "connect",
      setup:
        through(39) +
        legacyRows +
        `
INSERT INTO security_targets VALUES('kept-id','/synthetic/beta','kept name','old-created','old-updated');
UPDATE scans SET target_id='kept-id' WHERE id='scan-b';
DROP INDEX scans_by_target;`,
      repeat: true,
    },
  },
  {
    name: "clock-failure",
    request: {
      action: "connect",
      setup: through(15) + legacyRows,
      clockErrorAt: 28,
    },
  },
  {
    name: "busy-clock-failure",
    request: { action: "connect", clockErrorAt: 1 },
  },
  {
    name: "busy-then-success",
    request: { action: "connect", failure: "locked", failures: 2 },
  },
  {
    name: "busy-exhausted",
    request: { action: "connect", failure: "locked", failures: 9 },
  },
  {
    name: "busy-named-table",
    request: { action: "connect", failure: "busy-name", failures: 9 },
  },
  {
    name: "constraint-not-retried",
    request: { action: "connect", failure: "constraint", failures: 9 },
  },
  {
    name: "unicode-name-not-retried",
    request: { action: "connect", failure: "folded-busy", failures: 9 },
  },
  {
    name: "missing-table-not-retried",
    request: { action: "connect", failure: "missing", failures: 9 },
  },
  {
    name: "database-is-directory",
    request: { action: "connect", databaseDirectory: true },
  },
];

function scalar(value: SqlValue): unknown {
  if (typeof value === "bigint") return String(value);
  if (Buffer.isBuffer(value)) return { blob: value.toString("hex") };
  if (typeof value === "number") {
    const bytes = Buffer.alloc(8);
    bytes.writeDoubleLE(value);
    return { real: bytes.toString("hex") };
  }
  return value;
}
function rows(connection: Connection, sql: string) {
  return connection
    .prepare(sql)
    .all()
    .map((row) =>
      Object.fromEntries(
        row.columns.map((column) => [column, scalar(row.get(column))]),
      ),
    );
}
function snapshot(connection: Connection): Snapshot {
  return {
    schema: rows(
      connection,
      "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name",
    ),
    tables: Object.fromEntries(
      rows(
        connection,
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
      ).map(({ name }) => [
        String(name),
        rows(
          connection,
          `SELECT * FROM "${String(name).replaceAll('"', '""')}" ORDER BY rowid`,
        ),
      ]),
    ),
    foreignKeys: rows(connection, "PRAGMA foreign_key_check"),
    inTransaction: connection.inTransaction,
  };
}
function failure(error: unknown): NonNullable<Report["error"]> {
  const caught = error as Error & { code?: string; sqliteErrorCode?: number };
  return {
    message: caught.message,
    code: caught.sqliteErrorCode === undefined ? caught.code ?? null : null,
    sqliteCode: caught.sqliteErrorCode ?? null,
  };
}
function sqliteFailure(kind: Failure): unknown {
  const connection = new Connection(native, ":memory:");
  try {
    if (kind === "locked") {
      connection.exec(
        "CREATE TABLE held(value); INSERT INTO held VALUES(1),(2)",
      );
      const statement = connection.raw.prepare("SELECT * FROM held");
      try {
        statement.bind([]);
        statement.step();
        connection.exec("DROP TABLE held");
      } finally {
        statement.finalize();
      }
    } else if (kind === "constraint") {
      connection.exec(
        "CREATE TABLE held(value CONSTRAINT busy CHECK(value > 0)); INSERT INTO held VALUES(0)",
      );
    } else
      connection.exec(
        `SELECT * FROM ${kind === "busy-name" ? "busy_fixture" : kind === "folded-busy" ? "buſy_fixture" : "missing_fixture"}`,
      );
  } catch (error) {
    return error;
  } finally {
    connection.close();
  }
  throw new Error("Expected a real SQLite failure.");
}

async function run(request: Request): Promise<Report> {
  if (request.rawEnvironment !== undefined) {
    const encode = (value: string) =>
      process.platform === "win32"
        ? Buffer.from(value, "utf16le")
        : encodePosixPath(value);
    const { rawEnvironment, ...child } = request;
    const result = processBinding().rawProcess({
      program: encode(process.execPath),
      args: [encode(process.argv[1]!)],
      input: Buffer.from(JSON.stringify(child)),
      environment: Object.entries(rawEnvironment).map(([name, value]) => ({
        name: encode(name),
        value: value === null ? null : encode(value),
      })),
    });
    if (result.error || result.returnCode !== 0 || result.stderr.length)
      throw new Error(
        `Raw environment child failed: ${result.error}/${result.returnCode}: ${result.stderr.toString()}`,
      );
    return JSON.parse(result.stdout.toString()) as Report;
  }
  if (request.action === "identities")
    return {
      identities: request.paths!.map((path) => {
        try {
          return { path, id: stableTargetId(path) };
        } catch (error) {
          return { path, error: (error as Error).message };
        }
      }),
    };
  const report: Report = { clock: [], opens: 0, closes: 0 };
  const now = () => {
    const index = report.clock!.length + 1;
    const timestamp =
      request.clockValues?.[index - 1] ??
      `2026-09-03T01:02:03.${String(index).padStart(6, "0")}Z`;
    report.clock!.push(timestamp);
    if (index === request.clockErrorAt) throw new Error("busy clock failure");
    return timestamp;
  };
  if (request.action === "targets") {
    const connection = new Connection(native, ":memory:");
    connection.exec(through(41) + (request.setup ?? ""));
    connection.prepare("PRAGMA foreign_keys=ON").run();
    report.steps = [];
    try {
      for (const step of request.steps ?? []) {
        let result: string | null = null,
          error: Report["error"] | null = null;
        try {
          if (step.operation === "ensure")
            result = ensureSecurityTarget(connection, step.value!, now);
          else if (step.operation === "backfill")
            backfillSecurityTargets(connection, now);
          else if (step.operation === "commit") connection.commit();
          else if (step.operation === "rollback") connection.rollback();
          else connection.prepare(step.value!).run();
        } catch (caught) {
          error = failure(caught);
        }
        report.steps.push({ result, error, snapshot: snapshot(connection) });
      }
    } finally {
      connection.close();
    }
    return report;
  }
  const handles: InstanceType<SqliteBinding["SqliteConnection"]>[] = [];
  try {
    report.stateDir = stateDir();
    report.databasePath = databasePath();
    if (request.action === "paths") return report;
    const path = report.databasePath;
    if (request.action === "inspect") {
      const connection = new Connection(native, path, { readOnly: true });
      try {
        report.snapshots = [snapshot(connection)];
      } finally {
        connection.close();
      }
      return report;
    }
    if (request.setup !== undefined) {
      mkdir(dirname(path));
      const setup = new Connection(native, path);
      try {
        setup.exec(request.setup);
      } finally {
        setup.close();
      }
    }
    if (request.databaseDirectory) mkdirSync(path, { recursive: true });
    if (request.initialMode !== undefined) chmod(path, request.initialMode);
    const injected =
      request.failure === undefined
        ? undefined
        : sqliteFailure(request.failure);
    const observed: SqliteBinding = {
      completeStatement: native.completeStatement,
      sqliteVersion: native.sqliteVersion,
      SqliteConnection: new Proxy(native.SqliteConnection, {
        construct(target, args: [Buffer, boolean, boolean]) {
          report.opens!++;
          const connection = new target(...args);
          handles.push(connection);
          return new Proxy(connection, {
            get(object, key) {
              if (key === "close")
                return () => {
                  report.closes!++;
                  object.close();
                };
              if (key === "prepare")
                return (sql: string) => {
                  if (
                    sql === "PRAGMA foreign_keys = ON" &&
                    report.opens! <= (request.failures ?? 0)
                  )
                    throw injected;
                  return object.prepare(sql);
                };
              const value: unknown = Reflect.get(object, key, object);
              return typeof value === "function" ? value.bind(object) : value;
            },
          });
        },
      }),
    };
    report.snapshots = [];
    const connection = await connect(observed, now);
    try {
      const value = (sql: string) =>
        String(connection.prepare(sql).get()!.get(0));
      report.pragmas = {
        foreignKeys: value("PRAGMA foreign_keys"),
        busyTimeout: value("PRAGMA busy_timeout"),
        journalMode: value("PRAGMA journal_mode"),
      };
      report.snapshots.push(snapshot(connection));
      if (request.pending)
        connection
          .prepare(
            "INSERT INTO security_targets VALUES('uncommitted','/uncommitted','pending','t','t')",
          )
          .run();
    } finally {
      connection.close();
    }
    if (process.platform !== "win32")
      report.mode = statSync(encodePosixPath(path)).mode & 0o777;
    if (request.repeat) {
      const reopened = await connect(observed, now);
      try {
        report.snapshots.push(snapshot(reopened));
      } finally {
        reopened.close();
      }
    }
  } catch (error) {
    report.error = failure(error);
  }
  report.activeHandles = handles.filter((connection) => {
    try {
      connection.prepare("SELECT 1").finalize();
      return true;
    } catch (error) {
      if ((error as Error).message !== "connection is closed") throw error;
      return false;
    }
  }).length;
  return report;
}

if (process.argv[2] === "worker") {
  process.stdout.write("ready\n");
  await once(process.stdin, "data");
  process.stdin.pause();
  let calls = 0;
  const connection = await connect(native, () => {
    if (++calls === 1)
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150);
    return "2026-09-03T01:02:03.123456Z";
  });
  try {
    console.log(JSON.stringify({ calls, snapshot: snapshot(connection) }));
  } finally {
    connection.close();
  }
} else if (process.argv[2] === "describe") {
  console.log(JSON.stringify({ scenarios, legacyRows }));
} else {
  console.log(
    JSON.stringify(await run(JSON.parse(readFileSync(0, "utf8")) as Request)),
  );
}
