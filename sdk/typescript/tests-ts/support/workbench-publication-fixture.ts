import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import * as publication from "../../../../plugins/codex-security/mcp-app/src/workbench-publication";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export const SCAN = "11111111-1111-4111-8111-111111111111";
export const WORKSPACE = "22222222-2222-4222-8222-222222222222";
type Values = Record<string, Parameter>;
export interface Action {
  operation:
    | "input"
    | "verify"
    | "prepare"
    | "inspect"
    | "record"
    | "sql"
    | "commit"
    | "rollback";
  payload?: Record<string, unknown>;
  omit?: string[];
  inputText?: string;
  inputHex?: string;
  inputPath?: string;
  recording?: boolean;
  sql?: string;
  parameters?: Parameter[];
  now?: string;
  nowSql?: string;
  nowError?: string;
  nowManifest?: string;
  databasePath?: string;
  databaseError?: string;
  captureConnection?: boolean;
  manifest?: string;
  scanMode?: number;
}
export interface Request {
  root: string;
  scan?: Values;
  occurrences?: Values[];
  receipts?: Values[];
  setupSql?: string[];
  migrationsBefore?: number;
  manifest?: string;
  pinManifest?: boolean;
  actions: Action[];
}
export interface Outcome {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  inTransaction: boolean;
  events: unknown[];
  databaseUnchanged: boolean;
}
export interface Response {
  outcomes: Outcome[];
  snapshot: Record<string, Record<string, unknown>[] | null>;
  manifest: string;
  node: string;
}
const parameter = (value: Parameter): Parameter =>
  value instanceof JsonFloat ? Number(value.source) : value;
function output(value: unknown): unknown {
  if (Buffer.isBuffer(value)) return { $bytes: value.toString("hex") };
  if (typeof value === "number") return new JsonFloat(String(value));
  if (Array.isArray(value)) return value.map(output);
  if (
    value !== null &&
    typeof value === "object" &&
    !(value instanceof JsonFloat)
  )
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, output(child)]),
    );
  return value;
}
function execute(request: Request): Response {
  rmSync(request.root, { recursive: true, force: true });
  mkdirSync(request.root, { recursive: true, mode: 0o700 });
  const scanDir = join(request.root, "scan"),
    database = join(request.root, "state #% data", "history #'()!% é.sqlite3"),
    manifest = join(scanDir, "scan-manifest.json");
  mkdirSync(scanDir, { mode: 0o700 });
  mkdirSync(join(request.root, "other-scan"), { mode: 0o700 });
  mkdirSync(dirname(database), { mode: 0o700 });
  symlinkSync(
    scanDir,
    join(request.root, "scan-alias"),
    process.platform === "win32" ? "junction" : "dir",
  );
  writeFileSync(manifest, request.manifest ?? "sealed\n", { mode: 0o600 });
  const connection = new Connection(sqliteBinding(), database);
  connection.exec("PRAGMA synchronous=OFF");
  const insert = (table: string, values: Values) =>
    connection
      .prepare(
        `INSERT INTO ${table} (${Object.keys(values).join(", ")}) VALUES (${Object.keys(
          values,
        )
          .map(() => "?")
          .join(", ")})`,
      )
      .run(Object.values(values).map(parameter));
  try {
    for (const [version, , sql] of MIGRATIONS)
      if (
        request.migrationsBefore === undefined ||
        version < BigInt(request.migrationsBefore)
      )
        connection.exec(sql);
    insert("workspaces", {
      id: WORKSPACE,
      created_at: "created",
      updated_at: "updated",
    });
    insert("scans", {
      id: SCAN,
      workspace_id: WORKSPACE,
      target_path: "/target",
      target_revision: "revision",
      scope: ".",
      mode: "standard",
      scan_dir: scanDir,
      status: "complete",
      phase: "reporting",
      started_at: "started",
      created_at: "created",
      updated_at: "updated",
      ...(request.pinManifest
        ? {
            seal_manifest_digest: `sha256:${createHash("sha256").update(readFileSync(manifest)).digest("hex")}`,
          }
        : {}),
      ...request.scan,
    });
    for (const [index, occurrence] of (
      request.occurrences ?? [{}, {}]
    ).entries()) {
      const finding = `finding-${index}`;
      insert("findings", {
        id: finding,
        fingerprint: finding,
        rule_id: "synthetic-rule",
        identity_anchor: "anchor",
        created_at: "created",
        updated_at: "updated",
      });
      insert("finding_occurrences", {
        id: `occurrence-${index}`,
        finding_id: finding,
        scan_id: SCAN,
        title: "Synthetic finding",
        summary: "Synthetic summary",
        severity: "high",
        confidence: "high",
        remediation: "Synthetic remediation",
        created_at: "created",
        ...occurrence,
      });
    }
    for (const receipt of request.receipts ?? [])
      insert("finding_publications", {
        scan_id: SCAN,
        finding_id: "finding-0",
        occurrence_id: "occurrence-0",
        destination_type: "linear",
        team_id: "synthetic-team",
        project_id: null,
        external_id: "SYNTHETIC-1",
        external_url: null,
        created_at: "created",
        ...receipt,
      });
    connection.commit();
    connection.exec("PRAGMA synchronous=FULL");
    connection.exec("PRAGMA foreign_keys=ON");
    connection.exec("CREATE TABLE synthetic_audit(value TEXT)");
    for (const sql of request.setupSql ?? []) connection.exec(sql);
    const outcomes = request.actions.map((action): Outcome => {
      const inputFile = action.inputPath ?? join(request.root, "input.json");
      const payload: Record<string, unknown> = {
        scanId: SCAN,
        scanDirectory: scanDir,
        destination: { type: "linear", teamId: "synthetic-team" },
        findings: (request.occurrences ?? [{}, {}]).map((value, index) => ({
          findingId: value["finding_id"] ?? `finding-${index}`,
          occurrenceId: value["id"] ?? `occurrence-${index}`,
        })),
        ...(action.operation === "record" || action.recording
          ? { publications: [] }
          : {}),
        ...action.payload,
      };
      for (const key of action.omit ?? []) delete payload[key];
      if (!action.inputPath)
        writeFileSync(
          inputFile,
          action.inputHex !== undefined
            ? Buffer.from(action.inputHex, "hex")
            : action.inputText ?? stringifyJson(payload),
          { mode: 0o600 },
        );
      if (action.manifest !== undefined)
        writeFileSync(manifest, action.manifest);
      if (action.scanMode !== undefined)
        chmodSync(scanDir, Number(action.scanMode));
      const before = readFileSync(database),
        events: unknown[] = [],
        restores: (() => void)[] = [],
        traced = new Set<Connection>();
      const originalPrepare = Connection.prototype.prepare,
        originalClose = Connection.prototype.close;
      const native = sqliteBinding(),
        nativeConnection = native.SqliteConnection;
      if (action.captureConnection)
        native.SqliteConnection = new Proxy(nativeConnection, {
          construct(_target, [filename, readOnly, uri]) {
            events.push([
              "connect",
              (filename as Buffer).toString("utf8"),
              readOnly,
              uri,
            ]);
            throw new Error("captured connection");
          },
        });
      const trace = (db: Connection) => {
        if (traced.has(db)) return;
        traced.add(db);
        const raw = db.raw,
          prepare = raw.prepare,
          exec = raw.exec;
        raw.prepare = (sql) => {
          events.push([
            "query",
            sql.trim().replace(/\s+/gu, " "),
            db.inTransaction,
          ]);
          const statement = prepare.call(raw, sql);
          if (/^(BEGIN|COMMIT|ROLLBACK)\b/iu.test(sql)) {
            const step = statement.step;
            let seen = false;
            statement.step = () => {
              if (!seen) {
                events.push(["transaction", sql, db.inTransaction]);
                seen = true;
              }
              return step.call(statement);
            };
          }
          return statement;
        };
        raw.exec = (sql) => {
          if (/^(BEGIN|COMMIT|ROLLBACK)\b/iu.test(sql))
            events.push(["transaction", sql, db.inTransaction]);
          return exec.call(raw, sql);
        };
        restores.push(() => {
          raw.prepare = prepare;
          raw.exec = exec;
        });
      };
      trace(connection);
      Connection.prototype.prepare = function (sql) {
        trace(this);
        return originalPrepare.call(this, sql);
      };
      Connection.prototype.close = function () {
        events.push(["close", this.inTransaction]);
        return originalClose.call(this);
      };
      const context = {
        databasePath: () => {
          events.push(["databasePath", connection.inTransaction]);
          if (action.databaseError) throw new Error(action.databaseError);
          return action.databasePath ?? database;
        },
        now: () => {
          events.push(["now", connection.inTransaction]);
          if (action.nowSql) connection.prepare(action.nowSql).run();
          if (action.nowManifest !== undefined)
            writeFileSync(manifest, action.nowManifest);
          if (action.nowError) throw new Error(action.nowError);
          return action.now ?? "2026-08-15T12:00:00Z";
        },
      };
      let result: Pick<Outcome, "value" | "error" | "systemExit">;
      try {
        let value: unknown = null;
        switch (action.operation) {
          case "input":
            value = publication.linearPublicationInput(
              { inputFile },
              action.recording ?? false,
            );
            break;
          case "verify": {
            const [input, , findings] = publication.linearPublicationInput(
              { inputFile },
              false,
            );
            value = publication
              .verifyLinearPublicationScan(connection, input, findings)
              .toObject();
            break;
          }
          case "prepare":
            value = publication.prepareLinearPublication(connection, {
              inputFile,
            });
            break;
          case "inspect":
            value = publication.inspectLinearPublication(context, {
              inputFile,
            });
            break;
          case "record":
            value = publication.recordLinearPublications(context, connection, {
              inputFile,
            });
            break;
          case "sql":
            connection
              .prepare(action.sql!)
              .run(action.parameters?.map(parameter));
            break;
          case "commit":
            connection.commit();
            break;
          case "rollback":
            connection.rollback();
            break;
        }
        result = { value };
      } catch (error) {
        result = {
          error: filesystemErrorMessage(error),
          systemExit: error instanceof WorkbenchValidationError,
        };
      } finally {
        for (const restore of restores) restore();
        Connection.prototype.prepare = originalPrepare;
        Connection.prototype.close = originalClose;
        native.SqliteConnection = nativeConnection;
      }
      return {
        ...result,
        events,
        inTransaction: connection.inTransaction,
        databaseUnchanged: before.equals(readFileSync(database)),
      };
    });
    return {
      node: process.versions.node,
      outcomes,
      manifest: readFileSync(manifest, "utf8"),
      snapshot: Object.fromEntries(
        [
          "scans",
          "finding_occurrences",
          "finding_publications",
          "synthetic_audit",
        ].map((table) => [
          table,
          connection
            .prepare(
              "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            )
            .get([table])
            ? connection
                .prepare(`SELECT * FROM ${table} ORDER BY rowid`)
                .all()
                .map((row) => row.toObject())
            : null,
        ]),
      ),
    };
  } finally {
    connection.close();
  }
}
process.stdout.write(
  stringifyJson(
    output((parseJson(readFileSync(0, "utf8")) as Request[]).map(execute)),
    { compact: true, sortKeys: true },
  ),
);
