import { createRequire } from "node:module";
import { join } from "node:path";
import {
  Connection,
  type Parameter,
  type SqliteBinding,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { nativeTarget } from "../../../../plugins/codex-security/native/platform.mjs";
import { PLUGIN_ROOT } from "../plugin-root.js";

const require = createRequire(import.meta.url);
export function withWorkbenchDatabase<T>(
  database: string,
  operation: (connection: Connection, native: SqliteBinding) => T,
): T {
  const native = require(
    join(
      PLUGIN_ROOT,
      "mcp",
      "native",
      nativeTarget,
      process.platform === "win32" ? "windows.node" : "unix.node",
    ),
  ) as SqliteBinding;
  const connection = new Connection(native, database);
  try {
    return operation(connection, native);
  } finally {
    connection.close();
  }
}

export function workbenchRows(
  database: string,
  sql: string,
  parameters: readonly Parameter[] = [],
): Record<string, unknown>[] {
  return withWorkbenchDatabase(database, (connection) =>
    connection.transaction(() =>
      connection
        .prepare(sql)
        .all(parameters)
        .map((row) =>
          Object.fromEntries(
            Object.entries(row.toObject()).map(([name, value]) => [
              name,
              typeof value === "bigint" ? Number(value) : value,
            ]),
          ),
        ),
    ),
  );
}

export function workbenchSnapshot(connection: Connection) {
  const schema = connection
    .prepare(
      "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name",
    )
    .all()
    .map((row) => row.toObject());
  return {
    schema,
    tables: Object.fromEntries(
      schema
        .filter((row) => row["type"] === "table")
        .map((row) => {
          const name = row["name"] as string;
          return [
            name,
            connection
              .prepare(`SELECT * FROM "${name.replaceAll('"', '""')}"`)
              .all()
              .map((row) => row.toObject()),
          ];
        }),
    ),
  };
}
