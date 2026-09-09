import { createRequire } from "node:module";
import path from "node:path";
import { Connection } from "../../native/sqlite.mjs";
import { nativeTarget } from "../../native/platform.mjs";

const require = createRequire(import.meta.url);
export function withWorkbenchDatabase(pluginRoot, database, operation) {
  const native = require(
    path.join(
      pluginRoot,
      "mcp",
      "native",
      nativeTarget,
      process.platform === "win32" ? "windows.node" : "unix.node",
    ),
  );
  const connection = new Connection(native, database);
  try {
    return operation(connection);
  } finally {
    connection.close();
  }
}

export function updateWorkbench(pluginRoot, database, sql, parameters) {
  return withWorkbenchDatabase(pluginRoot, database, (connection) =>
    connection.transaction(() => connection.prepare(sql).run(parameters)),
  );
}
