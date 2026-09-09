import { readFileSync } from "node:fs";
import {
  Row,
  type SqlValue,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  deepScanDeadlineReached,
  deepScanOutputPath,
  deepScanPath,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-files";
import { parsePythonDateTime } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-date-time";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";

export type Operation =
  | {
      kind: "path" | "output";
      scanDir: string;
      value: string;
      label: string;
      pathKind?: string;
      canonicalDir?: string;
      callbackError?: "validation" | "runtime" | "os" | "type" | "value";
    }
  | { kind: "deadline"; now: string; created: unknown; hours: unknown }
  | { kind: "timestamp"; value: string };

const values = parseJson(readFileSync(0, "utf8")) as Operation[];
const parameter = (value: unknown) =>
  (value instanceof JsonFloat ? Number(value.source) : value) as SqlValue;
const results = values.map((operation) => {
  const calls: string[] = [];
  try {
    let value: unknown;
    if (operation.kind === "timestamp")
      value = parsePythonDateTime(operation.value);
    else if (operation.kind === "deadline") {
      const row = new Row(
        ["created_at", "max_time_hours"],
        [parameter(operation.created), parameter(operation.hours)],
      );
      value = deepScanDeadlineReached(row, () => operation.now);
    } else {
      const canonical = (path: string) => {
        calls.push(path);
        if (operation.callbackError === "validation")
          throw new WorkbenchValidationError("Scan directory must be private.");
        if (operation.callbackError === "runtime")
          throw new Error("canonical runtime failure");
        if (operation.callbackError === "value")
          throw new RangeError("canonical value failure");
        if (operation.callbackError === "type")
          throw new TypeError("canonical type failure");
        if (operation.callbackError === "os")
          throw Object.assign(new Error("canonical OS failure"), {
            errno: -13,
            code: "EACCES",
          });
        return operation.canonicalDir ?? path;
      };
      const scan = new Row(["scan_dir"], [operation.scanDir]);
      value =
        operation.kind === "path"
          ? deepScanPath(
              scan,
              operation.value,
              operation.label,
              operation.pathKind ?? "file",
              canonical,
            )
          : deepScanOutputPath(
              scan,
              operation.value,
              operation.label,
              canonical,
            );
    }
    return { value, calls };
  } catch (error) {
    return {
      error: filesystemErrorMessage(error),
      systemExit: error instanceof WorkbenchValidationError,
      calls,
    };
  }
});
process.stdout.write(stringifyJson(results, { compact: true, sortKeys: true }));
