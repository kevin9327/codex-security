import fs from "node:fs";
import * as validation from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { Connection } from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
export interface Request {
  operation: string;
  source: string;
}
export interface Response {
  result?: string;
  error?: string;
  kind?: string;
  reads: number;
}
const cases = JSON.parse(fs.readFileSync(0, "utf8")) as {
  operation: string;
  source: string;
}[];
const results = cases.map((item) => {
  const args = parseJson(item.source) as Record<string, unknown>;
  let reads = 0;
  const value = () => {
    switch (item.operation) {
      case "uuid":
        return validation.requireUuid(args["value"] as string, "id");
      case "text":
        return validation.optionalText(
          args["value"] as string | null,
          args["maximum"] === null || args["maximum"] === undefined
            ? undefined
            : Number(args["maximum"]),
        );
      case "busy":
        return validation.sqliteBusy(new Error(args["value"] as string));
      case "scope":
        return validation.pathWithinScope(
          args["path"] as string,
          args["scope"] as string,
        );
      case "note":
        return (
          validation.requireCloseNote(
            args["reason"] as string | null,
            args["note"] as string | null,
          ) ?? null
        );
      case "context":
        return validation.userContextArgument(
          {
            userContext: args["value"] as string | null,
            userContextStdin: args["stdin"] as boolean,
          },
          () => {
            reads++;
            return args["input"] as string;
          },
        );
      case "cost":
        return validation.parseScanCost(args["value"] as string | null);
      case "legacy":
        return validation.validLegacyScanCost(args["value"]);
      case "measured":
        return validation.validMeasuredScanUsage(args["value"]);
      case "counts":
        return validation.validScanTokenCounts(args["value"]);
      case "bounded":
        return validation.boundedOutputText(
          args["value"],
          Number(args["maximum"]),
        );
      case "occurrence": {
        const c = new Connection(sqliteBinding(), ":memory:");
        try {
          c.exec(
            "CREATE TABLE finding_occurrences (id TEXT, details TEXT, ordinal INTEGER)",
          );
          c.prepare("INSERT INTO finding_occurrences VALUES (?, ?, ?)").run([
            "known",
            "record",
            1n,
          ]);
          return validation.requireOccurrence(
            c,
            args["value"] as string | null,
          );
        } finally {
          c.close();
        }
      }
      default:
        throw new Error(item.operation);
    }
  };
  try {
    return { result: stringifyJson(value()), reads };
  } catch (error) {
    return {
      error: (error as Error).message,
      kind: (error as Error).constructor.name,
      reads,
    };
  }
});
process.stdout.write(JSON.stringify(results));
