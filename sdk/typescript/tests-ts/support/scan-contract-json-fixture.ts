import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  contractJsonBytes,
  jsonBytes,
  loadsJson,
  readJson,
  readScanLocalJson,
  readScanLocalJsonBytes,
  requireSafeJsonString,
  requireSafeJsonValue,
  writeScanLocalJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-contract-json";
import {
  parseJson,
  parseJsonBytes,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodeTomlBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/toml-file";

import { decodeUtf8 } from "../../../../plugins/codex-security/mcp-app/src/helpers/utf8";

export interface JsonCase {
  operation:
    | "loads"
    | "validate"
    | "string"
    | "jsonBytes"
    | "contractBytes"
    | "read"
    | "scanRead"
    | "scanReadBytes"
    | "write"
    | "defaultUtf8"
    | "decode"
    | "defaultBytes";
  source?: string;
  hex?: string;
  validateStrings?: boolean;
  relative?: string;
  missing?: boolean;
  directory?: boolean;
  size?: number;
  escaped?: boolean;
  depth?: number;
  summarize?: boolean;
}
export interface JsonRequest {
  root: string;
  cases: JsonCase[];
}

const request = JSON.parse(readFileSync(0, "utf8")) as JsonRequest;
const describe = (bytes: Buffer) => ({
  length: bytes.length,
  sha256: createHash("sha256").update(bytes).digest("hex"),
});
function run(item: JsonCase, index: number): unknown {
  const directory = join(request.root, String(index));
  rmSync(directory, { recursive: true, force: true });
  mkdirSync(directory, { recursive: true });
  const relative = item.relative ?? "data.json",
    path = join(directory, "data.json");
  let source = item.source ?? "{}";
  if (item.size !== undefined)
    source = JSON.stringify({
      metadata: (item.escaped ? "\n" : "x").repeat(item.size),
    });
  if (item.depth !== undefined)
    source = "[".repeat(item.depth) + "0" + "]".repeat(item.depth);
  const raw =
    item.hex === undefined ? Buffer.from(source) : Buffer.from(item.hex, "hex");
  const output = (value: unknown) => {
    const encoded = stringifyJson(value, { compact: true });
    return item.summarize ? describe(Buffer.from(encoded)) : { json: encoded };
  };
  try {
    switch (item.operation) {
      case "loads":
        return output(loadsJson(item.hex === undefined ? source : raw));
      case "defaultBytes":
        return output(parseJsonBytes(raw));
      case "defaultUtf8":
        return { text: decodeUtf8(raw) };
      case "decode":
        return { text: decodeTomlBytes(raw) };
      case "validate":
        requireSafeJsonValue(
          parseJson(source),
          "document",
          item.validateStrings,
        );
        return null;
      case "string":
        requireSafeJsonString(source, "document");
        return null;
      case "jsonBytes":
      case "contractBytes": {
        const bytes =
          item.operation === "jsonBytes"
            ? jsonBytes(parseJson(source))
            : contractJsonBytes("document", parseJson(source));
        return item.summarize
          ? describe(bytes)
          : { hex: bytes.toString("hex") };
      }
      case "read":
      case "scanRead":
      case "scanReadBytes": {
        if (!item.missing) {
          if (item.directory) mkdirSync(path);
          else writeFileSync(path, raw);
        }
        if (item.operation === "read") return output(readJson(path));
        if (item.operation === "scanRead")
          return output(readScanLocalJson(directory, relative, "document"));
        const [value, original] = readScanLocalJsonBytes(
          directory,
          relative,
          "document",
        );
        return { ...output(value), raw: describe(original) };
      }
      case "write": {
        writeFileSync(path, "previous contents");
        try {
          writeScanLocalJson(
            item.missing ? join(directory, "missing") : directory,
            relative,
            parseJson(source),
          );
        } catch (error) {
          return {
            ...failure(error),
            after: readFileSync(path).toString("hex"),
          };
        }
        return { hex: readFileSync(join(directory, relative)).toString("hex") };
      }
    }
  } catch (error) {
    return failure(error);
  } finally {
    if (existsSync(directory))
      rmSync(directory, { recursive: true, force: true });
  }
}
function failure(error: unknown) {
  const value = error as Error & { code?: string; winerror?: number };
  if (value.winerror === 5) return { osError: "EACCES" };
  if (value.code) return { osError: value.code };
  const names: Record<string, string> = {
    JsonSyntaxError: "JSONDecodeError",
    JsonValueError: "ValueError",
  };
  return {
    error: names[value.constructor.name] ?? value.constructor.name,
    message: value.message,
  };
}
process.stdout.write(JSON.stringify(request.cases.map(run)));
