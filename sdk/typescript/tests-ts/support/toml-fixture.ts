import { readFileSync } from "node:fs";
import {
  parseToml,
  TomlDate,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/toml";
import {
  JsonFloat,
  object,
  objectEntries,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface TomlResult {
  ok: boolean;
  value?: unknown;
  error?: string;
}
function encode(value: unknown): unknown {
  if (value instanceof TomlDate) return [value.kind, value.iso];
  if (value instanceof JsonFloat) {
    const number = Number(value.source);
    const bits = Buffer.alloc(8);
    bits.writeDoubleBE(number);
    return ["float", Number.isNaN(number) ? "nan" : bits.toString("hex")];
  }
  if (typeof value === "bigint") return ["int", String(value)];
  if (typeof value === "boolean") return ["bool", value];
  if (typeof value === "string") return ["str", value];
  if (Array.isArray(value)) return ["array", value.map(encode)];
  if (object(value))
    return [
      "object",
      objectEntries(value).map(([key, child]) => [key, encode(child)]),
    ];
  throw new Error("Unexpected TOML value");
}
const requests = JSON.parse(readFileSync(0, "utf8")) as string[];
const responses = requests.map((source): TomlResult => {
  try {
    return { ok: true, value: encode(parseToml(source)) };
  } catch (error) {
    return { ok: false, error: (error as Error).message };
  }
});
process.stdout.write(JSON.stringify(responses));
