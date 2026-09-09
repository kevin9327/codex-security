import { readFileSync } from "node:fs";
import { compareCapability } from "../../../../plugins/codex-security/mcp-app/src/helpers/config-preflight";
import { decodeTomlBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/toml-file";
import { parseToml } from "../../../../plugins/codex-security/mcp-app/src/helpers/toml";
import {
  object,
  pythonRepr,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

interface Request {
  bytes?: number[];
  source?: string;
  other?: string;
}
export interface Response {
  text?: string;
  repr?: string;
  table?: boolean;
  equal?: boolean;
  jsonError?: string;
  error?: string;
}
const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
const results = requests.map((request): Response => {
  try {
    if (request.bytes !== undefined)
      return { text: decodeTomlBytes(Buffer.from(request.bytes)) };
    const value = parseToml(`value = ${request.source}`)["value"];
    let jsonError: string | undefined;
    try {
      stringifyJson(value);
    } catch (error) {
      jsonError = (error as Error).message;
    }
    return {
      repr: pythonRepr(value),
      table: object(value),
      jsonError,
      ...(request.other === undefined
        ? {}
        : {
            equal: compareCapability(
              value,
              "==",
              parseToml(`value = ${request.other}`)["value"],
            ),
          }),
    };
  } catch (error) {
    return { error: (error as Error).message };
  }
});
process.stdout.write(JSON.stringify(results));
