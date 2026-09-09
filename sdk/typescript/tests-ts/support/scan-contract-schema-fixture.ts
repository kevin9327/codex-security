import { readFileSync } from "node:fs";
import {
  validateAgainstSchema,
  type ContractSchema,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-schema";
import { validateDateTime } from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-date-time";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface Request {
  source: string;
  timestamp?: boolean;
}
export interface Response {
  error: string | null;
  kind?: string;
  unchanged: boolean;
}
const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
const results = requests.map(({ source, timestamp }): Response => {
  const [value, schema] = parseJson(source) as [unknown, ContractSchema];
  const before = stringifyJson([value, schema]);
  let error: string | null = null,
    kind: string | undefined;
  try {
    if (timestamp) validateDateTime(value as string, "artifact");
    else validateAgainstSchema(value, schema, "artifact");
  } catch (failure) {
    error = (failure as Error).message;
    const caught = failure as Error;
    kind = caught.name === "Error" ? caught.constructor.name : caught.name;
  }
  return {
    error,
    ...(kind === undefined ? {} : { kind }),
    unchanged: before === stringifyJson([value, schema]),
  };
});
process.stdout.write(JSON.stringify(results));
