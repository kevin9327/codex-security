import { readFileSync } from "node:fs";
import {
  buildCsvProjection,
  csvCell,
  findingCandidateId,
  legacySealedFindingsForValidation,
  type CsvFinding,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/saved-findings-projection";
import {
  objectEntries,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { encodeUtf8 } from "../../../../plugins/codex-security/mcp-app/src/helpers/utf8";

export interface Request {
  operation: "legacy" | "csv" | "candidate" | "cell" | "entries" | "encode";
  source: string;
}
export interface Response {
  source?: string;
  hex?: string;
  error?: string;
  unchanged: boolean;
}
const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
process.stdout.write(
  JSON.stringify(
    requests.map(({ operation, source }): Response => {
      const value = parseJson(source);
      const before = stringifyJson(value);
      const table = value as Record<string, unknown>;
      let result: Omit<Response, "unchanged">;
      try {
        if (operation === "csv") {
          const [findings, coverage] = value as [
            { findings: CsvFinding[] },
            Record<string, unknown>,
          ];
          result = {
            hex: buildCsvProjection(findings, coverage).toString("hex"),
          };
        } else if (operation === "encode")
          result = { hex: encodeUtf8(value as string).toString("hex") };
        else if (operation === "entries") {
          delete table["remove"];
          result = { source: stringifyJson(objectEntries(table)) };
        } else
          result = {
            source: stringifyJson(
              operation === "legacy"
                ? legacySealedFindingsForValidation(table)
                : operation === "candidate"
                  ? findingCandidateId(table)
                  : csvCell(value),
            ),
          };
      } catch (failure) {
        result = { error: (failure as Error).message };
      }
      return {
        ...result,
        unchanged: operation === "entries" || before === stringifyJson(value),
      };
    }),
  ),
);
