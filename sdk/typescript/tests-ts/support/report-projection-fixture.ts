import { readFileSync } from "node:fs";
import {
  buildReportMarkdown,
  generateReportMarkdown,
  type ReportCoverage,
  type ReportFinding,
  type ReportManifest,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/report-projection";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export type Documents = [
  ReportManifest,
  { findings: ReportFinding[] },
  ReportCoverage,
];
export interface Request {
  source: string;
  generate?: boolean;
}
export interface Response {
  result?: string;
  error?: string;
  errorType?: string;
  unchanged: boolean;
}

const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
const responses = requests.map(({ source, generate }): Response => {
  const documents = parseJson(source) as Documents;
  const before = stringifyJson(documents);
  let result: Omit<Response, "unchanged">;
  try {
    result = {
      result: generate
        ? generateReportMarkdown(...documents).toString("base64")
        : buildReportMarkdown(...documents),
    };
  } catch (error) {
    result = {
      error: error instanceof Error ? error.message : String(error),
      errorType: error instanceof Error ? error.constructor.name : "unknown",
    };
  }
  return { ...result, unchanged: before === stringifyJson(documents) };
});
process.stdout.write(JSON.stringify(responses));
