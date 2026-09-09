import { readFileSync } from "node:fs";
import { processBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { cleanWorktreeContentDigest } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import {
  findingSourceExcerpt,
  safeSourcePath,
  scannedSourceText,
  type ExcerptScan,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/workbench-source-excerpt";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface Request {
  action: "excerpt" | "source" | "safe" | "clean";
  target?: string | null;
  scan?: string;
  path?: string;
  locations?: string;
}
export interface Response {
  result?: string | null;
  queries: string[][];
  unchanged?: boolean;
  error?: string;
}
const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
const native = processBinding(),
  execute = native.rawProcess;
const responses = requests.map((request): Response => {
  const queries: string[][] = [];
  native.rawProcess = (args) => {
    queries.push(
      args.args.map((value) =>
        process.platform === "win32"
          ? value.toString("utf16le")
          : decodePosixBytes(value),
      ),
    );
    return execute(args);
  };
  try {
    const scan = parseJson(request.scan ?? "{}") as ExcerptScan;
    const locations = parseJson(request.locations ?? "[]") as Record<
      string,
      unknown
    >[];
    const before = stringifyJson([scan, locations], { compact: true });
    const target = request.target ?? null;
    const result =
      request.action === "clean"
        ? cleanWorktreeContentDigest()
        : request.action === "safe"
          ? safeSourcePath(target!, request.path!)
          : request.action === "source"
            ? scannedSourceText(scan, target!, request.path!)
            : findingSourceExcerpt(scan, target, locations);
    return {
      result,
      queries,
      unchanged: before === stringifyJson([scan, locations], { compact: true }),
    };
  } catch (error) {
    return { queries, error: (error as Error).message };
  } finally {
    native.rawProcess = execute;
  }
});
process.stdout.write(JSON.stringify(responses));
