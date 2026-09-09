import { readFileSync } from "node:fs";
import { processBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { generateRankInputCommand } from "../../../../plugins/codex-security/mcp-app/src/helpers/generate-rank-input";

const [repository, scopes, output] = process.argv.slice(2) as [
  string,
  string,
  string,
];
const queries: { pathspec: string; count: number }[] = [];
const native = processBinding();
const execute = native.rawProcess;
native.rawProcess = (request) => {
  const result = execute(request);
  const args = request.args.map((arg) =>
    arg.toString(process.platform === "win32" ? "utf16le" : "utf8"),
  );
  if (args.includes("ls-files"))
    queries.push({
      pathspec: args.at(-1)!,
      count: result.stdout.toString().split("\0").filter(Boolean).length,
    });
  return result;
};
try {
  process.exitCode = generateRankInputCommand("make-repo-scope-input", [
    "--repo",
    repository,
    "--scopes-file",
    scopes,
    "--out",
    output,
  ]);
  if (process.exitCode === 0) {
    const paths = readFileSync(output, "utf8")
      .trimEnd()
      .split("\n")
      .filter(Boolean)
      .map((row) => (JSON.parse(row) as { path: string }).path);
    console.log(JSON.stringify({ paths, queries }));
  }
} finally {
  native.rawProcess = execute;
}
