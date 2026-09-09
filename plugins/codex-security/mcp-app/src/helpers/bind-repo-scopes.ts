import { decodeUtf8 } from "./utf8";
import { readFile, writeFile } from "./helper-files";
import { object, parseJson, stringifyJson } from "./python-json";
import {
  ArgumentError,
  argumentsFor,
  loadScopesFile,
  print,
  worklistPath,
} from "./rank-worklists";

const read = (path: string) => parseJson(decodeUtf8(readFile(path)));

export function bindRepoScopesCommand(
  args: string[],
  posixHome = process.env.HOME,
): number {
  const required = ["scopes-file", "manifest", "coverage"];
  const usage =
    "usage: launch_codex_security_mcp[.cmd] --helper bind-repo-scopes [-h] --scopes-file PATH --manifest PATH --coverage PATH";
  try {
    const values = argumentsFor(args, required);
    if (values.help) {
      print(
        `${usage}\n\nCopy SDK scoped-path targets into the unsealed manifest and coverage documents.\n\noptions:\n  -h, --help  show this help message and exit\n${required.map((name) => `  --${name} PATH`).join("\n")}`,
      );
      return 0;
    }
    const scopesPath = worklistPath(values["scopes-file"] as string, posixHome);
    const scopes = loadScopesFile(scopesPath);
    const manifestPath = worklistPath(values.manifest as string, posixHome);
    const coveragePath = worklistPath(values.coverage as string, posixHome);
    let manifest: unknown, coverage: unknown, scope: unknown;
    try {
      manifest = read(manifestPath);
      coverage = read(coveragePath);
      if (!object(manifest) || !object(coverage) || !object(manifest.scan))
        throw new Error("expected JSON objects");
      scope = manifest.scan.scope;
      if (!object(scope))
        throw new Error("manifest.scan.scope must be an object");
    } catch {
      throw new Error("Unable to bind requested scopes into the scan contract");
    }
    scope.includePaths = scopes;
    coverage.includePaths = scopes;
    for (const [path, value] of [
      [manifestPath, manifest],
      [coveragePath, coverage],
    ] as const) {
      const contents = stringifyJson(value) + "\n";
      writeFile(path, [
        Buffer.from(
          process.platform === "win32"
            ? contents.replaceAll("\n", "\r\n")
            : contents,
        ),
      ]);
    }
    print(`Bound ${scopes.length} requested scopes into the scan contract`);
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    print(
      error instanceof ArgumentError
        ? `${usage}\nbind-repo-scopes: error: ${message}`
        : message,
      true,
    );
    return error instanceof ArgumentError ? 2 : 1;
  }
}
