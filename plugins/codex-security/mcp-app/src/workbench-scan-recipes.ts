import type { Connection } from "../../native/sqlite.mjs";
import { fileInfo } from "./helpers/helper-files";
import { JsonSyntaxError, object } from "./helpers/python-json";
import { appendPath, pathKey, relativePath } from "./helpers/rank-selection";
import { resolvedPath } from "./helpers/resolve-path";
import { parsedPath } from "./helpers/resolve-security-md";
import { JsonValueError, loadsJson } from "./helpers/scan-contract-json";
import { encodeUtf8, UnicodeDecodeError } from "./helpers/utf8";
import { requireScan } from "./workbench-records";
import { requireTarget } from "./workbench-setup";
import { WorkbenchValidationError } from "./workbench-validation";

export interface ScanRecipe extends Record<string, unknown> {
  repository: string;
  mode: "standard" | "deep";
  config: Record<string, unknown>;
  target: Record<string, unknown> &
    (
      | { kind: "repository" | "paths"; paths: string[] }
      | {
          kind: "refs" | "working_tree";
          paths: string[];
          base: string;
          head: string;
        }
    );
}

function member(value: unknown, choices: readonly string[]): boolean {
  if (Array.isArray(value) || object(value))
    throw new TypeError(
      `unhashable type: '${Array.isArray(value) ? "list" : "dict"}'`,
    );
  return typeof value === "string" && choices.includes(value);
}

export function parseScanRecipe(value: string, repository: string): ScanRecipe {
  if (encodeUtf8(value).length > 256 * 1024)
    throw new WorkbenchValidationError(
      "Scan launch recipe must be no larger than 256 KiB.",
    );
  let recipe: unknown;
  try {
    recipe = loadsJson(value);
  } catch (error) {
    if (
      !(
        error instanceof TypeError ||
        error instanceof JsonSyntaxError ||
        error instanceof JsonValueError ||
        error instanceof UnicodeDecodeError
      )
    )
      throw error;
    throw new WorkbenchValidationError(
      "Scan launch recipe must be a valid JSON object.",
    );
  }
  if (!object(recipe))
    throw new WorkbenchValidationError(
      "Scan launch recipe must be a JSON object.",
    );
  repository = parsedPath(repository);
  const requestedRepository = recipe["repository"];
  if (
    typeof requestedRepository !== "string" ||
    pathKey(requireTarget(requestedRepository)) !== pathKey(repository)
  )
    throw new WorkbenchValidationError(
      "Scan launch recipe repository must match the scanned repository.",
    );
  if (!member(recipe["mode"], ["standard", "deep"]))
    throw new WorkbenchValidationError(
      "Scan launch recipe mode must be standard or deep.",
    );
  if (!object(recipe["config"]))
    throw new WorkbenchValidationError(
      "Scan launch recipe config must be a JSON object.",
    );
  const target = recipe["target"];
  if (
    !object(target) ||
    !member(target["kind"], ["repository", "paths", "refs", "working_tree"])
  )
    throw new WorkbenchValidationError(
      "Scan launch recipe target must identify a supported scan target.",
    );
  const paths = target["paths"];
  if (!Array.isArray(paths) || !paths.every((path) => typeof path === "string"))
    throw new WorkbenchValidationError(
      "Scan launch recipe target paths must be an array of strings.",
    );
  if (target["kind"] === "paths" && paths.length === 0)
    throw new WorkbenchValidationError(
      "A scoped scan launch recipe must include at least one target path.",
    );
  if (target["kind"] !== "paths" && paths.length !== 0)
    throw new WorkbenchValidationError(
      "Only scoped scan launch recipes can include target paths.",
    );
  for (const path of paths) {
    const candidate = appendPath(repository, path);
    if (
      !path ||
      path.startsWith("/") ||
      path.split("/").includes("..") ||
      path.includes("\\") ||
      path.includes("\0") ||
      (process.platform !== "win32" &&
        /[\ud800-\udc7f\udd00-\udfff]/u.test(path)) ||
      fileInfo(candidate) === undefined ||
      relativePath(
        resolvedPath(candidate, false, { preserveRelativeErrors: true }),
        repository,
      ) === undefined
    )
      throw new WorkbenchValidationError(
        "Scan launch recipe target paths must exist inside the repository.",
      );
  }
  if (target["kind"] === "refs" || target["kind"] === "working_tree") {
    if (
      typeof target["base"] !== "string" ||
      typeof target["head"] !== "string"
    )
      throw new WorkbenchValidationError(
        "Diff scan launch recipes require resolved base and head revisions.",
      );
  }
  return recipe as ScanRecipe;
}

export function setScanThread(
  connection: Connection,
  args: { scanId: string; threadId: string },
  now: () => string,
): { scanId: string; threadId: string } {
  const scan = requireScan(connection, args.scanId);
  connection.transaction(() => {
    connection
      .prepare(
        "UPDATE scans SET continuation_thread_id = ?, updated_at = ? WHERE id = ?",
      )
      .run([args.threadId, now(), scan.get("id")]);
  });
  return { scanId: scan.get("id") as string, threadId: args.threadId };
}

export function getScanRecipe(
  connection: Connection,
  args: { scanId: string },
): Record<string, unknown> {
  const scan = requireScan(connection, args.scanId);
  if (scan.get("recipe_json") === null)
    throw new WorkbenchValidationError(
      "This scan does not have a saved launch recipe.",
    );
  return {
    parentScanId: scan.get("parent_scan_id"),
    recipe: loadsJson(scan.get("recipe_json") as string | Buffer),
    scanId: scan.get("id"),
  };
}
