import { readdirSync } from "node:fs";
import { basename, dirname } from "node:path";
import type { Connection, Parameter } from "../../native/sqlite.mjs";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { windowsBinding } from "./native";
import { environment } from "./helpers/environment";
import { fileInfo } from "./helpers/helper-files";
import { encodePosixPath } from "./helpers/posix-path";
import { preflightInteger } from "./helpers/preflight-config";
import {
  JsonFloat,
  jsonGet,
  jsonItem,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { appendPath, relativePath } from "./helpers/rank-selection";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { ensureSecurityTarget } from "./workbench-db";
import { requireCanonicalScanDirectory } from "./workbench-files";
import { registerWorkflowScan } from "./workbench-finding-workflows";
import { requireScan, requireWorkspace } from "./workbench-records";
import { scanContract } from "./workbench-results";
import { parseScanRecipe } from "./workbench-scan-recipes";
import {
  archiveScan,
  insertRunningScan,
  scanDiffIdentity,
} from "./workbench-scan-start";
import {
  requireReviewChangesTarget,
  requireScannableTarget,
  requireTarget,
  resolveGitCommit,
} from "./workbench-setup";
import {
  directorySnapshotRegularFileCount,
  scanTargetIdentity,
  worktreeContentDigest,
} from "./workbench-target";
import { requireUuid, WorkbenchValidationError } from "./workbench-validation";

export interface CliRegistrationArguments {
  repository: string;
  scanDir: string;
  recipeJson: string | null;
  recipeJsonStdin: boolean;
  registrationJsonStdin: boolean;
  parentScanId: string | null;
  archivedScanDir: string | null;
  archiveExisting: boolean;
}
export interface CliRegistrationContext {
  now(): string;
  uuid(): string;
  stdin(): string;
}
export interface RegisteredCliScan {
  contract: ReturnType<typeof scanContract>;
  scanDir: string;
  scanId: string;
  scopeFileCount: bigint;
  targetId: string;
  targetRevision: string;
}

function registrationRecipeJson(value: unknown): string {
  return stringifyJson(value, {
    compact: true,
    separators: [",", ":"],
  }).replace(
    /\\(?:u([0-9a-f]{4})|[\s\S])/gu,
    (escape, hex: string | undefined) =>
      hex !== undefined && Number.parseInt(hex, 16) >= 0x7f
        ? String.fromCharCode(Number.parseInt(hex, 16))
        : escape,
  );
}
const parameter = (value: unknown): Parameter =>
  (value instanceof JsonFloat ? Number(value.source) : value) as Parameter;

export function registerCliScan(
  context: CliRegistrationContext,
  connection: Connection,
  args: CliRegistrationArguments,
): RegisteredCliScan {
  const repository = requireTarget(args.repository);
  requireScannableTarget(repository);
  const scanDir = requireCanonicalScanDirectory(
    expandHome(parsedPath(args.scanDir), environment("HOME")),
  );
  if (relativePath(scanDir, repository) !== undefined)
    throw new WorkbenchValidationError(
      "The scan artifact directory must be outside the selected target.",
    );
  const entries =
    process.platform === "win32"
      ? windowsFileSystem(windowsBinding()).entriesWithTypes(widePath(scanDir))
      : readdirSync(encodePosixPath(scanDir), { encoding: "buffer" });
  if (entries.length)
    throw new WorkbenchValidationError(
      "The scan artifact directory must be empty before the scan starts.",
    );
  let userContext: unknown = null,
    workflowId: unknown = null,
    recipeJson: string;
  if (args.registrationJsonStdin) {
    const registration = parseJson(context.stdin(), false, preflightInteger);
    recipeJson = registrationRecipeJson(jsonItem(registration, "recipe"));
    userContext = jsonGet(registration, "userContext");
    workflowId = jsonGet(registration, "workflowId");
  } else recipeJson = args.recipeJsonStdin ? context.stdin() : args.recipeJson!;
  const recipe = parseScanRecipe(recipeJson, repository),
    requestedTarget = recipe.target,
    paths = requestedTarget.paths,
    scope = paths.length === 1 ? paths[0]! : ".";
  let diffTarget: Record<string, string> | null = null;
  if (
    requestedTarget.kind === "refs" ||
    requestedTarget.kind === "working_tree"
  ) {
    const currentHead = requireReviewChangesTarget(repository),
      base = resolveGitCommit(
        repository,
        requestedTarget.base,
        "Base revision",
      ),
      head = resolveGitCommit(
        repository,
        requestedTarget.head,
        "Head revision",
      );
    diffTarget = {
      kind: requestedTarget.kind === "refs" ? "range" : "working_tree",
      baseRevision: base,
      headRevision: head,
    };
    if (requestedTarget.kind === "working_tree") {
      if (head !== currentHead)
        throw new WorkbenchValidationError(
          "Working-tree HEAD changed before the scan started.",
        );
      diffTarget["contentDigest"] = worktreeContentDigest(repository);
    }
  }
  const mode = diffTarget !== null ? "diff" : recipe.mode,
    targetIdentity = scanTargetIdentity(repository, diffTarget),
    scopeFileCount = paths.length
      ? paths.reduce((count, path) => {
          const target = appendPath(repository, path);
          return (
            count +
            (fileInfo(target)?.isFile()
              ? 1n
              : BigInt(directorySnapshotRegularFileCount(target)))
          );
        }, 0n)
      : BigInt(directorySnapshotRegularFileCount(repository)),
    parentScanId =
      args.parentScanId !== null
        ? requireUuid(args.parentScanId, "parent-scan-id")
        : null,
    timestamp = context.now(),
    scanId = context.uuid(),
    workspaceId = context.uuid();
  connection.prepare("BEGIN IMMEDIATE").run();
  let targetId: string;
  try {
    archiveScan(
      connection,
      args,
      scanDir,
      timestamp,
      requireCanonicalScanDirectory,
    );
    targetId = ensureSecurityTarget(connection, repository, () =>
      context.now(),
    );
    if (
      parentScanId !== null &&
      requireScan(connection, parentScanId).get("target_id") !== targetId
    )
      throw new WorkbenchValidationError(
        "A rerun must belong to the same repository as its parent scan.",
      );
    connection
      .prepare(
        `
      INSERT INTO workspaces (
          id, target_id, target_path, target_title, default_scope, default_mode,
          diff_target_kind, diff_base_revision, diff_head_revision,
          diff_content_digest, submitted, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `,
      )
      .run([
        workspaceId,
        targetId,
        repository,
        basename(repository),
        scope,
        mode,
        ...scanDiffIdentity(diffTarget),
        timestamp,
        timestamp,
      ]);
    const workspace = requireWorkspace(connection, workspaceId);
    insertRunningScan(connection, {
      scanId,
      workspace,
      target: repository,
      scope,
      diffTarget,
      targetIdentity,
      targetRoot: dirname(scanDir),
      targetSummary: null,
      scopeFileCount,
      timestamp,
      handoffStatus: "delivered",
      scanDir,
    });
    connection
      .prepare(
        "UPDATE scans SET recipe_json = ?, parent_scan_id = ?, user_context = ? WHERE id = ?",
      )
      .run([
        stringifyJson(recipe, {
          allowNan: false,
          separators: [",", ":"],
          compact: true,
          sortKeys: true,
        }),
        parentScanId,
        parameter(userContext),
        scanId,
      ]);
    if (workflowId !== null)
      registerWorkflowScan(
        connection,
        parameter(workflowId) as string,
        scanId,
        scanDir,
        timestamp,
      );
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  const scan = requireScan(connection, scanId);
  return {
    contract: scanContract(scan),
    scanDir,
    scanId,
    scopeFileCount,
    targetId,
    targetRevision: scan.get("target_revision") as string,
  };
}
