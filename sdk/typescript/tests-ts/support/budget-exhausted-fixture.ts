import { readFileSync } from "node:fs";
import {
  Row,
  type SqlValue,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  budgetExhaustedCandidates,
  budgetExhaustedDraft,
  type BudgetCandidate,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-budget-exhausted";
import { canonicalDiscoveryArtifacts } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-files";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { parsedPath } from "../../../../plugins/codex-security/mcp-app/src/helpers/resolve-security-md";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";

export interface Action {
  kind: "canonical" | "candidates" | "draft" | "draftFromLedger";
  scanDir: string;
  scan?: Record<string, unknown>;
  candidates?: BudgetCandidate[];
  warning?: string;
}
export interface Outcome {
  value?: unknown;
  error?: string;
  systemExit?: boolean;
  node: string;
}

const actions = parseJson(readFileSync(0, "utf8")) as Action[];
const results = actions.map((action): Outcome => {
  const fields: Record<string, unknown> = {
    scan_dir: action.scanDir,
    target_path: "/synthetic/repository",
    target_id: "synthetic-target",
    target_revision: "unversioned",
    target_snapshot_digest: "snapshot",
    scope: ".",
    mode: "deep",
    recipe_json: null,
    diff_target_kind: null,
    diff_base_revision: null,
    diff_head_revision: null,
    diff_content_digest: null,
    ...action.scan,
  };
  const scan = new Row(
    Object.keys(fields),
    Object.values(fields).map(
      (value) =>
        (value instanceof JsonFloat ? Number(value.source) : value) as SqlValue,
    ),
  );
  try {
    const directory = parsedPath(action.scanDir);
    let value: unknown = null;
    if (action.kind === "canonical") value = canonicalDiscoveryArtifacts(scan);
    else if (action.kind === "candidates")
      value = budgetExhaustedCandidates(scan, directory);
    else
      budgetExhaustedDraft(
        scan,
        directory,
        action.kind === "draftFromLedger"
          ? budgetExhaustedCandidates(scan, directory)
          : action.candidates ?? [],
        action.warning ?? "Synthetic cost limit reached.",
      );
    return { value, node: process.versions.node };
  } catch (error) {
    return {
      error: filesystemErrorMessage(error),
      systemExit: error instanceof WorkbenchValidationError,
      node: process.versions.node,
    };
  }
});
process.stdout.write(stringifyJson(results, { compact: true, sortKeys: true }));
