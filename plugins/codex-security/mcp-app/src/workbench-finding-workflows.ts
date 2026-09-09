import { createHash } from "node:crypto";
import type { Connection, Parameter, SqlValue } from "../../native/sqlite.mjs";
import { contractValuesEqual } from "./helpers/contract-validation";
import { preflightInteger } from "./helpers/preflight-config";
import {
  JsonFloat,
  jsonContains,
  jsonGet,
  jsonItem,
  jsonTypeName,
  object,
  objectEntries,
  parseJson,
  parseJsonBytes,
  stringifyJson,
} from "./helpers/python-json";
import { parsedPath } from "./helpers/resolve-security-md";
import { resolvedPath } from "./helpers/resolve-path";
import { encodeUtf8 } from "./helpers/utf8";
import { gitOutput } from "./workbench-git";
import { directoryContentDigest, gitRevision } from "./workbench-target";
import { optionalText, WorkbenchValidationError } from "./workbench-validation";

const bindings = {
  repositoryPath: "repository_path",
  scanRequestDigest: "scan_request_digest",
  scanId: "scan_id",
  scanDir: "scan_dir",
  artifactDigest: "artifact_digest",
  destination: "destination",
} as const;
const stages = ["scan", "publish", "dedupe"] as const;
type Stage = (typeof stages)[number];
interface StageState extends Record<string, unknown> {
  status: SqlValue;
}
export interface FindingWorkflowState extends Record<string, unknown> {
  id: SqlValue;
  stages: Record<Stage, StageState>;
}
const parameters = (values: unknown[]): Parameter[] =>
  values.map((value) =>
    value instanceof JsonFloat ? Number(value.source) : value,
  ) as Parameter[];
function storedJson(value: SqlValue): unknown {
  if (typeof value === "string")
    return parseJson(value, false, preflightInteger);
  if (Buffer.isBuffer(value))
    return parseJsonBytes(value, false, preflightInteger);
  throw new TypeError(
    `the JSON object must be str, bytes or bytearray, not ${jsonTypeName(value)}`,
  );
}
function workflowJson(value: unknown): string {
  return stringifyJson(value, { compact: true, allowNan: false });
}

export function readFindingWorkflow(
  connection: Connection,
  workflowId: string,
): FindingWorkflowState | null {
  const row = connection
    .prepare("SELECT * FROM finding_workflows WHERE id = ?")
    .get([workflowId]);
  if (row === undefined) return null;
  const state: FindingWorkflowState = {
    id: row.get("id"),
    stages: {} as Record<Stage, StageState>,
  };
  for (const [field, column] of Object.entries(bindings))
    if (row.get(column) !== null) state[field] = row.get(column);
  if (row.get("scope_repository_id") !== null)
    state["scope"] = { repositoryId: row.get("scope_repository_id") };
  else if (row.get("scope_all_repositories") !== null)
    state["scope"] = {
      allRepositories: Boolean(row.get("scope_all_repositories")),
    };
  const results = storedJson(row.get("results_json"));
  for (const stage of stages) {
    const current: StageState = { status: row.get(`${stage}_status`) };
    if (row.get(`${stage}_error`) !== null)
      current["error"] = row.get(`${stage}_error`);
    if (jsonContains(results, stage))
      current["result"] = jsonItem(results, stage);
    state.stages[stage] = current;
  }
  if (jsonContains(results, "dedupePendingWrite"))
    state.stages.dedupe["pendingWrite"] = jsonItem(
      results,
      "dedupePendingWrite",
    );
  return state;
}

export function saveFindingWorkflow(
  connection: Connection,
  state: FindingWorkflowState,
  timestamp: string,
): void {
  const values: Record<string, unknown> = { id: jsonItem(state, "id") };
  for (const [field, column] of Object.entries(bindings))
    values[column] = jsonGet(state, field);
  const scope = jsonGet(state, "scope", {});
  values["scope_repository_id"] = jsonGet(scope, "repositoryId");
  values["scope_all_repositories"] = jsonGet(scope, "allRepositories");
  const results: Record<string, unknown> = {};
  for (const stage of stages) {
    const current = jsonItem(jsonItem(state, "stages"), stage);
    values[`${stage}_status`] = jsonItem(current, "status");
    values[`${stage}_error`] = jsonGet(current, "error");
    if (jsonContains(current, "result"))
      results[stage] = jsonItem(current, "result");
  }
  const dedupe = jsonItem(jsonItem(state, "stages"), "dedupe");
  if (jsonContains(dedupe, "pendingWrite"))
    results["dedupePendingWrite"] = jsonItem(dedupe, "pendingWrite");
  values["results_json"] = workflowJson(results);
  values["created_at"] = timestamp;
  values["updated_at"] = timestamp;
  const columns = Object.keys(values),
    updates = columns
      .filter((column) => column !== "id" && column !== "created_at")
      .map((column) => `${column} = excluded.${column}`)
      .join(", ");
  connection
    .prepare(
      `INSERT INTO finding_workflows (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")}) ON CONFLICT(id) DO UPDATE SET ${updates}`,
    )
    .run(parameters(Object.values(values)));
}

export function bindFindingWorkflow(
  state: FindingWorkflowState,
  binding: unknown,
): void {
  if (!object(binding))
    throw new TypeError(
      `'${jsonTypeName(binding)}' object has no attribute 'items'`,
    );
  for (const [field, value] of objectEntries(binding)) {
    if (!Object.hasOwn(bindings, field) && field !== "scope")
      throw new WorkbenchValidationError("Unknown workflow binding.");
    if (
      Object.hasOwn(state, field) &&
      !contractValuesEqual(state[field], value)
    )
      throw new WorkbenchValidationError(
        `Workflow ${state.id} is already bound to a different ${field}. Use another --workflow-id.`,
      );
    state[field] = value;
  }
}

export function registerWorkflowScan(
  connection: Connection,
  workflowId: string,
  scanId: string,
  scanDir: string,
  timestamp: string,
): void {
  const state = readFindingWorkflow(connection, workflowId);
  if (state === null)
    throw new WorkbenchValidationError(
      "The workflow must be started before registering its scan.",
    );
  if (state.stages.scan.status === "completed")
    throw new WorkbenchValidationError(
      "The workflow scan is already complete.",
    );
  const previous = jsonGet(state, "scanId");
  if (previous !== null) {
    const row = connection
      .prepare("SELECT status FROM scans WHERE id = ?")
      .get(parameters([previous]));
    if (row !== undefined && row.get("status") === "complete")
      throw new WorkbenchValidationError(
        "Reuse the workflow's completed scan instead of registering another.",
      );
  }
  state["scanId"] = scanId;
  state["scanDir"] = scanDir;
  saveFindingWorkflow(connection, state, timestamp);
}

export function findingWorkflow(
  connection: Connection,
  payload: unknown,
  timestamp: string,
): Record<string, unknown> {
  const id = jsonItem(payload, "id");
  if (typeof id !== "string" || optionalText(id) === null)
    throw new WorkbenchValidationError("workflowId must be a nonempty string.");
  if (jsonItem(payload, "action") === "get")
    return { workflow: readFindingWorkflow(connection, id) };
  if (jsonItem(payload, "action") === "source") {
    const repository = jsonItem(payload, "repository");
    if (typeof repository !== "string")
      throw new TypeError(
        `argument should be a str or an os.PathLike object where __fspath__ returns a str, not '${jsonTypeName(repository)}'`,
      );
    const target = resolvedPath(parsedPath(repository), true);
    return {
      source: {
        repository: target,
        revision: gitRevision(target),
        refsDigest: createHash("sha256")
          .update(encodeUtf8(gitOutput(target, ["show-ref"]) || ""))
          .digest("hex"),
        content: directoryContentDigest(target, { includeIgnored: true }),
      },
    };
  }
  if (jsonItem(payload, "action") === "get-review") {
    const row = connection
      .prepare(
        "SELECT result_json FROM finding_workflow_reviews WHERE workflow_id = ? AND review_key = ?",
      )
      .get(parameters([id, jsonItem(payload, "key")]));
    return {
      review: row === undefined ? null : storedJson(row.get("result_json")),
    };
  }
  if (jsonItem(payload, "action") === "save-review") {
    const binding = jsonItem(payload, "binding"),
      source = jsonItem(binding, "source"),
      scope = jsonItem(binding, "scope");
    connection.transaction(() => {
      connection
        .prepare(
          `INSERT INTO finding_workflow_reviews
        (workflow_id, review_key, review_contract_version, codex_version,
         source_repository_path, source_revision, source_refs_digest, source_content_digest,
         scope_repository_id, scope_all_repositories, model, effort, settings_digest,
         prompt_digest, contract_digest, result_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(workflow_id, review_key) DO NOTHING`,
        )
        .run(
          parameters([
            id,
            jsonItem(payload, "key"),
            jsonItem(binding, "version"),
            jsonItem(binding, "codexVersion"),
            jsonItem(source, "repository"),
            jsonItem(source, "revision"),
            jsonItem(source, "refsDigest"),
            jsonItem(source, "content"),
            jsonGet(scope, "repositoryId"),
            jsonGet(scope, "allRepositories"),
            jsonItem(binding, "model"),
            jsonItem(binding, "effort"),
            jsonGet(binding, "settingsDigest"),
            jsonItem(binding, "promptDigest"),
            jsonItem(binding, "contractDigest"),
            workflowJson(jsonItem(payload, "result")),
            timestamp,
          ]),
        );
    });
    return {};
  }
  connection.prepare("BEGIN IMMEDIATE").run();
  return connection.transaction(() => {
    const state = readFindingWorkflow(connection, id) ?? {
      id,
      stages: Object.fromEntries(
        stages.map((stage) => [stage, { status: "pending" }]),
      ) as FindingWorkflowState["stages"],
    };
    bindFindingWorkflow(state, jsonGet(payload, "binding", {}));
    const action = jsonItem(payload, "action");
    if (action !== "bind") {
      const stage = jsonItem(payload, "stage");
      if (Array.isArray(stage) || object(stage))
        throw new TypeError(`unhashable type: '${jsonTypeName(stage)}'`);
      if (typeof stage !== "string" || !Object.hasOwn(state.stages, stage))
        throw new WorkbenchValidationError("Unknown workflow stage.");
      const current = state.stages[stage as Stage];
      if (current.status !== "completed") {
        if (action === "begin") current.status = "running";
        else if (action === "complete")
          state.stages[stage as Stage] = {
            status: "completed",
            result: jsonItem(payload, "result"),
          };
        else if (action === "fail")
          Object.assign(current, {
            status: "failed",
            error: jsonItem(payload, "error"),
          });
        else if (action === "prepare-dedupe")
          Object.assign(current, {
            result: jsonItem(payload, "result"),
            pendingWrite: jsonItem(payload, "pendingWrite"),
          });
        else throw new WorkbenchValidationError("Unknown workflow action.");
      }
    }
    saveFindingWorkflow(connection, state, timestamp);
    return { workflow: state };
  });
}
