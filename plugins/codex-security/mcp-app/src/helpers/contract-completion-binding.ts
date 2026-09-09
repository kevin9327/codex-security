import { processBinding } from "../native";
import { validateDateTime } from "./contract-date-time";
import {
  contractValuesEqual,
  requireDict,
  SCHEMA_VERSION,
} from "./contract-validation";
import { environment } from "./environment";
import { hasText } from "./finding-root-cause";
import {
  assignJson,
  copyJson,
  object,
  objectEntries,
  objectFromEntries,
  pythonRepr,
} from "./python-json";
import { ContractError } from "./scan-contract-errors";
import { timestamp } from "./utc-timestamp";

type Table = Record<string, unknown>;
const get = (value: Table, key: string, fallback: unknown = null): unknown =>
  Object.hasOwn(value, key) ? value[key] : fallback;
const at = (value: Table, key: string): unknown => {
  if (!Object.hasOwn(value, key)) throw new Error(pythonRepr(key));
  return value[key];
};
const trim = (value: string) =>
  value.replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );

export function populateUnsealedTargetBinding(
  target: Table,
  binding: Table,
): void {
  const kind = get(target, "kind");
  const required =
    kind === "git_revision"
      ? "revision"
      : kind === "git_worktree" ||
          kind === "git_diff" ||
          kind === "directory_snapshot"
        ? "snapshotDigest"
        : null;
  for (const field of [
    "revision",
    "baseRevision",
    "headRevision",
    "snapshotDigest",
  ])
    if (!Object.hasOwn(binding, field) && field !== required)
      delete target[field];
  assignJson(target, copyJson(binding) as Table);
}

export function populateUnsealedManifestEnvelope(
  manifest: Table,
  scan: Table,
  binding: Table | null,
  now: () => string = () =>
    timestamp(processBinding().wallClockMicroseconds()).replace("+00:00", "Z"),
): void {
  manifest["documentType"] = "codex-security.scan-manifest";
  manifest["schemaVersion"] = SCHEMA_VERSION;
  scan["status"] =
    binding === null ? "completed" : get(binding, "status", "completed");
  scan["coverageRef"] = "coverage.json";
  scan["findingsRef"] = "findings.json";
  if (binding === null) {
    const startedAt = environment("CODEX_SECURITY_STARTED_AT");
    if (startedAt !== undefined) {
      validateDateTime(startedAt, "CODEX_SECURITY_STARTED_AT");
      scan["startedAt"] = startedAt;
      scan["completedAt"] = now();
    }
    return;
  }
  scan["id"] = at(binding, "scanId");
  scan["startedAt"] = at(binding, "startedAt");
  scan["completedAt"] = at(binding, "completedAt");
  scan["producer"] = copyJson(at(binding, "producer"));
  const target = get(scan, "target");
  if (object(target))
    populateUnsealedTargetBinding(target, at(binding, "target") as Table);
  const scope = get(scan, "scope");
  if (object(scope)) assignJson(scope, copyJson(at(binding, "scope")) as Table);
}

export function populateUnsealedArtifactEnvelope(
  manifest: Table,
  findings: Table,
  coverage: Table,
  binding: Table | null,
): void {
  findings["documentType"] = "codex-security.findings";
  findings["schemaVersion"] = SCHEMA_VERSION;
  coverage["documentType"] = "codex-security.coverage";
  coverage["schemaVersion"] = SCHEMA_VERSION;
  if (binding === null) return;
  const scanId = at(binding, "scanId");
  findings["scanId"] = scanId;
  coverage["scanId"] = scanId;
  coverage["mode"] = at(binding, "coverageMode");
  const scan = requireDict(manifest, "scan", "manifest");
  const scope = requireDict(scan, "scope", "manifest.scan");
  for (const field of ["includePaths", "excludePaths"])
    if (Object.hasOwn(scope, field)) coverage[field] = copyJson(scope[field]);
}

export function normalizeUnsealedOpenQuestions(coverage: Table): void {
  const questions = get(coverage, "openQuestions");
  if (!Array.isArray(questions)) {
    delete coverage["openQuestions"];
    return;
  }
  const normalized: Table[] = [];
  for (const item of questions) {
    if (typeof item === "string") {
      const question = trim(item);
      if (question) normalized.push({ question });
    } else if (object(item) && hasText(get(item, "question"))) {
      const row = objectFromEntries(objectEntries(item));
      row["question"] = trim(item["question"] as string);
      if (!hasText(get(row, "followUpPrompt"))) delete row["followUpPrompt"];
      normalized.push(row);
    }
  }
  coverage["openQuestions"] = normalized;
}

export function normalizeUnsealedDeepRepositoryInventoryStrategy(
  coverage: Table,
  expectedCoverageMode: string | null,
): void {
  if (expectedCoverageMode === "deep_repository")
    coverage["inventoryStrategy"] = "repository";
}

export function validateCompletionBinding(
  manifest: Table,
  findings: Table,
  coverage: Table,
  binding: Table | null,
): void {
  if (binding === null) return;
  const scan = requireDict(manifest, "scan", "manifest");
  const check = (actual: unknown, expected: unknown, message: string) => {
    if (!contractValuesEqual(actual, expected))
      throw new ContractError(message);
  };
  check(
    get(scan, "id"),
    at(binding, "scanId"),
    "manifest.scan.id: must match the workbench scan",
  );
  check(
    get(scan, "status"),
    get(binding, "status", "completed"),
    "manifest.scan.status: must match the workbench outcome",
  );
  check(
    get(scan, "startedAt"),
    at(binding, "startedAt"),
    "manifest.scan.startedAt: must match the workbench scan",
  );
  check(
    get(scan, "completedAt"),
    at(binding, "completedAt"),
    "manifest.scan.completedAt: must match the workbench completion",
  );
  check(
    get(scan, "producer"),
    at(binding, "producer"),
    "manifest.scan.producer: must match the workbench producer",
  );
  const target = requireDict(scan, "target", "manifest.scan");
  const allowed = at(binding, "allowedTargetKinds") as unknown[];
  if (!allowed.some((kind) => contractValuesEqual(get(target, "kind"), kind)))
    throw new ContractError(
      "scan.target.kind: must match the workbench target",
    );
  for (const [key, expected] of objectEntries(at(binding, "target") as Table))
    check(
      get(target, key),
      expected,
      `scan.target.${key}: must match the workbench target`,
    );
  const scope = requireDict(scan, "scope", "manifest.scan");
  const bindingScope = at(binding, "scope") as Table;
  for (const [key, expected] of objectEntries(bindingScope))
    check(
      get(scope, key),
      expected,
      `manifest.scan.scope.${key}: must match the workbench scan`,
    );
  check(
    get(findings, "scanId"),
    at(binding, "scanId"),
    "findings.scanId: must match the workbench scan",
  );
  check(
    get(coverage, "scanId"),
    at(binding, "scanId"),
    "coverage.scanId: must match the workbench scan",
  );
  check(
    get(coverage, "mode"),
    at(binding, "coverageMode"),
    "coverage.mode: must match the workbench scan",
  );
  for (const [key, expected] of objectEntries(bindingScope))
    check(
      get(coverage, key),
      expected,
      `coverage.${key}: must match the workbench scan`,
    );
}
