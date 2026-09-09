import { createHash } from "node:crypto";
import { basename, dirname } from "node:path";
import decimalDigit from "@unicode/unicode-15.0.0/General_Category/Decimal_Number/regex.js";
import type { Row } from "../../native/sqlite.mjs";
import { contractValuesEqual as equal } from "./helpers/contract-validation";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { fileInfo } from "./helpers/helper-files";
import { preflightInteger } from "./helpers/preflight-config";
import {
  copyJson,
  JsonFloat,
  JsonSyntaxError,
  jsonTypeName,
  object,
  objectEntries,
  objectFromEntries,
  pythonRepr,
} from "./helpers/python-json";
import { appendPath, relativePath } from "./helpers/rank-selection";
import { compare } from "./helpers/rank-worklists";
import { parsedPath } from "./helpers/resolve-security-md";
import { findingCandidateId } from "./helpers/saved-findings-projection";
import { ContractError } from "./helpers/scan-contract-errors";
import { JsonValueError } from "./helpers/scan-contract-json";
import { writeScanLocalBytes } from "./helpers/scan-local-files";
import { schemaDirectory } from "./helpers/sealed-scan";
import {
  findingStrength,
  recoverUnsealedFindings,
} from "./helpers/unsealed-recovery";
import { lowercase } from "./helpers/unicode-case";
import { encodeUtf8, UnicodeDecodeError } from "./helpers/utf8";
import {
  encodedSavedResult as encoded,
  latestSuccessfulReducer,
  readSavedParentResult,
  readSavedResult,
  savedResultChildren,
  savedResultDigest as digest,
} from "./workbench-saved-result-sources";
import { pathWithinScope } from "./workbench-validation";

type Table = Record<string, unknown>;
type Source = [string, Table, string | null];
type ReducerKey = [string, string, bigint];
export interface SavedMergeBinding {
  status: string;
  allowedTargetKinds: string[];
  target: Table;
  scope: Table & { includePaths: string[] };
  coverageMode: string;
}
export interface SavedMergeOptions {
  stopped: boolean;
  reason: string;
  frozenSourceDigests?: Record<string, string> | null;
  allowFrozenLegacyParent?: boolean;
}
const get = (value: Table, key: string, fallback: unknown = null): unknown =>
  Object.hasOwn(value, key) ? value[key] : fallback;
const clone = (value: Table): Table => copyJson(value) as Table;
const truth = (value: unknown): boolean =>
  value instanceof JsonFloat
    ? Number(value.source) !== 0
    : Array.isArray(value) || Buffer.isBuffer(value)
      ? value.length !== 0
      : object(value)
        ? objectEntries(value).length !== 0
        : Boolean(value);
const str = (value: unknown): string =>
  typeof value === "string" ? value : pythonRepr(value);
function setdefault(value: Table, key: string, fallback: unknown): unknown {
  if (!Object.hasOwn(value, key)) value[key] = fallback;
  return value[key];
}
function pop(value: Table, key: string): unknown {
  const previous = get(value, key, []);
  delete value[key];
  return previous;
}
function sourceError(error: unknown): boolean {
  const system = error as { errno?: number; winerror?: number };
  return (
    error instanceof ContractError ||
    error instanceof JsonValueError ||
    error instanceof JsonSyntaxError ||
    error instanceof UnicodeDecodeError ||
    system.errno !== undefined ||
    system.winerror !== undefined
  );
}
// Path.exists returns false when the filesystem cannot represent the supplied name.
function pathExists(path: string): boolean {
  if (
    path.includes("\0") ||
    (process.platform !== "win32" && /[\ud800-\udc7f\udd00-\udfff]/u.test(path))
  )
    return false;
  return fileInfo(path) !== undefined;
}
function relative(scanDir: string, value: unknown): string {
  if (typeof value !== "string")
    throw new TypeError(
      `argument should be a str or an os.PathLike object where __fspath__ returns a str, not '${Buffer.isBuffer(value) ? "bytes" : jsonTypeName(value)}'`,
    );
  const result = relativePath(parsedPath(value), parsedPath(scanDir));
  if (result === undefined) throw new JsonValueError("outside scan directory");
  return posix(result || ".");
}
const posix = (value: string) =>
  process.platform === "win32" ? value.replaceAll("\\", "/") : value;
const attemptName = new RegExp(
  `^attempt-((?:${decimalDigit.source})+)$(?![\\s\\S])`,
  "u",
);
function integer(value: unknown): bigint {
  if (typeof value === "bigint" || typeof value === "boolean")
    return BigInt(value);
  if (value instanceof JsonFloat) value = Number(value.source);
  if (typeof value === "number") return BigInt(Math.trunc(value));
  if (typeof value !== "string")
    throw new TypeError(
      `int() argument must be a string, a bytes-like object or a real number, not '${jsonTypeName(value)}'`,
    );
  const normalized = Array.from(value, (character) => {
    if (!decimalDigit.test(character)) return character;
    const point = character.codePointAt(0)!;
    let first = point;
    while (decimalDigit.test(String.fromCodePoint(first - 1))) first--;
    return String((point - first) % 10);
  })
    .join("")
    .replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
  if (!/^[+-]?[0-9]+(?:_[0-9]+)*$(?![\s\S])/u.test(normalized))
    throw new JsonValueError(
      `invalid literal for int() with base 10: ${pythonRepr(value)}`,
    );
  return preflightInteger(normalized);
}
// Python tuple keys compare numeric values by value and reject unhashable fields.
function tupleKey(values: unknown[]): string {
  return JSON.stringify(
    values.map((value) => {
      if (Buffer.isBuffer(value)) return ["bytes", value.toString("hex")];
      if (Array.isArray(value) || object(value))
        throw new TypeError(`unhashable type: '${jsonTypeName(value)}'`);
      if (value instanceof JsonFloat) value = Number(value.source);
      if (typeof value === "boolean") value = BigInt(value);
      if (typeof value === "number" && Number.isInteger(value))
        value = BigInt(value);
      if (typeof value === "bigint" || typeof value === "number")
        return ["number", String(value)];
      return [typeof value, value];
    }),
  );
}
function inSet(value: unknown, ...items: string[]): boolean {
  tupleKey([value]);
  return items.includes(value as string);
}
function after(left: ReducerKey, right: ReducerKey): boolean {
  return (
    compare(left[0], right[0]) > 0 ||
    (left[0] === right[0] &&
      (compare(left[1], right[1]) > 0 ||
        (left[1] === right[1] && left[2] > right[2])))
  );
}
function identitySource(finding: Table): Table {
  const extensions = finding["extensions"];
  const candidate = object(extensions) ? get(extensions, "candidateId") : null;
  const source = truth(candidate)
    ? candidate
    : truth(get(finding, "title"))
      ? finding["title"]
      : "finding";
  return {
    anchor:
      lowercase(str(source))
        .replace(/[^a-z0-9._/-]+/gu, "-")
        .replace(/^[._/-]+|[._/-]+$/gu, "") || "finding",
  };
}
function preservedIdentity(finding: Table): unknown {
  const provenance = finding["provenance"];
  return object(provenance)
    ? get(provenance, "preservedIdentity", get(finding, "identity"))
    : get(finding, "identity");
}

export function savedFindingKey(finding: Table): string {
  const preserved = preservedIdentity(finding);
  const locations = get(finding, "locations", []);
  const ordered = (Array.isArray(locations) ? locations : [])
    .filter(object)
    .map((location) => [
      get(location, "path"),
      get(location, "startLine"),
      get(location, "endLine", get(location, "startLine")),
    ])
    .sort((a, b) => Buffer.compare(encoded(a), encoded(b)));
  return digest([
    get(finding, "ruleId"),
    object(preserved) ? preserved : identitySource(finding),
    ordered,
  ]);
}
export function workerCandidateKey(
  workerId: string,
  candidateId: string,
  finding: Table,
): unknown[] {
  let identity = preservedIdentity(finding);
  if (!object(identity)) {
    const normalized = objectFromEntries(objectEntries(finding));
    ensureSavedFindingIdentity(normalized);
    identity = get(normalized, "identity");
  }
  return [
    workerId,
    candidateId,
    get(finding, "ruleId"),
    object(identity) ? get(identity, "anchor") : null,
    object(identity) ? get(identity, "instance") : null,
  ];
}
export function savedFindingContent(finding: Table): Table {
  return objectFromEntries(
    objectEntries(finding).filter(
      ([key]) =>
        ![
          "findingId",
          "occurrenceId",
          "fingerprints",
          "identity",
          "provenance",
        ].includes(key),
    ),
  );
}
export function ensureSavedFindingIdentity(
  finding: unknown,
  candidateOnly = false,
): void {
  if (!object(finding) || Object.hasOwn(finding, "identity")) return;
  if (candidateOnly && !findingCandidateId(finding)) return;
  finding["identity"] = identitySource(finding);
}
export function* retainedSavedFindings(finding: Table): Generator<Table> {
  const pending = [finding],
    seen = new Set<Table>();
  while (pending.length) {
    const current = pending.pop()!;
    if (seen.has(current)) continue;
    seen.add(current);
    yield current;
    const provenance = current["provenance"];
    if (!object(provenance)) continue;
    const previous = provenance["previousFindings"],
      sources = provenance["sourceFindings"];
    if (Array.isArray(previous))
      for (const entry of previous.slice().reverse())
        if (object(entry)) pending.push(entry);
    if (Array.isArray(sources))
      for (const source of sources.slice().reverse())
        if (object(source) && object(source["finding"]))
          pending.push(source["finding"]);
  }
}

/** Return the original unsealed, loss-preserving union of bound saved results. */
export function mergeSavedResults(
  scanDir: string,
  scanId: string,
  binding: SavedMergeBinding,
  workers: readonly Row[],
  warnings: string[],
  options: SavedMergeOptions,
): [Table, Table, Table] | null {
  const { stopped, reason, allowFrozenLegacyParent = false } = options;
  let frozen = options.frozenSourceDigests ?? null;
  const initialWarnings = new Set(
    warnings.map((warning) => tupleKey([warning])),
  );
  let parent: Table | null = null,
    parentManifest: Table | null = null;
  if (frozen === null || allowFrozenLegacyParent) {
    try {
      [parentManifest, parent] = readSavedParentResult(scanDir, scanId);
    } catch (error) {
      if (!sourceError(error) || !stopped) throw error;
      if (pathExists(appendPath(scanDir, "scan-manifest.json")))
        warnings.push(
          `Could not read the saved parent draft: ${filesystemErrorMessage(error)}`,
        );
      parentManifest = null;
      parent = null;
    }
    if (parentManifest !== null && parent !== null) {
      const parentScan = parentManifest["scan"] as Table;
      if (!truth(get(parentScan, "sealedAt")) || allowFrozenLegacyParent) {
        const payload = encoded(parent),
          parentDigest = digest(parent);
        const checkpoint = `checkpoints/${parentDigest}.json`;
        writeScanLocalBytes(scanDir, checkpoint, payload);
        if (frozen !== null) frozen = { ...frozen, [checkpoint]: parentDigest };
      }
    }
  }
  const sources: Source[] = [];
  let preservedSources: Table = {};
  const sourceDigests = new Map<string, unknown>();
  if (parentManifest !== null) {
    const recorded = get(
      parentManifest["scan"] as Table,
      "preservedSources",
      {},
    );
    if (object(recorded)) {
      preservedSources = recorded;
      for (const [key, value] of objectEntries(recorded))
        sourceDigests.set(key, value);
    }
  }
  let paths = new Map<string, string | null>();
  const reducerPaths = new Set<string>();
  const currentResults = new Set<string>();
  const reducerOutputs: [Row, string, string[], bigint][] = [];
  const reducer = latestSuccessfulReducer(workers);
  let latestReducer: string | null = null;
  if (reducer !== null) {
    try {
      latestReducer = relative(scanDir, reducer.get("result_manifest_path"));
      paths.set(latestReducer, null);
      reducerPaths.add(latestReducer);
    } catch (error) {
      if (!(error instanceof JsonValueError)) throw error;
      warnings.push("Skipped a reducer result outside the scan directory.");
    }
  }
  function checkpoints(directory: string, workerId: string | null): void {
    for (const name of savedResultChildren(scanDir, directory))
      if (/^[0-9a-f]{64}\.json$(?![\s\S])/u.test(name))
        paths.set(`${directory}/${name}`, workerId);
  }
  function attempts(output: string): string {
    const path = parsedPath(output);
    return posix(
      appendPath(
        basename(path) === "output" ? dirname(path) : path,
        "attempts",
      ),
    );
  }
  checkpoints("checkpoints", null);
  for (const worker of workers) {
    let output: string;
    try {
      output = relative(scanDir, worker.get("artifact_dir"));
    } catch (error) {
      if (!(error instanceof TypeError || error instanceof JsonValueError))
        throw error;
      warnings.push("Skipped a worker checkpoint outside the scan directory.");
      continue;
    }
    if (worker.get("kind") === "dedup") {
      function reducerOutput(directory: string, attempt: bigint): void {
        const resultPath = `${directory}/result.json`;
        const checkpointPaths = savedResultChildren(
          scanDir,
          `${directory}/checkpoints`,
        )
          .filter((name) => /^[0-9a-f]{64}\.json$(?![\s\S])/u.test(name))
          .map((name) => `${directory}/checkpoints/${name}`);
        if (!checkpointPaths.length) return;
        paths.set(resultPath, null);
        reducerPaths.add(resultPath);
        for (const checkpointPath of checkpointPaths) {
          paths.set(checkpointPath, null);
          reducerPaths.add(checkpointPath);
        }
        reducerOutputs.push([worker, resultPath, checkpointPaths, attempt]);
      }
      reducerOutput(output, integer(worker.get("attempt") || 0n));
      const directory = attempts(output);
      for (const name of savedResultChildren(scanDir, directory)) {
        const match = attemptName.exec(name);
        if (match)
          reducerOutput(posix(appendPath(directory, name)), integer(match[1]!));
      }
      continue;
    }
    if (worker.get("kind") !== "discovery") continue;
    const workerId = worker.get("id") as string;
    paths.set(`${output}/result.json`, workerId);
    currentResults.add(`${output}/result.json`);
    checkpoints(`${output}/checkpoints`, workerId);
    const directory = attempts(output);
    for (const name of savedResultChildren(scanDir, directory)) {
      if (!attemptName.test(name)) continue;
      const archived = posix(appendPath(directory, name));
      paths.set(`${archived}/result.json`, workerId);
      checkpoints(`${archived}/checkpoints`, workerId);
    }
    if (truth(worker.get("result_manifest_path"))) {
      try {
        const current = relative(scanDir, worker.get("result_manifest_path"));
        paths.set(current, workerId);
        currentResults.add(current);
      } catch (error) {
        if (!(error instanceof JsonValueError)) throw error;
        warnings.push("Skipped a worker result outside the scan directory.");
      }
    }
  }
  if (frozen !== null) {
    paths = new Map([...paths].filter(([key]) => Object.hasOwn(frozen!, key)));
    for (const current of currentResults)
      if (!Object.hasOwn(frozen, current)) currentResults.delete(current);
    if (latestReducer === null || !Object.hasOwn(frozen, latestReducer))
      latestReducer = null;
  }
  for (const [path, workerId] of paths) {
    try {
      const [draft, hash] = readSavedResult(
        scanDir,
        path,
        scanId,
        reducerPaths.has(path) ? "dedup" : null,
      );
      if (frozen !== null && frozen[path] !== hash)
        throw new ContractError("checkpoint changed after the scan stopped");
      sourceDigests.set(path, hash);
      // Add recovery coverage only after hashing the original reducer result.
      sources.push([path, { coverage: {}, ...draft }, workerId]);
    } catch (error) {
      if (!sourceError(error)) throw error;
      if (pathExists(appendPath(scanDir, path)))
        warnings.push(
          `Preserved unreadable checkpoint ${path}: ${filesystemErrorMessage(error)}`,
        );
    }
  }
  if (
    frozen !== null &&
    objectEntries(frozen).some(([key]) => !sourceDigests.has(key))
  )
    throw new ContractError(
      "Frozen stopped-scan checkpoint set is incomplete.",
    );
  const drafts = new Map(sources.map(([path, draft]) => [path, draft]));
  let latestKey: ReducerKey | null =
    reducer !== null && latestReducer !== null && drafts.has(latestReducer)
      ? [
          (reducer.get("completed_at") || "") as string,
          reducer.get("id") as string,
          integer(reducer.get("attempt") || 0n),
        ]
      : null;
  if (latestKey === null) latestReducer = null;
  for (const [worker, resultPath, checkpointPaths, attempt] of reducerOutputs) {
    const result = drafts.get(resultPath);
    if (
      result === undefined ||
      !checkpointPaths.some((path) => equal(drafts.get(path) ?? null, result))
    )
      continue;
    currentResults.add(resultPath);
    const key: ReducerKey = [
      (worker.get("completed_at") || "") as string,
      worker.get("id") as string,
      attempt,
    ];
    if (latestKey === null || after(key, latestKey)) {
      latestKey = key;
      latestReducer = resultPath;
    }
  }
  if (parent === null && latestReducer !== null)
    parent = drafts.get(latestReducer) ?? null;
  if (parent === null && !sources.length) return null;
  const sourceMap = objectFromEntries(sourceDigests);
  const parentScan = parentManifest?.["scan"] as Table | undefined;
  if (
    parentScan &&
    truth(get(parentScan, "sealedAt")) &&
    parentScan["status"] === binding.status &&
    equal(get(parentScan, "preservedSources"), sourceMap) &&
    warnings.every((warning) => initialWarnings.has(tupleKey([warning])))
  )
    return null;
  let targetKind = binding.allowedTargetKinds[0]!;
  if (
    targetKind === "git_worktree" &&
    !Object.hasOwn(binding.target, "snapshotDigest") &&
    binding.allowedTargetKinds.includes("git_revision")
  )
    targetKind = "git_revision";
  const target: Table = { kind: targetKind, ...binding.target };
  if (
    target["kind"] === "git_diff" &&
    !Object.hasOwn(target, "snapshotDigest")
  ) {
    const diffKind = (
      { commit: "commit", branch_diff: "range" } as Record<string, string>
    )[binding.coverageMode]!;
    const hash = createHash("sha256")
      .update(
        Buffer.concat([
          Buffer.from("codex-security-diff/v1\0"),
          encodeUtf8(diffKind),
          Buffer.from([0]),
          encodeUtf8(target["baseRevision"] as string),
          Buffer.from([0]),
          encodeUtf8(target["headRevision"] as string),
        ]),
      )
      .digest("hex");
    target["snapshotDigest"] = `codex-security-snapshot/v1:sha256:${hash}`;
  }
  const manifest =
    parentManifest !== null
      ? clone(parentManifest)
      : { scan: { target, scope: binding.scope } };
  const scan = manifest["scan"] as Table;
  delete scan["sealedAt"];
  delete scan["artifacts"];
  scan["preservedSources"] = sourceMap;
  const coverage: Table =
    parent !== null && truth(parent["coverage"])
      ? clone(parent["coverage"] as Table)
      : {
          completeness: "partial",
          mode: binding.coverageMode,
          inventoryStrategy: ["commit", "branch_diff", "working_tree"].includes(
            binding.coverageMode,
          )
            ? "diff"
            : binding.coverageMode === "scoped_path"
              ? "scoped_path"
              : "repository",
          ...binding.scope,
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
        };
  const canonicalRows = new Set(
    parentManifest !== null
      ? ["surfaces", "explicitExclusions", "deferred"].flatMap((field) =>
          Array.isArray(coverage[field]) ? coverage[field] : [],
        )
      : [],
  );
  const findings: unknown[] = [],
    positions = new Map<string, number>();
  const represented = new Map<string, string | null>(),
    representedCandidates = new Map<string, string | null>();
  const representedHistory = new Map<string, Set<string>>(),
    candidateHistory = new Map<string, Set<string>>();
  const rejectedHistory = new Map<string, Table[]>();
  const stoppedParentSeal =
    stopped && parentScan !== undefined && truth(get(parentScan, "sealedAt"));
  function validFinding(value: unknown): boolean {
    const document: Table = { scanId, findings: [copyJson(value)] };
    ensureSavedFindingIdentity((document["findings"] as unknown[])[0], true);
    recoverUnsealedFindings(
      { scan: { id: scanId, target: binding.target } },
      document,
      schemaDirectory(),
      scanDir,
      [],
    );
    return (document["findings"] as unknown[]).length > 0;
  }
  const allSources: Source[] = [
    ...(parent !== null ? [["parent", parent, null] as Source] : []),
    ...sources,
  ];
  const currentDrafts: [string | null, Table][] = [
    ...(parent !== null ? [[null, parent] as [null, Table]] : []),
    ...sources
      .filter(([path]) => currentResults.has(path))
      .map(([, draft, workerId]): [string | null, Table] => [workerId, draft]),
  ];
  const resolved = new Map<string, string>();
  for (const [owner, draft] of currentDrafts) {
    for (const finding of draft["findings"] as unknown[]) {
      if (!object(finding) || !validFinding(finding)) continue;
      const candidate = findingCandidateId(finding);
      if (candidate) {
        const key = tupleKey([owner, candidate]);
        if (!resolved.has(key)) resolved.set(key, "reported");
      }
    }
    for (const field of ["surfaces", "explicitExclusions"]) {
      const items = get(draft["coverage"] as Table, field, []);
      for (const item of Array.isArray(items) ? items : [])
        if (
          object(item) &&
          typeof item["candidateId"] === "string" &&
          inSet(
            get(item, "disposition"),
            "reported",
            "rejected",
            "not_applicable",
          )
        ) {
          const key = tupleKey([owner, item["candidateId"]]);
          if (!resolved.has(key))
            resolved.set(key, item["disposition"] as string);
        }
    }
  }
  // Only the current parent may claim another worker's finding was absorbed.
  for (const finding of parent !== null
    ? (parent["findings"] as Table[])
    : []) {
    if (!validFinding(finding)) continue;
    const canonicalKey = savedFindingKey(finding);
    for (const retained of retainedSavedFindings(finding)) {
      const key = savedFindingKey(retained);
      if (retained !== finding) {
        if (!representedHistory.has(key))
          representedHistory.set(key, new Set());
        representedHistory.get(key)!.add(digest(savedFindingContent(retained)));
      }
      if (!represented.has(key)) represented.set(key, canonicalKey);
      else if (represented.get(key) !== canonicalKey)
        represented.set(key, null);
    }
    const originals = get(finding["provenance"] as Table, "sourceFindings", []);
    for (const original of Array.isArray(originals) ? originals : []) {
      if (!object(original) || !object(original["finding"])) continue;
      const sourceId = original["id"],
        candidateId = findingCandidateId(original["finding"]);
      if (
        typeof sourceId !== "string" ||
        !sourceId.includes(":") ||
        !candidateId
      )
        continue;
      const key = tupleKey(
        workerCandidateKey(
          sourceId.slice(0, sourceId.lastIndexOf(":")),
          candidateId,
          original["finding"],
        ),
      );
      if (!representedCandidates.has(key))
        representedCandidates.set(key, canonicalKey);
      else if (representedCandidates.get(key) !== canonicalKey)
        representedCandidates.set(key, null);
      if (!candidateHistory.has(key)) candidateHistory.set(key, new Set());
      candidateHistory
        .get(key)!
        .add(digest(savedFindingContent(original["finding"])));
      if (!resolved.has(key)) resolved.set(key, "reported");
    }
  }
  for (const [path, draft, workerId] of allSources) {
    const superseded =
      (workerId === null &&
        parent !== null &&
        get(parent, "complete") !== false &&
        path !== "parent" &&
        (!stoppedParentSeal || Object.hasOwn(preservedSources, path))) ||
      (!currentResults.has(path) &&
        sources.some(
          ([savedPath, current, savedWorker]) =>
            savedWorker === workerId &&
            currentResults.has(savedPath) &&
            get(current, "complete") !== false,
        ));
    if (
      (path !== "parent" || parentManifest === null) &&
      !superseded &&
      (get(draft, "complete") === false ||
        get(draft["coverage"] as Table, "completeness") !== "complete") &&
      inSet(get(coverage, "completeness"), "complete", "unknown")
    )
      coverage["completeness"] = "partial";
    if (
      superseded &&
      !stopped &&
      (parent !== null ? (parent["findings"] as unknown[]) : []).every(
        validFinding,
      )
    )
      continue;
    if (!Object.hasOwn(scan, "threatModel") && object(draft["threatModel"]))
      scan["threatModel"] = clone(draft["threatModel"]);
    for (const value of draft["findings"] as unknown[]) {
      if (path === "parent" && parentManifest !== null) {
        const finding = copyJson(value);
        ensureSavedFindingIdentity(finding, true);
        const provenance = object(finding) ? finding["provenance"] : null;
        const owner = object(provenance) ? get(provenance, "workerId") : null;
        const candidateId = object(finding)
          ? findingCandidateId(finding)
          : null;
        if (
          stoppedParentSeal &&
          typeof owner === "string" &&
          candidateId &&
          inSet(
            resolved.get(tupleKey([owner, candidateId])) ?? null,
            "rejected",
            "not_applicable",
          )
        ) {
          const rejectedKey = tupleKey([owner, candidateId]);
          if (!rejectedHistory.has(rejectedKey))
            rejectedHistory.set(rejectedKey, []);
          rejectedHistory.get(rejectedKey)!.push(finding as Table);
          continue;
        }
        if (validFinding(finding)) {
          const key = savedFindingKey(finding as Table);
          if (!positions.has(key)) positions.set(key, findings.length);
        }
        findings.push(finding);
        continue;
      }
      if (
        path !== "parent" &&
        parent !== null &&
        (parent["findings"] as unknown[]).some((previous) =>
          equal(value, previous),
        )
      )
        continue;
      if (!object(value)) {
        warnings.push(`Retained malformed finding evidence in ${path}.`);
        continue;
      }
      const sourceValue = clone(value),
        finding = clone(value),
        candidateId = findingCandidateId(finding);
      if (
        path !== "parent" &&
        inSet(
          resolved.get(tupleKey([workerId, candidateId])) ?? null,
          "rejected",
          "not_applicable",
        )
      ) {
        const surfaces = coverage["surfaces"];
        for (const item of Array.isArray(surfaces) ? surfaces : []) {
          if (!object(item) || !equal(get(item, "candidateId"), candidateId))
            continue;
          if (!Array.isArray(item["previousFindings"]))
            item["previousFindings"] = [];
          const history = item["previousFindings"] as unknown[];
          if (!history.some((previous) => sameFinding(previous, finding)))
            history.push(finding);
        }
        continue;
      }
      for (const key of ["findingId", "occurrenceId", "fingerprints"])
        delete finding[key];
      const locations = get(finding, "locations", []);
      if (
        !Array.isArray(locations) ||
        !locations.some(
          (location) =>
            object(location) &&
            typeof location["path"] === "string" &&
            binding.scope.includePaths.some((scope) =>
              pathWithinScope(location["path"] as string, scope),
            ),
        )
      ) {
        warnings.push(`Skipped out-of-scope finding from ${path}.`);
        coverage["completeness"] = "partial";
        continue;
      }
      const provenance = setdefault(finding, "provenance", {
        source: "local_plugin",
      });
      if (!object(provenance)) {
        findings.push(finding);
        continue;
      }
      if (truth(workerId)) setdefault(provenance, "workerId", workerId);
      ensureSavedFindingIdentity(finding);
      if (!validFinding(finding)) {
        findings.push(finding);
        continue;
      }
      let key = savedFindingKey(finding),
        representedByParent = false;
      if (path !== "parent") {
        let mappedKey: string | null, historical: Set<string>;
        if (represented.has(key)) {
          mappedKey = represented.get(key)!;
          historical = representedHistory.get(key) ?? new Set();
        } else if (workerId && candidateId) {
          const candidateKey = tupleKey(
            workerCandidateKey(workerId, candidateId, finding),
          );
          if (!representedCandidates.has(candidateKey))
            representedCandidates.set(candidateKey, key);
          mappedKey = representedCandidates.get(candidateKey)!;
          historical = candidateHistory.get(candidateKey) ?? new Set();
        } else {
          mappedKey = null;
          historical = new Set();
        }
        if (mappedKey !== null) {
          key = mappedKey;
          representedByParent = historical.has(
            digest(savedFindingContent(sourceValue)),
          );
        }
      }
      if (positions.has(key)) {
        let retained = findings[positions.get(key)!] as Table;
        if (!equal(finding, retained)) {
          let previous: Table, previousHistory: unknown;
          if (!representedByParent && strongerFinding(finding, retained)) {
            previous = clone(retained);
            previousHistory = pop(
              previous["provenance"] as Table,
              "previousFindings",
            );
            retained = finding;
            findings[positions.get(key)!] = retained;
          } else {
            previous = clone(sourceValue);
            previousHistory = pop(
              get(previous, "provenance", {}) as Table,
              "previousFindings",
            );
          }
          const retainedProvenance = retained["provenance"] as Table,
            retainedHistory = retainedProvenance["previousFindings"];
          const history: Table[] = Array.isArray(retainedHistory)
            ? retainedHistory.filter(object)
            : [];
          retainedProvenance["previousFindings"] = history;
          for (const original of [
            ...(Array.isArray(previousHistory) ? previousHistory : []),
            previous,
          ]) {
            if (!object(original)) continue;
            const alreadyRetained = [...retainedSavedFindings(retained)].some(
              (historical) => sameFinding(historical, original),
            );
            if (
              !alreadyRetained &&
              !history.some((item) => equal(item, original)) &&
              !equal(original, retained)
            )
              history.push(original);
          }
        }
        continue;
      }
      positions.set(key, findings.length);
      findings.push(finding);
    }
    if (superseded) continue;
    for (const field of [
      "surfaces",
      "explicitExclusions",
      "deferred",
      "openQuestions",
    ]) {
      const items = get(draft["coverage"] as Table, field, []);
      if (!Array.isArray(items)) continue;
      const output = setdefault(coverage, field, []);
      // Keep malformed canonical collections for the finalizer's existing recovery.
      if (!Array.isArray(output)) continue;
      for (let item of items) {
        if (field === "openQuestions" && typeof item === "string")
          item = {
            question: item.replace(
              /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
              "",
            ),
          };
        if (
          field === "surfaces" &&
          object(item) &&
          inSet(get(item, "disposition"), "rejected", "not_applicable") &&
          typeof item["candidateId"] === "string"
        ) {
          const historyFindings = rejectedHistory.get(
            tupleKey([workerId, item["candidateId"]]),
          );
          if (historyFindings?.length) {
            item = clone(item);
            if (!Array.isArray(item["previousFindings"]))
              item["previousFindings"] = [];
            const history = item["previousFindings"] as unknown[];
            for (const finding of historyFindings)
              if (!history.some((previous) => sameFinding(previous, finding)))
                history.push(clone(finding));
          }
        }
        if (
          object(item) &&
          resolved.has(tupleKey([workerId, get(item, "candidateId")])) &&
          (field === "deferred" || item["disposition"] === "needs_follow_up")
        )
          continue;
        if (object(item) && !Object.hasOwn(item, "id")) {
          const semanticItem = objectFromEntries(objectEntries(item));
          if (field === "surfaces") setdefault(semanticItem, "receiptRefs", []);
          if (
            output.some(
              (existing) =>
                object(existing) &&
                equal(
                  objectFromEntries(
                    objectEntries(existing).filter(([key]) => key !== "id"),
                  ),
                  semanticItem,
                ),
            )
          )
            continue;
        }
        if (!output.some((existing) => equal(item, existing)))
          output.push(copyJson(item));
      }
    }
  }
  const identities = new Map<string, string>();
  for (const value of findings) {
    if (!validFinding(value)) continue;
    const finding = value as Table,
      identity = finding["identity"];
    if (!object(identity)) continue;
    const key = encoded([get(finding, "ruleId"), identity]).toString("utf8"),
      variant = savedFindingKey(finding);
    if (identities.has(key) && identities.get(key) !== variant) {
      (setdefault(finding, "provenance", {}) as Table)["preservedIdentity"] =
        clone(identity);
      identity["instance"] =
        `${str(get(identity, "instance", "saved"))}-${variant.slice(0, 16)}`;
    }
    identities.set(key, variant);
  }
  for (const field of ["surfaces", "explicitExclusions", "deferred"]) {
    const used = new Set<string>(),
      items = setdefault(coverage, field, []);
    for (const item of Array.isArray(items) ? items : []) {
      if (!object(item)) continue;
      if (canonicalRows.has(item)) {
        if (typeof item["id"] === "string") used.add(tupleKey([item["id"]]));
        continue;
      }
      setdefault(
        item,
        "id",
        truth(get(item, "candidateId"))
          ? item["candidateId"]
          : `saved-${digest(item).slice(0, 16)}`,
      );
      if (used.has(tupleKey([item["id"]])))
        item["id"] = `${str(item["id"])}-${digest(item).slice(0, 16)}`;
      used.add(tupleKey([item["id"]]));
      if (field === "surfaces") setdefault(item, "receiptRefs", []);
    }
  }
  if (
    stopped ||
    warnings.some((warning) => !initialWarnings.has(tupleKey([warning])))
  )
    coverage["completeness"] = "partial";
  if (stopped) {
    if (!Array.isArray(coverage["deferred"])) coverage["deferred"] = [];
    const deferred = coverage["deferred"] as unknown[],
      item = { id: "scan-stopped", reason };
    if (!deferred.some((existing) => equal(item, existing)))
      deferred.push(item);
  }
  return [manifest, { findings }, coverage];
}
function sameFinding(previous: unknown, finding: Table): boolean {
  return (
    object(previous) &&
    savedFindingKey(previous) === savedFindingKey(finding) &&
    equal(savedFindingContent(previous), savedFindingContent(finding))
  );
}

function strongerFinding(finding: Table, retained: Table): boolean {
  const left = findingStrength(finding),
    right = findingStrength(retained);
  for (let index = 0; index < left.length; index++)
    if (left[index] !== right[index]) return left[index]! > right[index]!;
  return false;
}
