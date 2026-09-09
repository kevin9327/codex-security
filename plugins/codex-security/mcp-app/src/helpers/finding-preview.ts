import { hasText, mergedRootCause } from "./finding-root-cause";
import {
  JsonFloat,
  object,
  objectEntries,
  objectFromEntries,
  stringifyJson,
} from "./python-json";

type Table = Record<string, unknown>;
type Budget = [number];
type ReservedFields = readonly (readonly [readonly string[], number])[];
export const FINDING_DETAILS_PREVIEW_BYTES = 16_000;
export const FINDING_ROOT_CAUSE_PREVIEW_BYTES = 2_000;
export const FINDING_VALIDATION_PREVIEW_BYTES = 3_000;
export const FINDING_ATTACK_PATH_PREVIEW_BYTES = 4_000;
export const FINDING_CODE_EVIDENCE_LIMIT = 4;
export const FINDING_CODE_EVIDENCE_SNIPPET_BYTES = 1_500;
export const FINDING_EVIDENCE_EXCERPT_BYTES = 8_000;

// The original budgets count ASCII JSON with no separator spaces.
function jsonSize(value: unknown): number {
  if (Array.isArray(value))
    return (
      2 +
      Math.max(0, value.length - 1) +
      value.reduce((size, item) => size + jsonSize(item), 0)
    );
  if (object(value)) {
    const entries = objectEntries(value);
    return (
      2 +
      Math.max(0, entries.length - 1) +
      entries.reduce(
        (size, [key, item]) => size + jsonSize(key) + 1 + jsonSize(item),
        0,
      )
    );
  }
  return stringifyJson(value).length;
}

function consume(budget: Budget, size: number): boolean {
  if (budget[0] < size) {
    budget[0] = 0;
    return false;
  }
  budget[0] -= size;
  return true;
}

export function boundedJsonText(
  value: string,
  maximumBytes: number,
): [string, number] {
  const points = Array.from(value);
  let low = 0,
    high = points.length,
    selected = "",
    selectedSize = 2;
  while (low <= high) {
    const midpoint = Math.floor((low + high) / 2);
    const candidate = points.slice(0, midpoint).join("");
    const size = jsonSize(candidate);
    if (size <= maximumBytes) {
      selected = candidate;
      selectedSize = size;
      low = midpoint + 1;
    } else high = midpoint - 1;
  }
  return [selected, selectedSize];
}

export function boundedJsonValue(
  value: unknown,
  budget: Budget,
  depth = 0,
  maxDepth = 4,
): unknown {
  if (budget[0] <= 0) return null;
  if (depth >= maxDepth) {
    consume(budget, 4);
    return null;
  }
  if (typeof value === "string") {
    const [bounded, size] = boundedJsonText(value, budget[0]);
    consume(budget, size);
    return bounded;
  }
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "bigint" ||
    typeof value === "number" ||
    value instanceof JsonFloat
  ) {
    consume(budget, jsonSize(value));
    return value;
  }
  if (Array.isArray(value)) {
    if (!consume(budget, 2)) return [];
    const result: unknown[] = [];
    for (const item of value) {
      const remaining = budget[0],
        separator = result.length ? 1 : 0;
      if (!consume(budget, separator)) break;
      const bounded = boundedJsonValue(item, budget, depth + 1, maxDepth);
      const size = jsonSize(bounded);
      if (
        separator + size > remaining ||
        (typeof item === "string" && item && bounded === "")
      ) {
        budget[0] = remaining;
        break;
      }
      budget[0] = remaining - separator - size;
      result.push(bounded);
    }
    return result;
  }
  if (object(value)) {
    if (!consume(budget, 2)) return objectFromEntries([]);
    const result = new Map<string, unknown>();
    for (const [key, item] of objectEntries(value).slice(0, 20)) {
      if (budget[0] <= 0) break;
      const remaining = budget[0],
        separator = result.size ? 1 : 0;
      if (!consume(budget, separator)) {
        budget[0] = remaining;
        break;
      }
      const [boundedKey, keySize] = boundedJsonText(
        key,
        Math.min(budget[0], 512),
      );
      if (!consume(budget, keySize + 1)) {
        budget[0] = remaining;
        break;
      }
      let itemBudget = budget;
      if (depth === 0 && key === "remediationTests") {
        const controls = value["preventiveControls"];
        if (
          Array.isArray(item) &&
          typeof item[0] === "string" &&
          item[0] &&
          Array.isArray(controls) &&
          typeof controls[0] === "string" &&
          controls[0]
        ) {
          const minimumTests = jsonSize([Array.from(item[0])[0]!]);
          for (const control of [controls[0], Array.from(controls[0])[0]!]) {
            const reserved = jsonSize({ preventiveControls: [control] }) - 1;
            if (budget[0] >= minimumTests + reserved) {
              itemBudget = [budget[0] - reserved];
              break;
            }
          }
        }
      }
      const bounded = boundedJsonValue(item, itemBudget, depth + 1, maxDepth);
      const size = separator + keySize + 1 + jsonSize(bounded);
      if (
        size > remaining ||
        (typeof item === "string" && item && bounded === "")
      ) {
        budget[0] = remaining;
        break;
      }
      budget[0] = remaining - size;
      result.set(boundedKey, bounded);
    }
    return objectFromEntries(result);
  }
  consume(budget, 4);
  return null;
}

function validEvidence(item: unknown): item is Table {
  return object(item) && hasText(item["id"]) && hasText(item["code"]);
}

export function mergedCodeEvidence(value: Table): [string | null, unknown] {
  const keys = ["codeEvidence", "code_evidence"].filter((key) =>
    Object.hasOwn(value, key),
  );
  if (!keys.length) return [null, null];
  const first = keys[0]!;
  const catalogs = keys.map((key) => value[key]).filter(Array.isArray);
  if (!catalogs.length) return [first, value[first]];
  const merged: Table[] = [],
    seen = new Set<string>();
  for (const catalog of catalogs)
    for (const item of catalog) {
      if (!validEvidence(item)) continue;
      const id = item["id"] as string;
      if (seen.has(id)) continue;
      seen.add(id);
      merged.push(item);
    }
  return [first, merged];
}

export function boundedCodeEvidence(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  const bounded: Table[] = [];
  for (const item of value) {
    if (!validEvidence(item)) continue;
    if (bounded.length >= FINDING_CODE_EVIDENCE_LIMIT) break;
    const evidence = new Map(objectEntries(item));
    for (const field of ["explanation", "label", "language", "path"])
      if (evidence.has(field) && typeof evidence.get(field) !== "string")
        evidence.delete(field);
    const role = evidence.get("role");
    if (evidence.has("role") && role !== null && typeof role !== "string")
      evidence.delete("role");
    for (const field of ["startLine", "endLine"]) {
      const line = evidence.get(field);
      if (
        evidence.has(field) &&
        !(field === "endLine" && line === null) &&
        !(typeof line === "bigint"
          ? line >= 1n
          : typeof line === "number" && Number.isInteger(line) && line >= 1)
      )
        evidence.delete(field);
    }
    evidence.set(
      "code",
      boundedJsonText(
        item["code"] as string,
        FINDING_CODE_EVIDENCE_SNIPPET_BYTES,
      )[0],
    );
    bounded.push(objectFromEntries(evidence));
  }
  return bounded;
}

export function boundedFindingSection(
  value: unknown,
  maximumBytes: number,
  priorityKeys: readonly string[],
  reservedFields: ReservedFields,
): unknown {
  if (!object(value)) return boundedJsonValue(value, [maximumBytes]);
  const ordered = new Map<string, unknown>();
  for (const [aliases, fieldBytes] of reservedFields) {
    const key = aliases.find((alias) => Object.hasOwn(value, alias));
    if (key !== undefined)
      ordered.set(key, boundedJsonValue(value[key], [fieldBytes]));
  }
  for (const key of [
    ...priorityKeys,
    ...objectEntries(value).map(([key]) => key),
  ])
    if (Object.hasOwn(value, key) && !ordered.has(key))
      ordered.set(key, value[key]);
  const [evidenceKey, evidence] = mergedCodeEvidence(
    objectFromEntries(ordered),
  );
  if (evidenceKey !== null) {
    ordered.set(evidenceKey, boundedCodeEvidence(evidence));
    ordered.delete(
      evidenceKey === "codeEvidence" ? "code_evidence" : "codeEvidence",
    );
  }
  return boundedJsonValue(objectFromEntries(ordered), [maximumBytes]);
}

const sections: readonly (readonly [
  readonly string[],
  number,
  readonly string[],
  ReservedFields,
])[] = [
  [
    ["rootCause", "root_cause"],
    FINDING_ROOT_CAUSE_PREVIEW_BYTES,
    [
      "summary",
      "description",
      "detail",
      "cause",
      "rationale",
      "why",
      "explanation",
      "evidenceRefs",
      "evidence_refs",
    ],
    [
      [
        ["summary", "description", "detail", "cause", "rationale", "why"],
        1_000,
      ],
      [["evidenceRefs", "evidence_refs"], 400],
    ],
  ],
  [
    ["validation"],
    FINDING_VALIDATION_PREVIEW_BYTES,
    [
      "summary",
      "conclusion",
      "method",
      "status",
      "disposition",
      "result",
      "rationale",
      "evidenceRef",
      "evidence_ref",
      "evidenceRefs",
      "evidence_refs",
      "assertions",
      "evidence",
      "counterEvidence",
      "limitations",
    ],
    [
      [["summary", "conclusion", "rationale", "detail", "disposition"], 800],
      [["method"], 256],
      [["status"], 128],
      [["evidenceRefs", "evidence_refs"], 400],
      [["assertions"], 400],
      [["evidence"], 400],
      [["counterEvidence"], 400],
      [["limitations"], 400],
    ],
  ],
  [
    ["attackPath"],
    FINDING_ATTACK_PATH_PREVIEW_BYTES,
    [
      "narrative",
      "summary",
      "description",
      "dataFlow",
      "data_flow",
      "dataflow",
      "path",
      "reachability",
      "steps",
      "authScope",
      "auth_scope",
      "vector",
      "preconditions",
      "assumptions",
      "impact",
      "likelihood",
      "evidenceRefs",
      "evidence_refs",
    ],
    [
      [["narrative", "summary", "description"], 600],
      [["dataFlow", "data_flow", "dataflow", "path"], 600],
      [["reachability"], 500],
      [["steps"], 500],
      [["authScope", "auth_scope"], 200],
      [["vector"], 200],
      [["preconditions"], 500],
      [["assumptions"], 300],
      [["evidenceRefs", "evidence_refs"], 300],
    ],
  ],
];

export function boundedFindingDetails(value: unknown): Table {
  if (!object(value)) return objectFromEntries([]);
  const prepared = new Map<string, unknown>();
  for (const [aliases, maximum, priority, reserved] of sections) {
    let [key, section] =
      aliases[0] === "rootCause"
        ? mergedRootCause(value)
        : (() => {
            const key = aliases.find((alias) => Object.hasOwn(value, alias));
            return [key ?? null, key === undefined ? null : value[key]] as [
              string | null,
              unknown,
            ];
          })();
    if (key === null) continue;
    if (key === "attackPath" && object(section)) {
      const copy = new Map(objectEntries(section));
      for (const assessment of ["impact", "likelihood"]) {
        const item = copy.get(assessment);
        if (typeof item !== "string") continue;
        // Python's Unicode IGNORECASE also matches dotted and dotless I.
        const label =
          /^(critical|high|medium|low|informational|ignore|unknown)$/iu.test(
            item.replace(/[İı]/gu, "i"),
          )
            ? "level"
            : "rationale";
        copy.set(assessment, { [label]: item });
      }
      section = objectFromEntries(copy);
    }
    prepared.set(
      key,
      boundedFindingSection(section, maximum, priority, reserved),
    );
  }
  const writeup = value["writeup"];
  if (object(writeup) && typeof writeup["reportPath"] === "string")
    prepared.set("writeup", {
      reportPath: boundedJsonText(writeup["reportPath"], 512)[0],
    });
  const [evidenceKey, evidence] = mergedCodeEvidence(value);
  if (evidenceKey !== null)
    prepared.set(evidenceKey, boundedCodeEvidence(evidence));
  for (const key of [
    "confidence",
    "detectedAt",
    "evidence",
    "evidenceExcerpt",
    "identity",
    "provenance",
    "ruleId",
    "severity",
    "status",
    "taxonomy",
    "preventiveControls",
    "remediationTests",
  ]) {
    if (!Object.hasOwn(value, key)) continue;
    const item = value[key];
    prepared.set(
      key,
      key === "evidenceExcerpt" && typeof item === "string"
        ? boundedJsonText(item, FINDING_EVIDENCE_EXCERPT_BYTES)[0]
        : item,
    );
  }
  const guidance = new Map<string, unknown[]>();
  for (const key of ["remediationTests", "preventiveControls"]) {
    const item = prepared.get(key);
    if (Array.isArray(item)) guidance.set(key, item);
  }
  const coreKeys = [
    "writeup",
    "rootCause",
    "root_cause",
    "validation",
    "attackPath",
    "codeEvidence",
    "code_evidence",
    "confidence",
    "detectedAt",
    "identity",
    "provenance",
    "ruleId",
    "severity",
    "status",
    "taxonomy",
    "evidence",
    "evidenceExcerpt",
  ];
  const core = objectFromEntries(
    coreKeys
      .filter((key) => prepared.has(key))
      .map((key) => [key, prepared.get(key)]),
  );
  const extras = [...prepared].filter(
    ([key]) => !Object.hasOwn(core, key) && !guidance.has(key),
  );
  const complete = objectFromEntries(
    [...guidance].map(([key, items]) => [key, items.slice(0, 1)]),
  );
  const minimum = objectFromEntries(
    [...guidance].map(([key, items]) => [
      key,
      typeof items[0] === "string"
        ? [Array.from(items[0]).slice(0, 1).join("")]
        : [],
    ]),
  );
  let projectedCore: Table = objectFromEntries([]);
  for (const selected of [complete, minimum]) {
    const reserved = objectEntries(selected).length
      ? jsonSize(selected) - 1
      : 0;
    if (reserved >= FINDING_DETAILS_PREVIEW_BYTES) continue;
    projectedCore = boundedJsonValue(
      core,
      [FINDING_DETAILS_PREVIEW_BYTES - reserved],
      0,
      5,
    ) as Table;
    if (objectEntries(core).every(([key]) => Object.hasOwn(projectedCore, key)))
      break;
  }
  const orderedGuidance = [...guidance].sort(
    (a, b) => Number(Boolean(a[1].length)) - Number(Boolean(b[1].length)),
  );
  const bounded = boundedJsonValue(
    objectFromEntries([
      ...objectEntries(projectedCore),
      ...orderedGuidance,
      ...extras,
    ]),
    [FINDING_DETAILS_PREVIEW_BYTES],
    0,
    5,
  );
  return object(bounded) ? bounded : objectFromEntries([]);
}
