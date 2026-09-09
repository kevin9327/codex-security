import { object, objectEntries, objectFromEntries } from "./python-json";

type Table = Record<string, unknown>;
export const hasText = (value: unknown): value is string =>
  typeof value === "string" && /[^\p{White_Space}\u001c-\u001f]/u.test(value);

/** Combine canonical and legacy root-cause fields without changing either input. */
export function mergedRootCause(value: Table): [string | null, unknown] {
  const keys = ["rootCause", "root_cause"].filter((key) =>
    Object.hasOwn(value, key),
  );
  if (!keys.length) return [null, null];
  const first = keys[0]!;
  if (keys.length === 1) {
    const detail = value[first];
    return [
      first,
      typeof detail === "string" || object(detail) ? detail : null,
    ];
  }
  const details = keys.flatMap((key): Table[] => {
    const detail = value[key];
    return typeof detail === "string"
      ? [{ summary: detail }]
      : object(detail)
        ? [detail]
        : [];
  });
  if (!details.length) return [first, null];
  const merged = new Map<string, unknown>();
  const textFields = new Set([
    "cause",
    "code",
    "description",
    "detail",
    "explanation",
    "rationale",
    "summary",
    "why",
  ]);
  for (const detail of details) {
    for (const [field, item] of objectEntries(detail)) {
      if (
        [
          "evidenceRefs",
          "evidence_refs",
          "codeEvidence",
          "code_evidence",
          "language",
        ].includes(field)
      )
        continue;
      if (textFields.has(field) && !hasText(item)) continue;
      const current = merged.get(field);
      if (
        !merged.has(field) ||
        current === null ||
        (typeof current === "string" && !hasText(current)) ||
        (Array.isArray(current) && !current.length) ||
        (object(current) && !objectEntries(current).length)
      )
        merged.set(field, item);
    }
  }
  const evidenceValues = details.flatMap((detail) =>
    ["evidenceRefs", "evidence_refs"]
      .filter((field) => Object.hasOwn(detail, field))
      .map((field) => detail[field]),
  );
  if (evidenceValues.length) {
    const references = new Set<string>();
    for (const evidence of evidenceValues)
      for (const item of Array.isArray(evidence) ? evidence : [evidence])
        if (typeof item === "string") references.add(item);
    merged.set("evidenceRefs", [...references]);
  }
  const embedded = details.flatMap((detail) =>
    ["codeEvidence", "code_evidence"].flatMap((field) =>
      Array.isArray(detail[field]) ? detail[field] : [],
    ),
  );
  if (embedded.length) merged.set("codeEvidence", embedded);
  const code = merged.get("code");
  const matching = hasText(code)
    ? details.filter((detail) => detail["code"] === code)
    : details;
  const language = matching.map((detail) => detail["language"]).find(hasText);
  if (language !== undefined) merged.set("language", language);
  return [first, objectFromEntries(merged)];
}
