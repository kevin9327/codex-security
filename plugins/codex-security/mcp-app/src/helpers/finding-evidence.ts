import { hasText } from "./finding-root-cause";
import { object } from "./python-json";

type Table = Record<string, unknown>;

export function primaryFindingLocation<T extends { role?: unknown }>(finding: {
  locations: T[];
}): T {
  return (
    finding.locations.find((location) => location.role === "root_control") ??
    finding.locations[0]!
  );
}

export function mergedCodeEvidence(finding: Table): Table[] {
  const catalog = new Map<string, Table>();
  for (const key of ["codeEvidence", "code_evidence"]) {
    const entries = finding[key];
    if (!Array.isArray(entries)) continue;
    for (const evidence of entries) {
      if (!object(evidence)) continue;
      const id = evidence["id"];
      if (typeof id === "string" && id !== "" && !catalog.has(id))
        catalog.set(id, evidence);
    }
  }
  return [...catalog.values()];
}

export function findingEvidenceStrength(finding: Table): number {
  const evidence = mergedCodeEvidence(finding);
  const ids = new Set(evidence.map((item) => item["id"]).filter(hasText));
  const codes = new Set(evidence.map((item) => item["code"]).filter(hasText));
  let strength = evidence.length;
  for (const name of ["rootCause", "root_cause"]) {
    const section = finding[name];
    if (!object(section)) continue;
    for (const evidenceName of ["codeEvidence", "code_evidence"]) {
      const embedded = section[evidenceName];
      if (!Array.isArray(embedded)) continue;
      for (const item of embedded) {
        if (!object(item)) continue;
        const code = item["code"],
          id = item["id"];
        if (!hasText(code) || codes.has(code)) continue;
        if (hasText(id)) {
          if (ids.has(id)) continue;
          ids.add(id);
        }
        codes.add(code);
        strength++;
      }
    }
    const code = section["code"];
    if (hasText(code) && !codes.has(code)) {
      codes.add(code);
      strength++;
    }
  }
  return strength;
}
