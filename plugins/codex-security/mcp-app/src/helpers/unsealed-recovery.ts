import { validateAgainstSchema } from "./contract-schema";
import {
  contractValuesEqual,
  populateUnsealedFindingIdentities,
  requireDict,
  requireHardeningPortfolioFile,
  requireList,
  requireScanLocalFile,
  requireString,
  validateFinding,
} from "./contract-validation";
import { findingEvidenceStrength } from "./finding-evidence";
import { hasText } from "./finding-root-cause";
import { copyJson, object } from "./python-json";
import { appendPath } from "./rank-selection";
import { legacySealedFindingsForValidation } from "./saved-findings-projection";
import { ContractError } from "./scan-contract-errors";
import { readJson, requireSafeJsonString } from "./scan-contract-json";
import { requirePortableRelativePath } from "./scan-local-files";
import { lowercase } from "./unicode-case";

type Table = Record<string, unknown>;
type Strength = [number, number, number];
const slug = /^[a-z0-9][a-z0-9._/-]*$(?![\s\S])/u;

export function findingStrength(finding: Table): Strength {
  const severity = [
    "informational",
    "low",
    "medium",
    "high",
    "critical",
  ].indexOf((finding["severity"] as Table)["level"] as string);
  if (severity === -1) throw new Error("tuple.index(x): x not in tuple");
  const confidence = ["low", "medium", "high"].indexOf(
    (finding["confidence"] as Table)["level"] as string,
  );
  if (confidence === -1) throw new Error("tuple.index(x): x not in tuple");
  return [severity, confidence, findingEvidenceStrength(finding)];
}

function noStronger(left: Table, right: Table): boolean {
  const a = findingStrength(left),
    b = findingStrength(right);
  for (let index = 0; index < a.length; index++)
    if (a[index] !== b[index]) return a[index]! < b[index]!;
  return true;
}

/** Recover draft findings while retaining the finalizer's warnings and history. */
export function recoverUnsealedFindings(
  manifest: Table,
  findings: Table,
  schemaDir: string,
  scanDir: string,
  warnings: string[],
): string[] {
  const schema = readJson(appendPath(schemaDir, "findings.schema.json"));
  const properties = requireDict(schema, "properties", "findings.schema");
  const findingArray = requireDict(
    properties,
    "findings",
    "findings.schema.properties",
  );
  const findingSchema = requireDict(
    findingArray,
    "items",
    "findings.schema.properties.findings",
  );
  const findingProperties = requireDict(
    findingSchema,
    "properties",
    "findings.schema.properties.findings.items",
  );
  const writeupSchema = requireDict(
    findingProperties,
    "writeup",
    "findings.schema.properties.findings.items.properties",
  );
  const auxiliarySchemas = ["remediationTests", "preventiveControls"].map(
    (name): [string, Table] => [
      name,
      requireDict(
        findingProperties,
        name,
        "findings.schema.properties.findings.items.properties",
      ),
    ],
  );
  const scan = requireDict(manifest, "scan", "manifest");
  const scanId = requireString(scan, "id", "manifest.scan");
  if (findings["scanId"] !== scanId)
    throw new ContractError("findings.scanId: must match manifest scan id");

  const recovered: Table[] = [],
    discarded: string[] = [];
  const findingPositions = new Map<string, number>(),
    writeupPaths = new Set<string>();
  for (const [index, originalFinding] of requireList(
    findings,
    "findings",
    "findings",
  ).entries()) {
    const context = `findings.findings[${index}]`;
    let finding: Table, findingId: string, previousPosition: number | undefined;
    let normalizedFields: string[];
    try {
      if (!object(originalFinding))
        throw new ContractError(`${context}: expected an object`);
      finding = (
        legacySealedFindingsForValidation({ findings: [originalFinding] })[
          "findings"
        ] as Table[]
      )[0]!;
      const normalizedLegacyDetails = !contractValuesEqual(
        finding,
        originalFinding,
      );
      const identity = requireDict(finding, "identity", context);
      const fields: [Table, string, string, string][] = [
        [finding, "ruleId", context, "rule identifier"],
        [identity, "anchor", `${context}.identity`, "semantic anchor"],
      ];
      if (Object.hasOwn(identity, "instance"))
        fields.push([identity, "instance", `${context}.identity`, "instance"]);
      normalizedFields = normalizedLegacyDetails
        ? ["legacy finding details"]
        : [];
      for (const [parent, field, fieldContext, label] of fields) {
        const value = requireString(parent, field, fieldContext);
        if (slug.test(value)) continue;
        const normalized = lowercase(value)
          .replace(/[^a-z0-9._/-]+/gu, "-")
          .replace(/^[._/-]+|[._/-]+$/gu, "");
        if (!slug.test(normalized))
          throw new ContractError(
            `${fieldContext}.${field}: expected a stable lowercase semantic slug`,
          );
        parent[field] = normalized;
        normalizedFields.push(label);
      }
      const severity = finding["severity"];
      if (object(severity)) {
        const conditions = severity["changeConditions"];
        if (
          Array.isArray(conditions) &&
          conditions.length &&
          conditions.every(hasText)
        ) {
          conditions.forEach((condition, at) =>
            requireSafeJsonString(
              condition,
              `${context}.severity.changeConditions[${at}]`,
            ),
          );
          severity["changeConditions"] = conditions
            .map((condition) =>
              condition.replace(
                /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
                "",
              ),
            )
            .join(" ");
          normalizedFields.push("severity change conditions");
        }
      }
      populateUnsealedFindingIdentities(manifest, {
        scanId,
        findings: [finding],
      });
      findingId = finding["findingId"] as string;
      previousPosition = findingPositions.get(findingId);
      validateFinding(finding, context);
      if (Object.hasOwn(finding, "writeup")) {
        try {
          validateAgainstSchema(
            finding["writeup"],
            writeupSchema,
            `${context}.writeup`,
          );
          const reportPath = (finding["writeup"] as Table)[
            "reportPath"
          ] as string;
          const previousWriteup =
            previousPosition === undefined
              ? undefined
              : (recovered[previousPosition]!["writeup"] as Table | undefined);
          if (
            writeupPaths.has(reportPath) &&
            (previousWriteup == null ||
              previousWriteup["reportPath"] !== reportPath)
          )
            throw new ContractError(
              `${context}.writeup.reportPath: duplicate report path`,
            );
          requireScanLocalFile(
            scanDir,
            reportPath,
            `${context}.writeup.reportPath`,
          );
        } catch (error) {
          if (!(error instanceof ContractError)) throw error;
          delete finding["writeup"];
          warnings.push(
            `Skipped malformed writeup for finding ${index + 1}: ${error.message}.`,
          );
        }
      }
      for (const [auxiliary, auxiliarySchema] of auxiliarySchemas) {
        if (!Object.hasOwn(finding, auxiliary)) continue;
        try {
          validateAgainstSchema(
            finding[auxiliary],
            auxiliarySchema,
            `${context}.${auxiliary}`,
          );
        } catch (error) {
          if (!(error instanceof ContractError)) throw error;
          delete finding[auxiliary];
          warnings.push(
            `Skipped malformed ${auxiliary} for finding ${index + 1}: ${error.message}.`,
          );
        }
      }
      validateAgainstSchema(finding, findingSchema, context);
    } catch (error) {
      if (!(error instanceof ContractError)) throw error;
      const warning = `Skipped malformed finding ${index + 1}: ${error.message}.`;
      warnings.push(warning);
      discarded.push(warning);
      continue;
    }
    if (previousPosition !== undefined) {
      const previous = recovered[previousPosition]!;
      const [strongest, earlier] = noStronger(finding, previous)
        ? [previous, finding]
        : [finding, previous];
      if (!contractValuesEqual(strongest, earlier)) {
        const original = copyJson(earlier) as Table;
        const provenance = original["provenance"] as Table;
        const older = provenance["previousFindings"] ?? [];
        delete provenance["previousFindings"];
        const strongestProvenance = strongest["provenance"] as Table;
        if (!Array.isArray(strongestProvenance["previousFindings"]))
          strongestProvenance["previousFindings"] = [];
        const history = strongestProvenance["previousFindings"] as unknown[];
        for (const record of [...(Array.isArray(older) ? older : []), original])
          if (!history.some((entry) => contractValuesEqual(record, entry)))
            history.push(record);
      }
      if (noStronger(finding, previous)) {
        warnings.push(
          `Skipped malformed finding ${index + 1}: duplicate logical finding.`,
        );
        continue;
      }
      const previousWriteup = previous["writeup"];
      if (previousWriteup != null)
        writeupPaths.delete((previousWriteup as Table)["reportPath"] as string);
      recovered[previousPosition] = finding;
      warnings.push(
        `Recovered finding ${index + 1}: retained stronger duplicate logical finding.`,
      );
    } else {
      findingPositions.set(findingId, recovered.length);
      recovered.push(finding);
    }
    if (Object.hasOwn(finding, "writeup"))
      writeupPaths.add((finding["writeup"] as Table)["reportPath"] as string);
    if (normalizedFields.length)
      warnings.push(
        `Recovered finding ${index + 1}: normalized ${normalizedFields.join(", ")}.`,
      );
  }
  findings["findings"] = recovered;
  return discarded;
}

export function recoverUnsealedCoverage(
  coverage: Table,
  schemaDir: string,
  scanDir: string,
  warnings: string[],
  discardedFindings: string[],
): void {
  const schema = readJson(appendPath(schemaDir, "coverage.schema.json"));
  const properties = requireDict(schema, "properties", "coverage.schema");
  const completeness = coverage["completeness"];
  let partial = !["complete", "partial", "unknown"].includes(
    completeness as string,
  );
  if (partial)
    warnings.push(
      "Recovered malformed coverage completeness; marked coverage as partial.",
    );
  if (
    coverage["mode"] === "deep_repository" &&
    coverage["inventoryStrategy"] !== "repository"
  ) {
    coverage["inventoryStrategy"] = "repository";
    warnings.push(
      "Recovered malformed Deep Scan inventory strategy; marked coverage as partial.",
    );
    partial = true;
  }
  const surfaceIds = new Set<string>();
  for (const [field, label] of [
    ["surfaces", "coverage surface"],
    ["explicitExclusions", "coverage exclusion"],
    ["deferred", "deferred coverage item"],
  ] as const) {
    const arraySchema = requireDict(
      properties,
      field,
      "coverage.schema.properties",
    );
    const itemSchema = requireDict(
      arraySchema,
      "items",
      `coverage.schema.properties.${field}`,
    );
    const items = coverage[field];
    if (!Array.isArray(items)) {
      warnings.push(`Skipped malformed ${label} records: expected an array.`);
      coverage[field] = [];
      partial = true;
      continue;
    }
    const recovered: Table[] = [];
    for (const [index, item] of items.entries()) {
      const context = `coverage.${field}[${index}]`;
      let surfaceId: string | undefined;
      try {
        if (!object(item))
          throw new ContractError(`${context}: expected an object`);
        if (field === "surfaces") {
          surfaceId = requireString(item, "id", context);
          if (surfaceIds.has(surfaceId))
            throw new ContractError(`${context}.id: duplicate surface id`);
          const disposition = item["disposition"];
          let surfaceRecovered = false;
          if (
            typeof disposition !== "string" ||
            ![
              "reported",
              "no_issue_found",
              "rejected",
              "not_applicable",
              "needs_follow_up",
            ].includes(disposition)
          ) {
            warnings.push(
              `Recovered coverage surface ${index + 1}: the review disposition could not be verified.`,
            );
            item["disposition"] = "needs_follow_up";
            surfaceRecovered = true;
          }
          let receiptRefs = item["receiptRefs"];
          if (!Array.isArray(receiptRefs)) {
            warnings.push(
              `Skipped malformed receipt references for coverage surface ${index + 1}: expected an array.`,
            );
            receiptRefs = [];
            surfaceRecovered = true;
          }
          const recoveredReceipts: string[] = [];
          for (const [refIndex, ref] of (receiptRefs as unknown[]).entries()) {
            const refContext = `${context}.receiptRefs[${refIndex}]`;
            let normalizedRef: string;
            try {
              if (typeof ref !== "string")
                throw new ContractError(`${refContext}: expected a string`);
              normalizedRef = requirePortableRelativePath(ref, refContext);
              if (!normalizedRef.startsWith("artifacts/"))
                throw new ContractError(
                  `${refContext}: expected a file under artifacts/`,
                );
              requireScanLocalFile(scanDir, normalizedRef, refContext);
            } catch (error) {
              if (!(error instanceof ContractError)) throw error;
              warnings.push(
                `Skipped malformed coverage receipt ${index + 1}.${refIndex + 1}: ${error.message}.`,
              );
              surfaceRecovered = true;
              continue;
            }
            recoveredReceipts.push(normalizedRef);
          }
          item["receiptRefs"] = recoveredReceipts;
          if (surfaceRecovered || item["disposition"] === "needs_follow_up") {
            if (!surfaceRecovered && completeness !== "partial")
              warnings.push(
                `Coverage surface ${index + 1} requires follow-up; marked coverage as partial.`,
              );
            item["disposition"] = "needs_follow_up";
            partial = true;
          }
        }
        validateAgainstSchema(item, itemSchema, context);
      } catch (error) {
        if (!(error instanceof ContractError)) throw error;
        warnings.push(
          `Skipped malformed ${label} ${index + 1}: ${error.message}.`,
        );
        partial = true;
        continue;
      }
      if (field === "surfaces") surfaceIds.add(surfaceId!);
      recovered.push(item);
    }
    coverage[field] = recovered;
  }
  if (discardedFindings.length) {
    for (const surface of coverage["surfaces"] as Table[])
      surface["disposition"] = "needs_follow_up";
    for (const [index, warning] of discardedFindings.entries())
      (coverage["deferred"] as unknown[]).push({
        id: `discarded-finding-${index + 1}`,
        reason: warning,
      });
    partial = true;
  }
  if (
    (coverage["deferred"] as unknown[]).length &&
    completeness !== "partial"
  ) {
    if (!discardedFindings.length)
      warnings.push(
        "Coverage has deferred review work; marked coverage as partial.",
      );
    partial = true;
  }
  if (partial) coverage["completeness"] = "partial";
}

export function recoverUnsealedHardening(
  manifest: Table,
  scanDir: string,
  warnings: string[],
): void {
  const scan = requireDict(manifest, "scan", "manifest");
  if (!Object.hasOwn(scan, "hardening")) return;
  try {
    const hardening = requireDict(scan, "hardening", "manifest.scan");
    const portfolioPath = requireString(
      hardening,
      "portfolioPath",
      "manifest.scan.hardening",
    );
    if (portfolioPath !== "hardening/hardening.md")
      throw new ContractError(
        "manifest.scan.hardening.portfolioPath: expected hardening/hardening.md",
      );
    requireHardeningPortfolioFile(scanDir, scan);
  } catch (error) {
    if (!(error instanceof ContractError)) throw error;
    delete scan["hardening"];
    warnings.push(`Skipped malformed hardening portfolio: ${error.message}.`);
  }
}
