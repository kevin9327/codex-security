import { createHash } from "node:crypto";
import { basename, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { validateAgainstSchema } from "./contract-schema";
import {
  contractValuesEqual,
  requireDict,
  requireString,
  validateContractRefs,
  validateCoverage,
  validateDerivedFindingIdentities,
  validateFindings,
  validateManifest,
} from "./contract-validation";
import { fileInfo } from "./helper-files";
import { SymlinkLoopError } from "./posix-path";
import { object } from "./python-json";
import { appendPath } from "./rank-selection";
import { compare } from "./rank-worklists";
import { resolvedPath } from "./resolve-path";
import { parsedPath } from "./resolve-security-md";
import {
  buildCsvProjection,
  legacySealedFindingsForValidation,
} from "./saved-findings-projection";
import {
  buildSarif,
  validateSarif,
  type SarifFinding,
  type SarifManifest,
} from "./sarif-projection";
import { ContractError } from "./scan-contract-errors";
import {
  jsonBytes,
  readJson,
  readScanLocalJson,
  readScanLocalJsonBytes,
  writeScanLocalJson,
} from "./scan-contract-json";
import {
  requirePortableRelativePath,
  requireScanDirectory,
  sha256ScanLocalFile,
  validateScanLocalOutputPath,
} from "./scan-local-files";
import { lowercase, uppercase } from "./unicode-case";

type Table = Record<string, unknown>;
type SealedScan = [Table, Table, Table, Buffer];
export const EXPORT_PATHS = {
  csv: "exports/findings.csv",
  json: "exports/findings.json",
  sarif: "exports/results.sarif",
} as const;
const get = (table: Table, key: string): unknown =>
  Object.hasOwn(table, key) ? table[key] : null;
const sha256 = (contents: Buffer) =>
  createHash("sha256").update(contents).digest("hex");

export function schemaDirectory(directory?: string | null): string {
  return directory == null
    ? fileURLToPath(new URL("../schemas", import.meta.url))
    : parsedPath(directory);
}

export function validateContractSchema(payload: Table, path: string): void {
  const schema = readJson(path);
  validateAgainstSchema(payload, schema, basename(path, extname(path)), schema);
}

export function artifactRecord(
  scanDir: string,
  relative: string,
  mediaType: string,
  contents?: Buffer,
): Record<string, string> {
  relative = requirePortableRelativePath(relative, "artifact path");
  if (contents !== undefined)
    validateScanLocalOutputPath(
      scanDir,
      appendPath(scanDir, relative),
      relative,
    );
  return {
    mediaType,
    path: relative,
    sha256:
      contents === undefined
        ? sha256ScanLocalFile(scanDir, relative, relative)
        : sha256(contents),
  };
}

export function coverageReceiptRefs(coverage: Table): string[] {
  const refs = new Set<string>();
  for (const surface of coverage["surfaces"] as Table[])
    for (const ref of (Object.hasOwn(surface, "receiptRefs")
      ? surface["receiptRefs"]
      : []) as string[])
      refs.add(ref);
  return [...refs].sort(compare);
}

export function validateSealedCoverageReceipts(
  scan: Table,
  coverage: Table,
): void {
  const paths = new Set(
    (scan["artifacts"] as Table[]).map((artifact) =>
      requirePortableRelativePath(
        artifact["path"] as string,
        "sealed artifact path",
      ),
    ),
  );
  for (const ref of coverageReceiptRefs(coverage))
    if (!paths.has(ref))
      throw new ContractError(
        `coverage receipt is missing from sealed artifacts: ${ref}`,
      );
}

export function validateExistingSeal(
  scanDir: string,
  scan: Table,
  artifactContents: ReadonlyMap<string, Buffer> = new Map(),
): void {
  const sealedAt = get(scan, "sealedAt"),
    artifacts = get(scan, "artifacts");
  if (sealedAt === null && artifacts === null) return;
  if (!contractValuesEqual(sealedAt, get(scan, "completedAt")))
    throw new ContractError("manifest.scan.sealedAt: must match completedAt");
  if (!Array.isArray(artifacts) || !artifacts.length)
    throw new ContractError(
      "manifest.scan.artifacts: sealed manifest requires artifact records",
    );
  const collisionKeys = new Set<string>();
  for (const [index, artifact] of artifacts.entries()) {
    const context = `manifest.scan.artifacts[${index}]`;
    if (!object(artifact))
      throw new ContractError(`${context}: expected an object`);
    const path = requirePortableRelativePath(
      requireString(artifact, "path", context),
      `${context}.path`,
    );
    const collisionKey = lowercase(path);
    if (collisionKeys.has(collisionKey))
      throw new ContractError(`${context}.path: duplicate artifact path`);
    collisionKeys.add(collisionKey);
    const expected = requireString(artifact, "sha256", context),
      contents = artifactContents.get(path);
    const actual =
      contents === undefined
        ? sha256ScanLocalFile(scanDir, path, context)
        : sha256(contents);
    if (actual !== expected)
      throw new ContractError(
        `${context}: sealed artifact changed or is missing`,
      );
  }
}

export function readSealedScan(
  scanDir: string,
  schemas: string | null | undefined,
  requiredFor: string,
): SealedScan {
  scanDir = requireScanDirectory(scanDir);
  schemas = schemaDirectory(schemas);
  const manifest = readScanLocalJson(
    scanDir,
    "scan-manifest.json",
    "scan-manifest.json",
  );
  const scan = requireDict(manifest, "scan", "manifest");
  validateContractRefs(scan);
  if (get(scan, "sealedAt") === null || get(scan, "artifacts") === null)
    throw new ContractError(
      `manifest.scan: ${requiredFor} requires a sealed scan`,
    );
  const findingsRef = scan["findingsRef"] as string,
    coverageRef = scan["coverageRef"] as string;
  const [findings, findingsBytes] = readScanLocalJsonBytes(
    scanDir,
    findingsRef,
    findingsRef,
  );
  const [coverage, coverageBytes] = readScanLocalJsonBytes(
    scanDir,
    coverageRef,
    coverageRef,
  );
  validateExistingSeal(
    scanDir,
    scan,
    new Map([
      [findingsRef, findingsBytes],
      [coverageRef, coverageBytes],
    ]),
  );
  validateManifest(manifest);
  const compatible = legacySealedFindingsForValidation(findings);
  validateFindings(manifest, compatible);
  validateCoverage(manifest, coverage, scanDir);
  validateSealedCoverageReceipts(scan, coverage);
  validateContractSchema(
    manifest,
    appendPath(schemas, "scan-manifest.schema.json"),
  );
  validateContractSchema(
    compatible,
    appendPath(schemas, "findings.schema.json"),
  );
  validateContractSchema(coverage, appendPath(schemas, "coverage.schema.json"));
  validateDerivedFindingIdentities(manifest, findings);
  return [manifest, findings, coverage, findingsBytes];
}

export function buildSarifProjection(
  scanDir: string,
  sourceRoot?: string | null,
  schemas?: string | null,
): Table {
  if (sourceRoot != null) {
    let directory = false;
    try {
      sourceRoot = resolvedPath(sourceRoot);
      directory = fileInfo(sourceRoot)?.isDirectory() ?? false;
    } catch (error) {
      const system = error as { errno?: number; winerror?: number };
      if (
        system.errno === undefined &&
        system.winerror === undefined &&
        !(error instanceof SymlinkLoopError)
      )
        throw error;
    }
    if (!directory)
      throw new ContractError("source root: expected an existing directory");
  }
  const [manifest, findings, coverage] = readSealedScan(
    scanDir,
    schemas,
    "SARIF projection",
  );
  const sarif = buildSarif(
    manifest as unknown as SarifManifest,
    findings as { findings: SarifFinding[] },
    sourceRoot ?? undefined,
  );
  const successful = (manifest["scan"] as Table)["status"] === "completed";
  if (!successful || coverage["completeness"] !== "complete") {
    const run = (sarif["runs"] as Table[])[0]!;
    (run["properties"] as Table)["codexSecurityCoverageCompleteness"] =
      coverage["completeness"];
    run["invocations"] = [
      {
        executionSuccessful: successful,
        toolExecutionNotifications: (coverage["deferred"] as Table[]).map(
          (item) => ({ level: "warning", message: { text: item["reason"] } }),
        ),
      },
    ];
  }
  validateSarif(sarif);
  return sarif;
}

export function writeSarifProjection(
  scanDir: string,
  sourceRoot?: string | null,
  schemas?: string | null,
): void {
  writeScanLocalJson(
    scanDir,
    "exports/results.sarif",
    buildSarifProjection(scanDir, sourceRoot, schemas),
  );
}

export function buildFindingsExport(
  scanDir: string,
  format: string,
  sourceRoot?: string | null,
  schemas?: string | null,
): Buffer {
  if (!Object.hasOwn(EXPORT_PATHS, format))
    throw new ContractError(`unsupported export format: ${format}`);
  if (format === "sarif")
    return jsonBytes(buildSarifProjection(scanDir, sourceRoot, schemas));
  if (sourceRoot != null)
    throw new ContractError("source-root is only supported for SARIF exports");
  const [, findings, coverage, findingsBytes] = readSealedScan(
    scanDir,
    schemas,
    `${uppercase(format)} export`,
  );
  return format === "json"
    ? findingsBytes
    : buildCsvProjection(findings as { findings: SarifFinding[] }, coverage);
}
