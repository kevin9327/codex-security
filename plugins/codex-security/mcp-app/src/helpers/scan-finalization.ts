import {
  normalizeUnsealedDeepRepositoryInventoryStrategy,
  normalizeUnsealedOpenQuestions,
  populateUnsealedArtifactEnvelope,
  populateUnsealedManifestEnvelope,
  validateCompletionBinding,
} from "./contract-completion-binding";
import {
  contractValuesEqual,
  populateUnsealedFindingIdentities,
  requireDerivedWriteupFiles,
  requireDict,
  requireHardeningPortfolioFile,
  requireString,
  SCHEMA_VERSION,
  validateContractRefs,
  validateCoverage,
  validateDerivedFindingIdentities,
  validateFindings,
  validateManifest,
  validateTarget,
} from "./contract-validation";
import { filesystemErrorMessage } from "./file-errors";
import { copyJson, object, pythonRepr } from "./python-json";
import { appendPath } from "./rank-selection";
import { print } from "./rank-worklists";
import {
  generateReportMarkdown,
  ReportProjectionError,
  type ReportCoverage,
  type ReportFinding,
  type ReportManifest,
} from "./report-projection";
import { legacySealedFindingsForValidation } from "./saved-findings-projection";
import {
  ContractError,
  RecoverableContractError,
} from "./scan-contract-errors";
import {
  contractJsonBytes,
  jsonBytes,
  readScanLocalJson,
  readScanLocalJsonBytes,
  writeScanLocalJson,
} from "./scan-contract-json";
import {
  removeScanLocalFileIfExists,
  requireScanDirectory,
  validateScanLocalOutputPath,
  writeScanLocalBytes,
} from "./scan-local-files";
import {
  artifactRecord,
  coverageReceiptRefs,
  schemaDirectory,
  validateContractSchema,
  validateExistingSeal,
  validateSealedCoverageReceipts,
  writeSarifProjection,
} from "./sealed-scan";
import {
  recoverUnsealedCoverage,
  recoverUnsealedFindings,
  recoverUnsealedHardening,
} from "./unsealed-recovery";

type Table = Record<string, unknown>;
export type ScanDocuments = [Table, Table, Table];
export interface PreparedScanFinalization {
  scanDir: string;
  schemaDir: string;
  manifest: Table;
  findings: Table;
  coverage: Table;
  wasSealed: boolean;
  reportMarkdown: Buffer;
}
export interface FinalizationOptions {
  expectedCoverageMode?: string | null;
  completionBinding?: Table | null;
  completionWarnings?: string[] | null;
  draftDocuments?: ScanDocuments | null;
  /** The workbench supplies its existing retry count for deep reports. */
  reportAttempts?: number;
}
const get = (table: Table, key: string): unknown =>
  Object.hasOwn(table, key) ? table[key] : null;
const at = (table: Table, key: string): unknown => {
  if (!Object.hasOwn(table, key)) throw new Error(pythonRepr(key));
  return table[key];
};
const osError = (error: unknown): boolean => {
  const value = error as { errno?: number; winerror?: number };
  return value.errno !== undefined || value.winerror !== undefined;
};

export function generateReportProjection(
  manifest: Table,
  findings: Table,
  coverage: Table,
  deepAttempts = 1,
): Buffer {
  const attempts = coverage["mode"] === "deep_repository" ? deepAttempts : 1;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return generateReportMarkdown(
        manifest as unknown as ReportManifest,
        findings as { findings: ReportFinding[] },
        coverage as ReportCoverage,
      );
    } catch (error) {
      if (osError(error)) {
        if (attempt === attempts - 1)
          throw new RecoverableContractError(
            `report projection failed: ${filesystemErrorMessage(error)}`,
          );
        Atomics.wait(
          new Int32Array(new SharedArrayBuffer(4)),
          0,
          0,
          50 * 2 ** attempt,
        );
      } else if (
        error instanceof ReportProjectionError ||
        (error instanceof Error && error.constructor === Error)
      ) {
        throw new ContractError(`report projection failed: ${error.message}`);
      } else throw error;
    }
  }
  throw new Error("Report projection retry loop exhausted unexpectedly.");
}

export function validateCanonicalSchemasBeforeProjection(
  manifest: Table,
  findings: Table,
  coverage: Table,
  schemaDir: string,
): void {
  const provisional = copyJson(manifest) as Table;
  const scan = requireDict(provisional, "scan", "manifest");
  scan["artifacts"] = ["findings.json", "coverage.json"].map((path) => ({
    path,
    sha256: "0".repeat(64),
    mediaType: "application/json",
  }));
  validateContractSchema(
    provisional,
    appendPath(schemaDir, "scan-manifest.schema.json"),
  );
  validateContractSchema(
    findings,
    appendPath(schemaDir, "findings.schema.json"),
  );
  validateContractSchema(
    coverage,
    appendPath(schemaDir, "coverage.schema.json"),
  );
}

/** Read, populate and validate a scan before writing any output files. */
export function prepareScanFinalization(
  scanDir: string,
  schemas?: string | null,
  options: FinalizationOptions = {},
): PreparedScanFinalization {
  scanDir = requireScanDirectory(scanDir);
  const schemaDir = schemaDirectory(schemas);
  const binding = options.completionBinding ?? null;
  const draft = options.draftDocuments;
  const manifest =
    draft == null
      ? readScanLocalJson(scanDir, "scan-manifest.json", "scan-manifest.json")
      : (copyJson(draft[0]) as Table);
  const scan = requireDict(manifest, "scan", "manifest");
  const wasSealed =
    get(scan, "sealedAt") !== null || get(scan, "artifacts") !== null;
  if (!wasSealed) populateUnsealedManifestEnvelope(manifest, scan, binding);
  validateContractRefs(scan);
  const findingsRef = scan["findingsRef"] as string,
    coverageRef = scan["coverageRef"] as string;
  let findings: Table,
    coverage: Table,
    findingsInput: Buffer,
    coverageInput: Buffer;
  if (draft == null) {
    [findings, findingsInput] = readScanLocalJsonBytes(
      scanDir,
      findingsRef,
      findingsRef,
    );
    [coverage, coverageInput] = readScanLocalJsonBytes(
      scanDir,
      coverageRef,
      coverageRef,
    );
  } else {
    [findings, coverage] = copyJson(draft.slice(1)) as [Table, Table];
    findingsInput = jsonBytes(findings);
    coverageInput = jsonBytes(coverage);
  }
  if (!wasSealed) {
    populateUnsealedArtifactEnvelope(manifest, findings, coverage, binding);
    normalizeUnsealedDeepRepositoryInventoryStrategy(
      coverage,
      options.expectedCoverageMode ?? null,
    );
    normalizeUnsealedOpenQuestions(coverage);
  }
  if (get(manifest, "schemaVersion") !== SCHEMA_VERSION)
    throw new ContractError(
      `manifest.schemaVersion: expected ${SCHEMA_VERSION}`,
    );
  const status = get(scan, "status");
  if (Array.isArray(status) || object(status))
    throw new TypeError(
      `unhashable type: '${Array.isArray(status) ? "list" : "dict"}'`,
    );
  if (
    !["completed", "failed", "canceled", "interrupted"].includes(
      status as string,
    )
  )
    throw new ContractError(
      "manifest.scan.status: expected a terminal scan outcome before sealing",
    );
  const expectedMode = options.expectedCoverageMode;
  if (
    expectedMode != null &&
    binding !== null &&
    !contractValuesEqual(at(binding, "coverageMode"), expectedMode)
  )
    throw new ContractError(
      "completion binding coverage mode does not match expected mode",
    );
  if (
    expectedMode != null &&
    !contractValuesEqual(get(coverage, "mode"), expectedMode)
  )
    throw new ContractError(
      `coverage.mode: must match selected scan mode ${expectedMode}`,
    );
  validateExistingSeal(
    scanDir,
    scan,
    new Map([
      [findingsRef, findingsInput],
      [coverageRef, coverageInput],
    ]),
  );
  scan["sealedAt"] = requireString(scan, "completedAt", "manifest.scan");
  validateTarget(requireDict(scan, "target", "manifest.scan"));
  validateCompletionBinding(manifest, findings, coverage, binding);
  const compatible = wasSealed
    ? legacySealedFindingsForValidation(findings)
    : findings;
  if (wasSealed) {
    validateFindings(manifest, compatible);
    validateDerivedFindingIdentities(manifest, findings);
  } else if (options.completionWarnings != null) {
    const discarded = recoverUnsealedFindings(
      manifest,
      findings,
      schemaDir,
      scanDir,
      options.completionWarnings,
    );
    recoverUnsealedCoverage(
      coverage,
      schemaDir,
      scanDir,
      options.completionWarnings,
      discarded,
    );
    recoverUnsealedHardening(manifest, scanDir, options.completionWarnings);
  } else populateUnsealedFindingIdentities(manifest, findings);
  validateFindings(manifest, compatible);
  validateCoverage(manifest, coverage, scanDir);
  validateCanonicalSchemasBeforeProjection(
    manifest,
    compatible,
    coverage,
    schemaDir,
  );
  requireDerivedWriteupFiles(scanDir, findings);
  requireHardeningPortfolioFile(scanDir, scan);
  if (wasSealed) {
    validateSealedCoverageReceipts(scan, coverage);
    validateManifest(manifest);
    validateContractSchema(
      manifest,
      appendPath(schemaDir, "scan-manifest.schema.json"),
    );
    validateContractSchema(
      compatible,
      appendPath(schemaDir, "findings.schema.json"),
    );
    validateContractSchema(
      coverage,
      appendPath(schemaDir, "coverage.schema.json"),
    );
    const reportMarkdown = generateReportProjection(
      manifest,
      findings,
      coverage,
      options.reportAttempts,
    );
    validateScanLocalOutputPath(
      scanDir,
      appendPath(scanDir, "report.md"),
      "report.md",
    );
    return {
      scanDir,
      schemaDir,
      manifest,
      findings,
      coverage,
      wasSealed,
      reportMarkdown,
    };
  }
  const findingsBytes = contractJsonBytes("findings.json", findings),
    coverageBytes = contractJsonBytes("coverage.json", coverage);
  const reportMarkdown = generateReportProjection(
    manifest,
    findings,
    coverage,
    options.reportAttempts,
  );
  validateScanLocalOutputPath(
    scanDir,
    appendPath(scanDir, "report.md"),
    "report.md",
  );
  scan["artifacts"] = [
    artifactRecord(scanDir, "findings.json", "application/json", findingsBytes),
    artifactRecord(scanDir, "coverage.json", "application/json", coverageBytes),
    ...coverageReceiptRefs(coverage).map((ref) =>
      artifactRecord(scanDir, ref, "application/octet-stream"),
    ),
  ];
  validateSealedCoverageReceipts(scan, coverage);
  validateManifest(manifest);
  validateContractSchema(
    manifest,
    appendPath(schemaDir, "scan-manifest.schema.json"),
  );
  validateContractSchema(
    compatible,
    appendPath(schemaDir, "findings.schema.json"),
  );
  validateContractSchema(
    coverage,
    appendPath(schemaDir, "coverage.schema.json"),
  );
  contractJsonBytes("scan-manifest.json", manifest);
  return {
    scanDir,
    schemaDir,
    manifest,
    findings,
    coverage,
    wasSealed,
    reportMarkdown,
  };
}

function writeSarifIfPossible(
  scanDir: string,
  sourceRoot: string | null | undefined,
  schemaDir: string,
): void {
  try {
    writeSarifProjection(scanDir, sourceRoot, schemaDir);
  } catch (error) {
    if (!(error instanceof ContractError) && !osError(error)) throw error;
    const detail =
      error instanceof ContractError
        ? error.message
        : filesystemErrorMessage(error);
    print(
      `codex-security: warning: automatic SARIF export failed: ${detail}. Run \`codex-security export <scan-dir> --export-format sarif\` to retry.`,
      true,
    );
  }
}

/** Write a previously validated finalization result in the original publication order. */
export function writePreparedScanFinalization(
  prepared: PreparedScanFinalization,
  sourceRoot?: string | null,
): ScanDocuments {
  const {
    scanDir,
    schemaDir,
    manifest,
    findings,
    coverage,
    wasSealed,
    reportMarkdown,
  } = prepared;
  const scan = requireDict(manifest, "scan", "manifest");
  if (!wasSealed) {
    writeScanLocalJson(scanDir, "findings.json", findings);
    writeScanLocalJson(scanDir, "coverage.json", coverage);
  }
  writeScanLocalBytes(scanDir, "report.md", reportMarkdown);
  removeScanLocalFileIfExists(scanDir, "report.html");
  if (!wasSealed) {
    writeScanLocalJson(scanDir, "scan-manifest.json", manifest);
    validateExistingSeal(scanDir, scan);
  }
  writeSarifIfPossible(scanDir, sourceRoot, schemaDir);
  return [manifest, findings, coverage];
}

export function finalizeScan(
  scanDir: string,
  schemas?: string | null,
  sourceRoot?: string | null,
  options: FinalizationOptions = {},
): ScanDocuments {
  return writePreparedScanFinalization(
    prepareScanFinalization(scanDir, schemas, options),
    sourceRoot,
  );
}
