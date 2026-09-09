import {
  requireDict,
  requireScanLocalFile,
  validateCoverage,
  validateDerivedFindingIdentities,
  validateFindings,
  validateManifest,
} from "./contract-validation";
import { environment } from "./environment";
import { filesystemErrorMessage } from "./file-errors";
import { stringifyJson } from "./python-json";
import { appendPath } from "./rank-selection";
import { ArgumentError, argumentsFor, print } from "./rank-worklists";
import { resolvedPath } from "./resolve-path";
import { expandHome, parsedPath } from "./resolve-security-md";
import { legacySealedFindingsForValidation } from "./saved-findings-projection";
import { ContractError } from "./scan-contract-errors";
import { readScanLocalJsonBytes } from "./scan-contract-json";
import { requireScanDirectory } from "./scan-local-files";
import {
  schemaDirectory,
  validateContractSchema,
  validateExistingSeal,
  validateSealedCoverageReceipts,
} from "./sealed-scan";

type Table = Record<string, unknown>;
export interface ValidatedScan {
  scanDir: string;
  manifest: Table;
  findings: Table;
  coverage: Table;
}
export interface TrackingSelector {
  findingId?: string | null;
  fingerprint?: string | null;
}

/** Validate a sealed scan without changing its canonical documents or report. */
export function validateContract(
  scanDir: string,
  posixHome = environment("HOME"),
): ValidatedScan {
  scanDir = requireScanDirectory(
    resolvedPath(expandHome(parsedPath(scanDir), posixHome), true, {
      preserveRelativeErrors: true,
    }),
  );
  const schemas = schemaDirectory();
  const [manifest] = readScanLocalJsonBytes(
    scanDir,
    "scan-manifest.json",
    "scan-manifest.json",
  );
  validateManifest(manifest);
  validateContractSchema(
    manifest,
    appendPath(schemas, "scan-manifest.schema.json"),
  );
  const scan = requireDict(manifest, "scan", "manifest"),
    findingsRef = scan["findingsRef"] as string,
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
  const compatible = legacySealedFindingsForValidation(findings);
  validateFindings(manifest, compatible);
  validateDerivedFindingIdentities(manifest, findings);
  validateCoverage(manifest, coverage, scanDir);
  validateSealedCoverageReceipts(scan, coverage);
  validateContractSchema(
    compatible,
    appendPath(schemas, "findings.schema.json"),
  );
  validateContractSchema(coverage, appendPath(schemas, "coverage.schema.json"));
  requireScanLocalFile(scanDir, "report.md", "report.md");
  return { scanDir, manifest, findings, coverage };
}

export function scanContractReceipt(
  validated: ValidatedScan,
): Record<string, string> {
  const scanDir = parsedPath(validated.scanDir),
    scan = validated.manifest["scan"] as Table;
  return {
    status: "valid",
    scanDir,
    manifestPath: appendPath(scanDir, "scan-manifest.json"),
    findingsPath: appendPath(scanDir, scan["findingsRef"] as string),
    coveragePath: appendPath(scanDir, scan["coverageRef"] as string),
    reportPath: appendPath(scanDir, "report.md"),
  };
}

export function validateTrackingSource(
  scanDir: string,
  selector: TrackingSelector = {},
  posixHome = environment("HOME"),
): Table[] {
  const { findingId, fingerprint } = selector;
  if (findingId != null && fingerprint != null)
    throw new Error("use only one of --finding-id or --fingerprint");
  const findings = validateContract(scanDir, posixHome).findings[
    "findings"
  ] as Table[];
  if (findingId == null && fingerprint == null) return findings;
  const matches = findings.filter((finding) =>
    findingId != null
      ? finding["findingId"] === findingId
      : (finding["fingerprints"] as Table)["primary"] === fingerprint,
  );
  if (matches.length !== 1)
    throw new Error("the selector did not resolve exactly one finding");
  return matches;
}

export function scanValidationCommand(
  command: "validate-scan-contract" | "validate-tracking-source",
  args: string[],
  posixHome = environment("HOME"),
): number {
  const tracking = command === "validate-tracking-source";
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h]${tracking ? " [--finding-id FINDING_ID | --fingerprint FINGERPRINT] scan_dir" : " --scan-dir SCAN_DIR"}`;
  let values: ReturnType<typeof argumentsFor>;
  let selector: string | undefined;
  try {
    values = argumentsFor(
      args,
      tracking ? [] : ["scan-dir"],
      [],
      tracking ? { "finding-id": undefined, fingerprint: undefined } : {},
      (name) => {
        if (name !== "finding-id" && name !== "fingerprint") return;
        if (selector !== undefined && selector !== name)
          throw new ArgumentError(
            `argument --${name}: not allowed with argument --${selector}`,
          );
        selector = name;
      },
      [],
      undefined,
      tracking ? ["scan_dir"] : [],
    );
    if (values["help"]) {
      print(
        tracking
          ? `${usage}\n\nValidate a sealed scan and list or select findings for tracking.\n\npositional arguments:\n  scan_dir\n\noptions:\n  -h, --help            show this help message and exit\n  --finding-id FINDING_ID\n  --fingerprint FINGERPRINT`
          : `${usage}\n\nValidate a sealed Codex Security scan contract without mutating it.\n\noptions:\n  -h, --help           show this help message and exit\n  --scan-dir SCAN_DIR`,
      );
      return 0;
    }
  } catch (error) {
    if (!(error instanceof ArgumentError)) throw error;
    print(`${usage}\n${command}: error: ${error.message}`, true);
    return 2;
  }
  try {
    const path = values[tracking ? "scan_dir" : "scan-dir"] as string;
    if (tracking) {
      for (const finding of validateTrackingSource(
        path,
        {
          findingId: values["finding-id"] as string | undefined,
          fingerprint: values["fingerprint"] as string | undefined,
        },
        posixHome,
      ))
        print(finding["findingId"] as string);
    } else
      print(
        stringifyJson(scanContractReceipt(validateContract(path, posixHome)), {
          compact: true,
          sortKeys: true,
        }),
      );
    return 0;
  } catch (error) {
    const failure = error as Error & { errno?: number; winerror?: number };
    const osError =
      failure.errno !== undefined || failure.winerror !== undefined;
    if (
      !osError &&
      !(error instanceof ContractError) &&
      !(error instanceof RangeError) &&
      !(error instanceof Error && error.constructor === Error)
    )
      throw error;
    print(
      `${tracking ? "tracking source preflight" : "scan contract validation"} failed: ${osError ? filesystemErrorMessage(error) : failure.message}`,
      true,
    );
    return 2;
  }
}
