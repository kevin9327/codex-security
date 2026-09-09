import { writeExportOutput, writeSarifOutput } from "./export-output";
import { ArgumentError, argumentsFor, print } from "./rank-worklists";
import { parsedPath } from "./resolve-security-md";
import { ContractError } from "./scan-contract-errors";
import { jsonBytes } from "./scan-contract-json";
import { finalizeScan } from "./scan-finalization";
import { buildFindingsExport, buildSarifProjection } from "./sealed-scan";

const usage = `usage: finalize_scan_contract.py [-h] --scan-dir SCAN_DIR
                                 [--schema-dir SCHEMA_DIR]
                                 [--source-root SOURCE_ROOT] [--sarif-only]
                                 [--sarif-output SARIF_OUTPUT]
                                 [--export-format {csv,json,sarif}]
                                 [--export-output EXPORT_OUTPUT]`;

export function finalizeScanContractCommand(args: string[]): number {
  try {
    const values = argumentsFor(
      args,
      ["scan-dir"],
      [],
      {
        "schema-dir": undefined,
        "source-root": undefined,
        "sarif-only": undefined,
        "sarif-output": undefined,
        "export-format": ["csv", "json", "sarif"],
        "export-output": undefined,
      },
      undefined,
      ["sarif-only"],
    );
    if (values.help) {
      print(`${usage}

Validate and seal additive Codex Security scan-contract artifacts.

options:
  -h, --help            show this help message and exit
  --scan-dir SCAN_DIR
  --schema-dir SCHEMA_DIR
  --source-root SOURCE_ROOT
  --sarif-only
  --sarif-output SARIF_OUTPUT
  --export-format {csv,json,sarif}
  --export-output EXPORT_OUTPUT`);
      return 0;
    }
    if (values["sarif-only"] && values["export-format"] !== undefined)
      throw new ArgumentError(
        "--sarif-only cannot be combined with --export-format",
      );
    if (
      values["export-output"] !== undefined &&
      values["export-format"] === undefined
    )
      throw new ArgumentError("--export-output requires --export-format");
    if (values["sarif-output"] !== undefined && !values["sarif-only"])
      throw new ArgumentError("--sarif-output requires --sarif-only");
    const path = (name: string) =>
      values[name] === undefined
        ? undefined
        : parsedPath(values[name] as string);
    const scanDir = path("scan-dir")!;
    const schemaDir = path("schema-dir");
    const sourceRoot = path("source-root");
    const exportFormat = values["export-format"] as string | undefined;
    if (exportFormat !== undefined) {
      const contents = buildFindingsExport(
        scanDir,
        exportFormat,
        sourceRoot,
        schemaDir,
      );
      const output = path("export-output");
      if (output === undefined) process.stdout.write(contents);
      else writeExportOutput(scanDir, output, exportFormat, contents);
    } else if (values["sarif-only"]) {
      const sarif = buildSarifProjection(scanDir, sourceRoot, schemaDir);
      const output = path("sarif-output");
      if (output === undefined) process.stdout.write(jsonBytes(sarif));
      else writeSarifOutput(scanDir, output, sarif);
    } else {
      finalizeScan(scanDir, schemaDir, sourceRoot);
    }
    return 0;
  } catch (error) {
    if (
      !(error instanceof ArgumentError) &&
      !(error instanceof ContractError)
    ) {
      const exception = error as Error;
      print(`${exception.name}: ${exception.message}`, true);
      return 1;
    }
    print(usage, true);
    print(`finalize_scan_contract.py: error: ${error.message}`, true);
    return 2;
  }
}
