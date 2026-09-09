import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildReportMarkdown,
  type ReportManifest,
  type ReportFinding,
  type ReportCoverage,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/report-projection";
import {
  buildSarif,
  type SarifManifest,
  type SarifFinding,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/sarif-projection";
import { validateFinding } from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-validation";
import { validateAgainstSchema } from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-schema";
import { legacySealedFindingsForValidation } from "../../../../plugins/codex-security/mcp-app/src/helpers/saved-findings-projection";
import { recoverUnsealedFindings } from "../../../../plugins/codex-security/mcp-app/src/helpers/unsealed-recovery";
import { ContractError } from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-contract-errors";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

type Table = Record<string, unknown>;
export interface FindingDocument extends Table {
  findings: Table[];
}
export type Request =
  | { operation: "report"; details: Table }
  | { operation: "validate" | "sarif"; finding: Table }
  | {
      operation: "legacy";
      findings: FindingDocument;
      validate?: boolean;
      schema?: boolean;
    }
  | { operation: "recover"; findings: Table[] };
export interface LegacyResponse {
  original: FindingDocument;
  compatible: FindingDocument;
  originalUnchanged: boolean;
  error: string | null;
}
export interface RecoveryResponse {
  findings: Table[];
  warnings: string[];
}
const plugin = process.argv[2]!;
const examples = join(plugin, "examples/completed-scan");
const read = (path: string) => parseJson(readFileSync(path, "utf8"));
function contractError(operation: () => void): string | null {
  try {
    operation();
    return null;
  } catch (error) {
    if (error instanceof ContractError) return error.message;
    throw error;
  }
}
function execute(request: Request): unknown {
  switch (request.operation) {
    case "report": {
      const findings = read(join(examples, "findings.json")) as {
        findings: ReportFinding[];
      };
      Object.assign(findings.findings[0]!, request.details);
      return buildReportMarkdown(
        read(join(examples, "scan-manifest.json")) as ReportManifest,
        findings,
        read(join(examples, "coverage.json")) as ReportCoverage,
      );
    }
    case "validate":
      return contractError(() =>
        validateFinding(request.finding, "findings[0]"),
      );
    case "legacy": {
      const before = stringifyJson(request.findings, { sortKeys: true });
      const compatible = legacySealedFindingsForValidation(
        request.findings,
      ) as FindingDocument;
      const error = contractError(() => {
        if (request.validate)
          validateFinding(compatible.findings[0]!, "findings[0]");
        if (request.schema)
          validateAgainstSchema(
            compatible,
            read(join(plugin, "schemas/findings.schema.json")) as Table,
            "findings",
          );
      });
      return {
        original: request.findings,
        compatible,
        originalUnchanged:
          before === stringifyJson(request.findings, { sortKeys: true }),
        error,
      } satisfies LegacyResponse;
    }
    case "recover": {
      const manifest = read(join(examples, "scan-manifest.json")) as Table;
      const findings = {
        scanId: (manifest["scan"] as Table)["id"],
        findings: request.findings,
      };
      const warnings: string[] = [];
      recoverUnsealedFindings(
        manifest,
        findings,
        join(plugin, "schemas"),
        examples,
        warnings,
      );
      return {
        findings: findings.findings,
        warnings,
      } satisfies RecoveryResponse;
    }
    case "sarif": {
      const sarif = buildSarif(
        read(join(examples, "scan-manifest.json")) as SarifManifest,
        { findings: [request.finding as SarifFinding] },
      );
      const run = (sarif["runs"] as Table[])[0]!,
        result = (run["results"] as Table[])[0]!;
      return Object.fromEntries(
        (
          result["locations"] as {
            physicalLocation: {
              artifactLocation: { uri: string };
              region: Table;
            };
          }[]
        ).map(({ physicalLocation }) => [
          physicalLocation.artifactLocation.uri,
          physicalLocation.region,
        ]),
      );
    }
  }
}
process.stdout.write(
  stringifyJson(execute(parseJson(readFileSync(0, "utf8")) as Request)),
);
