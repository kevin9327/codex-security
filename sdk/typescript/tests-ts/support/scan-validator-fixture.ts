import { readFileSync } from "node:fs";
import { populateUnsealedFindingIdentities } from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-validation";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import {
  scanContractReceipt,
  validateContract,
  validateTrackingSource,
  type TrackingSelector,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/validate-scan-contract";

type Table = Record<string, unknown>;
export interface Request {
  operation: "validate" | "summary" | "receipt" | "tracking" | "identities";
  root: string;
  selector?: TrackingSelector;
  source?: string;
}
export interface Response {
  value?: string;
  error?: string;
  kind?: string;
}
const requests: Request[] = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(
  JSON.stringify(
    requests.map((request): Response => {
      try {
        let value: unknown;
        if (request.operation === "tracking")
          value = validateTrackingSource(request.root, request.selector);
        else if (request.operation === "identities") {
          const source = parseJson(request.source!) as Table;
          populateUnsealedFindingIdentities(
            source["manifest"] as Table,
            source["findings"] as Table,
          );
          value = source;
        } else {
          const validated = validateContract(request.root);
          value =
            request.operation === "receipt"
              ? scanContractReceipt(validated)
              : request.operation === "summary"
                ? {
                    metadataLength: (validated.manifest["metadata"] as string)
                      .length,
                    findings: (validated.findings["findings"] as unknown[])
                      .length,
                  }
                : validated;
        }
        return { value: stringifyJson(value) };
      } catch (failure) {
        const error = failure as Error;
        return {
          error: error.message,
          kind: error.name === "Error" ? error.constructor.name : error.name,
        };
      }
    }),
  ),
);
