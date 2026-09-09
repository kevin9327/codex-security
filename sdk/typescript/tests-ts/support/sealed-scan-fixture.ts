import { readFileSync } from "node:fs";
import {
  artifactRecord,
  buildFindingsExport,
  buildSarifProjection,
  coverageReceiptRefs,
  readSealedScan,
  validateExistingSeal,
  validateSealedCoverageReceipts,
  writeSarifProjection,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/sealed-scan";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

type Table = Record<string, unknown>;
export interface Request {
  operation:
    | "record"
    | "seal"
    | "receipts"
    | "sealedReceipts"
    | "read"
    | "sarif"
    | "export"
    | "writeSarif";
  root: string;
  source?: string;
  schemas?: string | null;
  sourceRoot?: string | null;
  relative?: string;
  mediaType?: string;
  contents?: string;
  artifactContents?: [string, string][];
  format?: string;
}
export interface Response {
  value?: string;
  bytes?: string;
  error?: string;
  kind?: string;
  after: string;
}
const requests: Request[] = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(
  JSON.stringify(
    requests.map((request): Response => {
      const payload = parseJson(request.source ?? "{}") as Table;
      try {
        let value: unknown = null,
          bytes: Buffer | undefined;
        switch (request.operation) {
          case "record":
            value = artifactRecord(
              request.root,
              request.relative!,
              request.mediaType ?? "application/octet-stream",
              request.contents === undefined
                ? undefined
                : Buffer.from(request.contents, "base64"),
            );
            break;
          case "seal":
            validateExistingSeal(
              request.root,
              payload,
              new Map(
                request.artifactContents?.map(([path, bytes]) => [
                  path,
                  Buffer.from(bytes, "base64"),
                ]),
              ),
            );
            break;
          case "receipts":
            value = coverageReceiptRefs(payload);
            break;
          case "sealedReceipts":
            validateSealedCoverageReceipts(
              payload["scan"] as Table,
              payload["coverage"] as Table,
            );
            break;
          case "read": {
            const [manifest, findings, coverage, raw] = readSealedScan(
              request.root,
              request.schemas,
              "test export",
            );
            value = [manifest, findings, coverage];
            bytes = raw;
            break;
          }
          case "sarif":
            value = buildSarifProjection(
              request.root,
              request.sourceRoot,
              request.schemas,
            );
            break;
          case "export":
            bytes = buildFindingsExport(
              request.root,
              request.format!,
              request.sourceRoot,
              request.schemas,
            );
            break;
          case "writeSarif":
            writeSarifProjection(
              request.root,
              request.sourceRoot,
              request.schemas,
            );
            break;
        }
        return {
          value: stringifyJson(value),
          ...(bytes === undefined ? {} : { bytes: bytes.toString("base64") }),
          after: stringifyJson(payload),
        };
      } catch (failure) {
        const error = failure as Error;
        return {
          error: error.message,
          kind: error.name === "Error" ? error.constructor.name : error.name,
          after: stringifyJson(payload),
        };
      }
    }),
  ),
);
