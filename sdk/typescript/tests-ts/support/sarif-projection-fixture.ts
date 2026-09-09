import fs, { readFileSync } from "node:fs";
import {
  buildSarif,
  githubLineHashes,
  githubLineHashesForSource,
  sarifLabel,
  validateSarif,
  type SarifFinding,
  type SarifManifest,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/sarif-projection";
import {
  findingEvidenceStrength,
  mergedCodeEvidence,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/finding-evidence";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import {
  lowercase,
  uppercase,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/unicode-case";

export interface Request {
  operation:
    | "sarif"
    | "validate"
    | "hash"
    | "sourceHashes"
    | "evidence"
    | "label"
    | "case";
  source?: string;
  root?: string;
  path?: string;
  hex?: string;
  chunk?: number;
  requested?: string[];
  traceFile?: string;
  readError?: boolean;
}
export interface Response {
  source?: string;
  error?: string;
  unchanged: boolean;
  reads?: number;
  maxRead?: number;
  sourceReads?: number;
  sourceCloses?: number;
}
const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
process.stdout.write(
  JSON.stringify(
    requests.map((request): Response => {
      const value = parseJson(request.source ?? "null"),
        before = stringifyJson(value);
      const requested =
        request.requested === undefined
          ? undefined
          : new Set(request.requested.map(BigInt));
      let output: unknown,
        reads: number | undefined,
        maxRead: number | undefined;
      let sourceReads = 0,
        sourceCloses = 0;
      const read = fs.readSync,
        close = fs.closeSync;
      if (request.traceFile !== undefined) {
        const target = fs.statSync(request.traceFile, { bigint: true }),
          descriptors = new Set<number>();
        fs.readSync = ((descriptor, buffer, offset, length, position) => {
          const metadata = fs.fstatSync(descriptor, { bigint: true });
          if (metadata.dev === target.dev && metadata.ino === target.ino) {
            descriptors.add(descriptor);
            sourceReads++;
            if (request.readError)
              throw Object.assign(new Error("synthetic read failure"), {
                errno: -13,
                code: "EACCES",
              });
          }
          return read(descriptor, buffer, offset, length, position);
        }) as typeof fs.readSync;
        fs.closeSync = (descriptor) => {
          if (descriptors.delete(descriptor)) sourceCloses++;
          close(descriptor);
        };
      }
      const trace = () =>
        request.traceFile === undefined ? {} : { sourceReads, sourceCloses };
      try {
        switch (request.operation) {
          case "sarif": {
            const [manifest, findings] = value as [
              SarifManifest,
              { findings: SarifFinding[] },
            ];
            output = buildSarif(manifest, findings, request.root);
            break;
          }
          case "validate":
            validateSarif(value as Record<string, unknown>);
            output = null;
            break;
          case "label":
            output = sarifLabel(value as string);
            break;
          case "case":
            output = [lowercase(value as string), uppercase(value as string)];
            break;
          case "evidence":
            output = [
              mergedCodeEvidence(value as Record<string, unknown>),
              findingEvidenceStrength(value as Record<string, unknown>),
            ];
            break;
          case "sourceHashes": {
            const hashes = githubLineHashesForSource(
              request.root!,
              request.path!,
              requested,
            );
            output = hashes === null ? null : Object.fromEntries(hashes);
            break;
          }
          case "hash": {
            const bytes = Buffer.from(request.hex!, "hex");
            let offset = 0;
            reads = 0;
            maxRead = 0;
            const hashes = githubLineHashes(
              {
                read(buffer) {
                  reads!++;
                  maxRead = Math.max(maxRead!, buffer.length);
                  const count = Math.min(
                    buffer.length,
                    request.chunk ?? buffer.length,
                    bytes.length - offset,
                  );
                  buffer.set(bytes.subarray(offset, offset + count));
                  offset += count;
                  return count;
                },
                size: () => BigInt(bytes.length),
                identity: () => [0n, 0n],
                close() {},
              },
              requested,
            );
            output = Object.fromEntries(hashes);
            break;
          }
        }
        return {
          source: stringifyJson(output),
          unchanged: before === stringifyJson(value),
          ...(reads === undefined ? {} : { reads, maxRead }),
          ...trace(),
        };
      } catch (error) {
        return {
          error: (error as Error).message,
          unchanged: before === stringifyJson(value),
          ...trace(),
        };
      } finally {
        fs.readSync = read;
        fs.closeSync = close;
      }
    }),
  ),
);
