import fs from "node:fs";
import { join } from "node:path";
import {
  finalizeScan,
  generateReportProjection,
  prepareScanFinalization,
  validateCanonicalSchemasBeforeProjection,
  writePreparedScanFinalization,
  type FinalizationOptions,
  type PreparedScanFinalization,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-finalization";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import { unixBinding } from "../../../../plugins/codex-security/mcp-app/src/native";

type Table = Record<string, unknown>;
export interface Request {
  operation:
    | "prepare"
    | "finalize"
    | "prepareWrite"
    | "write"
    | "report"
    | "schemas";
  root: string;
  schemas?: string | null;
  sourceRoot?: string | null;
  source?: string;
  trace?: boolean;
  failWriteAt?: number;
  afterPrepare?: { relative: string; bytes: string }[];
  reportFault?: { remaining: number; kind: "io" | "value" | "type" };
}
export interface Response {
  value?: string;
  bytes?: string;
  prepared?: string;
  error?: string;
  kind?: string;
  after: string;
  stderr: string;
  events: unknown[];
  reportCalls?: number;
  sleeps: number[];
}
const requests: Request[] = JSON.parse(fs.readFileSync(0, "utf8"));
const native = process.platform === "win32" ? undefined : unixBinding();
process.stdout.write(
  JSON.stringify(
    requests.map((request): Response => {
      const payload = parseJson(request.source ?? "{}") as Table;
      const supplied = (payload["options"] ?? {}) as FinalizationOptions;
      const options = {
        ...supplied,
        reportAttempts:
          supplied.reportAttempts === undefined
            ? undefined
            : Number(supplied.reportAttempts),
      };
      const events: unknown[] = [],
        sleeps: number[] = [];
      let stderr = "",
        prepared: PreparedScanFinalization | undefined,
        writes = 0;
      const oldWrite = process.stderr.write,
        oldRename = native?.renameAt,
        oldUnlink = native?.unlinkAt,
        oldWait = Atomics.wait;
      const globals = globalThis as unknown as {
        finalizationReportFault?: {
          remaining: number;
          kind: string;
          calls: number;
        };
      };
      if (request.reportFault)
        globals.finalizationReportFault = { ...request.reportFault, calls: 0 };
      process.stderr.write = ((value: string | Uint8Array) => {
        stderr +=
          typeof value === "string" ? value : Buffer.from(value).toString();
        return true;
      }) as typeof process.stderr.write;
      if (request.reportFault)
        Atomics.wait = ((...args: Parameters<typeof Atomics.wait>) => {
          sleeps.push(args[3] ?? Infinity);
          return "timed-out";
        }) as typeof Atomics.wait;
      if (native && request.trace) {
        native.renameAt = (...args) => {
          const name = decodePosixBytes(args[3]);
          events.push({ replace: name });
          if (++writes === request.failWriteAt) return { value: -1, errno: 5 };
          return oldRename!(...args);
        };
        native.unlinkAt = (...args) => {
          const name = decodePosixBytes(args[1]);
          if (!name.endsWith(".tmp")) events.push({ remove: name });
          return oldUnlink!(...args);
        };
      }
      const snapshot = () => ({
        after: stringifyJson(payload),
        stderr,
        events,
        sleeps,
        ...(prepared
          ? {
              prepared: stringifyJson({
                ...prepared,
                reportMarkdown: prepared.reportMarkdown.toString("base64"),
              }),
            }
          : {}),
        ...(globals.finalizationReportFault
          ? { reportCalls: globals.finalizationReportFault.calls }
          : {}),
      });
      try {
        let value: unknown = null,
          bytes: Buffer | undefined;
        switch (request.operation) {
          case "prepare":
            prepared = prepareScanFinalization(
              request.root,
              request.schemas,
              options,
            );
            break;
          case "finalize":
            value = finalizeScan(
              request.root,
              request.schemas,
              request.sourceRoot,
              options,
            );
            break;
          case "prepareWrite":
            prepared = prepareScanFinalization(
              request.root,
              request.schemas,
              options,
            );
            for (const change of request.afterPrepare ?? [])
              fs.writeFileSync(
                join(request.root, change.relative),
                Buffer.from(change.bytes, "base64"),
              );
            value = writePreparedScanFinalization(prepared, request.sourceRoot);
            break;
          case "write": {
            const source = payload["prepared"] as Omit<
              PreparedScanFinalization,
              "reportMarkdown"
            > & { reportMarkdown: string };
            prepared = {
              ...source,
              reportMarkdown: Buffer.from(source.reportMarkdown, "base64"),
            };
            value = writePreparedScanFinalization(prepared, request.sourceRoot);
            break;
          }
          case "report":
            bytes = generateReportProjection(
              payload["manifest"] as Table,
              payload["findings"] as Table,
              payload["coverage"] as Table,
              options.reportAttempts,
            );
            break;
          case "schemas":
            validateCanonicalSchemasBeforeProjection(
              payload["manifest"] as Table,
              payload["findings"] as Table,
              payload["coverage"] as Table,
              request.schemas!,
            );
            break;
        }
        return {
          value: stringifyJson(value),
          ...(bytes ? { bytes: bytes.toString("base64") } : {}),
          ...snapshot(),
        };
      } catch (failure) {
        const error = failure as Error;
        return {
          error: error.message,
          kind: error.name === "Error" ? error.constructor.name : error.name,
          ...snapshot(),
        };
      } finally {
        process.stderr.write = oldWrite;
        Atomics.wait = oldWait;
        delete globals.finalizationReportFault;
        if (native) {
          native.renameAt = oldRename!;
          native.unlinkAt = oldUnlink!;
        }
      }
    }),
  ),
);
