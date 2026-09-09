import fs from "node:fs";
import * as contract from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-validation";
import { validateDateTime } from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-date-time";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import { unixBinding } from "../../../../plugins/codex-security/mcp-app/src/native";

type Table = Record<string, unknown>;
export type Operation =
  | "dict"
  | "list"
  | "string"
  | "remote"
  | "date"
  | "target"
  | "fingerprint"
  | "stableId"
  | "location"
  | "derive"
  | "populate"
  | "identities"
  | "finding"
  | "manifest"
  | "findings"
  | "coverage"
  | "refs"
  | "file"
  | "writeups"
  | "hardening";
export interface Request {
  operation: Operation;
  source: string;
  root?: string;
  key?: string;
  context?: string;
  trace?: boolean;
  failClose?: boolean;
}
export interface Response {
  value?: string;
  error?: string;
  kind?: string;
  after: string;
  events: ({ open: string } | { close: string })[];
  leaked?: number;
}
const requests = JSON.parse(fs.readFileSync(0, "utf8")) as Request[];
const native = process.platform === "win32" ? undefined : unixBinding();
const descriptors = () =>
  process.platform === "linux"
    ? fs.readdirSync("/proc/self/fd").length
    : undefined;
const results = requests.map((request): Response => {
  const payload = parseJson(request.source),
    table = payload as Table,
    pair = payload as [Table, Table];
  const context = request.context ?? "context",
    events: Response["events"] = [];
  const opened = new Map<number, string>(),
    open = native?.openAt,
    close = fs.closeSync;
  if (request.trace && native) {
    native.openAt = (...args) => {
      const result = open!(...args);
      if (!result.errno && fs.fstatSync(result.value).isFile()) {
        const path = decodePosixBytes(args[1]);
        opened.set(result.value, path);
        events.push({ open: path });
      }
      return result;
    };
    fs.closeSync = (fd) => {
      const path = opened.get(fd);
      if (path !== undefined) {
        opened.delete(fd);
        events.push({ close: path });
      }
      close(fd);
      if (path !== undefined && request.failClose)
        throw new Error("synthetic close failure");
    };
  }
  const before = descriptors();
  try {
    let value: unknown = null;
    switch (request.operation) {
      case "dict":
        value = contract.requireDict(table, request.key!, context);
        break;
      case "list":
        value = contract.requireList(table, request.key!, context);
        break;
      case "string":
        value = contract.requireString(table, request.key!, context);
        break;
      case "remote":
        contract.validateRemote(payload as string, context);
        break;
      case "date":
        validateDateTime(payload as string, context);
        break;
      case "target":
        contract.validateTarget(table);
        break;
      case "fingerprint":
        value = contract.fingerprint(pair[0] as unknown as string, pair[1]);
        break;
      case "stableId": {
        const [prefix, ...parts] = payload as string[];
        value = contract.stableId(prefix!, ...parts);
        break;
      }
      case "location":
        contract.validateLocation(table, context);
        break;
      case "derive":
        value = contract.derivedFindingIdentityRows(...pair);
        break;
      case "populate":
        contract.populateUnsealedFindingIdentities(...pair);
        break;
      case "identities":
        contract.validateDerivedFindingIdentities(...pair);
        break;
      case "finding":
        contract.validateFinding(table, context);
        break;
      case "manifest":
        contract.validateManifest(table);
        break;
      case "findings":
        contract.validateFindings(...pair);
        break;
      case "coverage":
        contract.validateCoverage(...pair, request.root!);
        break;
      case "refs":
        contract.validateContractRefs(table);
        break;
      case "file":
        contract.requireScanLocalFile(
          request.root!,
          payload as string,
          context,
        );
        break;
      case "writeups":
        contract.requireDerivedWriteupFiles(request.root!, table);
        break;
      case "hardening":
        contract.requireHardeningPortfolioFile(request.root!, table);
        break;
    }
    return {
      value: stringifyJson(value),
      after: stringifyJson(payload),
      events,
      ...(before === undefined ? {} : { leaked: descriptors()! - before }),
    };
  } catch (error) {
    return {
      error: (error as Error).message,
      kind: (error as Error).constructor.name,
      after: stringifyJson(payload),
      events,
      ...(before === undefined ? {} : { leaked: descriptors()! - before }),
    };
  } finally {
    if (native) native.openAt = open!;
    fs.closeSync = close;
  }
});
process.stdout.write(JSON.stringify(results));
