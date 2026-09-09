import fs from "node:fs";
import * as recovery from "../../../../plugins/codex-security/mcp-app/src/helpers/unsealed-recovery";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import { unixBinding } from "../../../../plugins/codex-security/mcp-app/src/native";

type Table = Record<string, unknown>;
export type Operation = "findings" | "coverage" | "hardening" | "strength";
export interface Request {
  operation: Operation;
  source: string;
  root: string;
  schemaDir: string;
  trace?: boolean;
  failCloseAt?: number;
}
export interface Response {
  value?: string;
  error?: string;
  kind?: string;
  after: string;
  references: string;
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
    args = payload as unknown[];
  const table = args[0] as Table;
  const references =
    request.operation === "findings"
      ? (args[1] as Table)["findings"]
      : request.operation === "coverage"
        ? [
            table["surfaces"] ?? null,
            table["explicitExclusions"] ?? null,
            table["deferred"] ?? null,
          ]
        : payload;
  const events: Response["events"] = [],
    opened = new Map<number, string>();
  const open = native?.openAt,
    close = fs.closeSync;
  let closed = 0;
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
      if (path !== undefined && ++closed === request.failCloseAt)
        throw new Error("synthetic close failure");
    };
  }
  const before = descriptors();
  const snapshot = () => ({
    after: stringifyJson(payload),
    references: stringifyJson(references ?? null),
    events,
    ...(before === undefined ? {} : { leaked: descriptors()! - before }),
  });
  try {
    let value: unknown = null;
    switch (request.operation) {
      case "findings":
        value = recovery.recoverUnsealedFindings(
          table,
          args[1] as Table,
          request.schemaDir,
          request.root,
          args[2] as string[],
        );
        break;
      case "coverage":
        recovery.recoverUnsealedCoverage(
          table,
          request.schemaDir,
          request.root,
          args[1] as string[],
          args[2] as string[],
        );
        break;
      case "hardening":
        recovery.recoverUnsealedHardening(
          table,
          request.root,
          args[1] as string[],
        );
        break;
      case "strength":
        value = recovery.findingStrength(payload as Table);
        break;
    }
    return { value: stringifyJson(value), ...snapshot() };
  } catch (error) {
    return {
      error: (error as Error).message,
      kind: (error as Error).constructor.name,
      ...snapshot(),
    };
  } finally {
    if (native) native.openAt = open!;
    fs.closeSync = close;
  }
});
process.stdout.write(JSON.stringify(results));
