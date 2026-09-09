import fs from "node:fs";
import { join } from "node:path";
import {
  writeExportOutput,
  writeSarifOutput,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/export-output";
import { parseJson } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import { unixBinding } from "../../../../plugins/codex-security/mcp-app/src/native";

export interface Request {
  scanDir: string;
  output: string;
  format?: string;
  contents?: string;
  sarif?: string;
  trace?: boolean;
  replaceAfterOpen?: string;
  failIdentity?: string;
  failClose?: string;
  failOutputStat?: boolean;
}
export interface Response {
  error?: string;
  kind?: string;
  events: ({ open: string } | { close: string } | { identity: string })[];
  leaked?: number;
}
const requests = JSON.parse(fs.readFileSync(0, "utf8")) as Request[];
const native = process.platform === "win32" ? undefined : unixBinding();
const count = () =>
  process.platform === "linux"
    ? fs.readdirSync("/proc/self/fd").length
    : undefined;
const results = requests.map((request): Response => {
  const events: Response["events"] = [],
    opened = new Map<number, string>();
  const open = native?.openAt,
    close = fs.closeSync,
    fstat = fs.fstatSync,
    lstat = fs.lstatSync;
  let replaced = false;
  if (request.trace && native) {
    native.openAt = (...args) => {
      const result = open!(...args);
      if (
        !result.errno &&
        !(args[2] & fs.constants.O_CREAT) &&
        fstat(result.value).isFile()
      ) {
        const path = decodePosixBytes(args[1]);
        opened.set(result.value, path);
        events.push({ open: path });
        if (
          !replaced &&
          request.replaceAfterOpen &&
          path === request.replaceAfterOpen
        ) {
          replaced = true;
          const source = join(request.scanDir, path);
          fs.renameSync(source, `${source}.retained`);
          fs.writeFileSync(source, "replacement");
        }
      }
      return result;
    };
    fs.fstatSync = ((fd: number, options?: { bigint?: boolean }) => {
      const path = opened.get(fd);
      if (path !== undefined && options?.bigint) {
        events.push({ identity: path });
        if (path === request.failIdentity)
          throw new Error("synthetic identity failure");
      }
      return fstat(fd, options as { bigint: true });
    }) as typeof fs.fstatSync;
    fs.closeSync = (fd) => {
      const path = opened.get(fd);
      if (path !== undefined) {
        opened.delete(fd);
        events.push({ close: path });
      }
      close(fd);
      if (path !== undefined && path === request.failClose)
        throw new Error("synthetic close failure");
    };
  }
  if (request.failOutputStat)
    Object.defineProperty(fs, "lstatSync", {
      value: ((path: fs.PathLike, options?: { bigint?: boolean }) => {
        if (String(path) === request.output && options?.bigint)
          throw Object.assign(new Error("synthetic stat failure"), {
            code: "EACCES",
            errno: 13,
          });
        return lstat(path, options as { bigint: true });
      }) as typeof fs.lstatSync,
    });
  const before = count();
  let failure: Pick<Response, "error" | "kind"> = {};
  try {
    if (request.sarif !== undefined)
      writeSarifOutput(
        request.scanDir,
        request.output,
        parseJson(request.sarif) as Record<string, unknown>,
      );
    else
      writeExportOutput(
        request.scanDir,
        request.output,
        request.format ?? "csv",
        Buffer.from(request.contents ?? "export", "base64"),
      );
  } catch (error) {
    failure = {
      error: (error as Error).message,
      kind: (error as Error).constructor.name,
    };
  } finally {
    if (native) native.openAt = open!;
    fs.closeSync = close;
    fs.fstatSync = fstat;
    Object.defineProperty(fs, "lstatSync", { value: lstat });
  }
  return {
    ...failure,
    events,
    ...(before === undefined ? {} : { leaked: count()! - before }),
  };
});
process.stdout.write(JSON.stringify(results));
