import {
  appendFileSync,
  closeSync,
  constants,
  openSync,
  readFileSync,
  readSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import type { WindowsCompletionFile } from "../../../../plugins/codex-security/native/windows-binding.mjs";
import { widePath } from "../../../../plugins/codex-security/native/windows-files.mjs";
import {
  unixBinding,
  windowsBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  acquireCompletionFileLock,
  releaseCompletionFileLock,
  withScanCompletionLock,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-completion-lock";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";

export interface Request {
  state?: string;
  scanId?: string;
  operationError?: string;
  initialSize?: string;
  writeErrors?: number[];
  seekErrors?: number[];
  lockErrors?: number[];
  unlockError?: number;
  waitError?: string;
}
export interface Response {
  events: (string | number)[][];
  result?: unknown;
  error?: string;
  errno?: number;
  systemExit?: boolean;
  size?: string;
  node: string;
}
const scanId = "11111111-1111-4111-8111-111111111111";

function execute(request: Request, model: boolean): Response {
  const events: (string | number)[][] = [];
  let size = BigInt(request.initialSize ?? "0");
  try {
    if (model) {
      const writes = [...(request.writeErrors ?? [])],
        seeks = [...(request.seekErrors ?? [])],
        locks = [...(request.lockErrors ?? [])];
      const file: WindowsCompletionFile = {
        size: () => {
          events.push(["size", size.toString()]);
          return { error: 0, value: size.toString() };
        },
        seekStart: () => {
          const errno = seeks.shift() ?? 0;
          events.push(["seek", errno]);
          return errno;
        },
        writeZero: () => {
          const errno = writes.shift() ?? 0;
          events.push(["write", errno]);
          if (!errno) size = 1n;
          return { errno, value: errno ? -1 : 1 };
        },
        locking: (unlock) => {
          const errno = unlock ? request.unlockError ?? 0 : locks.shift() ?? 0;
          events.push([unlock ? "unlock" : "lock", errno]);
          return errno;
        },
        close: () => 0,
      };
      acquireCompletionFileLock(file, () => {
        events.push(["wait"]);
        if (request.waitError) throw new Error(request.waitError);
      });
      try {
        events.push(["callback"]);
        if (request.operationError) throw new Error(request.operationError);
      } finally {
        releaseCompletionFileLock(file);
      }
      return { events, size: size.toString(), node: process.versions.node };
    }
    process.env["CODEX_SECURITY_STATE_DIR"] = request.state!;
    const result = withScanCompletionLock(request.scanId ?? scanId, () => {
      events.push(["callback"]);
      if (request.operationError) throw new Error(request.operationError);
      return "returned";
    });
    return { events, result, node: process.versions.node };
  } catch (error) {
    const errno = (error as { errno?: number }).errno;
    return {
      events,
      error: filesystemErrorMessage(error),
      errno: errno === undefined ? undefined : Math.abs(errno),
      systemExit: error instanceof WorkbenchValidationError,
      size: size.toString(),
      node: process.versions.node,
    };
  }
}

const mode = process.argv[2];
if (mode === "hold" || mode === "visit") {
  const state = process.argv[3]!,
    label = process.argv[4]!;
  process.env["CODEX_SECURITY_STATE_DIR"] = state;
  process.stdout.write("waiting\n");
  withScanCompletionLock(scanId, () => {
    appendFileSync(join(state, "events"), `${label}-enter\n`);
    process.stdout.write("acquired\n");
    if (mode === "hold") readSync(0, Buffer.alloc(1), 0, 1, null);
    appendFileSync(join(state, "events"), `${label}-exit\n`);
  });
} else if (mode === "probe") {
  const path = join(process.argv[3]!, "completion-locks", `${scanId}.lock`);
  let errno: number;
  if (process.platform === "win32") {
    const opened = windowsBinding().openWindowsCompletionFile(widePath(path));
    if (opened.errno) throw new Error(`open failed: ${opened.errno}`);
    try {
      errno = opened.file!.locking(false);
      if (!errno) opened.file!.locking(true);
    } finally {
      opened.file!.close();
    }
  } else {
    const fd = openSync(path, constants.O_RDWR);
    try {
      errno = unixBinding().fileLock(fd, false, true).errno;
      if (!errno) unixBinding().fileLock(fd, true, false);
    } finally {
      closeSync(fd);
    }
  }
  console.log(JSON.stringify({ errno, size: statSync(path).size }));
} else {
  const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
  process.stdout.write(
    JSON.stringify(
      requests.map((request) => execute(request, mode === "model")),
    ),
  );
}
