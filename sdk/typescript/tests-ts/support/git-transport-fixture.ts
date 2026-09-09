import { readFileSync } from "node:fs";
import {
  decodeGitBatchBlobs,
  gitBlobBytes,
  gitBytes,
  gitCommand,
  gitOutput,
  type GitContext,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-git";

interface Request {
  action: "command" | "bytes" | "output" | "blobs" | "decode";
  target: string;
  args: string[];
  context?: GitContext;
  input?: string;
  count?: number;
}
const request = JSON.parse(readFileSync(0, "utf8")) as Request;
const encode = (value: Buffer | null) => value?.toString("base64") ?? null;
try {
  let result: unknown;
  switch (request.action) {
    case "command": {
      const value = gitCommand(request.target, request.args, {
        ...request.context,
        input:
          request.input === undefined
            ? undefined
            : Buffer.from(request.input, "base64"),
      });
      result = {
        ...value,
        stdout: encode(value.stdout),
        stderr: encode(value.stderr),
      };
      break;
    }
    case "bytes":
      result = encode(gitBytes(request.target, request.args, request.context));
      break;
    case "output":
      result = gitOutput(request.target, request.args, request.context);
      break;
    case "blobs":
      result = gitBlobBytes(request.target, request.args, request.context).map(
        encode,
      );
      break;
    case "decode":
      result = decodeGitBatchBlobs(
        Buffer.from(request.input!, "base64"),
        request.count!,
      ).map(encode);
      break;
  }
  console.log(JSON.stringify({ result }));
} catch (error) {
  const value = error as Error & { errno?: number; winerror?: number };
  console.log(
    JSON.stringify({
      error: value.message,
      errno: value.errno,
      winerror: value.winerror,
    }),
  );
}
