import { readFileSync } from "node:fs";
import {
  gitDirectorySnapshotPaths,
  gitWorktreeContext,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";

const request = JSON.parse(readFileSync(0, "utf8")) as {
  action: "paths" | "context";
  target: string;
};
try {
  console.log(
    JSON.stringify({
      result:
        request.action === "paths"
          ? gitDirectorySnapshotPaths(request.target)
          : gitWorktreeContext(request.target),
    }),
  );
} catch (error) {
  const caught = error as Error & {
    code?: string;
    errno?: number;
    winerror?: number;
  };
  console.log(
    JSON.stringify({
      error: caught.message,
      code: caught.code,
      errno: caught.errno,
      winerror: caught.winerror,
    }),
  );
}
