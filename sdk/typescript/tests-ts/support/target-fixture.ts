import { readFileSync } from "node:fs";
import { copyGitWorktreeFiles } from "../../../../plugins/codex-security/mcp-app/src/workbench-copy";
import { gitWorktreeContext } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import { gitTargetMetadata } from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import { requireDiffTarget } from "../../../../plugins/codex-security/mcp-app/src/workbench-setup";
import { stringifyJson } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
export type Request =
  | { operation: "copy"; repository: string; checkout: string }
  | { operation: "target"; repository: string; head: string };
const request = JSON.parse(readFileSync(0, "utf8")) as Request;
if (request.operation === "copy") {
  copyGitWorktreeFiles(request.repository, request.checkout, []);
  process.stdout.write("null");
} else {
  const [root, pathspec] = gitWorktreeContext(request.repository);
  const metadata = gitTargetMetadata(request.repository);
  const diff = requireDiffTarget(
    request.repository,
    "commit",
    null,
    request.head,
    null,
  );
  process.stdout.write(
    stringifyJson({ root, pathspec, subject: metadata.commitSubject, diff }),
  );
}
