import { readFileSync } from "node:fs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { connect } from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import {
  resultCallbacks,
  scanContext,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-results";
import { copyGitWorktreeFiles } from "../../../../plugins/codex-security/mcp-app/src/workbench-copy";
import { gitOutput } from "../../../../plugins/codex-security/mcp-app/src/workbench-git";
import {
  worktreeContentDigest,
  worktreeContentDigestForContext,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-target";

export type Request =
  | { action: "context"; scanId: string; occurrenceId: string }
  | { action: "copy"; source: string; destination: string };

type Context = {
  scan: { findings: { occurrenceId: string }[] };
  workspace: { results: { findings: unknown[] } };
};

async function main(request: Request) {
  if (request.action === "copy") {
    const checkout = copyGitWorktreeFiles(
      request.source,
      request.destination,
      [],
    );
    const gitDir = gitOutput(request.source, [
      "rev-parse",
      "--absolute-git-dir",
    ]);
    if (gitDir === null) throw new Error("Missing fixture Git directory");
    return {
      original: worktreeContentDigest(request.source),
      copied: worktreeContentDigestForContext(checkout, ".", {
        gitDir,
        workTree: checkout,
      }),
    };
  }
  const db = await connect(sqliteBinding(), () => new Date().toISOString());
  try {
    return db.transaction(() => {
      let calls = 0;
      const callbacks = {
        ...resultCallbacks,
        backfillFindingDetails: (
          ...args: Parameters<typeof resultCallbacks.backfillFindingDetails>
        ) => {
          calls++;
          resultCallbacks.backfillFindingDetails(...args);
        },
      };
      const ordinary = scanContext(
        db,
        request.scanId,
        callbacks,
      ) as unknown as Context;
      const ordinaryCalls = calls;
      calls = 0;
      const selected = scanContext(
        db,
        request.scanId,
        callbacks,
        request.occurrenceId,
      ) as unknown as Context;
      return {
        ordinaryCalls,
        selectedCalls: calls,
        ordinaryCount: ordinary.scan.findings.length,
        selectedCount: selected.scan.findings.length,
        workspaceCount: selected.workspace.results.findings.length,
        selectedIncluded: selected.scan.findings.some(
          (finding) => finding.occurrenceId === request.occurrenceId,
        ),
      };
    });
  } finally {
    db.close();
  }
}
void main(JSON.parse(readFileSync(0, "utf8")) as Request).then((result) => {
  process.stdout.write(JSON.stringify(result));
});
