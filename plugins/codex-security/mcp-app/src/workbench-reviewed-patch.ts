import { createHash } from "node:crypto";
import { copyDirectoryExcluding, copyGitWorktreeFiles } from "./workbench-copy";
import { openScanLocalFile } from "./workbench-files";
import { gitCommand, gitOutput } from "./workbench-git";
import { gitWorktreeContext } from "./workbench-git-snapshot";
import {
  directoryContentDigest,
  gitSubmodulePaths,
  remediationCheckoutSnapshot,
  requireScanTargetIdentity,
  worktreeContentDigestForContext,
  type RemediationScan,
} from "./workbench-target";
import { WorkbenchValidationError } from "./workbench-validation";
import { appendPath } from "./helpers/rank-selection";
import {
  withTemporaryDirectory,
  writeExclusiveFile,
} from "./workbench-temporary";

export interface ReviewedPatchDigests {
  base_revision: string | null;
  base_content_digest: string | null;
  patch_digest: string | null;
}

export function requireReviewedPatchApplied(
  scan: RemediationScan,
  remediation: ReviewedPatchDigests,
  patchPath: string,
): string {
  const target = requireScanTargetIdentity(scan);
  const [, contentDigest] = remediationCheckoutSnapshot(
    scan,
    remediation.base_revision,
  );
  if (contentDigest === remediation.base_content_digest)
    throw new WorkbenchValidationError(
      "The selected checkout is unchanged; apply the reviewed patch before recording it as applied.",
    );
  const unversioned = remediation.base_revision === "unversioned";
  const excluded = [scan.scan_dir];
  let gitDir: string | undefined;
  let pathspec: string | undefined;
  if (!unversioned) {
    [, pathspec] = gitWorktreeContext(target);
    gitDir =
      gitOutput(target, ["rev-parse", "--absolute-git-dir"]) ?? undefined;
    if (gitDir === undefined)
      throw new WorkbenchValidationError(
        "Could not inspect the selected Git working tree.",
      );
    excluded.push(...gitSubmodulePaths(target));
  }
  withTemporaryDirectory("codex-security-remediation-", (temporary) => {
    const reviewedPatch = appendPath(temporary, "reviewed.patch");
    const digest = createHash("sha256");
    const source = openScanLocalFile(scan.scan_dir, patchPath);
    try {
      writeExclusiveFile(
        reviewedPatch,
        (function* () {
          const buffer = Buffer.alloc(1024 * 1024);
          for (;;) {
            const count = source.read(buffer);
            if (count === 0) break;
            const chunk = buffer.subarray(0, count);
            digest.update(chunk);
            yield chunk;
          }
        })(),
      );
    } finally {
      source.close();
    }
    if (`sha256:${digest.digest("hex")}` !== remediation.patch_digest)
      throw new WorkbenchValidationError(
        "Patch digest does not match the scan-local patch file.",
      );
    const checkoutRoot = appendPath(temporary, "checkout");
    let checkout: string;
    if (unversioned) {
      checkout = checkoutRoot;
      copyDirectoryExcluding(target, checkout, excluded);
    } else checkout = copyGitWorktreeFiles(target, checkoutRoot, excluded);
    const args = ["apply", "--reverse", "--whitespace=nowarn"];
    if (unversioned) args.push("--no-index");
    else if (pathspec !== ".") args.push(`--directory=${pathspec}`);
    args.push(reviewedPatch);
    const context =
      gitDir === undefined ? {} : { gitDir, workTree: checkoutRoot };
    const applied = gitCommand(
      unversioned ? checkout : checkoutRoot,
      args,
      context,
    );
    if (applied.returnCode !== 0)
      throw new WorkbenchValidationError(
        "The selected checkout does not contain the reviewed remediation patch. Apply exactly that patch before recording it as applied.",
      );
    let revertedDigest = unversioned
      ? directoryContentDigest(checkout)
      : worktreeContentDigestForContext(checkoutRoot, pathspec || ".", context);
    if (revertedDigest !== remediation.base_content_digest && unversioned) {
      checkout = appendPath(temporary, "checkout-lf");
      copyDirectoryExcluding(target, checkout, excluded);
      const appliedWithoutConversion = gitCommand(checkout, [
        "-c",
        "core.autocrlf=input",
        ...args,
      ]);
      if (appliedWithoutConversion.returnCode === 0)
        revertedDigest = directoryContentDigest(checkout);
    }
    if (revertedDigest !== remediation.base_content_digest)
      throw new WorkbenchValidationError(
        "The selected checkout contains changes outside the reviewed patch. Remove them before recording the patch as applied.",
      );
  });
  return contentDigest;
}
