import { createHash } from "node:crypto";
import { artifactPath, openScanLocalFile } from "./workbench-files";
import {
  remediationCheckoutSnapshot,
  type RemediationScan,
} from "./workbench-target";
import { optionalText, WorkbenchValidationError } from "./workbench-validation";

export interface RemediationCheckoutDigests {
  base_revision: string | null;
  base_content_digest: string | null;
  applied_content_digest: string | null;
}
export function requireRemediationCheckoutUnchanged(
  scan: RemediationScan,
  remediation: RemediationCheckoutDigests,
  options: {
    requireAppliedContent?: boolean;
    requireBaseContent?: boolean;
  } = {},
): void {
  const [, contentDigest] = remediationCheckoutSnapshot(
    scan,
    remediation.base_revision,
  );
  const expected = options.requireAppliedContent
    ? remediation.applied_content_digest
    : options.requireBaseContent
      ? remediation.base_content_digest
      : null;
  if (expected !== null && contentDigest !== expected)
    throw new WorkbenchValidationError(
      "Working-tree contents changed. Regenerate the remediation patch against the current checkout.",
    );
}
export function requireSha256Digest(
  value: string | null,
  label: string,
): string {
  const normalized = optionalText(value, 71);
  if (
    normalized === null ||
    !/^sha256:[0-9a-f]{64}$(?![\s\S])/u.test(normalized)
  )
    throw new WorkbenchValidationError(
      `${label} must use sha256:<64 lowercase hex characters>.`,
    );
  return normalized;
}
export function requireScanRelativeFile(
  scan: Pick<RemediationScan, "scan_dir">,
  value: string | null,
): string {
  const normalized = optionalText(value, 4096);
  if (normalized === null || normalized.includes("\\"))
    throw new WorkbenchValidationError(
      "Patch path must identify a scan-local regular file.",
    );
  const parts = normalized
    .split("/")
    .filter((part) => part !== "" && part !== ".");
  if (normalized.startsWith("/") || parts.includes(".."))
    throw new WorkbenchValidationError(
      "Patch path must identify a scan-local regular file.",
    );
  const relative = parts.join("/") || ".";
  if (artifactPath(scan.scan_dir, relative, true) === null)
    throw new WorkbenchValidationError(
      "Patch path must identify a scan-local regular file.",
    );
  return relative;
}
export function requireMatchingPatchDigest(
  scan: Pick<RemediationScan, "scan_dir">,
  patchPath: string,
  patchDigest: string,
): void {
  const digest = createHash("sha256"),
    file = openScanLocalFile(scan.scan_dir, patchPath);
  try {
    const buffer = Buffer.alloc(1024 * 1024);
    for (;;) {
      const count = file.read(buffer);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
    }
  } finally {
    file.close();
  }
  if (`sha256:${digest.digest("hex")}` !== patchDigest)
    throw new WorkbenchValidationError(
      "Patch digest does not match the scan-local patch file.",
    );
}
