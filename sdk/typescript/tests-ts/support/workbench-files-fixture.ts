import { readFileSync, readdirSync } from "node:fs";
import * as guards from "../../../../plugins/codex-security/mcp-app/src/workbench-remediation-guards";
import {
  remediationCheckoutSnapshot,
  scanTargetIdentity,
  type RemediationScan,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import * as files from "../../../../plugins/codex-security/mcp-app/src/workbench-files";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";

export interface Request {
  operation:
    | "canonical"
    | "available"
    | "artifact"
    | "json"
    | "reject"
    | "open"
    | "regular"
    | "preview"
    | "finding"
    | "sha256"
    | "relativeFile"
    | "matchingPatch"
    | "unchanged"
    | "checkoutSnapshot"
    | "targetIdentity";
  root?: string;
  path?: string;
  relative?: string | null;
  digest?: string | null;
  required?: boolean;
  details?: Record<string, unknown>;
  cwd?: string;
  uid?: number;
  value?: string | null;
  label?: string;
  scan?: RemediationScan;
  remediation?: guards.RemediationCheckoutDigests;
  requireAppliedContent?: boolean;
  requireBaseContent?: boolean;
  readerThrow?: boolean;
}
export interface Outcome {
  result?: unknown;
  error?: string;
  systemExit?: boolean;
  descriptors: bigint | null;
}
export interface Response {
  node: string;
  outcomes: Outcome[];
}
const descriptors = () =>
  process.platform === "linux" ? readdirSync("/proc/self/fd").length : null;
const requests = parseJson(readFileSync(0, "utf8")) as unknown as Request[];
const outcomes = requests.map((request): Outcome => {
  const cwd = process.cwd(),
    uid = process.geteuid,
    before = descriptors();
  try {
    if (request.cwd) process.chdir(request.cwd);
    if (request.uid !== undefined && uid)
      process.geteuid = () => Number(request.uid);
    let result: unknown;
    switch (request.operation) {
      case "sha256":
        result = guards.requireSha256Digest(
          request.value!,
          request.label ?? "Patch digest",
        );
        break;
      case "relativeFile":
        result = guards.requireScanRelativeFile(
          { scan_dir: request.root! },
          request.value!,
        );
        break;
      case "matchingPatch":
        guards.requireMatchingPatchDigest(
          { scan_dir: request.root! },
          request.relative!,
          request.digest!,
        );
        result = null;
        break;
      case "targetIdentity":
        result = scanTargetIdentity(request.path!, null);
        break;
      case "checkoutSnapshot":
        result = remediationCheckoutSnapshot(request.scan!);
        break;
      case "unchanged":
        guards.requireRemediationCheckoutUnchanged(
          request.scan!,
          request.remediation!,
          request,
        );
        result = null;
        break;
      case "canonical":
        result = files.requireCanonicalScanDirectory(request.root!);
        break;
      case "available":
        result = files.availableArtifactPath(request.root!, request.path!);
        break;
      case "artifact":
        result = files.artifactPath(
          request.root!,
          request.path!,
          request.required ?? true,
        );
        break;
      case "json":
        result = files.readJsonObject(request.path!);
        break;
      case "reject":
        result = files.rejectNonFiniteJson(request.path!);
        break;
      case "regular":
        result = files.scanLocalRegularFile(request.root!, request.relative!);
        break;
      case "preview":
        result = files.patchArtifactPreview(
          request.root!,
          request.relative ?? null,
          request.digest ?? null,
        );
        break;
      case "finding":
        result = files.findingArtifactPaths(
          request.root!,
          request.details ?? {},
        );
        break;
      case "open": {
        const file = files.openScanLocalFile(request.root!, request.relative!),
          chunks: Buffer[] = [];
        try {
          const buffer = Buffer.alloc(64 * 1024);
          for (;;) {
            const count = file.read(buffer);
            if (request.readerThrow)
              throw new Error("Synthetic reader consumer failed.");
            if (!count) break;
            chunks.push(Buffer.from(buffer.subarray(0, count)));
          }
        } finally {
          file.close();
        }
        result = Buffer.concat(chunks).toString("base64");
        break;
      }
    }
    const after = descriptors();
    return {
      result,
      descriptors:
        before === null || after === null ? null : BigInt(after - before),
    };
  } catch (error) {
    const after = descriptors();
    return {
      error: filesystemErrorMessage(error),
      systemExit:
        error instanceof WorkbenchValidationError ||
        error instanceof TargetInspectionError,
      descriptors:
        before === null || after === null ? null : BigInt(after - before),
    };
  } finally {
    process.chdir(cwd);
    process.geteuid = uid;
  }
});
process.stdout.write(stringifyJson({ node: process.versions.node, outcomes }));
