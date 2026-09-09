import { readFileSync, readdirSync } from "node:fs";
import { processBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { decodeFilename } from "../../../../plugins/codex-security/mcp-app/src/workbench-git";
import { TargetInspectionError } from "../../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import {
  requireReviewedPatchApplied,
  type ReviewedPatchDigests,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-reviewed-patch";
import {
  remediationCheckoutSnapshot,
  scanTargetIdentity,
  type RemediationScan,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface Request {
  operation: "snapshot" | "applied";
  scan: RemediationScan;
  remediation?: ReviewedPatchDigests;
  patchPath?: string;
  deriveIdentity?: boolean;
}
export interface Response {
  result?: string | [string, string];
  error?: string;
  systemExit?: boolean;
  identity?: unknown;
  descriptors: number | null;
  calls: { args: string[]; status: number | null }[];
}
const descriptors = () =>
  process.platform === "linux" ? readdirSync("/proc/self/fd").length : 0;
function run(request: Request): Response {
  const native = processBinding(),
    original = native.rawProcess;
  const calls: Response["calls"] = [];
  native.rawProcess = (options) => {
    const result = original(options);
    calls.push({
      args: options.args.map((arg) =>
        process.platform === "win32"
          ? arg.toString("utf16le")
          : decodeFilename(arg),
      ),
      status: result.returnCode,
    });
    return result;
  };
  const before = descriptors();
  try {
    if (request.deriveIdentity)
      request.scan.target_inode = scanTargetIdentity(
        request.scan.target_path,
        null,
      )[3];
    const result =
      request.operation === "snapshot"
        ? remediationCheckoutSnapshot(request.scan)
        : requireReviewedPatchApplied(
            request.scan,
            request.remediation!,
            request.patchPath ?? "patch.diff",
          );
    return {
      result,
      calls,
      ...(request.operation === "snapshot"
        ? { identity: request.scan.target_inode }
        : {}),
      descriptors: process.platform === "linux" ? descriptors() - before : null,
    };
  } catch (error) {
    return {
      error: (error as Error).message,
      systemExit:
        error instanceof WorkbenchValidationError ||
        error instanceof TargetInspectionError,
      calls,
      descriptors: process.platform === "linux" ? descriptors() - before : null,
    };
  } finally {
    native.rawProcess = original;
  }
}
const requests = parseJson(readFileSync(0, "utf8")) as unknown as Request[];
console.log(stringifyJson(requests.map(run)));
