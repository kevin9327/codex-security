import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { Row } from "../../../../plugins/codex-security/native/sqlite.mjs";
import {
  gitBytes,
  gitCommand,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-git";
import {
  directoryContentDigest,
  gitTargetMetadata,
  scanTargetIdentity,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-target";
import { requireScope } from "../../../../plugins/codex-security/mcp-app/src/workbench-setup";
import {
  artifactPath,
  patchArtifactPreview,
  requireCanonicalScanDirectory,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-files";
import { deepScanPath } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-files";
import {
  requireScanDirectory,
  validateScanLocalOutputPath,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-local-files";
import { requireMatchingPatchDigest } from "../../../../plugins/codex-security/mcp-app/src/workbench-remediation-guards";
import { requireReviewedPatchApplied } from "../../../../plugins/codex-security/mcp-app/src/workbench-reviewed-patch";
import { ContractError } from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-contract-errors";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { stringifyJson } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
export type Request =
  | { operation: "unicode"; repository: string }
  | { operation: "private"; scanDirectory: string }
  | {
      operation: "boundaries";
      mode: "posix" | "windows";
      scanDirectory: string;
      aliasScanDirectory?: string;
    }
  | { operation: "scopes" | "line-endings"; root: string }
  | { operation: "patch"; scanDirectory: string; digest: string };
function failure(action: () => unknown): string | null {
  try {
    action();
    return null;
  } catch (error) {
    if (
      error instanceof WorkbenchValidationError ||
      error instanceof ContractError
    )
      return error.message;
    throw error;
  }
}
function git(target: string, ...args: string[]): void {
  const result = gitCommand(target, args);
  if (result.returnCode !== 0) throw new Error(result.stderr.toString("utf8"));
}
function execute(request: Request): unknown {
  switch (request.operation) {
    case "unicode": {
      git(request.repository, "init", "-q");
      const subjects = [
        ["UTF-8", "docs: 日本語 한국어 🔧"],
        ["ISO-8859-1", "docs: café"],
      ] as const;
      for (const [encoding, subject] of subjects) {
        git(
          request.repository,
          "-c",
          "user.name=Test",
          "-c",
          "user.email=test@example.invalid",
          "-c",
          "commit.gpgsign=false",
          "commit",
          "--allow-empty",
          "-qm",
          subject,
        );
        git(request.repository, "config", "i18n.logOutputEncoding", encoding);
        for (const locale of ["C", "C.UTF-8"]) {
          process.env["LC_ALL"] = locale;
          if (gitTargetMetadata(request.repository).commitSubject !== subject)
            throw new Error("Incorrect commit subject");
          if (
            !gitBytes(request.repository, [
              "show",
              "-s",
              "--format=%s",
              "HEAD",
            ])?.equals(Buffer.from(subject + "\n"))
          )
            throw new Error("Incorrect commit bytes");
        }
      }
      return { subjects: subjects.length, locales: 2 };
    }
    case "private": {
      const error = failure(() =>
        requireCanonicalScanDirectory(request.scanDirectory),
      );
      return error === null ? { accepted: true } : { accepted: false, error };
    }
    case "boundaries": {
      const scan = request.scanDirectory;
      const aliasScan =
        request.mode === "windows"
          ? scan.toUpperCase()
          : request.aliasScanDirectory!;
      const aliasDirectory =
        request.mode === "windows"
          ? join(aliasScan, "pRoMpTs")
          : join(scan, "prompts");
      const artifact =
        request.mode === "windows"
          ? "pRoMpTs/PrOmPt.TxT"
          : "prompts/prompt.txt";
      const candidate =
        request.mode === "windows" ? "PrOmPt.TxT" : "prompt.txt";
      return {
        deepScanPath:
          failure(() =>
            deepScanPath(
              new Row(["scan_dir"], [scan]),
              join(aliasDirectory, candidate),
              "Worker prompt path",
              "file",
              requireCanonicalScanDirectory,
            ),
          ) === null,
        finalizerScanDirectory:
          failure(() => requireScanDirectory(aliasScan)) === null,
        finalizerOutputParent:
          failure(() =>
            validateScanLocalOutputPath(
              scan,
              join(aliasDirectory, "output.json"),
              `${basename(aliasDirectory)}/output.json`,
            ),
          ) === null,
        workbenchArtifact:
          failure(() => artifactPath(scan, artifact, true)) === null,
        workbenchScanDirectory:
          failure(() => requireCanonicalScanDirectory(aliasScan)) === null,
      };
    }
    case "scopes": {
      const target = join(request.root, "repository");
      mkdirSync(join(target, "src/nested"), { recursive: true });
      mkdirSync(join(request.root, "other"));
      const accepted = [
        requireScope(join(target, "src"), "standard", target),
        requireScope("src/nested", "standard", target),
        requireScope(target, "deep", target),
      ];
      const rejected = [
        ["src\\nested", "standard"],
        [join(request.root, "other"), "standard"],
        [target + "/../other", "standard"],
        ["src", "deep"],
      ].map(
        ([scope, mode]) =>
          failure(() => requireScope(scope!, mode!, target)) !== null,
      );
      return { accepted, rejected };
    }
    case "patch": {
      const scan = { scan_dir: request.scanDirectory };
      requireMatchingPatchDigest(scan, "remediation.patch", request.digest);
      const [preview, stats] = patchArtifactPreview(
        request.scanDirectory,
        "remediation.patch",
        request.digest,
      );
      const mismatch = failure(() =>
        requireMatchingPatchDigest(
          scan,
          "remediation.patch",
          "sha256:" + "0".repeat(64),
        ),
      );
      return { preview, stats, mismatch };
    }
    case "line-endings": {
      Object.assign(process.env, {
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.autocrlf",
        GIT_CONFIG_VALUE_0: "true",
      });
      return ["\n", "\r\n"].map((ending, index) => {
        const target = join(request.root, `target-${index}`),
          scanDirectory = join(request.root, `scan-${index}`);
        mkdirSync(target);
        mkdirSync(scanDirectory, { mode: 0o700 });
        writeFileSync(join(target, "source.txt"), "vulnerable" + ending);
        const base = directoryContentDigest(target);
        const patch = Buffer.from(
          "diff --git a/source.txt b/source.txt\n--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-vulnerable\n+fixed\n",
        );
        const path = join(scanDirectory, "remediation.patch");
        writeFileSync(path, patch);
        git(target, "apply", "--no-index", path);
        const scan = {
          target_path: target,
          target_inode: scanTargetIdentity(target, null)[3],
          target_revision: "unversioned",
          scan_dir: scanDirectory,
        };
        const remediation = {
          base_revision: "unversioned",
          base_content_digest: base,
          patch_digest:
            "sha256:" + createHash("sha256").update(patch).digest("hex"),
        };
        const current = directoryContentDigest(target);
        const applied =
          requireReviewedPatchApplied(
            scan,
            remediation,
            "remediation.patch",
          ) === current;
        const unchanged = directoryContentDigest(target) === current;
        writeFileSync(join(target, "unrelated.txt"), "unrelated\n");
        const error = failure(() =>
          requireReviewedPatchApplied(scan, remediation, "remediation.patch"),
        );
        return {
          applied,
          unchanged,
          unrelatedRejected:
            error?.includes("changes outside the reviewed patch") ?? false,
        };
      });
    }
  }
}
process.stdout.write(
  stringifyJson(execute(JSON.parse(readFileSync(0, "utf8")) as Request)),
);
