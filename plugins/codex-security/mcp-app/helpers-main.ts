import { closeSync, readFileSync } from "node:fs";
import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";
import { normalizeCandidatesCommand } from "./src/helpers/normalize-candidates";
import { validatePatchRiskAssessmentCommand } from "./src/helpers/validate-patch-risk-assessment";
import { deepReviewInputCommand } from "./src/helpers/deep-review-input";
import { rankShardsCommand } from "./src/helpers/rank-shards";
import { rankPoolCommand } from "./src/helpers/rank-pool";
import { bindRepoScopesCommand } from "./src/helpers/bind-repo-scopes";
import { snapshotSqliteCommand } from "./src/helpers/snapshot-sqlite";
import { generateInScopeFilesCommand } from "./src/helpers/generate-in-scope-files";
import { workbenchCommand } from "./src/helpers/workbench-command";
import { generateRankInputCommand } from "./src/helpers/generate-rank-input";
import { configPreflightCommand } from "./src/helpers/config-preflight-command";
import { scanArtifactRestorerCommand } from "./src/helpers/scan-artifact-restorer";
import { finalizeScanContractCommand } from "./src/helpers/finalize-scan-contract";
import { scanValidationCommand } from "./src/helpers/validate-scan-contract";

let commandLine = process.argv.slice(2);
if (process.platform === "win32") {
  const original = windowsBinding().windowsArguments();
  commandLine = original
    .slice(original.length - commandLine.length)
    .map((argument) => argument.toString("utf16le"));
}
let posixHome = process.env.HOME;
if (commandLine[0] === "--helper") {
  if (process.platform === "win32") {
    commandLine = commandLine.slice(1);
  } else {
    const encoded = readFileSync(3, "ascii");
    closeSync(3);
    const [homeSet, home, ...args] = decodePosixBytes(
      Buffer.from(encoded.trim(), "hex"),
    )
      .split("\0")
      .slice(0, -1);
    posixHome = homeSet ? home : undefined;
    commandLine = args;
  }
}
const [command, ...args] = commandLine;
if (command === "resolve-security-md") {
  process.exitCode = resolveSecurityMdCommand(args, posixHome);
} else if (command === "normalize-candidates") {
  process.exitCode = normalizeCandidatesCommand(args, posixHome);
} else if (command === "validate-patch-risk-assessment") {
  process.exitCode = validatePatchRiskAssessmentCommand(args);
} else if (
  command === "validate-scan-contract" ||
  command === "validate-tracking-source"
) {
  process.exitCode = scanValidationCommand(command, args, posixHome);
} else if (
  command === "copy-deep-review-input" ||
  command === "select-deep-review-input"
) {
  process.exitCode = deepReviewInputCommand(command, args, posixHome);
} else if (
  command === "make-rank-shards" ||
  command === "validate-rank-shard" ||
  command === "merge-rank-outputs"
) {
  process.exitCode = rankShardsCommand(command, args, posixHome);
} else if (
  command === "make-rank-pool-plan" ||
  command === "validate-rank-worker" ||
  command === "validate-rank-pool"
) {
  process.exitCode = rankPoolCommand(command, args, posixHome);
} else if (command === "bind-repo-scopes") {
  process.exitCode = bindRepoScopesCommand(args, posixHome);
} else if (command === "snapshot-sqlite") {
  void snapshotSqliteCommand(args, posixHome).then((status) => {
    process.exitCode = status;
  });
} else if (command === "generate-in-scope-files") {
  process.exitCode = generateInScopeFilesCommand(args, posixHome);
} else if (
  command === "dashboard" ||
  command === "database-info" ||
  command === "store-findings" ||
  command === "list-stored-findings" ||
  command === "find-potential-duplicates" ||
  command === "store-dedupe-groups" ||
  command === "list-dedupe-groups" ||
  command === "list-global-findings" ||
  command === "list-repositories" ||
  command === "list-scans" ||
  command === "get-scan-feedback"
) {
  void workbenchCommand(command, args).then((status) => {
    process.exitCode = status;
  });
} else if (
  command === "make-repo-rank-input" ||
  command === "make-repo-scope-input" ||
  command === "make-diff-rank-input"
) {
  process.exitCode = generateRankInputCommand(command, args, posixHome);
} else if (command === "config-preflight") {
  process.exitCode = configPreflightCommand(args);
} else if (command === "scan-artifact-restorer") {
  process.exitCode = scanArtifactRestorerCommand(args);
} else if (command === "finalize-scan-contract") {
  process.exitCode = finalizeScanContractCommand(args);
} else {
  console.error(
    "Usage: launch_codex_security_mcp[.cmd] --helper <resolve-security-md | normalize-candidates | validate-patch-risk-assessment | validate-scan-contract | validate-tracking-source | copy-deep-review-input | select-deep-review-input | make-rank-shards | validate-rank-shard | merge-rank-outputs | make-rank-pool-plan | validate-rank-worker | validate-rank-pool | bind-repo-scopes | snapshot-sqlite | generate-in-scope-files | dashboard | database-info | store-findings | list-stored-findings | find-potential-duplicates | store-dedupe-groups | list-dedupe-groups | list-global-findings | list-repositories | list-scans | make-repo-rank-input | make-repo-scope-input | make-diff-rank-input | config-preflight | finalize-scan-contract> [options]",
  );
  process.exitCode = 2;
}
