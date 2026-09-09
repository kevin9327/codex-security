import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  sqliteBinding,
  unixBinding,
  windowsBinding,
} from "../../../../plugins/codex-security/mcp-app/src/native";
import { connect } from "../../../../plugins/codex-security/mcp-app/src/workbench-db";
import { cancelScanLocked } from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-stop";
import { preserveScanResultsLocked } from "../../../../plugins/codex-security/mcp-app/src/workbench-preserve-saved-results";

type Table = Record<string, unknown>;
interface Finding extends Table {
  locations: { startLine: number; endLine: number }[];
  provenance?: { candidateId?: string; previousFindings?: Finding[] };
  identity: { anchor: string; instance?: string };
}
interface Payload {
  scanId: string;
  findings: Finding[];
  coverage: Table;
  threatModel: Table;
  complete?: boolean;
}

// Fail one atomic publication write so rollback and retry still run.
function failPublication<T>(operation: () => T): T {
  let failures = 0;
  const selected = (path: string) =>
    failures === 0 && /(?:^|[/\\])\.findings\.json\.[0-9a-f]+\.tmp$/.test(path);
  if (process.platform === "win32") {
    const native = windowsBinding(),
      open = native.openWindowsFile;
    native.openWindowsFile = (path, ...args) => {
      if (selected(path.toString("utf16le"))) {
        failures++;
        return { error: 5 };
      }
      return open.call(native, path, ...args);
    };
    try {
      return operation();
    } finally {
      native.openWindowsFile = open;
      assert.equal(failures, 1);
    }
  }
  const native = unixBinding(),
    open = native.openAt;
  native.openAt = (parent, path, ...args) => {
    if (selected(path.toString("utf8"))) {
      failures++;
      return { value: -1, errno: 5 };
    }
    return open.call(native, parent, path, ...args);
  };
  try {
    return operation();
  } finally {
    native.openAt = open;
    assert.equal(failures, 1);
  }
}

async function main(): Promise<unknown> {
  const [plugin, root, source, terminalStatus = "failed"] = process.argv.slice(
    2,
  ) as [string, string, string, string?];
  const state = join(root, "state"),
    home = join(root, "codex-home"),
    target = join(root, "target");
  const targetFile = join(target, "src", "extract.py"),
    config = join(home, "codex-security", "config.toml");
  mkdirSync(dirname(targetFile), { recursive: true });
  writeFileSync(targetFile, "\n".repeat(50));
  mkdirSync(dirname(config), { recursive: true });
  writeFileSync(config, "[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n");
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: state,
    CODEX_HOME: home,
    PYTHON: "/unavailable/python",
  };
  Object.assign(process.env, environment);
  const run = (...args: string[]): Table => {
    const child = spawnSync(
      process.execPath,
      [join(plugin, "mcp/helpers.mjs"), ...args],
      { env: environment, encoding: "utf8" },
    );
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stderr, "");
    return JSON.parse(child.stdout) as Table;
  };
  const started = run(
    "begin-deep-scan",
    "--thread-id",
    "stopped-result-owner",
    "--target-path",
    target,
    "--scope",
    ".",
    "--scan-root",
    join(root, "scans"),
    "--available-parallelism",
    "4",
  )["deepScan"] as Table;
  const scanId = started["scanId"] as string,
    scanDir = started["scanDir"] as string;
  const artifactDir = join(scanDir, "artifacts", "deep_discovery", source),
    promptPath = join(artifactDir, "prompt.md"),
    resultPath = join(artifactDir, "result.json");
  mkdirSync(artifactDir, { recursive: true });
  writeFileSync(promptPath, "Review the fixture.\n");
  const base = [
    "upsert-deep-scan-worker",
    "--scan-id",
    scanId,
    "--worker-id",
    randomUUID(),
    "--kind",
    "discovery",
    "--prompt-path",
    promptPath,
    "--artifact-dir",
    artifactDir,
    "--attempt",
    "1",
  ];
  run(...base, "--status", "running");
  const finding = (
    JSON.parse(
      readFileSync(
        join(plugin, "examples/completed-scan/findings.json"),
        "utf8",
      ),
    ) as { findings: Finding[] }
  ).findings[0]!;
  finding.provenance = {
    ...finding.provenance,
    candidateId: "checkpoint-candidate",
  };
  const payload: Payload = {
    scanId,
    findings: [finding],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [
        {
          candidateId: "pending-validation",
          reason: "Validation stopped with the scan.",
          paths: ["src/extract.py"],
        },
      ],
    },
    threatModel: { summary: "Synthetic stopped-scan threat model." },
  };
  const checkpoint: Payload = { ...payload, complete: false },
    checkpointDir = join(artifactDir, "checkpoints");
  const writeCheckpoint = (document: Payload) => {
    const bytes = Buffer.from(JSON.stringify(document)),
      digest = createHash("sha256").update(bytes).digest("hex");
    writeFileSync(join(checkpointDir, `${digest}.json`), bytes);
  };
  if (source === "accepted") {
    writeFileSync(resultPath, JSON.stringify(payload));
    run(...base, "--status", "succeeded", "--result-manifest-path", resultPath);
  } else {
    mkdirSync(checkpointDir);
    if (source === "refined-checkpoint") {
      const earlier = structuredClone(checkpoint),
        later = structuredClone(checkpoint);
      Object.assign(earlier.findings[0]!.locations[0]!, {
        startLine: 21,
        endLine: 26,
      });
      Object.assign(later.findings[0]!.locations[0]!, {
        startLine: 24,
        endLine: 26,
      });
      for (const document of [earlier, later]) writeCheckpoint(document);
      writeFileSync(resultPath, JSON.stringify(later));
    } else {
      if (source === "distinct-instances")
        checkpoint.findings = ["first", "second"].map((instance) => ({
          ...structuredClone(finding),
          identity: { anchor: "shared-anchor", instance },
        }));
      writeCheckpoint(checkpoint);
      writeFileSync(resultPath, "{incomplete");
    }
  }
  const now = () => new Date().toISOString(),
    context = { now };
  const manifestPath = join(scanDir, "scan-manifest.json"),
    findingsPath = join(scanDir, "findings.json");
  const findings = () =>
    existsSync(findingsPath)
      ? (
          JSON.parse(readFileSync(findingsPath, "utf8")) as {
            findings: Finding[];
          }
        ).findings
      : [];
  if (source === "cancel-io-retry") {
    const connection = await connect(sqliteBinding(), now);
    try {
      failPublication(() =>
        cancelScanLocked(context, connection, { scanId, threadId: null }),
      );
    } finally {
      connection.close();
    }
    run(
      "preserve-scan-results",
      "--scan-id",
      scanId,
      "--thread-id",
      "stopped-result-owner",
    );
    const stored = run("get-scan", "--scan-id", scanId)["scan"] as Table;
    const database = await connect(sqliteBinding(), now);
    try {
      const frozen = database
        .prepare("SELECT retained_source_digests_json FROM scans WHERE id = ?")
        .get([scanId])!
        .get(0) as string | null;
      return {
        findingCount: stored["findingCount"],
        progressStatus: (stored["progress"] as Table)["status"],
        artifactFindingCount: findings().length,
        frozen: frozen ? JSON.parse(frozen) : null,
      };
    } finally {
      database.close();
    }
  }
  run(
    "fail-deep-scan",
    "--scan-id",
    scanId,
    "--message",
    "Synthetic worker stopped.",
    "--deep-status",
    terminalStatus,
  );
  if (source === "legacy-seal-io-retry") {
    rmSync(artifactDir, { recursive: true });
    const legacy = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      scan: Table;
    };
    legacy.scan["status"] = "completed";
    delete legacy.scan["preservedSources"];
    writeFileSync(manifestPath, JSON.stringify(legacy, null, 2) + "\n");
    const connection = await connect(sqliteBinding(), now);
    try {
      connection
        .prepare(
          "UPDATE scans SET seal_manifest_digest = NULL, retained_source_digests_json = NULL WHERE id = ?",
        )
        .run([scanId]);
      connection.commit();
      let firstFailed = false;
      failPublication(() => {
        try {
          preserveScanResultsLocked(context, connection, scanId);
        } catch {
          firstFailed = true;
        }
      });
      const frozen = () =>
        connection
          .prepare(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?",
          )
          .get([scanId])!
          .get(0) as string | null;
      const frozenAfterFailure = frozen(),
        retryPublished = preserveScanResultsLocked(context, connection, scanId),
        afterSuccess = frozen();
      return {
        firstFailed,
        frozenAfterFailure,
        retryPublished,
        frozenAfterSuccess: afterSuccess ? JSON.parse(afterSuccess) : null,
        status: (
          JSON.parse(readFileSync(manifestPath, "utf8")) as { scan: Table }
        ).scan["status"],
        findingCount: findings().length,
      };
    } finally {
      connection.close();
    }
  }
  const manifestBefore = readFileSync(manifestPath),
    findingsBefore = readFileSync(findingsPath);
  if (source === "late-checkpoint") {
    const late = structuredClone(checkpoint),
      lateFinding = structuredClone(finding);
    Object.assign(lateFinding, {
      occurrenceId: "occ_111111111111111111111111",
      ruleId: "late.checkpoint",
      title: "Late checkpoint finding",
    });
    Object.assign(lateFinding.locations[0]!, { startLine: 10, endLine: 12 });
    lateFinding.provenance = {
      ...lateFinding.provenance,
      candidateId: "late-checkpoint-candidate",
    };
    late.findings.push(lateFinding);
    writeCheckpoint(late);
  }
  const stored = run("get-scan", "--scan-id", scanId)["scan"] as Table,
    saved = findings();
  const result = {
    findingCount: stored["findingCount"],
    artifactFindingCount: saved.length,
  };
  if (source === "late-checkpoint")
    return {
      ...result,
      manifestUnchanged: manifestBefore.equals(readFileSync(manifestPath)),
      findingsUnchanged: findingsBefore.equals(readFileSync(findingsPath)),
    };
  if (source === "distinct-instances")
    return {
      ...result,
      instances: saved.map((finding) => finding.identity.instance).sort(),
    };
  const progressStatus = (stored["progress"] as Table)["status"];
  if (source === "refined-checkpoint") {
    const histories = saved.flatMap(
      (finding) => finding.provenance?.previousFindings ?? [],
    );
    return {
      ...result,
      progressStatus,
      historyCount: histories.length,
      representedStartLines: [...saved, ...histories]
        .map((finding) => finding.locations[0]!.startLine)
        .sort((a, b) => a - b),
    };
  }
  return { ...result, progressStatus };
}
void main().then((result) => process.stdout.write(JSON.stringify(result)));
