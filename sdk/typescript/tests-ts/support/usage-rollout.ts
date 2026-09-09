import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { withWorkbenchDatabase, workbenchRows } from "./workbench-database.js";
import { expect } from "bun:test";

export const scanThreadId = "scan-thread";
export const lowerUuid7Turn = "019f9e4d-b3ba-7000-8000-000000000001";
export const childUuid7Thread = "019f9e4d-b3ba-7000-8000-000000000002";
export const higherUuid7Turn = "019f9e4d-b3ba-7000-8000-000000000003";
const uuid7EventTimestamp = "2026-07-26T12:02:00.250Z";
export const ownedSdkUsage = {
  input_tokens: 100,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 10,
  reasoning_output_tokens: 0,
  total_tokens: 110,
};
export const ownedWorkbenchUsage = {
  inputTokens: 100,
  cachedInputTokens: 0,
  cacheWriteInputTokens: 0,
  outputTokens: 10,
  reasoningOutputTokens: 0,
  totalTokens: 110,
};

function uuid7TaskStarted(turnId: string): Record<string, unknown> {
  return {
    type: "event_msg",
    timestamp: uuid7EventTimestamp,
    payload: {
      type: "task_started",
      turn_id: turnId,
      started_at: 1_785_067_320,
    },
  };
}

function uuid7TokenSnapshot(
  inputTokens: number,
  outputTokens: number,
): Record<string, unknown> {
  return {
    type: "event_msg",
    timestamp: uuid7EventTimestamp,
    payload: {
      type: "token_count",
      info: {
        total_token_usage: {
          ...ownedSdkUsage,
          input_tokens: inputTokens,
          output_tokens: outputTokens,
          total_tokens: inputTokens + outputTokens,
        },
      },
    },
  };
}

export function ownershipRollout(
  replayedTurnIds: readonly string[],
): Record<string, unknown>[] {
  return [
    {
      type: "session_meta",
      payload: {
        id: childUuid7Thread,
        timestamp: uuid7EventTimestamp,
        source: {
          subagent: { thread_spawn: { parent_thread_id: scanThreadId } },
        },
      },
    },
    {
      type: "session_meta",
      payload: {
        id: scanThreadId,
        timestamp: "2026-07-26T12:00:00.000Z",
        source: "exec",
      },
    },
    ...replayedTurnIds.map(uuid7TaskStarted),
    uuid7TokenSnapshot(1_000, 100),
    uuid7TaskStarted(higherUuid7Turn),
    uuid7TokenSnapshot(1_100, 110),
  ];
}

export function readWorkbenchRolloutUsage(
  pluginRoot: string,
  rolloutPath: string,
): unknown {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "workbench-rollout-")));
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const state = join(root, "state"),
    database = join(state, "workbench.sqlite3"),
    codexDatabase = join(root, "state_5.sqlite"),
    target = join(root, "target"),
    scanDirectory = join(root, "scan");
  const environment = {
    ...process.env,
    PATH: "",
    PYTHON: "/unavailable/python",
    CODEX_SECURITY_STATE_DIR: state,
    CODEX_HOME: join(root, "codex"),
    CODEX_SQLITE_HOME: root,
    CODEX_STATE_DB: codexDatabase,
  };
  function helper(args: string[]): Record<string, unknown> {
    const result = spawnSync(
      node!,
      [join(pluginRoot, "mcp/helpers.mjs"), ...args],
      {
        env: environment,
        encoding: "utf8",
        windowsHide: true,
      },
    );
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    return JSON.parse(result.stdout) as Record<string, unknown>;
  }
  try {
    mkdirSync(target);
    mkdirSync(scanDirectory, { mode: 0o700 });
    writeFileSync(join(target, "source.ts"), "synthetic source\n");
    const registered = helper([
      "register-cli-scan",
      "--repository",
      target,
      "--scan-dir",
      scanDirectory,
      "--recipe-json",
      JSON.stringify({
        repository: target,
        mode: "standard",
        maxCostUsd: 0.5,
        config: {},
        target: { kind: "repository", paths: [] },
      }),
    ]);
    const scanId = registered["scanId"] as string;
    const scan = workbenchRows(database, "SELECT * FROM scans WHERE id = ?", [
      scanId,
    ])[0]!;
    withWorkbenchDatabase(database, (connection) => {
      connection
        .prepare("UPDATE workspaces SET thread_id = ? WHERE id = ?")
        .run([childUuid7Thread, scan["workspace_id"] as string]);
      connection
        .prepare("UPDATE scans SET started_at = ? WHERE id = ?")
        .run(["2026-07-26T12:00:00Z", scanId]);
      connection.commit();
    });
    withWorkbenchDatabase(codexDatabase, (connection) => {
      connection.raw.exec(
        "CREATE TABLE threads(id, rollout_path); CREATE TABLE thread_spawn_edges(parent_thread_id, child_thread_id);",
      );
      connection
        .prepare("INSERT INTO threads VALUES (?, ?)")
        .run([childUuid7Thread, rolloutPath]);
      connection.commit();
    });
    const readExample = (name: string) =>
      JSON.parse(
        readFileSync(join(pluginRoot, "examples/completed-scan", name), "utf8"),
      ) as Record<string, unknown>;
    const manifest = readExample("scan-manifest.json"),
      manifestScan = manifest["scan"] as Record<string, unknown>;
    delete manifestScan["sealedAt"];
    delete manifestScan["artifacts"];
    manifestScan["startedAt"] = "2026-07-26T12:00:00Z";
    manifestScan["completedAt"] = "2026-07-26T12:03:00Z";
    manifestScan["target"] = {
      kind: "directory_snapshot",
      snapshotDigest: scan["target_snapshot_digest"],
    };
    const findings = readExample("findings.json");
    for (const finding of findings["findings"] as Record<string, unknown>[])
      for (const key of ["findingId", "occurrenceId", "fingerprints"])
        delete finding[key];
    const drafts = join(scan["scan_dir"] as string, "drafts");
    const draft = join(drafts, "a-b.json");
    mkdirSync(drafts, { recursive: true });
    writeFileSync(
      draft,
      JSON.stringify({
        manifest,
        findings,
        coverage: readExample("coverage.json"),
      }),
    );
    helper(["write-scan-draft", "--scan-id", scanId, "--draft-path", draft]);
    const completed = helper(["complete-scan", "--scan-id", scanId]);
    const completedScan = completed["scan"] as Record<string, unknown>;
    expect(completedScan).toMatchObject({
      scanId,
      progress: { status: "complete" },
    });
    const usage = completedScan["usage"] as Record<string, unknown>;
    expect(usage).toMatchObject({
      coverage: "complete",
      source: "codex_rollout",
      threadCount: 1,
    });
    return {
      usage: Object.fromEntries(
        Object.keys(ownedWorkbenchUsage).map((key) => [key, usage[key]]),
      ),
      warnings: usage["warnings"] ?? [],
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
