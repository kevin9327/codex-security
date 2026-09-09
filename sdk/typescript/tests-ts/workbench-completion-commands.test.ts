import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Operation } from "./support/navigation-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-completion-command-")),
);
const node = Bun.which("node")!,
  fixture = join(root, "fixture.cjs");
const workspace = "11111111-1111-4111-8111-111111111111";
const environment = { ...process.env, PATH: "", PYTHON: "/unavailable/python" };
const nodeMajor = Number(
  spawnSync(node, ["-p", "process.versions.node.split('.')[0]"], {
    encoding: "utf8",
  }).stdout,
);
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/navigation-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(root, { recursive: true, force: true }));
function setup() {
  const directory = mkdtempSync(join(root, "case-")),
    target = join(directory, "target"),
    state = join(directory, "state"),
    scanRoot = join(directory, "outputs");
  mkdirSync(target);
  writeFileSync(join(target, "source.ts"), "synthetic source\n");
  return { directory, target, state, scanRoot };
}
type Setup = ReturnType<typeof setup>;
function helper(args: string[], s: Setup, input?: string | Buffer) {
  return spawnSync(node, [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args], {
    input,
    encoding: "utf8",
    env: {
      ...environment,
      CODEX_SECURITY_STATE_DIR: s.state,
      CODEX_HOME: join(s.directory, "codex"),
      CODEX_SQLITE_HOME: join(s.directory, "sqlite"),
    },
  });
}
function result(
  args: string[],
  s: Setup,
  input?: string,
): Record<string, unknown> {
  const child = helper(args, s, input);
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Record<string, unknown>;
}
function snapshot(s: Setup) {
  const child = spawnSync(node, [fixture, join(s.state, "workbench.sqlite3")], {
    input: stringifyJson({ operations: [{ snapshot: true }] }),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  return (
    JSON.parse(child.stdout) as {
      value: Record<string, Record<string, unknown>[]>;
    }[]
  )[0]!.value;
}
const current = (s: Setup) => snapshot(s)["scans"]![0]!;
const workspaceArgs = (s: Setup) => [
  "--workspace-id",
  workspace,
  "--target-path",
  s.target,
  "--scope",
  ".",
  "--mode",
  "standard",
];
const token = "22222222-2222-4222-8222-222222222222";
const cost = JSON.stringify({
  model: "synthetic",
  inputTokens: 10,
  cachedInputTokens: 0,
  cacheWriteInputTokens: 0,
  outputTokens: 2,
  estimatedUsd: 0.25,
});
function startScan(s: Setup) {
  result(
    ["create-workspace", "--workspace-id", workspace, "--thread-id", "owner"],
    s,
  );
  result(["save-workspace", ...workspaceArgs(s)], s);
  const started = result(
    ["start-scan", "--workspace-id", workspace, "--scan-root", s.scanRoot],
    s,
  );
  const scanId = (started["results"] as Record<string, unknown>)[
    "scanId"
  ] as string;
  result(
    ["claim-handoff-delivery", "--scan-id", scanId, "--claim-token", token],
    s,
  );
  result(
    [
      "mark-handoff-delivered",
      "--scan-id",
      scanId,
      "--claim-token",
      token,
      "--thread-id",
      "owner",
    ],
    s,
  );
  return scanId;
}
type Table = Record<string, unknown>;
function draft(s: Setup) {
  const scan = current(s),
    directory = scan["scan_dir"] as string;
  const read = (name: string) =>
    JSON.parse(
      readFileSync(join(PLUGIN_ROOT, "examples/completed-scan", name), "utf8"),
    ) as Table;
  const manifest = read("scan-manifest.json"),
    manifestScan = manifest["scan"] as Table;
  delete manifestScan["sealedAt"];
  delete manifestScan["artifacts"];
  manifestScan["target"] = {
    kind: "directory_snapshot",
    snapshotDigest: scan["target_snapshot_digest"],
  };
  const findings = read("findings.json"),
    coverage = read("coverage.json");
  for (const finding of findings["findings"] as Table[])
    for (const key of ["findingId", "occurrenceId", "fingerprints"])
      delete finding[key];
  const path = join(directory, "drafts", "a-b.json");
  mkdirSync(join(directory, "drafts"), { recursive: true });
  writeFileSync(path, JSON.stringify({ manifest, findings, coverage }));
  return { path, directory };
}

test("draft, preparation and completion seal the registered scan without Python", () => {
  const s = setup(),
    scanId = startScan(s),
    staged = draft(s);
  const identity = ["--scan-id", scanId, "--claim-token", token];
  expect(
    result(["write-scan-draft", ...identity, "--draft-path", staged.path], s),
  ).toEqual({ scanId, status: "draft_written" });
  result(["prepare-scan-completion", ...identity], s);
  expect(current(s)["status"]).toBe("running");
  expect(existsSync(join(staged.directory, "report.md"))).toBe(true);
  const sealed = JSON.parse(
    readFileSync(join(staged.directory, "scan-manifest.json"), "utf8"),
  ) as { scan: Table };
  expect(sealed.scan["id"]).toBe(scanId);
  expect(sealed.scan["sealedAt"]).toBeString();
  result(["write-scan-draft", ...identity, "--draft-path", staged.path], s);
  result(
    ["complete-scan", ...identity, "--cost-json", cost, "--thread-id", "owner"],
    s,
  );
  const completed = current(s);
  expect(completed["status"]).toBe("complete");
  expect(completed["seal_manifest_digest"]).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(JSON.parse(completed["cost_json"] as string)).toMatchObject({
    estimatedUsd: 0.25,
  });
  const before = snapshot(s);
  result(["complete-scan", ...identity], s);
  expect(snapshot(s)).toEqual(before);
});

test("failure preserves retained evidence and recovery republishes it", () => {
  const s = setup(),
    scanId = startScan(s),
    staged = draft(s);
  const identity = ["--scan-id", scanId, "--claim-token", token];
  const checkpointPath = join(
    staged.directory,
    "drafts",
    "a-b.checkpoint.json",
  );
  writeFileSync(
    checkpointPath,
    JSON.stringify({
      scanId,
      findings: [],
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
    }),
  );
  result(
    [
      "write-scan-draft",
      ...identity,
      "--draft-path",
      staged.path,
      "--checkpoint-path",
      checkpointPath,
    ],
    s,
  );
  result(
    [
      "fail-scan",
      ...identity,
      "--message",
      "Worker stopped",
      "--cost-json",
      cost,
    ],
    s,
  );
  expect(current(s)).toMatchObject({
    status: "failed",
    failure_message: "Worker stopped",
  });
  result(["preserve-scan-results", ...identity, "--thread-id", "owner"], s);
  result(["recover-scan-results", "--scan-id", scanId], s);
  const after = current(s);
  expect(after).toMatchObject({
    status: "failed",
    failure_message: "Worker stopped",
  });
  expect(after["seal_manifest_digest"]).toMatch(/^sha256:[a-f0-9]{64}$/);
  expect(existsSync(join(staged.directory, "report.md"))).toBe(true);
});

test("cancellation enforces ownership and blocks stopped-scan recovery", () => {
  const s = setup(),
    scanId = startScan(s);
  const wrong = helper(
    ["cancel-scan", "--scan-id", scanId, "--thread-id", "other"],
    s,
  );
  expect(wrong.status).toBe(1);
  expect(wrong.stderr).toContain("owning Codex thread");
  expect(current(s)["status"]).toBe("running");
  result(["cancel-scan", "--scan-id", scanId, "--thread-id", "owner"], s);
  expect(current(s)).toMatchObject({ status: "failed" });
  expect(current(s)["canceled_at"]).toBeString();
  const recovery = helper(["recover-scan-results", "--scan-id", scanId], s);
  expect(recovery.status).toBe(1);
  expect(recovery.stderr).toContain("Canceled scans cannot recover");
});

test("completion validates arguments and scan bindings", () => {
  const s = setup();
  for (const args of [
    ["prepare-scan-completion"],
    ["complete-scan", "--scan-id"],
    ["complete-budget-exhausted-scan", "--scan-id", workspace],
    ["write-scan-draft", "--scan-id", workspace],
    [
      "preserve-scan-results",
      "--scan-id",
      workspace,
      "--coordinator-generation",
      "0",
    ],
  ])
    expect(helper(args, s).status).toBe(2);
  expect(existsSync(s.state)).toBe(false);
  const help = helper(["recover-scan-results", "--help"], s);
  expect(help.status).toBe(0);
  expect(help.stdout).toContain("Validate and republish retained checkpoints");
  expect(help.stdout).toContain("ID of the stopped scan to recover.");
  const scanId = startScan(s);
  const before = snapshot(s);
  for (const args of [
    [
      "complete-budget-exhausted-scan",
      "--scan-id",
      scanId,
      "--cost-json",
      cost,
    ],
    ["preserve-scan-results", "--scan-id", scanId],
    ["recover-scan-results", "--scan-id", scanId],
    [
      "write-scan-draft",
      "--scan-id",
      scanId,
      "--claim-token",
      token,
      "--draft-path",
      join(s.directory, "outside.json"),
    ],
    ["complete-scan", "--scan-id", scanId, "--claim-token", workspace],
  ]) {
    const child = helper(args, s);
    expect(child.status, child.stderr).toBe(1);
    expect(snapshot(s)).toEqual(before);
  }
});

test("budget completion publishes successful discovery through the helper", () => {
  const s = setup(),
    scanDir = join(s.directory, "scan");
  mkdirSync(scanDir, { mode: 0o700 });
  const recipe = {
    repository: s.target,
    mode: "deep",
    maxCostUsd: 0.1,
    config: {},
    target: { kind: "repository", paths: [] },
  };
  const scanId = result(
    [
      "register-cli-scan",
      "--repository",
      s.target,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify(recipe),
    ],
    s,
  )["scanId"] as string;
  const discovery = join(scanDir, "artifacts/02_discovery");
  mkdirSync(discovery, { recursive: true });
  writeFileSync(join(discovery, "in_scope_files.txt"), "source.ts\n");
  writeFileSync(join(discovery, "candidate_ledger.jsonl"), "");
  const operation: Operation = {
    sql: "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, phase, workers, subagents, stop_after_no_new, max_discovery_runs, status, terminal_reason, manifest_path, created_at, updated_at) VALUES (?, 1, 'deep-security-scan/v1', 'terminal', 4, 1, 3, 40, 'succeeded', 'saturated', ?, 'created', 'updated')",
    parameters: [scanId, join(discovery, "scan-manifest.json")],
  };
  const child = spawnSync(node, [fixture, join(s.state, "workbench.sqlite3")], {
    input: stringifyJson({ operations: [operation, { sql: "COMMIT" }] }),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(
    (JSON.parse(child.stdout) as { error?: string }[])[0]!.error,
  ).toBeUndefined();
  result(
    [
      "complete-budget-exhausted-scan",
      "--scan-id",
      scanId,
      "--cost-json",
      cost,
      "--message",
      "Cost limit reached",
    ],
    s,
  );
  expect(current(s)).toMatchObject({ status: "complete", mode: "deep" });
  expect(
    JSON.parse(readFileSync(join(scanDir, "coverage.json"), "utf8")),
  ).toMatchObject({ mode: "deep_repository", completeness: "partial" });
});

test.skipIf(nodeMajor < 22)(
  "SDK completion and stop routes execute without Python",
  () => {
    function sdk(s: Setup, commands: string[][]) {
      const operations: Operation[] = commands.map((sdk) => ({
        sdk,
        pluginRoot: PLUGIN_ROOT,
        stateDir: s.state,
      }));
      const child = spawnSync(node, [fixture], {
        input: stringifyJson({ operations }),
        encoding: "utf8",
        env: environment,
      });
      expect(child.status, child.stderr).toBe(0);
      return JSON.parse(child.stdout) as { error?: string; value: Table }[];
    }
    const s = setup(),
      scanId = startScan(s),
      staged = draft(s);
    const identity = ["--scan-id", scanId, "--claim-token", token];
    const completed = sdk(s, [
      ["write-scan-draft", ...identity, "--draft-path", staged.path],
      ["prepare-scan-completion", ...identity],
      ["write-scan-draft", ...identity, "--draft-path", staged.path],
      ["complete-scan", ...identity, "--cost-json", cost],
    ]);
    for (const response of completed) expect(response.error).toBeUndefined();
    expect(current(s)["status"]).toBe("complete");
    const failed = setup(),
      failedId = startScan(failed);
    const stopped = sdk(failed, [
      [
        "complete-budget-exhausted-scan",
        "--scan-id",
        failedId,
        "--cost-json",
        cost,
      ],
      [
        "fail-scan",
        "--scan-id",
        failedId,
        "--claim-token",
        token,
        "--message",
        "Worker stopped",
      ],
      ["preserve-scan-results", "--scan-id", failedId, "--claim-token", token],
      ["recover-scan-results", "--scan-id", failedId],
    ]);
    expect(stopped[0]!.error).toContain("Only a running CLI Deep Scan");
    expect(stopped[1]!.error).toBeUndefined();
    expect(stopped[2]!.error).toBeUndefined();
    expect(stopped[3]!.error).toContain("No saved stopped-scan results");
    const canceled = setup(),
      canceledId = startScan(canceled);
    expect(
      sdk(canceled, [
        ["cancel-scan", "--scan-id", canceledId, "--thread-id", "owner"],
      ])[0]!.error,
    ).toBeUndefined();
    expect(current(canceled)["canceled_at"]).toBeString();
  },
);
