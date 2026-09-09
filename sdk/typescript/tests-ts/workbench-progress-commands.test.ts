import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
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
  mkdtempSync(join(tmpdir(), "workbench-progress-command-")),
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
const otherToken = "33333333-3333-4333-8333-333333333333";
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
  return (started["results"] as Record<string, unknown>)["scanId"] as string;
}

test("handoff delivery, context and progress run through the helper without Python", () => {
  const s = setup(),
    scanId = startScan(s);
  const identity = ["--scan-id", scanId, "--claim-token", token];
  result(["claim-handoff-delivery", ...identity], s);
  expect(current(s)).toMatchObject({
    handoff_status: "pending",
    handoff_claim_token: token,
  });
  result(["release-handoff-delivery", ...identity], s);
  expect(current(s)["handoff_claim_token"]).toBeNull();
  result(["claim-handoff-delivery", ...identity], s);
  result(
    [
      "attach-scan-continuation-thread",
      ...identity,
      "--thread-id",
      "continuation",
    ],
    s,
  );
  result(
    ["mark-handoff-delivered", ...identity, "--thread-id", "continuation"],
    s,
  );
  const context = "Review Σ.\r\nKeep this context.";
  result(
    [
      "update-scan-context",
      ...identity,
      "--thread-id",
      "continuation",
      "--user-context-stdin",
    ],
    s,
    context,
  );
  const issues = [
    {
      capability: "test",
      reason: "Not available",
      severity: "warn",
      status: "unknown",
    },
  ];
  result(
    [
      "update-progress",
      ...identity,
      "--phase",
      "preflight",
      "--phase-items-total",
      "3",
      "--phase-items-completed",
      "2",
      "--phase-progress-unit",
      "checks",
      "--preflight-issues-json-stdin",
      "--model",
      "synthetic-model",
      "--reasoning-effort",
      "high",
    ],
    s,
    JSON.stringify(issues),
  );
  let state = snapshot(s);
  expect(state["scan_progress"]![0]).toMatchObject({
    phase_items_total: 3,
    phase_items_completed: 2,
    phase_progress_unit: "checks",
  });
  expect(
    JSON.parse(state["scan_progress"]![0]!["preflight_issues_json"] as string),
  ).toEqual(issues);
  expect(state["scans"]![0]).toMatchObject({
    handoff_status: "delivered",
    handoff_claim_token: token,
    continuation_thread_id: "continuation",
    user_context: context,
    model: "synthetic-model",
    reasoning_effort: "high",
  });
  expect(state["scans"]![0]!["updated_at"]).toMatch(
    /T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z$/,
  );
  result(
    [
      "update-progress",
      ...identity,
      "--phase",
      "validation",
      "--review-items-total",
      "5",
      "--review-items-completed",
      "1",
      "--reportable-findings-count",
      "2",
    ],
    s,
  );
  result(
    [
      "update-scan-context",
      "--scan-id",
      scanId,
      "--workspace-id",
      workspace,
      "--user-context",
      "Updated from workspace",
    ],
    s,
  );
  state = snapshot(s);
  expect(state["scans"]![0]).toMatchObject({
    phase: "validation",
    user_context: "Updated from workspace",
  });
  expect(state["workspaces"]![0]!["user_context"]).toBe(
    "Updated from workspace",
  );
  expect(state["scan_progress"]![0]).toMatchObject({
    review_items_total: 5,
    review_items_completed: 1,
    reportable_findings_count: 2,
  });
});

test("stale claims, continuation ownership and invalid progress preserve state", () => {
  const s = setup(),
    scanId = startScan(s);
  const identity = ["--scan-id", scanId, "--claim-token", token];
  result(["claim-handoff-delivery", ...identity], s);
  result(
    [
      "claim-handoff-delivery",
      "--scan-id",
      scanId,
      "--claim-token",
      otherToken,
      "--take-over-stale",
    ],
    s,
  );
  expect(current(s)["handoff_claim_token"]).toBe(token);
  result(
    [
      "attach-scan-continuation-thread",
      ...identity,
      "--thread-id",
      "continuation",
    ],
    s,
  );
  const before = snapshot(s);
  for (const args of [
    ["attach-scan-continuation-thread", ...identity, "--thread-id", "other"],
    ["mark-handoff-delivered", ...identity, "--thread-id", "other"],
    [
      "update-scan-context",
      ...identity,
      "--thread-id",
      "other",
      "--user-context",
      "rejected",
    ],
    [
      "update-progress",
      "--scan-id",
      scanId,
      "--claim-token",
      otherToken,
      "--phase",
      "validation",
    ],
    ["update-progress", ...identity, "--coordinator-generation", "1"],
    ["update-progress", ...identity, "--deep-review-pass", "1"],
    ["update-progress", ...identity, "--preflight-issues-json", "invalid"],
  ]) {
    const child = helper(args, s);
    expect(child.status, child.stderr).toBe(1);
    expect(child.stdout).toBe("");
    expect(snapshot(s)).toEqual(before);
  }
});

test("progress and handoff argument errors precede database creation", () => {
  const s = setup();
  for (const args of [
    ["claim-handoff-delivery", "--scan-id", workspace],
    [
      "update-scan-context",
      "--scan-id",
      workspace,
      "--user-context",
      "context",
    ],
    [
      "update-scan-context",
      "--scan-id",
      workspace,
      "--workspace-id",
      workspace,
    ],
    [
      "update-scan-context",
      "--scan-id",
      workspace,
      "--workspace-id",
      workspace,
      "--thread-id",
      "owner",
      "--user-context",
      "context",
    ],
    ["update-progress", "--scan-id", workspace, "--phase-items-total", "-1"],
    ["update-progress", "--scan-id", workspace, "--deep-review-pass", "0"],
    ["update-progress", "--scan-id", workspace, "--phase", "other"],
    [
      "update-progress",
      "--scan-id",
      workspace,
      "--preflight-issues-json",
      "[]",
      "--preflight-issues-json-stdin",
    ],
  ]) {
    const child = helper(args, s, "[]");
    expect(child.status, child.stderr).toBe(2);
    expect(child.stdout).toBe("");
  }
  expect(helper(["update-progress", "--help"], s).status).toBe(0);
  expect(existsSync(s.state)).toBe(false);
});

test.skipIf(nodeMajor < 22)(
  "SDK routes all six progress and handoff commands through Node",
  () => {
    const s = setup(),
      scanId = startScan(s);
    const identity = ["--scan-id", scanId, "--claim-token", token];
    const commands = [
      ["claim-handoff-delivery", ...identity],
      ["release-handoff-delivery", ...identity],
      ["claim-handoff-delivery", ...identity],
      [
        "attach-scan-continuation-thread",
        ...identity,
        "--thread-id",
        "continuation",
      ],
      ["mark-handoff-delivered", ...identity, "--thread-id", "continuation"],
      [
        "update-scan-context",
        ...identity,
        "--thread-id",
        "continuation",
        "--user-context",
        "SDK context",
      ],
      [
        "update-progress",
        ...identity,
        "--phase",
        "discovery",
        "--phase-items-total",
        "7",
        "--phase-items-completed",
        "3",
        "--phase-progress-unit",
        "review_receipts",
      ],
    ];
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
    const responses = JSON.parse(child.stdout) as { error?: string }[];
    expect(responses).toHaveLength(commands.length);
    for (const response of responses) expect(response.error).toBeUndefined();
    const state = snapshot(s);
    expect(state["scans"]![0]).toMatchObject({
      handoff_status: "delivered",
      continuation_thread_id: "continuation",
      user_context: "SDK context",
      phase: "discovery",
    });
    expect(state["scan_progress"]![0]).toMatchObject({
      phase_items_total: 7,
      phase_items_completed: 3,
      phase_progress_unit: "review_receipts",
    });
  },
);
