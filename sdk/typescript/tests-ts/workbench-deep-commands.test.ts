import { spawnSync } from "node:child_process";
import {
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

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-deep-commands-")),
);
const node = Bun.which("node")!,
  fixture = join(root, "sdk.cjs");
const nodeMajor = Number(
  spawnSync(node, ["-p", "process.versions.node.split('.')[0]"], {
    encoding: "utf8",
  }).stdout,
);
const first = "11111111-1111-4111-8111-111111111111",
  second = "22222222-2222-4222-8222-222222222222",
  reducer = "33333333-3333-4333-8333-333333333333";
const environment = { ...process.env, PATH: "", PYTHON: "/unavailable/python" };
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
function setup(sdk = false) {
  const directory = mkdtempSync(join(root, "case-")),
    target = join(directory, "target"),
    state = join(directory, "state"),
    scanRoot = join(directory, "scans"),
    config = join(directory, "config.toml");
  mkdirSync(target);
  writeFileSync(join(target, "source.ts"), "synthetic source\n");
  writeFileSync(config, "[deep_scan]\nstop_after_no_new = 2\n");
  const env = {
    ...environment,
    CODEX_SECURITY_STATE_DIR: state,
    CODEX_HOME: join(directory, "codex"),
    CODEX_SQLITE_HOME: join(directory, "sqlite"),
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: config,
  };
  const run = (args: string[], input?: string) => {
    if (!sdk)
      return spawnSync(node, [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args], {
        input,
        encoding: "utf8",
        env,
      });
    return spawnSync(node, [fixture], {
      input: stringifyJson({
        operations: [{ sdk: args, pluginRoot: PLUGIN_ROOT, stateDir: state }],
      }),
      encoding: "utf8",
      env,
    });
  };
  const result = (args: string[], input?: string): Record<string, unknown> => {
    const child = run(args, input);
    expect(child.status, child.stderr).toBe(0);
    expect(child.stderr).toBe("");
    if (!sdk) return JSON.parse(child.stdout) as Record<string, unknown>;
    const outcome = (
      JSON.parse(child.stdout) as {
        error?: string;
        value: Record<string, unknown>;
      }[]
    )[0]!;
    expect(outcome.error).toBeUndefined();
    return outcome.value;
  };
  const begin = result([
    "begin-deep-scan",
    "--thread-id",
    "owner",
    "--target-path",
    target,
    "--scan-root",
    scanRoot,
    "--available-parallelism",
    "4",
  ]);
  const deep = begin["deepScan"] as Record<string, unknown>,
    scanId = deep["scanId"] as string,
    scanDir = deep["scanDir"] as string;
  return {
    directory,
    target,
    state,
    scanRoot,
    run,
    result,
    begin,
    scanId,
    scanDir,
  };
}
type Setup = ReturnType<typeof setup>;
const deep = (value: Record<string, unknown>) =>
  value["deepScan"] as Record<string, unknown>;
function worker(s: Setup, id: string) {
  const directory = join(s.scanDir, id);
  mkdirSync(directory);
  const prompt = join(directory, "prompt.txt"),
    manifest = join(directory, "manifest.json");
  writeFileSync(prompt, "synthetic prompt\n");
  writeFileSync(manifest, "{}");
  return {
    directory,
    prompt,
    manifest,
    args: [
      "--scan-id",
      s.scanId,
      "--worker-id",
      id,
      "--prompt-path",
      prompt,
      "--artifact-dir",
      directory,
      "--coordinator-generation",
      "2",
    ],
  };
}
function reduceAndFinish(s: Setup) {
  expect(s.begin).toMatchObject({ startDisposition: "created" });
  expect(
    deep(
      s.result([
        "get-deep-scan",
        "--scan-id",
        s.scanId,
        "--thread-id",
        "owner",
      ]),
    ),
  ).toMatchObject({
    status: "running",
    config: { stopAfterNoNew: 2 },
    workflowVersion: "deep-security-scan/v1",
  });
  const claim = s.result([
    "claim-deep-scan-coordinator",
    "--scan-id",
    s.scanId,
    "--thread-id",
    "owner",
  ]);
  expect(deep(claim)["coordinatorGeneration"]).toBe(2);
  const discovery = join(s.scanDir, "artifacts", "02_discovery");
  mkdirSync(discovery, { recursive: true });
  writeFileSync(join(discovery, "in_scope_files.txt"), "source.ts\n");
  writeFileSync(join(discovery, "candidate_ledger.jsonl"), "candidate\n");
  for (const id of [first, second]) {
    const w = worker(s, id);
    s.result([
      "upsert-deep-scan-worker",
      ...w.args,
      "--kind",
      "discovery",
      "--status",
      "running",
    ]);
    s.result([
      "upsert-deep-scan-worker",
      ...w.args,
      "--kind",
      "discovery",
      "--status",
      "succeeded",
      "--result-manifest-path",
      w.manifest,
    ]);
  }
  const r = worker(s, reducer);
  const claimArgs = [
    "claim-deep-scan-dedup",
    ...r.args,
    "--input-worker-id",
    first,
    "--input-worker-id",
    second,
  ];
  const claimed = s.result(claimArgs);
  expect(s.result(claimArgs)).toEqual(claimed);
  expect(deep(claimed)["dedupInputs"]).toMatchObject([
    { discoveryWorkerId: first, inputOrder: 0 },
    { discoveryWorkerId: second, inputOrder: 1 },
  ]);
  const completed = deep(
    s.result([
      "commit-deep-scan-dedup",
      "--scan-id",
      s.scanId,
      "--worker-id",
      reducer,
      "--result-manifest-path",
      r.manifest,
      "--new-findings-count",
      "0",
      "--coordinator-generation",
      "2",
    ]),
  );
  expect(completed["noNewStreak"]).toBe(2);
  const manifest = join(s.scanDir, "coordinator.json");
  writeFileSync(manifest, "{}");
  const finished = deep(
    s.result([
      "finish-deep-scan",
      "--scan-id",
      s.scanId,
      "--terminal-reason",
      "saturated",
      "--manifest-path",
      manifest,
      "--coordinator-generation",
      "2",
    ]),
  );
  expect(finished).toMatchObject({
    status: "succeeded",
    terminalReason: "saturated",
    manifestPath: manifest,
  });
}
function failAndRecord(s: Setup) {
  s.result([
    "claim-deep-scan-coordinator",
    "--scan-id",
    s.scanId,
    "--thread-id",
    "owner",
  ]);
  const w = worker(s, first);
  s.result([
    "upsert-deep-scan-worker",
    ...w.args,
    "--kind",
    "discovery",
    "--status",
    "running",
  ]);
  const stopped = deep(
    s.result([
      "fail-deep-scan",
      "--scan-id",
      s.scanId,
      "--message",
      "synthetic interruption",
      "--deep-status",
      "interrupted",
      "--coordinator-generation",
      "2",
    ]),
  );
  expect(stopped).toMatchObject({
    status: "interrupted",
    cancelRequested: true,
  });
  expect(stopped["workers"]).toMatchObject([{ id: first, status: "canceled" }]);
  const recorded = deep(
    s.result([
      "record-deep-scan-publication-failure",
      "--scan-id",
      s.scanId,
      "--message",
      "publication unavailable",
      "--coordinator-generation",
      "2",
    ]),
  );
  expect(recorded["error"]).toContain("publication unavailable");
  expect(recorded["error"]).toContain("synthetic interruption");
}
test("typed commands carry two discovery results through reducer claims and saturation", () =>
  reduceAndFinish(setup()));
test("failure and publication commands preserve stopped state and original failure", () =>
  failAndRecord(setup()));
test("deep arguments enforce existing choices, bounds and repeated values", () => {
  const s = setup();
  for (const args of [
    [
      "begin-deep-scan",
      "--thread-id",
      "owner",
      "--target-path",
      s.target,
      "--scan-id",
      s.scanId,
    ],
    [
      "begin-deep-scan",
      "--thread-id",
      "owner",
      "--target-path",
      s.target,
      "--available-parallelism",
      "0",
    ],
    [
      "claim-deep-scan-coordinator",
      "--scan-id",
      s.scanId,
      "--thread-id",
      "owner",
      "--coordinator-generation",
      "bad",
    ],
    [
      "finish-deep-scan",
      "--scan-id",
      s.scanId,
      "--terminal-reason",
      "unknown",
      "--manifest-path",
      "missing",
    ],
  ]) {
    const child = s.run(args);
    expect(child.status, child.stderr).toBe(2);
    expect(child.stdout).toBe("");
  }
  const w = worker(s, first);
  const rejected = s.run([
    "upsert-deep-scan-worker",
    ...w.args,
    "--kind",
    "discovery",
    "--status",
    "running",
    "--attempt",
    "-1",
  ]);
  expect(rejected.status).toBe(2);
  expect(rejected.stderr).toContain("expected a non-negative integer");
  const help = s.run(["claim-deep-scan-dedup", "--help"]);
  expect(help.status).toBe(0);
  expect(help.stdout).toContain("--input-worker-id");
  const unowned = s.run([
    "get-deep-scan",
    "--scan-id",
    s.scanId,
    "--thread-id",
    "other",
  ]);
  expect(unowned.status).toBe(1);
  expect(unowned.stderr).toContain("owning Codex thread");
});
test.skipIf(nodeMajor < 22)(
  "SDK routes all nine deep commands through the native lifecycle",
  () => {
    reduceAndFinish(setup(true));
    failAndRecord(setup(true));
  },
  30000,
);
