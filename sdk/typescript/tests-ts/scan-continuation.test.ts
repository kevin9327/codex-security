import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { scanPreflightCodexConfig } from "../src/api.js";
import { main } from "../src/cli.js";
import { DEFAULT_CODEX_CONFIG } from "../src/config.js";
import { ScanCostTracker } from "../src/cost.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);
const previousCost = {
  model: "gpt-5.6-sol",
  inputTokens: 1000,
  cachedInputTokens: 0,
  cacheWriteInputTokens: 0,
  outputTokens: 50,
  estimatedUsd: 12.5,
};

async function savedScan(
  options: {
    mode?: "standard" | "deep";
    running?: boolean;
    cost?: boolean;
    maxCostUsd?: number;
    custom?: boolean;
  } = {},
) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const codexHome = join(root, "state", "codex-home");
  await mkdir(repository);
  await mkdir(scanDir, { mode: 0o700 });
  await mkdir(join(codexHome, "sessions"), { recursive: true });
  await writeFile(
    join(repository, "reviewed.ts"),
    "export const reviewed = true;\n",
  );
  await writeFile(
    join(repository, "pending.ts"),
    "export const pending = true;\n",
  );
  const python = Bun.which("python3") ?? Bun.which("python");
  if (python === null) throw new Error("Python is required.");
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: codexHome,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const command = (args: readonly string[], input?: string) =>
    runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args, input);
  const recipe = {
    repository,
    target: { kind: "repository", paths: [] },
    mode: options.mode ?? "standard",
    config: {
      ...scanPreflightCodexConfig({
        ...DEFAULT_CODEX_CONFIG,
        approval_policy: "never",
      }),
      approval_policy: "never",
    },
    pluginVersion: "0.1.0",
    ...(options.maxCostUsd === undefined
      ? {}
      : { maxCostUsd: options.maxCostUsd }),
    ...(options.custom ? { validationMode: "custom" } : {}),
  };
  const registration = await command(
    [
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--registration-json-stdin",
    ],
    JSON.stringify({
      recipe,
      userContext: "Preserve the original review instructions.",
    }),
  );
  const scanId = registration["scanId"] as string;
  const threadId = randomUUID();
  await command([
    "set-scan-thread",
    "--scan-id",
    scanId,
    "--thread-id",
    threadId,
  ]);
  const sessionPath = join(codexHome, "sessions", `rollout-${threadId}.jsonl`);
  await writeFile(
    sessionPath,
    JSON.stringify({
      type: "session_meta",
      payload: { id: threadId, cwd: scanDir },
    }) + "\n",
  );
  const finding = JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "examples", "completed-scan", "findings.json"),
      "utf8",
    ),
  ).findings[0];
  finding.locations = [{ path: "reviewed.ts", startLine: 1 }];
  const snapshot = {
    scanId,
    complete: false,
    findings: [finding],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      reviewedFiles: ["reviewed.ts"],
    },
  };
  async function checkpoint(directory: string, id: string, value: object) {
    const contents = JSON.stringify(value) + "\n";
    const path = join(
      directory,
      "checkpoints",
      `${createHash("sha256").update(contents).digest("hex")}.json`,
    );
    await mkdir(join(directory, "checkpoints"), { recursive: true });
    await writeFile(path, contents);
    await command([
      "record-scan-checkpoint",
      "--scan-id",
      id,
      "--checkpoint-path",
      path,
    ]);
  }
  await checkpoint(scanDir, scanId, snapshot);
  if (!options.running)
    await command([
      "fail-scan",
      "--scan-id",
      scanId,
      "--message",
      "Synthetic interrupted scan",
      ...(options.cost === false
        ? []
        : ["--cost-json", JSON.stringify(previousCost)]),
    ]);
  return {
    root,
    repository,
    scanDir,
    codexHome,
    python,
    environment,
    command,
    recipe,
    scanId,
    threadId,
    sessionPath,
    checkpoint,
  };
}

type Fixture = Awaited<ReturnType<typeof savedScan>>;
async function resume(
  f: Fixture,
  createCodex: NonNullable<
    ConstructorParameters<typeof TestClient>[1]["createCodex"]
  >,
  options: {
    failExport?: boolean;
    beforeWorkbench?: (args: readonly string[]) => Promise<void>;
  } = {},
) {
  await mkdir(f.codexHome, { recursive: true });
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: (config) =>
        new TestClient(config, {
          environment: f.environment,
          prepareRuntime: async () => {
            const runtime = preparedRuntime(f.codexHome);
            runtime.plugin.version = JSON.parse(
              await readFile(
                join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
                "utf8",
              ),
            ).version;
            return runtime;
          },
          resolvePluginPython: async () => f.python,
          runWorkbench: async (workbenchOptions, args, input) => {
            await options.beforeWorkbench?.(args);
            if (options.failExport && args[0] === "prepare-scan-completion")
              throw new Error("Synthetic local export failure");
            return runWorkbench(workbenchOptions, args, input);
          },
          createCodex,
        }),
    },
  );
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

async function finishChild(f: Fixture, scanDir: string, scanId: string) {
  const manifest = JSON.parse(
    await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
  );
  const findings = JSON.parse(
    await readFile(join(scanDir, "findings.json"), "utf8"),
  );
  const coverage = JSON.parse(
    await readFile(join(scanDir, "coverage.json"), "utf8"),
  );
  manifest.scan.complete = true;
  coverage.completeness = "complete";
  coverage.deferred = [];
  coverage.reviewedFiles = ["pending.ts", "reviewed.ts"];
  await f.checkpoint(scanDir, scanId, {
    scanId,
    complete: true,
    findings: findings.findings,
    coverage,
  });
  await writeFile(
    join(scanDir, "scan-manifest.json"),
    JSON.stringify(manifest) + "\n",
  );
  await writeFile(
    join(scanDir, "coverage.json"),
    JSON.stringify(coverage) + "\n",
  );
}

test("Standard continuation preserves the sealed parent and resumes only unfinished source with cumulative cost", async () => {
  const f = await savedScan();
  const parent = await readFile(join(f.scanDir, "scan-manifest.json"), "utf8");
  let childId = "";
  let childDirectory = "";
  let modelCalls = 0;
  const outcome = await resume(f, (options) => ({
    startThread(threadOptions) {
      childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
      childDirectory = threadOptions.workingDirectory!;
      expect(childId).not.toBe(f.scanId);
      expect(childDirectory).not.toBe(f.scanDir);
      const threadId = randomUUID();
      return {
        id: threadId,
        async runStreamed(prompt) {
          modelCalls++;
          expect(prompt).toContain(
            "Preserve the original review instructions.",
          );
          expect(prompt).toContain("Review only remainingFiles");
          expect(
            JSON.parse(
              await readFile(
                join(
                  childDirectory,
                  "artifacts",
                  "01_context",
                  "scan-continuation.json",
                ),
                "utf8",
              ),
            ),
          ).toEqual({
            parentScanId: f.scanId,
            reviewedFiles: ["reviewed.ts"],
            remainingFiles: ["pending.ts"],
          });
          const inherited = JSON.parse(
            await readFile(join(childDirectory, "findings.json"), "utf8"),
          );
          expect(inherited.findings).toHaveLength(1);
          await finishChild(f, childDirectory, childId);
          return { events: completedEvents(threadId) };
        },
      };
    },
    resumeThread() {
      throw new Error("A sealed parent cannot be reopened");
    },
  }));
  expect(outcome.code, outcome.stderr).toBe(0);
  expect(modelCalls).toBe(1);
  expect(await readFile(join(f.scanDir, "scan-manifest.json"), "utf8")).toBe(
    parent,
  );
  const result = JSON.parse(outcome.stdout);
  expect(result.findings.findings).toHaveLength(1);
  expect(result.cost.estimatedUsd).toBeGreaterThan(12.5);
  expect(result.cost.inputTokens).toBe(1010);
  expect(
    (await f.command(["get-scan", "--scan-id", childId]))["scan"],
  ).toMatchObject({
    parentScanId: f.scanId,
    progress: { status: "complete" },
    cost: result.cost,
    checkpoint: { remainingFileCount: 0 },
  });
  await expect(
    f.command(["get-cli-scan-resume", "--scan-id", childId]),
  ).rejects.toThrow("already completed");
});

test("missing Deep native history falls back to a new attempt from semantic checkpoints", async () => {
  const f = await savedScan({ mode: "deep", running: true });
  await rm(f.sessionPath);
  let childId = "";
  const outcome = await resume(f, (options) => ({
    startThread() {
      childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
      expect(childId).not.toBe(f.scanId);
      return {
        id: randomUUID(),
        async runStreamed() {
          throw new Error("Synthetic connection failure");
        },
      };
    },
    resumeThread() {
      throw new Error("Unavailable native history must not be resumed");
    },
  }));
  expect(outcome.code).not.toBe(0);
  expect(outcome.stderr).toContain("Synthetic connection failure");
  expect(
    (await f.command(["get-scan", "--scan-id", childId]))["scan"],
  ).toMatchObject({
    parentScanId: f.scanId,
    checkpoint: { reviewedFileCount: 1 },
  });
});

test.each([
  "changed source",
  "missing cost",
  "exhausted cost",
  "custom validation",
])("continuation refuses %s before invoking a model", async (scenario) => {
  const f = await savedScan({
    maxCostUsd:
      scenario === "missing cost"
        ? 20
        : scenario === "exhausted cost"
          ? 10
          : undefined,
    cost: scenario !== "missing cost",
    custom: scenario === "custom validation",
  });
  if (scenario === "changed source")
    await writeFile(join(f.repository, "pending.ts"), "changed\n");
  if (scenario === "missing cost") await rm(f.sessionPath);
  let calls = 0;
  const outcome = await resume(f, () => {
    calls++;
    throw new Error("Unexpected model invocation");
  });
  expect(outcome.code).not.toBe(0);
  expect(calls).toBe(0);
  expect(outcome.stderr).toContain(
    scenario === "changed source"
      ? "contents changed"
      : scenario === "missing cost"
        ? "cost is unavailable"
        : scenario === "exhausted cost"
          ? "saved total cost limit"
          : "--validation-prompt-file",
  );
});

test.each([false, true])(
  "historical cost read failures allow continuation only when no saved cap needs it: cap=%j",
  async (capped) => {
    const f = await savedScan({
      cost: false,
      ...(capped ? { maxCostUsd: 100 } : {}),
    });
    const tracker = spyOn(
      ScanCostTracker.prototype,
      "stop",
    ).mockRejectedValueOnce(new Error("Synthetic unreadable sibling rollout"));
    let modelCalls = 0;
    try {
      const outcome = await resume(f, (options) => ({
        startThread(threadOptions) {
          const threadId = randomUUID();
          return {
            id: threadId,
            async runStreamed() {
              modelCalls++;
              await finishChild(
                f,
                threadOptions.workingDirectory!,
                options.env!["CODEX_SECURITY_SCAN_ID"]!,
              );
              return { events: completedEvents(threadId) };
            },
          };
        },
        resumeThread() {
          throw new Error("A sealed parent requires a linked attempt");
        },
      }));
      expect(outcome.stderr).toContain("Previous scan cost is unavailable");
      expect(outcome.stderr).toContain("Synthetic unreadable sibling rollout");
      expect(outcome.code, outcome.stderr).toBe(capped ? 2 : 0);
      expect(modelCalls).toBe(capped ? 0 : 1);
      if (capped) expect(outcome.stderr).toContain("limit cannot be enforced");
      else expect(JSON.parse(outcome.stdout).findings.findings).toHaveLength(1);
    } finally {
      tracker.mockRestore();
    }
  },
);

test.each([false, true])(
  "unavailable native history permits uncapped checkpoint recovery: capped=%j",
  async (capped) => {
    const f = await savedScan({
      cost: false,
      ...(capped ? { maxCostUsd: 100 } : {}),
    });
    await rm(join(f.codexHome, "sessions"), { recursive: true });
    await writeFile(
      join(f.codexHome, "sessions"),
      "Unavailable native history\n",
    );
    let modelCalls = 0;
    const outcome = await resume(f, (options) => ({
      startThread(threadOptions) {
        const threadId = randomUUID();
        return {
          id: threadId,
          async runStreamed() {
            modelCalls++;
            await finishChild(
              f,
              threadOptions.workingDirectory!,
              options.env!["CODEX_SECURITY_SCAN_ID"]!,
            );
            return { events: completedEvents(threadId) };
          },
        };
      },
    }));
    expect(outcome.code, outcome.stderr).toBe(capped ? 2 : 0);
    expect(modelCalls).toBe(capped ? 0 : 1);
    expect(outcome.stderr).toContain(
      "Previous scan session logs are unavailable",
    );
    if (capped) expect(outcome.stderr).toContain("limit cannot be enforced");
    else expect(JSON.parse(outcome.stdout).findings.findings).toHaveLength(1);
  },
);

test.each([true, false])(
  "a hard-killed continuation requires bound native spend to enforce its saved cap: persistedThread=%j",
  async (persistedThread) => {
    const f = await savedScan({ maxCostUsd: 20 });
    const child = join(f.root, "interrupted-child");
    await mkdir(child, { mode: 0o700 });
    const registration = await f.command([
      "register-cli-scan",
      "--repository",
      f.repository,
      "--scan-dir",
      child,
      "--parent-scan-id",
      f.scanId,
      "--recipe-json",
      JSON.stringify(f.recipe),
    ]);
    const childId = registration["scanId"] as string;
    await f.command([
      "continue-scan-checkpoint",
      "--scan-id",
      childId,
      "--parent-scan-id",
      f.scanId,
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    const threadId = randomUUID();
    if (persistedThread)
      await f.command([
        "set-scan-thread",
        "--scan-id",
        childId,
        "--thread-id",
        threadId,
      ]);
    const sessionPath = join(
      f.codexHome,
      "sessions",
      `rollout-${threadId}.jsonl`,
    );
    await writeFile(
      sessionPath,
      JSON.stringify({
        type: "session_meta",
        payload: { id: threadId, cwd: child },
      }) + "\n",
    );
    await appendFile(
      sessionPath,
      JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: { input_tokens: 10000, output_tokens: 2000 },
          },
        },
      }) + "\n",
    );
    let latestId = "";
    let modelCalls = 0;
    const outcome = await resume({ ...f, scanId: childId }, (options) => ({
      startThread(threadOptions) {
        latestId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const newThread = randomUUID();
        return {
          id: newThread,
          async runStreamed() {
            modelCalls++;
            await finishChild(f, threadOptions.workingDirectory!, latestId);
            return { events: completedEvents(newThread) };
          },
        };
      },
    }));
    if (!persistedThread) {
      expect(outcome.code, outcome.stderr).toBe(2);
      expect(modelCalls).toBe(0);
      expect(outcome.stderr).toContain("cost is unavailable");
      expect(outcome.stderr).toContain("limit cannot be enforced");
      return;
    }
    expect(outcome.code, outcome.stderr).toBe(0);
    expect(modelCalls).toBe(1);
    const result = JSON.parse(outcome.stdout);
    expect(result.cost.estimatedUsd).toBeGreaterThan(12.5);
    expect(result.cost.inputTokens).toBe(11010);
    expect(result.cost.outputTokens).toBe(2053);
  },
);

async function saveCompleteCheckpoint(f: Fixture, missingReceipt = false) {
  const current = (
    await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
  )["checkpoint"] as {
    sources: Array<{ findings: object[]; coverage: object }>;
  };
  await f.checkpoint(f.scanDir, f.scanId, {
    scanId: f.scanId,
    complete: true,
    findings: current.sources[0]!.findings,
    coverage: {
      ...current.sources[0]!.coverage,
      completeness: "complete",
      deferred: [],
      reviewedFiles: ["pending.ts", "reviewed.ts"],
      ...(missingReceipt
        ? {
            surfaces: [
              {
                id: "missing-receipt",
                candidateId: "candidate-1",
                label: "Interrupted receipt write",
                disposition: "rejected",
                receiptRefs: ["artifacts/review/never-written.json"],
              },
            ],
          }
        : {}),
    },
  });
}

test.each(["available", "exhausted", "unknown"] as const)(
  "receipt recovery continues in one command only when the saved budget permits (%s)",
  async (budget) => {
    const f = await savedScan({
      running: true,
      maxCostUsd: budget === "exhausted" ? 10 : 100,
    });
    await saveCompleteCheckpoint(f, true);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic interruption before receipt write",
      ...(budget === "unknown"
        ? []
        : ["--cost-json", JSON.stringify(previousCost)]),
    ]);
    if (budget === "unknown") await rm(f.sessionPath);
    let modelCalls = 0;
    const outcome = await resume(f, (options) => ({
      startThread(threadOptions) {
        modelCalls++;
        const scanDir = threadOptions.workingDirectory!;
        const scanId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const threadId = randomUUID();
        return {
          id: threadId,
          async runStreamed() {
            const coverage = JSON.parse(
              await readFile(join(scanDir, "coverage.json"), "utf8"),
            );
            expect(coverage.completeness).toBe("partial");
            expect(coverage.surfaces[0].disposition).toBe("needs_follow_up");
            const receipt = "artifacts/review/never-written.json";
            await mkdir(join(scanDir, "artifacts", "review"), {
              recursive: true,
            });
            await writeFile(
              join(scanDir, receipt),
              "Completed validation evidence\n",
            );
            coverage.surfaces[0].disposition = "rejected";
            coverage.surfaces[0].receiptRefs = [receipt];
            await writeFile(
              join(scanDir, "coverage.json"),
              JSON.stringify(coverage),
            );
            await finishChild(f, scanDir, scanId);
            return { events: completedEvents(threadId) };
          },
        };
      },
      resumeThread() {
        throw new Error("A stopped parent uses a linked attempt");
      },
    }));
    if (budget === "available") {
      expect(outcome.code, outcome.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      expect(JSON.parse(outcome.stdout).cost.estimatedUsd).toBeGreaterThan(
        12.5,
      );
    } else {
      expect(outcome.code).not.toBe(0);
      expect(modelCalls).toBe(0);
      expect(outcome.stderr).toContain(
        budget === "unknown"
          ? "saved total cost limit cannot be enforced"
          : "reached its saved total cost limit",
      );
    }
  },
);

test("a complete Standard checkpoint retries final export without another model call or cost", async () => {
  const f = await savedScan({ running: true, maxCostUsd: 10 });
  await saveCompleteCheckpoint(f);
  await f.command([
    "fail-scan",
    "--scan-id",
    f.scanId,
    "--message",
    "Synthetic export failure after completed analysis",
    "--cost-json",
    JSON.stringify(previousCost),
  ]);
  // Native logs are unnecessary when analysis and spend are already durable.
  await rm(join(f.codexHome, "sessions"), { recursive: true });
  await writeFile(
    join(f.codexHome, "sessions"),
    "Unavailable native history\n",
  );
  const parent = await readFile(join(f.scanDir, "scan-manifest.json"), "utf8");
  let modelCalls = 0;
  const noModel = () => {
    modelCalls++;
    throw new Error("No Codex client is needed to finish saved results");
  };
  const failedExport = await resume(f, noModel, { failExport: true });
  expect(failedExport.code).not.toBe(0);
  expect(failedExport.stderr).toContain("Synthetic local export failure");
  const scans = (await f.command(["list-scans", "--repository", f.repository]))[
    "scans"
  ] as Array<{ scanId: string; parentScanId: string }>;
  const failedChild = scans.find((scan) => scan.parentScanId === f.scanId)!;
  const outcome = await resume({ ...f, scanId: failedChild.scanId }, noModel);
  expect(outcome.code, outcome.stderr).toBe(0);
  expect(modelCalls).toBe(0);
  expect(outcome.stderr).toContain("without another model call");
  expect(await readFile(join(f.scanDir, "scan-manifest.json"), "utf8")).toBe(
    parent,
  );
  const result = JSON.parse(outcome.stdout);
  expect(result.cost).toEqual(previousCost);
  expect(result.threadId).toBe(f.threadId);
  expect(result.coverage.completeness).toBe("complete");
  expect(result.findings.findings).toHaveLength(1);
});

test.each(["prepare-scan-completion", "complete-scan"])(
  "checkpoint-only resume reports source changes before %s",
  async (command) => {
    const f = await savedScan({ running: true });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic interruption after completed source review",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    let modelCalls = 0;
    const outcome = await resume(
      f,
      () => {
        modelCalls++;
        throw new Error("Saved source work needs no model call");
      },
      {
        beforeWorkbench: async (args) => {
          if (args[0] === command)
            await writeFile(
              join(f.repository, "pending.ts"),
              "export const pending = false;\n",
            );
        },
      },
    );
    expect(outcome.code, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain("Scan target changed during execution");
    expect(modelCalls).toBe(0);
    const result = JSON.parse(outcome.stdout);
    expect(result.cost).toEqual(previousCost);
    expect(result.findings.findings).toHaveLength(1);
    expect(result.coverage.completeness).toBe("complete");
  },
);
