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
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-scan-completion-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

type Table = Record<string, unknown>;
const scanId = "11111111-1111-4111-8111-111111111111";
const root = realpathSync(mkdtempSync(join(tmpdir(), "scan-budget-"))),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const cost = (estimatedUsd = 0.25) =>
  stringifyJson({
    model: "fixture",
    inputTokens: 10,
    cachedInputTokens: 2,
    cacheWriteInputTokens: 1,
    outputTokens: 3,
    estimatedUsd,
  });
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL(
          "./support/workbench-scan-completion-fixture.ts",
          import.meta.url,
        ),
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
function setup(
  actions: Action[] = [{ operation: "completeBudget", costJson: cost() }],
): { request: Request; directory: string; ledger: string } {
  const directory = mkdtempSync(join(root, "case-")),
    scanDir = join(directory, "scan"),
    discovery = join(scanDir, "artifacts/02_discovery");
  mkdirSync(scanDir, { mode: 0o700 });
  mkdirSync(discovery, { recursive: true });
  const ledger = join(discovery, "candidate_ledger.jsonl");
  writeFileSync(join(discovery, "in_scope_files.txt"), "src/file.ts\n");
  writeFileSync(
    ledger,
    stringifyJson(
      {
        candidate_id: "candidate-1",
        summary: "Unvalidated source flow",
        evidence: "Input reaches a statement",
        locations: [{ path: "src/file.ts" }, { path: "support/control.ts" }],
      },
      { compact: true },
    ) + "\n",
  );
  return {
    directory: scanDir,
    ledger,
    request: {
      environment: {
        CODEX_SECURITY_STATE_DIR: join(directory, "state"),
        CODEX_HOME: join(directory, "codex"),
        CODEX_SQLITE_HOME: join(directory, "sqlite"),
        CODEX_STATE_DB: join(directory, "missing.sqlite"),
      },
      scan: {
        scan_dir: scanDir,
        target_path: "/target",
        target_id: "target-id",
        target_revision: "revision",
        target_snapshot_digest: `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`,
        mode: "deep",
        recipe_json: stringifyJson({
          mode: "deep",
          maxCostUsd: 0.1,
          target: { kind: "repository" },
          extra: { retained: true },
        }),
      },
      records: {
        deep_scan_runs: [
          {
            scan_id: scanId,
            schema_version: 1,
            workflow_version: "deep-security-scan/v1",
            phase: "terminal",
            workers: 4,
            subagents: 1,
            stop_after_no_new: 3,
            max_discovery_runs: 40,
            status: "succeeded",
            terminal_reason: "saturated",
            manifest_path: join(discovery, "scan-manifest.json"),
            created_at: "created",
            updated_at: "updated",
          },
        ],
      },
      actions,
    },
  };
}
function run(request: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return (parseJson(child.stdout) as unknown as Response[])[0]!;
}
const scan = (response: Response) => response.snapshot["scans"]![0]!;
const success = (response: Response, index = 0) =>
  expect(response.outcomes[index]!.error).toBeUndefined();
const document = (directory: string, name: string) =>
  parseJson(readFileSync(join(directory, name), "utf8")) as Table;

test("budget completion seals partial discovery, retains evidence and records measured cost", () => {
  const input = setup(),
    original = readFileSync(input.ledger),
    response = run(input.request);
  success(response);
  expect(scan(response)["status"]).toBe("complete");
  expect(parseJson(scan(response)["cost_json"] as string)).toEqual(
    parseJson(cost()),
  );
  expect(readFileSync(input.ledger)).toEqual(original);
  const coverage = document(input.directory, "coverage.json");
  expect(coverage).toMatchObject({
    mode: "deep_repository",
    completeness: "partial",
  });
  expect((coverage["deferred"] as Table[])[0]).toMatchObject({
    id: "candidate-1",
    paths: ["src/file.ts", "support/control.ts"],
  });
  expect((coverage["surfaces"] as Table[])[0]!["disposition"]).toBe(
    "needs_follow_up",
  );
  expect(scan(response)["seal_manifest_digest"]).toMatch(
    /^sha256:[0-9a-f]{64}$/u,
  );
  expect(response.snapshot["scan_artifacts"]!.length).toBe(4);
  expect(readFileSync(join(input.directory, "report.md"), "utf8")).toContain(
    "No findings were validated before the scan reached its cost limit",
  );
});

test("a raised limit retains recipe fields and commits only after a valid increase", () => {
  const input = setup([
      { operation: "setLimit", maxCostUsd: 0.15 },
      { operation: "setLimit", maxCostUsd: 0.2 },
      { operation: "setLimit", maxCostUsd: 0.19 },
      { operation: "completeBudget", costJson: cost() },
      { operation: "setLimit", maxCostUsd: 0.3 },
    ]),
    response = run(input.request);
  success(response, 0);
  success(response, 1);
  success(response, 3);
  expect(response.outcomes[2]!.error).toBe(
    "The new cost limit must exceed the current limit.",
  );
  expect(response.outcomes[4]!.error).toBe(
    "Only a running CLI scan can increase its cost limit.",
  );
  expect(JSON.parse(scan(response)["recipe_json"] as string)).toMatchObject({
    maxCostUsd: 0.2,
    extra: { retained: true },
  });
  expect(scan(response)["updated_at"]).toBe("2026-01-02T00:00:00Z");
});

test("budget completion requires an exceeded limit and successfully completed Deep discovery", () => {
  for (const change of [
    "standard",
    "missing-cost",
    "equal-limit",
    "running-discovery",
    "missing-manifest",
  ] as const) {
    const input = setup();
    if (change === "standard") input.request.scan!["mode"] = "standard";
    if (change === "missing-cost") input.request.actions[0]!.costJson = null;
    if (change === "equal-limit")
      input.request.actions[0]!.costJson = cost(0.1);
    if (change === "running-discovery")
      input.request.records!["deep_scan_runs"]![0]!["status"] = "running";
    if (change === "missing-manifest")
      input.request.records!["deep_scan_runs"]![0]!["manifest_path"] = null;
    const response = run(input.request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(scan(response)["status"]).toBe("running");
    expect(response.snapshot["scan_artifacts"]).toEqual([]);
  }
});

test("cost-limit validation and failed updates leave the old recipe and transaction intact", () => {
  const input = setup([
      { operation: "setLimit", maxCostUsd: 0 },
      { operation: "setLimit", maxCostUsd: -1 },
      { operation: "setLimit", maxCostUsd: Infinity },
      { operation: "setLimit", maxCostUsd: NaN },
      { operation: "setLimit", maxCostUsd: 0.1 },
      { operation: "setLimit", maxCostUsd: 0.2, failNow: 1 },
    ]),
    response = run(input.request);
  for (const outcome of response.outcomes) {
    expect(outcome.error).toBeDefined();
    expect(outcome.inTransaction).toBe(false);
  }
  expect(scan(response)["recipe_json"]).toBe(
    input.request.scan!["recipe_json"],
  );
  expect(scan(response)["updated_at"]).toBe("scan-updated");
});

test("budget warnings preserve six-digit rounding and exponent formatting", () => {
  for (const [value, expected] of [
    [123456.5, "123456"],
    [123457.5, "123458"],
    [0.00001234565, "1.23456e-05"],
    [999999.5, "1e+06"],
    [1.23456789, "1.23457"],
  ] as const) {
    const input = setup([
      { operation: "completeBudget", costJson: cost(value) },
    ]);
    input.request.scan!["recipe_json"] =
      '{"mode":"deep","maxCostUsd":0,"target":{"kind":"repository"}}';
    const response = run(input.request);
    success(response);
    expect(
      parseJson(scan(response)["completion_warnings_json"] as string),
    ).toContain(
      `Deep Scan reached its cost limit after an estimated $${expected}; completed discovery was preserved.`,
    );
  }
});

test("the selected completion manifest bypasses canonical discovery reads", () => {
  const input = setup();
  input.request.records!["deep_scan_runs"]![0]!["manifest_path"] = join(
    input.directory,
    "scan-manifest.json",
  );
  rmSync(join(input.directory, "artifacts"), { recursive: true });
  const response = run(input.request);
  success(response);
  expect(document(input.directory, "coverage.json")["deferred"]).toEqual([
    {
      id: "scan-cost-limit",
      reason:
        "Validation was deferred because the scan reached its cost limit.",
    },
  ]);
});

test("committed budget warnings survive a later continuation rejection with partial drafts", () => {
  const input = setup();
  input.request.scan!["handoff_status"] = "pending";
  input.request.scan!["handoff_claim_token"] = "another-owner";
  input.request.actions[0]!.message = "  Discovery preserved  ";
  const response = run(input.request);
  expect(response.outcomes[0]!.error).toBe(
    "Scan completion is owned by another continuation.",
  );
  expect(response.outcomes[0]!.inTransaction).toBe(false);
  expect(scan(response)["status"]).toBe("running");
  expect(
    parseJson(scan(response)["completion_warnings_json"] as string),
  ).toEqual(["Discovery preserved"]);
  expect(document(input.directory, "coverage.json")["completeness"]).toBe(
    "partial",
  );
  expect(response.snapshot["scan_artifacts"]).toEqual([]);
});

test("whole-dollar cost limits retain CLI float parsing and storage", () => {
  const input = setup([{ operation: "setLimit", maxCostUsd: 1 }]),
    response = run(input.request);
  success(response);
  expect(
    JSON.parse(scan(response)["recipe_json"] as string)["maxCostUsd"],
  ).toBe(1);
  expect(scan(response)["recipe_json"]).toContain('"maxCostUsd": 1.0');
});
