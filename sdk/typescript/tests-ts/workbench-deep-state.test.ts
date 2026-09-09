import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
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
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Request, Response } from "./support/workbench-deep-state-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-deep-state-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const scanId = "11111111-1111-4111-8111-111111111111";
const worker = (digit: number) => `${digit}3333333-3333-4333-8333-333333333333`;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-deep-state-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    format: "cjs",
    platform: "node",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as unknown as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
const value = (response: Response, index = 0) =>
  response.outcomes[index]!.result as Record<string, unknown>;
const error = (response: Response, index = 0) =>
  response.outcomes[index]!.error;
const legacyDir = join(directory, "legacy"),
  ledger = join(legacyDir, "ledger");
const legacyRun = {
  status: "succeeded",
  phase: "terminal",
  terminal_reason: "capped",
  manifest_path: "coordinator-manifest.json",
  completed_at: "completed",
};

test("projects ordered workers, dedup inputs, and exact large review counters", () => {
  const [response] = run({
    run: {
      phase: "reducing",
      completion_sequence: 9007199254740993n,
      max_discovery_runs: 9007199254740995n,
    },
    workers: [
      { id: worker(3), status: "running", created_at: "b" },
      { id: worker(2), status: "queued", created_at: "a" },
      { id: worker(1), kind: "dedup", status: "running", created_at: "a" },
      {
        id: worker(4),
        status: "succeeded",
        created_at: "c",
        completion_sequence: 1n,
      },
    ],
    inputs: [
      {
        dedup_worker_id: worker(1),
        discovery_worker_id: worker(3),
        input_order: 1n,
      },
      {
        dedup_worker_id: worker(1),
        discovery_worker_id: worker(2),
        input_order: 0n,
      },
    ],
    actions: [
      { operation: "state" },
      { operation: "progress" },
      { operation: "worker", id: worker(4) },
    ],
  });
  const state = value(response!);
  expect(
    (state["workers"] as Record<string, unknown>[]).map((row) => row["id"]),
  ).toEqual([worker(1), worker(2), worker(3), worker(4)]);
  expect(
    (state["dedupInputs"] as Record<string, unknown>[]).map(
      (row) => row["discoveryWorkerId"],
    ),
  ).toEqual([worker(2), worker(3)]);
  expect(state["completionSequence"]).toBe(9007199254740993n);
  expect(state["canonicalArtifacts"]).toBeNull();
  expect(value(response!, 1)).toEqual({
    active: 2n,
    completed: 9007199254740993n,
    maximum: 9007199254740995n,
    consolidating: true,
    updatedAt: "updated",
  });
  expect(value(response!, 2)["id"]).toBe(worker(4));
  expect(response!.outcomes.every((outcome) => !outcome.inTransaction)).toBe(
    true,
  );
});

test("run creation leaves the caller transaction open and reuses an existing run", () => {
  const [response] = run({
    run: null,
    actions: [
      { operation: "ensure" },
      { operation: "ensure", config: {} as never },
      { operation: "rollback" },
      { operation: "run" },
    ],
  });
  expect(value(response!)["workflow_version"]).toBe("new-workflow");
  expect(response!.outcomes[0]!.inTransaction).toBe(true);
  expect(value(response!, 1)).toEqual(value(response!));
  expect(error(response!, 3)).toBe(
    "Codex Security Deep Scan orchestration state not found.",
  );
  expect(response!.snapshot["deep_scan_runs"]).toEqual([]);
  const [mode, status] = run(
    {
      scan: { mode: "standard", status: "complete" },
      run: null,
      actions: [{ operation: "ensure", config: {} as never }],
    },
    {
      scan: { status: "complete" },
      run: null,
      actions: [{ operation: "ensure", config: {} as never }],
    },
  );
  expect(error(mode!)).toBe(
    "Deep Scan orchestration requires a scan in deep mode.",
  );
  expect(error(status!)).toBe(
    "Only a running Deep Scan can start orchestration.",
  );
});

test("parent completion requires a successful deep run with a persisted manifest", () => {
  const responses = run(
    {
      scan: { mode: "standard" },
      run: null,
      actions: [{ operation: "ready" }],
    },
    { run: null, actions: [{ operation: "ready" }] },
    { run: { status: "succeeded" }, actions: [{ operation: "ready" }] },
    {
      run: { status: "succeeded", manifest_path: "" },
      actions: [{ operation: "ready" }],
    },
  );
  expect(error(responses[0]!)).toBeUndefined();
  expect(error(responses[1]!)).toContain(
    "must finish and persist its manifest",
  );
  expect(error(responses[2]!)).toBe(error(responses[1]!));
  expect(error(responses[3]!)).toBeUndefined();
});

test("ownership falls back to the workspace and validates rows before the owner", () => {
  const responses = run(
    { actions: [{ operation: "owned", threadId: "  owner\u001c" }] },
    {
      scan: { deep_scan_owner_thread_id: "scan-owner" },
      actions: [
        { operation: "owned" },
        { operation: "owned", threadId: "scan-owner" },
      ],
    },
    {
      scan: { workspace_id: "44444444-4444-4444-8444-444444444444" },
      actions: [{ operation: "owned", threadId: "" }],
    },
    { actions: [{ operation: "owned", threadId: "" }] },
  );
  expect(error(responses[0]!)).toBeUndefined();
  expect(error(responses[1]!)).toContain("owning Codex thread");
  expect(error(responses[1]!, 1)).toBeUndefined();
  expect(error(responses[2]!)).toContain("workspace not found");
  expect(error(responses[3]!)).toBe("thread-id is required.");
});

test("guards check canceled orchestration first and keep terminal workers terminal", () => {
  const [response] = run({
    run: { cancel_requested: 1n },
    scan: { status: "complete" },
    actions: [
      { operation: "running" },
      { operation: "transition", current: "queued", requested: "succeeded" },
      { operation: "transition", current: "running", requested: "succeeded" },
      { operation: "transition", current: "failed", requested: "running" },
      { operation: "transition", current: "failed", requested: "failed" },
    ],
  });
  expect(error(response!)).toBe(
    "Only a running Deep Scan can update orchestration state.",
  );
  expect(error(response!, 1)).toBe(
    "Deep Scan worker cannot transition from queued to succeeded.",
  );
  expect(error(response!, 2)).toBeUndefined();
  expect(error(response!, 3)).toContain("failed to running");
  expect(error(response!, 4)).toBeUndefined();
});

test("legacy canonical artifacts retain deadline and empty-ledger checks", () => {
  mkdirSync(join(legacyDir, "artifacts/02_discovery"), { recursive: true });
  writeFileSync(
    join(legacyDir, "artifacts/02_discovery/in_scope_files.txt"),
    "fixture.ts\n",
  );
  writeFileSync(ledger, "candidate\n");
  const [response] = run({
    scan: { scan_dir: legacyDir },
    run: legacyRun,
    actions: [
      {
        operation: "state",
        canonical: { candidateLedgerPath: ledger },
        deadline: false,
      },
      {
        operation: "state",
        canonical: { candidateLedgerPath: ledger },
        deadline: true,
      },
      { operation: "state", canonicalError: true, deadlineError: true },
    ],
  });
  expect(value(response!)["canonicalArtifacts"]).toEqual({
    candidateLedgerPath: ledger,
  });
  expect(error(response!, 1)).toBe(
    "A capped Deep Scan without completed discoveries requires an empty candidate ledger.",
  );
  expect(error(response!, 2)).toBe("canonical failed");
  expect(
    response!.outcomes[2]!.events.some(
      (event) => (event as string[])[0] === "deadline",
    ),
  ).toBe(false);
  writeFileSync(ledger, "");
  const [empty, published] = run(
    {
      scan: { scan_dir: legacyDir },
      run: legacyRun,
      actions: [
        {
          operation: "state",
          canonical: { candidateLedgerPath: ledger },
          deadline: true,
        },
      ],
    },
    {
      scan: { scan_dir: legacyDir },
      run: {
        ...legacyRun,
        manifest_path: join(legacyDir, "scan-manifest.json"),
      },
      actions: [{ operation: "state", canonicalError: true }],
    },
  );
  expect(error(empty!)).toBeUndefined();
  expect(value(published!)["canonicalArtifacts"]).toBeNull();
});

test("worker and dedup cursors remain open across canonical callbacks", () => {
  mkdirSync(join(legacyDir, "artifacts/02_discovery"), { recursive: true });
  writeFileSync(
    join(legacyDir, "artifacts/02_discovery/in_scope_files.txt"),
    "fixture.ts\n",
  );
  const [response] = run({
    scan: { scan_dir: legacyDir },
    run: legacyRun,
    workers: [{ id: worker(1) }],
    actions: [
      { operation: "state", canonicalSql: "DROP TABLE deep_scan_workers" },
      { operation: "worker", id: worker(1) },
    ],
  });
  expect(error(response!)).toBe("database table is locked");
  expect(value(response!, 1)["id"]).toBe(worker(1));
  expect(
    response!.outcomes[0]!.events.slice(0, 5).map(
      (event) => (event as string[])[0],
    ),
  ).toEqual(["query", "query", "query", "query", "canonical"]);
});

test("target reuse binds ownership and completed continuation reuse binds the snapshot", () => {
  const [response] = run({
    run: legacyRun,
    actions: [
      { operation: "existing" },
      { operation: "existing", threadId: "next-owner" },
      { operation: "terminal" },
      { operation: "terminal", digest: "changed" },
      { operation: "terminal", threadId: "owner" },
      {
        operation: "sql",
        sql: "UPDATE scans SET handoff_claim_token = 'active'",
      },
      { operation: "terminal" },
    ],
  });
  expect(value(response!)["id"]).toBe(scanId);
  expect(response!.outcomes[1]!.result).toBeNull();
  expect(value(response!, 2)["id"]).toBe(scanId);
  expect(response!.outcomes[3]!.result).toBeNull();
  expect(response!.outcomes[4]!.result).toBeNull();
  expect(response!.outcomes[6]!.result).toBeNull();
  expect(response!.outcomes[6]!.inTransaction).toBe(true);
});

test("combined errors budget Unicode code points and retain both source digests", () => {
  const publication = "🧭".repeat(4000),
    original = "é".repeat(3000);
  const [response] = run({
    actions: [
      { operation: "error", original, publication },
      { operation: "error", original },
      { operation: "bounded", message: "abcd", maximum: 0 },
      { operation: "bounded", message: "\ud800".repeat(20), maximum: 10 },
    ],
  });
  const combined = response!.outcomes[0]!.result as string;
  expect(Array.from(combined)).toHaveLength(2400);
  for (const message of [publication, original])
    expect(combined).toContain(
      createHash("sha256").update(message).digest("hex"),
    );
  expect(combined).toContain("\nOriginal Deep Scan failure:\n");
  expect(response!.outcomes[1]!.result).toBe(original);
  expect(response!.outcomes[2]!.result).toBe("");
  expect(error(response!, 3)).toContain("surrogates not allowed");
});

test("result disposition is optional and lookup failures keep distinct messages", () => {
  const [response] = run({
    actions: [
      { operation: "result" },
      { operation: "result", disposition: "" },
      { operation: "run", id: "invalid" },
      { operation: "worker" },
    ],
  });
  expect(Object.keys(value(response!))).toEqual(["deepScan"]);
  expect(value(response!, 1)["startDisposition"]).toBe("");
  expect(error(response!, 2)).toBe("scan-id must be a UUID.");
  expect(error(response!, 3)).toBe(
    "Codex Security Deep Scan worker not found.",
  );
});

test("Windows stat reads size through its owned handle and closes it on errors", () => {
  const [response] = run({
    actions: [
      { operation: "windowsSize", message: "é🧭" },
      { operation: "windowsSize", windowsError: 5 },
      { operation: "windowsSize", windowsDirectory: true, windowsError: 5 },
      { operation: "windowsSize", windowsType: 2, windowsError: 5 },
    ],
  });
  expect(value(response!)).toEqual({ size: 6n, file: true });
  expect(response!.outcomes[0]!.events).toEqual([
    { operation: "open", path: "C:\\work\\ledger" },
    { operation: "close", path: "C:\\work\\ledger" },
    ["closed", true],
  ]);
  expect(response!.outcomes[1]!.events.at(-1)).toEqual(["closed", true]);
  expect(error(response!, 1)).toContain("Windows filesystem error 5");
  for (const index of [2, 3]) {
    expect(value(response!, index)).toEqual({ size: 0n, file: false });
    expect(response!.outcomes[index]!.events.at(-1)).toEqual(["closed", true]);
  }
});

test("other running deep scans exclude the current scan and retain recency ordering", () => {
  const [response] = run({
    setupSql: [1, 2, 3, 4].map(
      (index) => `
      INSERT INTO workspaces (id, created_at, updated_at) VALUES ('${worker(index)}', 'created', 'updated');
      INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at)
      SELECT '${worker(index)}', '${worker(index)}', '/target-${index}', target_revision, scope, '${index === 4 ? "standard" : "deep"}', '/scan-${index}', 'running', phase, '${index}', created_at, '${index === 1 ? "z" : "a"}' FROM scans WHERE id = '${scanId}'
    `,
    ),
    actions: [{ operation: "others" }, { operation: "others", id: worker(1) }],
  });
  const others = response!.outcomes[0]!.result as Record<string, unknown>[];
  expect(others.map((row) => row["scanId"])).toEqual([
    worker(1),
    worker(3),
    worker(2),
  ]);
  expect(Object.keys(others[0]!)).toEqual([
    "phase",
    "scanId",
    "startedAt",
    "targetPath",
    "updatedAt",
  ]);
  const alternative = response!.outcomes[1]!.result as Record<
    string,
    unknown
  >[];
  expect(alternative.map((row) => row["scanId"])).toEqual([
    scanId,
    worker(3),
    worker(2),
  ]);
});
