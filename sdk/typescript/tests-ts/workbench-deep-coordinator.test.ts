import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Request, Response } from "./support/deep-coordinator-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "deep-coordinator-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const first = "33333333-3333-4333-8333-333333333333",
  second = "44444444-4444-4444-8444-444444444444",
  reducer = "55555555-5555-4555-8555-555555555555";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/deep-coordinator-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(request: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    env: { ...process.env, PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return (JSON.parse(child.stdout) as Response[])[0]!;
}
function setup(): Request {
  const root = realpathSync(mkdtempSync(join(directory, "case Σ "))),
    scan = join(root, "scan");
  mkdirSync(scan);
  return {
    environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
    scan: { scan_dir: scan, target_path: join(root, "target") },
    actions: [],
  };
}
function write(path: string, text: string) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  return path;
}
function heartbeat(request: Request, text: string) {
  return write(
    join(
      request.scan!["scan_dir"] as string,
      "artifacts",
      "deep_discovery",
      "coordinator-heartbeat-2.json",
    ),
    text,
  );
}
const storedRun = (response: Response) =>
  response.snapshot["deep_scan_runs"]![0]!;
const worker = (response: Response, id: string) =>
  response.snapshot["deep_scan_workers"]!.find((row) => row["id"] === id)!;

test("a first coordinator claims generation two and an explicit renewal keeps that generation", () => {
  const request = setup();
  request.actions = [
    { operation: "claim" },
    { operation: "claim", args: { coordinatorGeneration: 2n } },
    { operation: "claim" },
  ];
  const response = run(request);
  expect(
    response.outcomes.map(
      (value) =>
        (value.result as { coordinatorDisposition: string })
          .coordinatorDisposition,
    ),
  ).toEqual(["claimed", "claimed", "observing"]);
  expect(storedRun(response)["coordinator_generation"]).toBe(2);
  expect(response.outcomes.every((value) => !value.inTransaction)).toBe(true);
});

test("legacy leases require an active worker and expire at the grace boundary", () => {
  for (const [updated, status, expected] of [
    ["2026-01-01T23:58:00Z", "running", false],
    ["2026-01-01T23:58:00.000001Z", "queued", true],
    ["invalid", "succeeded", false],
  ] as const) {
    const request = setup();
    request.run = { updated_at: updated };
    request.workers = [{ status }];
    request.actions = [{ operation: "lease" }];
    expect(run(request).outcomes[0]!.result).toBe(expected);
  }
});

test("matching heartbeat timestamps extend the lease while malformed and stale generations are ignored", () => {
  for (const [data, expected] of [
    [
      '{"coordinatorGeneration":2,"updatedAt":"2026-01-01T23:59:30.000001Z"}',
      true,
    ],
    ['{"coordinatorGeneration":2.0,"updatedAt":"2026-01-01T23:59:30Z"}', false],
    ['{"coordinatorGeneration":1,"updatedAt":"2026-01-02T00:00:00Z"}', false],
    ['{"coordinatorGeneration":2,"updatedAt":"2026-01-02T00:00:00"}', false],
    ['{"coordinatorGeneration":2}', false],
    ["not JSON", false],
  ] as const) {
    const request = setup();
    request.run = {
      coordinator_generation: 2n,
      updated_at: "2026-01-01T23:59:00Z",
    };
    heartbeat(request, data);
    request.actions = [{ operation: "lease" }];
    expect(run(request).outcomes[0]!.result).toBe(expected);
  }
});

test("adoption returns interrupted discovery work and reducer inputs to their persisted retry states", () => {
  const request = setup();
  request.run = {
    coordinator_generation: 2n,
    phase: "reducing",
    updated_at: "2026-01-01T00:00:00Z",
    discovery_runs_dispatched: 5n,
  };
  request.workers = [
    { id: first, status: "running" },
    { id: second, status: "succeeded", merge_state: "merging" },
    {
      id: reducer,
      kind: "dedup",
      status: "failed",
      error_message: "retained failure",
    },
  ];
  request.inputs = [
    { dedup_worker_id: reducer, discovery_worker_id: second, input_order: 0n },
  ];
  request.actions = [{ operation: "locked" }];
  const response = run(request);
  expect(
    (response.outcomes[0]!.result as { coordinatorDisposition: string })
      .coordinatorDisposition,
  ).toBe("adopted");
  expect(storedRun(response)["coordinator_generation"]).toBe(3);
  expect(storedRun(response)["discovery_runs_dispatched"]).toBe(4);
  expect(storedRun(response)["phase"]).toBe("discovery");
  expect(worker(response, first)["status"]).toBe("canceled");
  expect(worker(response, second)["merge_state"]).toBe("buffered");
  expect(worker(response, reducer)["error_message"]).toBe("retained failure");
});

test("ownership and continuation conflicts roll back while an occupied caller transaction remains open", () => {
  for (const args of [
    { threadId: "other" },
    { claimToken: "66666666-6666-4666-8666-666666666666" },
    { coordinatorGeneration: 3n },
  ]) {
    const request = setup();
    request.run = { coordinator_generation: 2n };
    request.actions = [{ operation: "locked", args }];
    const response = run(request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(storedRun(response)["coordinator_generation"]).toBe(2);
  }
  const request = setup();
  request.actions = [
    { operation: "sql", sql: "UPDATE workspaces SET updated_at = 'caller'" },
    { operation: "locked" },
  ];
  const response = run(request);
  expect(response.outcomes[1]!.error).toContain("within a transaction");
  expect(response.outcomes[1]!.inTransaction).toBe(true);
  expect(response.snapshot["workspaces"]![0]!["updated_at"]).toBe("caller");
});

function publication(request: Request, status: string) {
  const scan = request.scan!["scan_dir"] as string,
    artifacts = join(scan, "reducer");
  const ledger = write(
    join(scan, "artifacts", "02_discovery", "candidate_ledger.jsonl"),
    "reducer output\n",
  );
  write(
    join(artifacts, "canonical", "candidate_ledger.jsonl"),
    "reducer output\n",
  );
  const older = write(
    join(dirname(ledger), ".candidate_ledger.jsonl.older.backup"),
    "older output\n",
  );
  const newer = write(
    join(dirname(ledger), ".candidate_ledger.jsonl.newer.backup"),
    "previous output\n",
  );
  const unrelated = write(
    join(dirname(ledger), ".candidate_ledger.jsonl.backup"),
    "unrelated file\n",
  );
  utimesSync(
    older,
    new Date("2026-01-01T00:00:00Z"),
    new Date("2026-01-01T00:00:00Z"),
  );
  utimesSync(
    newer,
    new Date("2026-01-02T00:00:00Z"),
    new Date("2026-01-02T00:00:00Z"),
  );
  request.workers = [
    { id: reducer, kind: "dedup", status, artifact_dir: artifacts },
  ];
  return { ledger, older, newer, unrelated };
}

test("ledger recovery restores the newest backup for interrupted reducers and preserves successful publication", () => {
  for (const status of ["running", "succeeded"]) {
    const request = setup(),
      paths = publication(request, status);
    request.actions = [{ operation: "ledger" }];
    expect(run(request).outcomes[0]!.result).toBeNull();
    expect(readFileSync(paths.ledger, "utf8")).toBe(
      status === "running" ? "previous output\n" : "reducer output\n",
    );
    expect(existsSync(paths.older)).toBe(false);
    expect(existsSync(paths.newer)).toBe(false);
    expect(readFileSync(paths.unrelated, "utf8")).toBe("unrelated file\n");
  }
});

test("database rollback preserves the already recovered ledger when a later adoption update fails", () => {
  const request = setup(),
    paths = publication(request, "running");
  request.run = {
    coordinator_generation: 2n,
    phase: "reducing",
    updated_at: "2026-01-01T00:00:00Z",
  };
  request.setupSql = [
    "CREATE TRIGGER rejected BEFORE UPDATE ON deep_scan_runs BEGIN SELECT RAISE(ABORT, 'rejected'); END",
  ];
  request.actions = [{ operation: "locked" }];
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe("rejected");
  expect(response.outcomes[0]!.inTransaction).toBe(false);
  expect(storedRun(response)["coordinator_generation"]).toBe(2);
  expect(worker(response, reducer)["status"]).toBe("running");
  expect(readFileSync(paths.ledger, "utf8")).toBe("previous output\n");
  expect(existsSync(paths.newer)).toBe(false);
});
