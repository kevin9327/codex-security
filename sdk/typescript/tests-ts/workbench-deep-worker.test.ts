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
import type { Request, Response } from "./support/deep-worker-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "deep-worker-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const first = "33333333-3333-4333-8333-333333333333",
  second = "44444444-4444-4444-8444-444444444444",
  reducer = "55555555-5555-4555-8555-555555555555";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/deep-worker-fixture.ts", import.meta.url),
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
  mkdirSync(scan, { mode: 0o700 });
  mkdirSync(join(scan, "worker"));
  writeFileSync(join(scan, "prompt.txt"), "prompt");
  writeFileSync(join(scan, "result.json"), "{}");
  return {
    scan: { scan_dir: scan, target_path: join(root, "target") },
    actions: [],
  };
}
const scanDirectory = (r: Request) => r.scan!["scan_dir"] as string;
function seedWorker(
  r: Request,
  values: NonNullable<Request["workers"]>[number] = {},
) {
  (r.workers ??= []).push({
    id: first,
    prompt_path: join(scanDirectory(r), "prompt.txt"),
    artifact_dir: join(scanDirectory(r), "worker"),
    ...values,
  });
}
const storedRun = (r: Response) => r.snapshot["deep_scan_runs"]![0]!;
const worker = (r: Response, id = first) =>
  r.snapshot["deep_scan_workers"]!.find((row) => row["id"] === id)!;
const errors = (r: Response) => r.outcomes.map((value) => value.error);

test("discovery dispatch, startup, completion and terminal replay update each counter once", () => {
  const request = setup(),
    result = join(scanDirectory(request), "result.json");
  request.actions = [
    { operation: "upsert" },
    {
      operation: "upsert",
      args: {
        status: "running",
        attempt: 1n,
        sdkThreadId: " worker-thread ",
        errorMessage: "previous error",
      },
    },
    {
      operation: "upsert",
      args: { status: "succeeded", resultManifestPath: result },
    },
    {
      operation: "upsert",
      args: { status: "succeeded", resultManifestPath: result },
    },
  ];
  const response = run(request);
  expect(errors(response)).toEqual([
    undefined,
    undefined,
    undefined,
    undefined,
  ]);
  expect(storedRun(response)["discovery_runs_dispatched"]).toBe(1);
  expect(storedRun(response)["completion_sequence"]).toBe(1);
  expect(worker(response)["attempt"]).toBe(1);
  expect(worker(response)["sdk_thread_id"]).toBe("worker-thread");
  expect(worker(response)["merge_state"]).toBe("buffered");
  expect(worker(response)["error_message"]).toBeNull();
  expect(response.outcomes.every((value) => !value.inTransaction)).toBe(true);
});

test("worker creation preserves status, attempt, setup uniqueness and dispatch limits", () => {
  for (const args of [
    { kind: "dedup" },
    { status: "succeeded" },
    { status: "running", attempt: 0n },
  ]) {
    const request = setup();
    request.actions = [{ operation: "upsert", args }];
    const response = run(request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(response.snapshot["deep_scan_workers"]).toEqual([]);
    expect(storedRun(response)["discovery_runs_dispatched"]).toBe(0);
  }
  const request = setup();
  seedWorker(request, { id: second, kind: "setup", status: "failed" });
  request.actions = [{ operation: "upsert", args: { kind: "setup" } }];
  expect(run(request).outcomes[0]!.error).toContain("only one setup");
  const capped = setup();
  capped.run = { discovery_runs_dispatched: 40n };
  capped.actions = [{ operation: "upsert" }];
  expect(run(capped).outcomes[0]!.error).toContain("maximum discovery runs");
});

test("worker paths are canonical and immutable and lease checks precede path validation", () => {
  const request = setup();
  seedWorker(request, { status: "running", attempt: 1n });
  request.run = { coordinator_generation: 2n };
  request.actions = [
    {
      operation: "upsert",
      args: { promptPath: "/missing", status: "running" },
    },
    {
      operation: "upsert",
      args: {
        coordinatorGeneration: 2n,
        promptPath: join(scanDirectory(request), "result.json"),
        status: "running",
      },
    },
    {
      operation: "upsert",
      args: {
        coordinatorGeneration: 2n,
        artifactDir: join(scanDirectory(request), ".."),
        status: "running",
      },
    },
  ];
  const response = run(request);
  expect(response.outcomes[0]!.error).toContain("current coordinator lease");
  expect(response.outcomes[1]!.error).toContain("paths are immutable");
  expect(response.outcomes[2]!.systemExit).toBe(true);
  expect(worker(response)["status"]).toBe("running");
});

test("terminal worker repeats reject changes and stopped runs still permit cancellation cleanup", () => {
  const request = setup();
  seedWorker(request, {
    status: "failed",
    attempt: 2n,
    error_message: "saved failure",
  });
  request.actions = [
    { operation: "upsert", args: { status: "failed", attempt: 3n } },
    {
      operation: "upsert",
      args: { status: "failed", errorMessage: "new failure" },
    },
    { operation: "upsert", args: { status: "failed" } },
  ];
  const response = run(request);
  expect(
    response.outcomes
      .slice(0, 2)
      .every((value) => value.error?.includes("terminal state is immutable")),
  ).toBe(true);
  expect(response.outcomes[2]!.error).toBeUndefined();
  expect(worker(response)["attempt"]).toBe(2);
  const stopped = setup();
  stopped.run = { status: "failed" };
  seedWorker(stopped, { status: "running", attempt: 1n });
  stopped.actions = [{ operation: "upsert", args: { status: "canceled" } }];
  const cleanup = run(stopped);
  expect(cleanup.outcomes[0]!.error).toBeUndefined();
  expect(worker(cleanup)["status"]).toBe("canceled");
});

test("replaceable discovery failures count once and later successful discovery clears the streak", () => {
  const request = setup();
  seedWorker(request, { status: "running", attempt: 1n });
  seedWorker(request, { id: second, status: "running", attempt: 1n });
  request.actions = [
    {
      operation: "upsert",
      args: {
        status: "canceled",
        replaceableFailureKind: "transient_error",
        errorMessage: "retry required",
      },
    },
    {
      operation: "upsert",
      args: {
        status: "canceled",
        replaceableFailureKind: "transient_error",
        errorMessage: "retry required",
      },
    },
    {
      operation: "query",
      sql: "SELECT consecutive_errors FROM deep_scan_runs",
    },
    {
      operation: "upsert",
      args: {
        workerId: second,
        status: "succeeded",
        resultManifestPath: join(scanDirectory(request), "result.json"),
      },
    },
  ];
  const response = run(request);
  expect(errors(response)).toEqual([
    undefined,
    undefined,
    undefined,
    undefined,
  ]);
  expect(response.outcomes[2]!.result).toEqual([{ consecutive_errors: 1 }]);
  expect(storedRun(response)["consecutive_errors"]).toBe(0);
});

test("a failed reducer returns claimed successful discoveries to the buffer", () => {
  const request = setup();
  seedWorker(request, { status: "succeeded", merge_state: "merging" });
  seedWorker(request, {
    id: reducer,
    kind: "dedup",
    status: "running",
    attempt: 1n,
  });
  request.inputs = [
    { dedup_worker_id: reducer, discovery_worker_id: first, input_order: 0n },
  ];
  request.actions = [
    {
      operation: "upsert",
      args: { workerId: reducer, kind: "dedup", status: "failed" },
    },
  ];
  const response = run(request);
  expect(response.outcomes[0]!.error).toBeUndefined();
  expect(worker(response)["merge_state"]).toBe("buffered");
  expect(storedRun(response)["phase"]).toBe("discovery");
});

function buffered(request: Request) {
  seedWorker(request, {
    status: "succeeded",
    completion_sequence: 1n,
    merge_state: "buffered",
  });
  seedWorker(request, {
    id: second,
    status: "succeeded",
    completion_sequence: 2n,
    merge_state: "buffered",
  });
}

test("dedup claims an ordered prefix once and records progress and replayed input order", () => {
  const request = setup();
  buffered(request);
  request.progress = { updated_at: "before", deep_review_pass: null };
  request.actions = [
    {
      operation: "dedup",
      args: { workerId: reducer, inputWorkerId: [first, second] },
    },
    {
      operation: "dedup",
      args: { workerId: reducer, inputWorkerId: [first, second] },
    },
  ];
  const response = run(request);
  expect(errors(response)).toEqual([undefined, undefined]);
  expect(worker(response, reducer)["status"]).toBe("queued");
  expect(worker(response)["merge_state"]).toBe("merging");
  expect(worker(response, second)["merge_state"]).toBe("merging");
  expect(storedRun(response)["phase"]).toBe("reducing");
  expect(response.snapshot["scan_progress"]![0]!["deep_review_pass"]).toBe(1);
  expect(
    response.snapshot["deep_scan_dedup_inputs"]!.map(
      (row) => row["discovery_worker_id"],
    ),
  ).toEqual([first, second]);
});

test("dedup rejects duplicate and reordered inputs before changing the buffer", () => {
  for (const ids of [[first, first], [second, first], []]) {
    const request = setup();
    buffered(request);
    request.actions = [
      { operation: "dedup", args: { workerId: reducer, inputWorkerId: ids } },
    ];
    const response = run(request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(response.snapshot["deep_scan_dedup_inputs"]).toEqual([]);
    expect(worker(response)["merge_state"]).toBe("buffered");
  }
});

test("a first singleton reducer is allowed at the cap only after active discoveries stop", () => {
  for (const active of [false, true]) {
    const request = setup();
    seedWorker(request, {
      status: "succeeded",
      completion_sequence: 1n,
      merge_state: "buffered",
    });
    if (active)
      seedWorker(request, { id: second, status: "running", attempt: 1n });
    request.run = { discovery_runs_dispatched: 40n };
    request.actions = [
      {
        operation: "dedup",
        args: { workerId: reducer, inputWorkerId: [first] },
      },
    ];
    const response = run(request);
    expect(response.outcomes[0]!.systemExit ?? false).toBe(active);
    expect(worker(response)["merge_state"]).toBe(
      active ? "buffered" : "merging",
    );
  }
});

test("failed inserts roll back dispatch counts and reducer input claims", () => {
  for (const operation of ["upsert", "dedup"] as const) {
    const request = setup();
    if (operation === "dedup") buffered(request);
    request.setupSql = [
      "CREATE TRIGGER rejected BEFORE INSERT ON deep_scan_workers BEGIN SELECT RAISE(ABORT, 'rejected'); END",
    ];
    request.actions = [
      {
        operation,
        args: { workerId: reducer, inputWorkerId: [first, second] },
      },
    ];
    const response = run(request);
    expect(response.outcomes[0]!.error).toBe("rejected");
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(storedRun(response)["discovery_runs_dispatched"]).toBe(0);
    expect(response.snapshot["deep_scan_dedup_inputs"]).toEqual([]);
  }
});

test("invalid SQLite text preserves the encoding error and rolls back dispatch", () => {
  const request = setup();
  request.actions = [
    { operation: "upsert", args: { sdkThreadId: "😀\udcff" } },
  ];
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe(
    "'utf-8' codec can't encode character '\\udcff' in position 1: surrogates not allowed",
  );
  expect(response.outcomes[0]!.inTransaction).toBe(false);
  expect(storedRun(response)["discovery_runs_dispatched"]).toBe(0);
  expect(response.snapshot["deep_scan_workers"]).toEqual([]);
});
