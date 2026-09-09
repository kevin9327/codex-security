import { spawnSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  readdirSync,
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
import type { Request, Response } from "./support/deep-finish-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "deep-finish-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const first = "33333333-3333-4333-8333-333333333333",
  second = "44444444-4444-4444-8444-444444444444",
  reducer = "55555555-5555-4555-8555-555555555555";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/deep-finish-fixture.ts", import.meta.url),
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

function ready() {
  const request = setup(),
    scan = scanDirectory(request);
  request.environment = { CODEX_SECURITY_STATE_DIR: join(scan, "..", "state") };
  request.run = { consecutive_no_new: 3n, completion_sequence: 1n };
  seedWorker(request, { id: reducer, kind: "dedup", status: "succeeded" });
  const discovery = join(scan, "artifacts", "02_discovery"),
    manifest = join(scan, "finish.json"),
    staged = join(scan, "staged.json");
  mkdirSync(discovery, { recursive: true });
  writeFileSync(join(discovery, "candidate_ledger.jsonl"), "candidate\n");
  writeFileSync(join(discovery, "in_scope_files.txt"), "source.ts\n");
  writeFileSync(manifest, "old\n");
  writeFileSync(staged, "new\n");
  request.actions = [{ operation: "finish" }];
  return { request, scan, discovery, manifest, staged };
}

test("saturated completion cancels active workers and accepts failed discovery workers", () => {
  const { request } = ready();
  seedWorker(request, { status: "running", attempt: 1n });
  seedWorker(request, {
    id: second,
    status: "failed",
    error_message: "failed discovery",
  });
  const response = run(request);
  expect(errors(response)).toEqual([undefined]);
  expect(storedRun(response)["status"]).toBe("succeeded");
  expect(storedRun(response)["terminal_reason"]).toBe("saturated");
  expect(worker(response)["status"]).toBe("canceled");
  expect(worker(response, second)["status"]).toBe("failed");
  expect(response.snapshot["scans"]![0]!["status"]).toBe("running");
});

test("saturation requires the threshold and exactly identifies omitted buffered workers", () => {
  for (const mismatch of ["threshold", "missing", "extra", "duplicate"]) {
    const { request } = ready();
    seedWorker(request, {
      status: "succeeded",
      merge_state: "buffered",
      completion_sequence: 1n,
    });
    request.actions[0]!.args = {
      omittedWorkerId:
        mismatch === "missing"
          ? []
          : mismatch === "extra"
            ? [first, second]
            : mismatch === "duplicate"
              ? [first, first]
              : [first],
    };
    if (mismatch === "threshold") request.run!["consecutive_no_new"] = 2n;
    const response = run(request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(storedRun(response)["status"]).toBe("running");
  }
  const { request } = ready();
  seedWorker(request, {
    status: "succeeded",
    merge_state: "buffered",
    completion_sequence: 1n,
  });
  request.actions[0]!.args = { omittedWorkerId: [first] };
  expect(errors(run(request))).toEqual([undefined]);
});

test("capped completion requires a configured cap and finished workers and buffers", () => {
  for (const blocker of ["cap", "active", "buffered", "failed"]) {
    const { request } = ready();
    request.run!["discovery_runs_dispatched"] = blocker === "cap" ? 1n : 40n;
    request.actions[0]!.args = { terminalReason: "capped" };
    if (blocker !== "cap")
      seedWorker(request, {
        status:
          blocker === "active"
            ? "running"
            : blocker === "failed"
              ? "failed"
              : "succeeded",
        merge_state: blocker === "buffered" ? "buffered" : "none",
      });
    const response = run(request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(storedRun(response)["status"]).toBe("running");
  }
});

test("an expired run with an empty canonical ledger can finish before any discovery succeeds", () => {
  const { request, discovery } = ready();
  request.run = { created_at: "2026-01-01T00:00:00Z", completion_sequence: 0n };
  request.workers = [];
  request.actions[0]!.args = { terminalReason: "capped" };
  writeFileSync(join(discovery, "candidate_ledger.jsonl"), "");
  const response = run(request);
  expect(errors(response)).toEqual([undefined]);
  expect(storedRun(response)["status"]).toBe("succeeded");
});

test("failure-capped parent evidence restores failed reducer inputs to the buffer and permits their omission", () => {
  const { request, scan } = ready();
  seedWorker(request, {
    status: "succeeded",
    merge_state: "merging",
    completion_sequence: 1n,
  });
  seedWorker(request, { id: second, kind: "dedup", status: "failed" });
  request.inputs = [
    { dedup_worker_id: second, discovery_worker_id: first, input_order: 0n },
  ];
  const manifest = join(scan, "scan-manifest.json");
  writeFileSync(manifest, "{}");
  writeFileSync(join(scan, "findings.json"), "{}");
  writeFileSync(
    join(scan, "coverage.json"),
    JSON.stringify({
      completeness: "partial",
      deferred: [
        { reason: "Deep Scan stopped before completion: synthetic failure" },
      ],
    }),
  );
  request.actions[0]!.args = {
    terminalReason: "capped",
    manifestPath: manifest,
    omittedWorkerId: [first],
  };
  const response = run(request);
  expect(errors(response)).toEqual([undefined]);
  expect(worker(response)["merge_state"]).toBe("buffered");
  expect(storedRun(response)["terminal_reason"]).toBe("capped");
});

test("a succeeded run attaches its missing manifest once and then requires an exact replay", () => {
  const { request, manifest } = ready();
  request.run = {
    status: "succeeded",
    terminal_reason: "saturated",
    manifest_path: null,
  };
  request.actions.push(
    { operation: "finish" },
    { operation: "finish", args: { terminalReason: "capped" } },
  );
  const response = run(request);
  expect(errors(response).slice(0, 2)).toEqual([undefined, undefined]);
  expect(response.outcomes[2]!.error).toContain("terminal state is immutable");
  expect(storedRun(response)["manifest_path"]).toBe(manifest);
});

test("a failed final update restores a staged manifest and rolls back worker cancellation", () => {
  const { request, manifest, staged, scan } = ready();
  seedWorker(request, { status: "running", attempt: 1n });
  request.actions[0]!.args = { stagedManifestPath: staged };
  request.setupSql = [
    "CREATE TRIGGER rejected BEFORE UPDATE ON deep_scan_runs BEGIN SELECT RAISE(ABORT,'rejected'); END",
  ];
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe("rejected");
  expect(storedRun(response)["status"]).toBe("running");
  expect(worker(response)["status"]).toBe("running");
  expect(readFileSync(manifest, "utf8")).toBe("old\n");
  expect(readFileSync(staged, "utf8")).toBe("new\n");
  expect(readdirSync(scan).some((name) => name.endsWith(".backup"))).toBe(
    false,
  );
});

test("successful staged manifest publication removes the old backup and staged path", () => {
  const { request, manifest, staged, scan } = ready();
  request.actions[0]!.args = { stagedManifestPath: staged };
  const response = run(request);
  expect(errors(response)).toEqual([undefined]);
  expect(readFileSync(manifest, "utf8")).toBe("new\n");
  expect(existsSync(staged)).toBe(false);
  expect(readdirSync(scan).some((name) => name.endsWith(".backup"))).toBe(
    false,
  );
});
