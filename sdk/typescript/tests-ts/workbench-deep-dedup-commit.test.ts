import { spawnSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
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
import type { Request, Response } from "./support/deep-dedup-commit-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "deep-dedup-commit-")),
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
        new URL("./support/deep-dedup-commit-fixture.ts", import.meta.url),
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

function claimed(publication = false) {
  const request = setup(),
    scan = scanDirectory(request);
  request.environment = { CODEX_SECURITY_STATE_DIR: join(scan, "..", "state") };
  seedWorker(request, {
    id: first,
    status: "succeeded",
    completion_sequence: 1n,
    merge_state: "merging",
  });
  seedWorker(request, {
    id: second,
    status: "succeeded",
    completion_sequence: 2n,
    merge_state: "merging",
  });
  seedWorker(request, {
    id: reducer,
    kind: "dedup",
    status: "running",
    attempt: 1n,
    error_message: "old error",
  });
  request.inputs = [first, second].map((id, order) => ({
    dedup_worker_id: reducer,
    discovery_worker_id: id,
    input_order: BigInt(order),
  }));
  const discovery = join(scan, "artifacts", "02_discovery"),
    ledger = join(discovery, "candidate_ledger.jsonl"),
    staged = join(scan, "staged.jsonl");
  mkdirSync(discovery, { recursive: true });
  writeFileSync(join(discovery, "in_scope_files.txt"), "source.ts\n");
  writeFileSync(ledger, "old\n");
  writeFileSync(staged, "new\n");
  request.actions = [
    {
      operation: "dedup",
      args: {
        workerId: reducer,
        candidateLedgerPath: publication ? staged : null,
      },
    },
  ];
  return { request, scan, discovery, ledger, staged };
}

test("dedup completion marks claimed inputs merged and advances the no-new streak", () => {
  const { request } = claimed();
  request.run = { consecutive_no_new: 3n };
  const response = run(request);
  expect(errors(response)).toEqual([undefined]);
  expect(worker(response, reducer)["status"]).toBe("succeeded");
  expect(worker(response, reducer)["error_message"]).toBeNull();
  expect(worker(response, reducer)["started_at"]).toBe("2026-01-02T00:00:00Z");
  expect(worker(response)["merge_state"]).toBe("merged");
  expect(worker(response, second)["merge_state"]).toBe("merged");
  expect(storedRun(response)["consecutive_no_new"]).toBe(5);
  expect(storedRun(response)["phase"]).toBe("discovery");
  expect(response.outcomes[0]!.inTransaction).toBe(false);
});

test("new findings reset the streak and a successful reducer replays before validating supplied paths", () => {
  const { request } = claimed();
  request.run = { consecutive_no_new: 9n };
  request.actions[0]!.args!.newFindingsCount = 1n;
  request.actions.push({
    operation: "dedup",
    args: {
      workerId: reducer,
      resultManifestPath: "/missing",
      candidateLedgerPath: "/missing",
    },
  });
  const response = run(request);
  expect(errors(response)).toEqual([undefined, undefined]);
  expect(storedRun(response)["consecutive_no_new"]).toBe(0);
  expect(worker(response)["merge_state"]).toBe("merged");
});

test("publishing a candidate ledger retains its staged snapshot and cleans publication backups", () => {
  const { request, discovery, ledger, staged } = claimed(true);
  const response = run(request);
  expect(errors(response)).toEqual([undefined]);
  expect(readFileSync(ledger, "utf8")).toBe("new\n");
  expect(readFileSync(staged, "utf8")).toBe("new\n");
  expect(readdirSync(discovery).sort()).toEqual([
    "candidate_ledger.jsonl",
    "in_scope_files.txt",
  ]);
  if (process.platform !== "win32")
    expect(statSync(ledger).ino).toBe(statSync(staged).ino);
});

test("a clock or database failure restores the old ledger and rolls back merged inputs", () => {
  for (const failure of ["clock", "update", "commit"]) {
    const { request, ledger, staged, discovery } = claimed(true);
    if (failure === "clock") request.actions[0]!.failNow = 1;
    else if (failure === "update")
      request.setupSql = [
        "CREATE TRIGGER rejected BEFORE UPDATE ON deep_scan_runs BEGIN SELECT RAISE(ABORT,'rejected'); END",
      ];
    else
      request.setupSql = [
        "PRAGMA foreign_keys=ON",
        "CREATE TABLE audit(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER rejected AFTER UPDATE ON deep_scan_runs BEGIN INSERT INTO audit VALUES('missing'); END",
      ];
    const response = run(request);
    expect(response.outcomes[0]!.error).toBe(
      failure === "clock"
        ? "clock failed"
        : failure === "update"
          ? "rejected"
          : "FOREIGN KEY constraint failed",
    );
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(worker(response, reducer)["status"]).toBe("running");
    expect(worker(response)["merge_state"]).toBe("merging");
    expect(readFileSync(ledger, "utf8")).toBe("old\n");
    expect(readFileSync(staged, "utf8")).toBe("new\n");
    expect(readdirSync(discovery).sort()).toEqual([
      "candidate_ledger.jsonl",
      "in_scope_files.txt",
    ]);
  }
});

test("invalid coordinator leases and input states are rejected before publication", () => {
  for (const failure of ["lease", "empty", "buffered", "worker"]) {
    const { request, ledger } = claimed(true);
    if (failure === "lease") request.run = { coordinator_generation: 2n };
    else if (failure === "empty") request.inputs = [];
    else if (failure === "buffered")
      request.workers![0]!["merge_state"] = "buffered";
    else request.workers![2]!["status"] = "failed";
    const response = run(request);
    expect(response.outcomes[0]!.systemExit).toBe(true);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(readFileSync(ledger, "utf8")).toBe("old\n");
  }
});

test("a failing begin leaves the caller transaction active", () => {
  const { request } = claimed();
  request.actions.unshift({
    operation: "sql",
    sql: "UPDATE deep_scan_runs SET updated_at='caller'",
  });
  request.actions.push({ operation: "rollback" });
  const response = run(request);
  expect(response.outcomes[1]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(response.outcomes[1]!.inTransaction).toBe(true);
  expect(worker(response)["merge_state"]).toBe("merging");
});

test("promotion failure removes the publication copy while retaining the staged snapshot", () => {
  const { request, discovery, staged } = claimed(true);
  const backup = join(
    discovery,
    ".candidate_ledger.jsonl.77777777-7777-4777-8777-777777777777.backup",
  );
  mkdirSync(backup);
  const response = run(request);
  expect(response.outcomes[0]!.error).toBeDefined();
  expect(response.outcomes[0]!.inTransaction).toBe(false);
  expect(existsSync(staged)).toBe(true);
  expect(
    readdirSync(discovery).filter((name) => name.endsWith(".publish")),
  ).toEqual([]);
  expect(worker(response, reducer)["status"]).toBe("running");
});
