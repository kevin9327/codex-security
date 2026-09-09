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
import type { Request, Response } from "./support/deep-failure-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "deep-failure-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const first = "33333333-3333-4333-8333-333333333333",
  second = "44444444-4444-4444-8444-444444444444";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/deep-failure-fixture.ts", import.meta.url),
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

function failureRequest() {
  const request = setup(),
    scan = scanDirectory(request),
    root = join(scan, "..");
  request.environment = {
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    CODEX_HOME: join(root, "codex"),
    CODEX_SQLITE_HOME: join(root, "sqlite"),
    CODEX_STATE_DB: join(root, "missing.sqlite3"),
  };
  request.progress = { updated_at: "before" };
  request.actions = [{ operation: "failure" }];
  return { request, scan };
}

test("failure records the terminal state, cancels active workers and marks the parent failed", () => {
  const { request } = failureRequest();
  seedWorker(request, { status: "running", attempt: 1n });
  seedWorker(request, { id: second, status: "succeeded" });
  const response = run(request);
  expect(errors(response)).toEqual([undefined]);
  expect(storedRun(response)["status"]).toBe("failed");
  expect(storedRun(response)["cancel_requested"]).toBe(1);
  expect(storedRun(response)["error_message"]).toBe("synthetic failure");
  expect(worker(response)["status"]).toBe("canceled");
  expect(worker(response, second)["status"]).toBe("succeeded");
  expect(response.snapshot["scans"]![0]!["failure_message"]).toBe(
    "synthetic failure",
  );
  expect(response.snapshot["scan_progress"]![0]!["updated_at"]).toBe(
    "2026-01-02T00:00:00Z",
  );
});

test("failure replays require the same status, parent failure, message and manifest", () => {
  const { request } = failureRequest();
  request.actions.push(
    { operation: "failure" },
    { operation: "failure", args: { message: "changed" } },
  );
  const response = run(request);
  expect(errors(response).slice(0, 2)).toEqual([undefined, undefined]);
  expect(response.outcomes[2]!.error).toContain(
    "terminal failure state is immutable",
  );
  expect(storedRun(response)["error_message"]).toBe("synthetic failure");
});

test("a terminal scan can still fail while waiting for its first coordinator manifest", () => {
  for (const bound of [false, true]) {
    const { request, scan } = failureRequest();
    request.run = {
      status: "succeeded",
      terminal_reason: "saturated",
      manifest_path: bound ? join(scan, "result.json") : null,
    };
    request.actions[0]!.args = { deepStatus: "interrupted" };
    const response = run(request);
    expect(response.outcomes[0]!.systemExit ?? false).toBe(bound);
    expect(storedRun(response)["status"]).toBe(
      bound ? "succeeded" : "interrupted",
    );
  }
});

test("staged failure manifests publish atomically and failed parent writes restore them", () => {
  for (const rejected of [false, true]) {
    const { request, scan } = failureRequest(),
      manifest = join(scan, "failure.json"),
      staged = join(scan, "staged.json");
    writeFileSync(manifest, "old\n");
    writeFileSync(staged, "new\n");
    request.actions[0]!.args = {
      manifestPath: manifest,
      stagedManifestPath: staged,
    };
    if (rejected)
      request.setupSql = [
        "CREATE TRIGGER ignored BEFORE UPDATE ON scans BEGIN SELECT RAISE(IGNORE); END",
      ];
    const response = run(request);
    if (rejected)
      expect(response.outcomes[0]!.error).toBe(
        "Deep Scan failure could not be persisted to its parent scan.",
      );
    else expect(response.outcomes[0]!.error).toBeUndefined();
    expect(storedRun(response)["status"]).toBe(rejected ? "running" : "failed");
    expect(readFileSync(manifest, "utf8")).toBe(rejected ? "old\n" : "new\n");
    expect(existsSync(staged)).toBe(rejected);
    expect(readdirSync(scan).some((name) => name.endsWith(".backup"))).toBe(
      false,
    );
  }
});

test("publication failures only update stopped scans and leave sealed results unchanged", () => {
  for (const state of ["running", "failed", "sealed"]) {
    const { request } = failureRequest();
    if (state !== "running") {
      request.run = { status: "failed" };
      request.scan!["status"] = "failed";
    }
    if (state === "sealed")
      request.scan!["seal_manifest_digest"] = "sha256:" + "a".repeat(64);
    request.actions = [
      {
        operation: "publication",
        args: { message: "publication unavailable" },
      },
      {
        operation: "publication",
        args: { message: "publication unavailable" },
        failNow: 1,
      },
    ];
    const response = run(request);
    if (state === "running")
      expect(response.outcomes[0]!.systemExit).toBe(true);
    else expect(errors(response)).toEqual([undefined, undefined]);
    expect(storedRun(response)["publication_error_message"]).toBe(
      state === "failed" ? "publication unavailable" : null,
    );
  }
});

test("message and lease errors precede mutations while a failed begin preserves the caller transaction", () => {
  const { request } = failureRequest();
  request.run = { coordinator_generation: 2n };
  request.actions = [
    { operation: "failure", args: { message: " " } },
    { operation: "failure" },
    { operation: "sql", sql: "UPDATE scans SET updated_at='caller'" },
    { operation: "failure" },
    { operation: "rollback" },
  ];
  const response = run(request);
  expect(response.outcomes[0]!.error).toBe("message is required.");
  expect(response.outcomes[1]!.error).toContain("current coordinator lease");
  expect(response.outcomes[3]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(response.outcomes[3]!.inTransaction).toBe(true);
  expect(storedRun(response)["status"]).toBe("running");
});
