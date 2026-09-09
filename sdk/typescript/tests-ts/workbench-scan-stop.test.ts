import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
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
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-scan-stop-fixture";

const scanId = "11111111-1111-4111-8111-111111111111";
const token = "33333333-3333-4333-8333-333333333333";
const directory = realpathSync(mkdtempSync(join(tmpdir(), "scan-stop-"))),
  fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const timestamp = "2026-01-02T00:00:00Z";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-scan-stop-fixture.ts", import.meta.url),
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
function request(actions: Action[]): Request {
  const scan = mkdtempSync(join(directory, "scan-"));
  return { scan: { scan_dir: scan }, actions };
}
function run(input: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([input]),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: {
      ...process.env,
      PATH: "",
      PYTHON: "/unavailable/python",
      CODEX_SECURITY_STATE_DIR: join(
        input.scan!["scan_dir"] as string,
        "state",
      ),
    },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const response = (parseJson(child.stdout) as unknown as Response[])[0]!;
  expect(response.node).toBe(nodeVersion);
  return response;
}
const row = (response: Response, table = "scans") =>
  response.snapshot[table]![0]!;
function checkpoint(input: Request): void {
  const value = {
    scanId,
    findings: [],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [
        {
          candidateId: "pending",
          reason: "Review pending.",
          paths: ["src/a.ts"],
        },
      ],
    },
  };
  const encoded = stringifyJson(value, {
    compact: true,
    sortKeys: true,
    separators: [",", ":"],
  });
  const path = join(input.scan!["scan_dir"] as string, "checkpoints");
  mkdirSync(path);
  writeFileSync(
    join(path, `${createHash("sha256").update(encoded).digest("hex")}.json`),
    encoded,
  );
}
function deep(input: Request, status = "running"): void {
  input.records = {
    deep_scan_runs: [
      {
        scan_id: scanId,
        schema_version: 1n,
        workflow_version: "deep-security-scan/v1",
        status,
        phase: "discovery",
        workers: 4n,
        subagents: 1n,
        stop_after_no_new: 3n,
        max_discovery_runs: 40n,
        publication_error_message: "retry needed",
        created_at: "created",
        updated_at: "updated",
      },
    ],
    deep_scan_workers: ["queued", "running", "succeeded"].map(
      (state, index) => ({
        id: `${index}3333333-3333-4333-8333-333333333333`,
        scan_id: scanId,
        kind: "discovery",
        status: state,
        prompt_path: "/prompt",
        artifact_dir: join(
          input.scan!["scan_dir"] as string,
          "workers",
          String(index),
        ),
        created_at: "created",
        updated_at: "updated",
      }),
    ),
  };
}
const sql = (value: string): Action => ({ operation: "sql", sql: value });

test("failing and canceling publish stopped evidence, cancel active workers, and render committed results", () => {
  for (const operation of ["fail", "cancel"] as const) {
    const input = request([
      { operation, message: "  worker stopped  ", threadId: "owner" },
    ]);
    deep(input);
    checkpoint(input);
    const response = run(input);
    expect(response.outcomes[0]!.error).toBeUndefined();
    expect(row(response)["status"]).toBe("failed");
    expect(row(response)["completed_at"]).toBe(timestamp);
    expect(row(response)["canceled_at"]).toBe(
      operation === "cancel" ? timestamp : null,
    );
    expect(row(response)["failure_message"]).toBe(
      operation === "fail" ? "worker stopped" : null,
    );
    expect(row(response, "deep_scan_runs")["status"]).toBe(
      operation === "fail" ? "failed" : "canceled",
    );
    expect(
      row(response, "deep_scan_runs")["publication_error_message"],
    ).toBeNull();
    expect(
      response.snapshot["deep_scan_workers"]!.map((worker) => worker["status"]),
    ).toEqual(["canceled", "canceled", "succeeded"]);
    expect(response.snapshot["scan_artifacts"]).toHaveLength(4);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    const scan = input.scan!["scan_dir"] as string;
    expect(
      existsSync(join(scan, "state", "completion-locks", `${scanId}.lock`)),
    ).toBe(true);
    const manifest = JSON.parse(
      readFileSync(join(scan, "scan-manifest.json"), "utf8"),
    );
    expect(manifest.scan.status).toBe(
      operation === "fail" ? "failed" : "canceled",
    );
    const result = response.outcomes[0]!.result as Record<
      string,
      Record<string, unknown>
    >;
    expect(
      (operation === "fail" ? result["scan"] : result["results"])!["scanId"],
    ).toBe(scanId);
  }
});

test("missing progress and ignored transition writes roll back the scan and workers", () => {
  for (const operation of ["failLocked", "cancelLocked"] as const) {
    for (const failure of ["missing", "ignored"]) {
      const input = request([{ operation }]);
      deep(input);
      if (failure === "missing") input.progress = null;
      else
        input.setupSql = [
          "CREATE TRIGGER skip BEFORE UPDATE OF status ON scans BEGIN SELECT RAISE(IGNORE); END",
        ];
      const response = run(input);
      expect(response.outcomes[0]!.systemExit).toBe(true);
      expect(row(response)["status"]).toBe("running");
      expect(row(response, "deep_scan_runs")["status"]).toBe("running");
      expect(response.snapshot["deep_scan_workers"]![0]!["status"]).toBe(
        "queued",
      );
      expect(response.outcomes[0]!.inTransaction).toBe(false);
    }
  }
});

test("BEGIN failure keeps the caller transaction and a clock failure rolls back its own transaction", () => {
  for (const operation of ["failLocked", "cancelLocked"] as const) {
    const input = request([
      sql("UPDATE workspaces SET updated_at='caller'"),
      { operation },
      { operation: "rollback" },
      { operation, failNow: 1 },
    ]);
    const response = run(input);
    expect(response.outcomes[1]!.error).toBe(
      "cannot start a transaction within a transaction",
    );
    expect(response.outcomes[1]!.inTransaction).toBe(true);
    expect(response.outcomes[3]!.error).toBe("clock failed");
    expect(response.outcomes[3]!.inTransaction).toBe(false);
    expect(row(response, "workspaces")["updated_at"]).toBe("workspace-updated");
  }
});

test("cost validation precedes BEGIN and failed replay bypasses continuation ownership", () => {
  const input = request([
    { operation: "failLocked", costJson: "{" },
    { operation: "failLocked", claimToken: "bad", message: "new" },
  ]);
  Object.assign(input.scan!, {
    status: "failed",
    handoff_status: "pending",
    handoff_claim_token: token,
    failure_message: "original",
  });
  const response = run(input);
  expect(response.outcomes[0]!.systemExit).toBe(true);
  expect(response.outcomes[0]!.events).toEqual([]);
  expect(response.outcomes[1]!.error).toBeUndefined();
  expect(row(response)["failure_message"]).toBe("original");
});

test("running failure requires the current continuation", () => {
  const input = request([
    { operation: "failLocked" },
    { operation: "failLocked", claimToken: token },
  ]);
  Object.assign(input.scan!, {
    handoff_status: "pending",
    handoff_claim_token: token,
  });
  const response = run(input);
  expect(response.outcomes[0]!.error).toBe(
    "Scan failure is owned by another continuation.",
  );
  expect(response.outcomes[1]!.error).toBeUndefined();
  expect(row(response)["status"]).toBe("failed");
});

test("cancellation checks the continuation owner even for a replay and accepts stored empty cancellation time", () => {
  const input = request([
    { operation: "cancelLocked", threadId: "owner" },
    { operation: "cancelLocked", threadId: "child" },
  ]);
  Object.assign(input.scan!, {
    status: "complete",
    continuation_thread_id: "child",
    canceled_at: "",
  });
  const response = run(input);
  expect(response.outcomes[0]!.error).toBe(
    "A scan can only be canceled from its owning Codex thread.",
  );
  expect(response.outcomes[1]!.error).toBeUndefined();
  expect(row(response)["status"]).toBe("complete");
});

test("canceling a running parent changes a succeeded deep run to canceled", () => {
  const input = request([{ operation: "cancelLocked" }]);
  deep(input, "succeeded");
  const response = run(input);
  expect(response.outcomes[0]!.error).toBeUndefined();
  expect(row(response, "deep_scan_runs")["status"]).toBe("canceled");
});

test("publication errors retain the transition and append one deduplicated follow-up warning", () => {
  const input = request([
    { operation: "failLocked" },
    { operation: "preserveStopped" },
  ]);
  Object.assign(input.scan!, {
    retained_source_digests_json: "{",
    completion_warnings_json: '[1,1.0,true,"kept","kept"]',
  });
  const response = run(input);
  expect(
    response.outcomes.every((outcome) => outcome.error === undefined),
  ).toBe(true);
  const warnings = JSON.parse(
    row(response)["completion_warnings_json"] as string,
  );
  expect(warnings).toHaveLength(3);
  expect(warnings.slice(0, 2)).toEqual([1, "kept"]);
  expect(warnings[2]).toStartWith(
    "Saved scan evidence remains on disk; result publication needs follow-up:",
  );
  expect(row(response)["status"]).toBe("failed");
  expect(row(response)["completed_at"]).toBe(timestamp);
});

test("publication catches value and exit errors while type and runtime errors propagate", () => {
  for (const kind of ["value", "exit", "type", "runtime"] as const) {
    const input = request([
      { operation: "failLocked", failNow: 2, nowError: kind },
    ]);
    checkpoint(input);
    const response = run(input),
      catches = kind === "value" || kind === "exit";
    expect(response.outcomes[0]!.error).toBe(
      catches ? undefined : "clock failed",
    );
    expect(row(response)["status"]).toBe("failed");
    expect(row(response)["retained_source_digests_json"]).not.toBeNull();
    expect(row(response)["seal_manifest_digest"]).toBeNull();
    expect(
      JSON.parse(row(response)["completion_warnings_json"] as string),
    ).toHaveLength(catches ? 1 : 0);
  }
});

test("SQL publication failure propagates after the stop and restores output files", () => {
  const input = request([{ operation: "failLocked" }]);
  checkpoint(input);
  input.setupSql = [
    "CREATE TRIGGER reject BEFORE UPDATE OF seal_manifest_digest ON scans BEGIN SELECT RAISE(ABORT,'pin rejected'); END",
  ];
  const response = run(input);
  expect(response.outcomes[0]!.error).toBe("pin rejected");
  expect(row(response)["status"]).toBe("failed");
  expect(row(response)["seal_manifest_digest"]).toBeNull();
  expect(row(response)["completion_warnings_json"]).toBe("[]");
  expect(
    existsSync(join(input.scan!["scan_dir"] as string, "scan-manifest.json")),
  ).toBe(false);
});

test("clearing publication failure happens after the publication commits", () => {
  const input = request([
    { operation: "failLocked", failNow: 3, nowError: "value" },
  ]);
  checkpoint(input);
  deep(input);
  const response = run(input);
  expect(response.outcomes[0]!.error).toBe("clock failed");
  expect(row(response)["seal_manifest_digest"]).toMatch(/^sha256:/);
  expect(row(response, "deep_scan_runs")["publication_error_message"]).toBe(
    "retry needed",
  );
  expect(row(response)["completion_warnings_json"]).toBe("[]");
});

test("a stopped-result warning commits caller writes and malformed warning arrays still throw", () => {
  const input = request([
    sql("UPDATE workspaces SET updated_at='caller'"),
    { operation: "preserveStopped" },
    { operation: "rollback" },
  ]);
  Object.assign(input.scan!, {
    status: "failed",
    retained_source_digests_json: "{",
  });
  const response = run(input);
  expect(response.outcomes[1]!.error).toBeUndefined();
  expect(row(response, "workspaces")["updated_at"]).toBe("caller");
  const invalid = request([{ operation: "failLocked" }]);
  Object.assign(invalid.scan!, {
    retained_source_digests_json: "{",
    completion_warnings_json: "[[]]",
  });
  const rejected = run(invalid);
  expect(rejected.outcomes[0]!.error).toBe("unhashable type: 'list'");
  expect(row(rejected)["status"]).toBe("failed");
});
