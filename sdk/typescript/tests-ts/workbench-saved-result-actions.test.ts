import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
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
} from "./support/workbench-results-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "saved-result-actions-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const scanId = "11111111-1111-4111-8111-111111111111";
const token = "33333333-3333-4333-8333-333333333333";
const snapshotDigest = `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`;
beforeAll(() =>
  buildSync({
    absWorkingDir: fileURLToPath(new URL("..", import.meta.url)),
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-results-fixture.ts", import.meta.url),
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
function setup(name: string, operation: Action["operation"] = "writeDraft") {
  const root = join(directory, name),
    scan = join(root, "scan"),
    state = join(root, "state");
  mkdirSync(root);
  mkdirSync(scan, { mode: 0o700 });
  const action: Action = { operation };
  const request: Request = {
    stateDirectory: state,
    traceLocks: true,
    scan: {
      target_path: join(root, "target"),
      target_id: "repo:synthetic",
      target_revision: "unversioned",
      target_snapshot_digest: snapshotDigest,
      scan_dir: scan,
      scope: "src",
      status: operation === "writeDraft" ? "running" : "failed",
      phase: "reporting",
      handoff_status: "delivered",
      started_at: "2026-01-01T00:00:00Z",
      completed_at: "2026-01-01T01:00:00Z",
      completion_warnings_json: "[]",
      failure_message: "Worker stopped.",
    },
    setupSql: ["PRAGMA foreign_keys=ON"],
    actions: [action],
  };
  return { root, scan, state, action, request };
}
type Setup = ReturnType<typeof setup>;
function write(scan: string, relative: string, value: unknown): string {
  const path = join(scan, relative);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, Buffer.isBuffer(value) ? value : stringifyJson(value));
  return path;
}
function documents() {
  return {
    manifest: {
      scan: {
        target: { kind: "directory_snapshot", snapshotDigest },
        scope: {},
      },
    },
    findings: { findings: [] },
    coverage: { completeness: "partial", deferred: [] },
  };
}
function draft(value: Setup, payload = documents()) {
  value.action.savedArgs = {
    ...value.action.savedArgs,
    draftPath: write(value.scan, "drafts/A-b.json", payload),
  };
  return payload;
}
function checkpoint(
  value: Setup,
  title = "Unchecked destination",
): Record<string, string> {
  const payload = {
    scanId,
    findings: [
      {
        ruleId: "unsafe-write",
        identity: { anchor: title },
        title,
        summary: "The destination is unchecked.",
        severity: { level: "medium", rationale: "Source trace" },
        confidence: { level: "high", rationale: "Source trace" },
        taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
        locations: [{ path: "src/a.ts", startLine: 1n, endLine: 1n }],
        remediation: "Check the destination.",
        provenance: { source: "local_plugin" },
      },
    ],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };
  const digest = createHash("sha256")
    .update(
      stringifyJson(payload, {
        compact: true,
        sortKeys: true,
        separators: [",", ":"],
      }),
    )
    .digest("hex");
  const path = `checkpoints/${digest}.json`;
  write(value.scan, path, payload);
  return { [path]: digest };
}
function deep(value: Setup, generation = 2n): void {
  value.request.records = {
    deep_scan_runs: [
      {
        scan_id: scanId,
        schema_version: 1n,
        workflow_version: "deep-security-scan/v1",
        phase: "terminal",
        workers: 1n,
        subagents: 0n,
        stop_after_no_new: 1n,
        max_discovery_runs: 1n,
        status: "failed",
        coordinator_generation: generation,
        publication_error_message: "Needs retry",
        created_at: "created",
        updated_at: "updated",
      },
    ],
  };
}
function run(request: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const result = (parseJson(child.stdout) as unknown as Response[])[0]!;
  expect(result.node).toBe(nodeVersion);
  return result;
}
const outcome = (response: Response) => response.outcomes.at(-1)!;
const rows = (response: Response, table: string) => response.snapshot[table]!;
const resultScan = (response: Response, index = response.outcomes.length - 1) =>
  (
    response.outcomes[index]!.result as {
      scan: {
        findingCount: bigint;
        progress: { status: string };
        reportAvailable: boolean;
        resultsRecoveryNeeded: boolean;
      };
    }
  ).scan;
const locks = (response: Response, index = response.outcomes.length - 1) =>
  response.outcomes[index]!.events.filter(
    (event) => (event as unknown[])[0] === "lock",
  );
const nowCalls = (response: Response) =>
  outcome(response).events.filter((event) => (event as unknown[])[0] === "now");

test("writes the original unsealed documents after validating bound copies", () => {
  const value = setup("draft"),
    payload = draft(value);
  const response = run(value.request);
  expect(outcome(response).result).toEqual({ scanId, status: "draft_written" });
  for (const [key, path] of [
    ["manifest", "scan-manifest.json"],
    ["findings", "findings.json"],
    ["coverage", "coverage.json"],
  ] as const)
    expect(readFileSync(join(value.scan, path), "utf8")).toBe(
      stringifyJson(payload[key], { allowNan: false }) + "\n",
    );
  expect(Object.hasOwn(payload["manifest"]["scan"], "id")).toBe(false);
  expect(rows(response, "scan_artifacts")).toEqual([]);
  expect(rows(response, "scans")[0]!["status"]).toBe("running");
  expect(nowCalls(response)).toHaveLength(1);
  expect(locks(response)).toEqual([
    ["lock", false, false],
    ["lock", true, false],
  ]);
});

test("malformed nested draft values retain assignment errors without writing canonical files", () => {
  for (const field of ["scan", "findings", "coverage"]) {
    const value = setup(`shape-${field}`),
      payload = documents();
    if (field === "scan")
      (payload.manifest as Record<string, unknown>)["scan"] = null;
    else (payload as Record<string, unknown>)[field] = [];
    draft(value, payload);
    const response = run(value.request);
    expect(outcome(response).error).toBe(
      field === "scan"
        ? "'NoneType' object does not support item assignment"
        : "list indices must be integers or slices, not str",
    );
    expect(nowCalls(response)).toHaveLength(1);
    expect(existsSync(join(value.scan, "findings.json"))).toBe(false);
    expect(locks(response).at(-1)).toEqual(["lock", true, false]);
  }
});

test("retains the exact staged checkpoint bytes before a draft digest conflict", () => {
  const value = setup("conflict");
  draft(value);
  const bytes = Buffer.from(`{ "scanId" : "${scanId}", "partial" : true }\n`);
  const path = write(value.scan, "drafts/a.checkpoint.json", bytes);
  value.action.savedArgs = {
    ...value.action.savedArgs,
    checkpointPath: path,
    expectedDraftDigest: "stale",
  };
  const response = run(value.request),
    digest = createHash("sha256").update(bytes).digest("hex");
  expect(outcome(response).error).toStartWith("scan_draft_conflict:");
  expect(
    readFileSync(join(value.scan, "checkpoints", `${digest}.json`)),
  ).toEqual(bytes);
  expect(existsSync(join(value.scan, "findings.json"))).toBe(false);
  expect(nowCalls(response)).toEqual([]);
  expect(locks(response).at(-1)).toEqual(["lock", true, false]);
});

test("draft digests include missing markers and the exact bytes of each canonical document", () => {
  const value = setup("digest", "draftDigest");
  value.action.directory = value.scan;
  const expected = createHash("sha256");
  for (const path of ["scan-manifest.json", "findings.json", "coverage.json"])
    expected.update(path).update("\0missing\0");
  expect(outcome(run(value.request)).result).toBe(expected.digest("hex"));
  write(value.scan, "findings.json", Buffer.from("{}\n"));
  const first = outcome(run(value.request)).result;
  write(value.scan, "findings.json", Buffer.from("{ }\n"));
  expect(outcome(run(value.request)).result).not.toBe(first);
  write(value.scan, "coverage.json", Buffer.from("{"));
  expect(outcome(run(value.request)).error).toBeDefined();
});

test("stopped, sealed and stale-continuation drafts fail before retaining a checkpoint", () => {
  for (const reason of ["stopped", "sealed", "continuation"]) {
    const value = setup(`blocked-${reason}`);
    draft(value);
    value.action.savedArgs!.checkpointPath = write(
      value.scan,
      "drafts/a.checkpoint.json",
      { scanId },
    );
    if (reason === "stopped") value.request.scan!["status"] = "failed";
    if (reason === "sealed")
      value.request.scan!["seal_manifest_digest"] = "sha256:stored";
    if (reason === "continuation")
      Object.assign(value.request.scan!, {
        handoff_status: "pending",
        handoff_claim_token: token,
      });
    const response = run(value.request);
    expect(outcome(response).error).toBeDefined();
    expect(existsSync(join(value.scan, "checkpoints"))).toBe(false);
    expect(nowCalls(response)).toEqual([]);
    expect(locks(response).at(-1)).toEqual(["lock", true, false]);
  }
});

test("rejects staged paths and foreign checkpoints without replacing canonical documents", () => {
  for (const reason of ["outside", "newline", "foreign"]) {
    const value = setup(`staged-${reason}`);
    draft(value);
    if (reason === "outside")
      value.action.savedArgs!.draftPath = write(
        value.root,
        "outside.json",
        documents(),
      );
    if (reason === "newline")
      value.action.savedArgs!.draftPath = join(
        value.scan,
        "drafts",
        "a.json\n",
      );
    if (reason === "foreign")
      value.action.savedArgs!.checkpointPath = write(
        value.scan,
        "drafts/a.checkpoint.json",
        { scanId: "different" },
      );
    const response = run(value.request);
    expect(outcome(response).systemExit).toBe(true);
    expect(nowCalls(response)).toEqual([]);
    expect(existsSync(join(value.scan, "findings.json"))).toBe(false);
  }
});

test("a later write failure retains earlier canonical writes and the checkpoint", () => {
  for (const blocked of ["coverage.json", "scan-manifest.json"]) {
    const value = setup(`partial-${blocked}`),
      payload = draft(value);
    const bytes = Buffer.from(stringifyJson({ scanId }));
    value.action.savedArgs!.checkpointPath = write(
      value.scan,
      "drafts/a.checkpoint.json",
      bytes,
    );
    mkdirSync(join(value.scan, blocked));
    const response = run(value.request);
    expect(outcome(response).error).toBeDefined();
    expect(readFileSync(join(value.scan, "findings.json"), "utf8")).toBe(
      stringifyJson(payload["findings"]) + "\n",
    );
    if (blocked === "scan-manifest.json")
      expect(readFileSync(join(value.scan, "coverage.json"), "utf8")).toBe(
        stringifyJson(payload["coverage"]) + "\n",
      );
    expect(statSync(join(value.scan, blocked)).isDirectory()).toBe(true);
    expect(
      readFileSync(
        join(
          value.scan,
          "checkpoints",
          `${createHash("sha256").update(bytes).digest("hex")}.json`,
        ),
      ),
    ).toEqual(bytes);
    expect(locks(response).at(-1)).toEqual(["lock", true, false]);
  }
});

test("draft writes preserve the caller transaction and retain checkpoints on clock failure", () => {
  const value = setup("caller");
  draft(value);
  value.request.actions.unshift({
    operation: "sql",
    sql: "UPDATE workspaces SET updated_at='caller'",
  });
  const response = run(value.request);
  expect(outcome(response).error).toBeUndefined();
  expect(outcome(response).inTransaction).toBe(true);
  expect(rows(response, "workspaces")[0]!["updated_at"]).toBe("caller");
  const failed = setup("clock");
  draft(failed);
  failed.action.savedArgs!.checkpointPath = write(
    failed.scan,
    "drafts/a.checkpoint.json",
    { scanId },
  );
  failed.action.failNow = true;
  const rejected = run(failed.request);
  expect(outcome(rejected).error).toBe("clock failed");
  expect(existsSync(join(failed.scan, "checkpoints"))).toBe(true);
  expect(existsSync(join(failed.scan, "findings.json"))).toBe(false);
});

test("preserves frozen results and explicitly recovers newly retained checkpoints", () => {
  const value = setup("recover", "preserveResults");
  const frozen = checkpoint(value, "First destination");
  checkpoint(value, "Second destination");
  value.request.scan!["retained_source_digests_json"] = stringifyJson(frozen);
  value.request.actions.push({ operation: "recoverResults" });
  const response = run(value.request);
  for (const item of response.outcomes) expect(item.error).toBeUndefined();
  expect(resultScan(response, 0)["findingCount"]).toBe(1n);
  expect(resultScan(response)["findingCount"]).toBe(2n);
  expect(resultScan(response)["progress"]["status"]).toBe("failed");
  expect(resultScan(response)["reportAvailable"]).toBe(true);
  expect(resultScan(response)["resultsRecoveryNeeded"]).toBe(false);
  expect(rows(response, "scan_artifacts")).toHaveLength(4);
  expect(
    Object.keys(
      parseJson(
        rows(response, "scans")[0]!["retained_source_digests_json"] as string,
      ) as object,
    ),
  ).toHaveLength(2);
  const events = outcome(response).events as unknown[][],
    released = events.findIndex(
      (event) => event[0] === "lock" && event[1] === true,
    );
  expect(released).toBeGreaterThan(0);
  expect(events.slice(released + 1).some((event) => event[0] === "query")).toBe(
    true,
  );
});

test("preservation checks thread ownership before leases and uses the current coordinator generation", () => {
  const wrong = setup("wrong-owner", "preserveResults");
  deep(wrong);
  wrong.request.scan!["continuation_thread_id"] = "continuation";
  wrong.action.savedArgs = {
    threadId: "owner",
    coordinatorGeneration: 1n,
    claimToken: "invalid",
  };
  const rejected = run(wrong.request);
  expect(outcome(rejected).error).toBe(
    "Saved results can only be published from the owning Codex thread.",
  );
  const value = setup("coordinator", "preserveResults");
  deep(value);
  checkpoint(value);
  value.action.savedArgs = {
    threadId: "owner",
    coordinatorGeneration: 2n,
    claimToken: "ignored-by-coordinator",
  };
  const response = run(value.request);
  expect(outcome(response).error).toBeUndefined();
  expect(resultScan(response)["findingCount"]).toBe(1n);
  expect(
    rows(response, "deep_scan_runs")[0]!["publication_error_message"],
  ).toBeNull();
});

test("recovery rejects canceled scans while canceled preservation requires published results", () => {
  for (const operation of ["recoverResults", "preserveResults"] as const) {
    const value = setup(operation, operation);
    value.request.scan!["canceled_at"] = "canceled";
    const response = run(value.request);
    expect(outcome(response).error).toBe(
      operation === "recoverResults"
        ? "Canceled scans cannot recover terminal results."
        : "Saved scan results could not be published or verified.",
    );
    expect(nowCalls(response)).toEqual([]);
  }
  const value = setup("canceled-published", "preserveResults");
  value.request.scan!["canceled_at"] = "canceled";
  value.request.scan!["retained_source_digests_json"] = stringifyJson(
    checkpoint(value),
  );
  const response = run(value.request);
  expect(outcome(response).error).toBeUndefined();
  expect(resultScan(response)["progress"]["status"]).toBe("canceled");
  expect(resultScan(response)["findingCount"]).toBe(1n);
});

test("a publication-clear or rendering failure keeps the committed publication", () => {
  for (const failure of ["clear", "render"]) {
    const value = setup(`published-${failure}`, "recoverResults");
    checkpoint(value);
    deep(value);
    if (failure === "clear")
      value.request.setupSql!.push(
        "CREATE TRIGGER reject_clear BEFORE UPDATE OF publication_error_message ON deep_scan_runs BEGIN SELECT RAISE(ABORT,'clear rejected'); END",
      );
    else value.request.progress = { preflight_issues_json: "{" };
    const response = run(value.request);
    expect(outcome(response).error).toBeDefined();
    expect(outcome(response).inTransaction).toBe(false);
    expect(rows(response, "scan_artifacts")).toHaveLength(4);
    expect(rows(response, "finding_occurrences")).toHaveLength(1);
    expect(rows(response, "scans")[0]!["seal_manifest_digest"]).toStartWith(
      "sha256:",
    );
    expect(existsSync(join(value.scan, "report.md"))).toBe(true);
    expect(
      rows(response, "deep_scan_runs")[0]!["publication_error_message"],
    ).toBe(failure === "clear" ? "Needs retry" : null);
    expect(locks(response).at(-1)).toEqual(["lock", true, false]);
  }
});
