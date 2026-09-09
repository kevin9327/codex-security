import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  Outcome,
  Request,
  Response,
} from "./support/workbench-progress-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-progress-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const workspaceId = "33333333-3333-4333-8333-333333333333";
const token = "11111111-1111-4111-8111-111111111111";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-progress-fixture.ts", import.meta.url),
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
    input: JSON.stringify(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = JSON.parse(child.stdout) as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
const names = (outcome: Outcome) =>
  outcome.events.map((event) => `${event.event}:${event.inTransaction}`);
const issue = {
  capability: " workers ",
  reason: " unavailable ",
  severity: "warn",
  status: "unknown",
};

test("accepts non-ASCII preflight JSON above 64 KiB and the maximum issue list through stdin", () => {
  const unicode = JSON.stringify(
    Array(24).fill({ ...issue, reason: "€".repeat(1000) }),
  );
  const maximum = JSON.stringify(
    Array(32).fill({ ...issue, reason: "x".repeat(1200) }),
  );
  expect(Buffer.byteLength(unicode)).toBeGreaterThan(64 * 1024);
  expect(unicode.length).toBeLessThan(30_000);
  const [response] = run({
    actions: [
      { operation: "issues", value: unicode },
      {
        operation: "progress",
        args: { preflightIssuesJsonStdin: true },
        stdin: maximum,
      },
    ],
  });
  expect(JSON.parse(response!.outcomes[0]!.result as string)).toHaveLength(24);
  expect(
    JSON.parse(
      response!.snapshot.progress[0]!["preflight_issues_json"] as string,
    ),
  ).toHaveLength(32);
  expect(response!.outcomes[1]!.events[0]!.event).toBe("stdin");
  expect(
    (
      JSON.parse(response!.outcomes[0]!.result as string) as {
        reason: string;
      }[]
    ).map(({ reason }) => reason),
  ).toEqual(Array(24).fill("€".repeat(1000)));
  expect(
    (
      JSON.parse(
        response!.snapshot.progress[0]!["preflight_issues_json"] as string,
      ) as { reason: string }[]
    ).map(({ reason }) => reason),
  ).toEqual(Array(32).fill("x".repeat(1200)));
});

test("missing progress rows fail when first read after earlier phase validation", () => {
  const [response] = run({
    scan: { phase: "discovery" },
    setupSql: ["DELETE FROM scan_progress"],
    actions: [
      { operation: "progress", args: { phase: "preflight" } },
      { operation: "progress" },
      {
        operation: "progress",
        args: { phase: "validation", phaseItemsTotal: 1 },
      },
    ],
  });
  expect(response!.outcomes.map((value) => value.error)).toEqual([
    "Scan progress cannot move to an earlier phase.",
    "'NoneType' object is not subscriptable",
    "Phase progress with a nonzero total requires a progress unit.",
  ]);
  expect(response!.outcomes.every((value) => !value.inTransaction)).toBe(true);
});

test("preflight issues retain exact compact JSON and count UTF-16 units", () => {
  const [response] = run({
    actions: [
      {
        operation: "issues",
        value: JSON.stringify([
          { ...issue, capability: "😀".repeat(64), reason: "\ud800" },
        ]),
      },
      {
        operation: "issues",
        value: JSON.stringify([{ ...issue, capability: "😀".repeat(65) }]),
      },
      {
        operation: "issues",
        value: JSON.stringify([{ ...issue, reason: "😀".repeat(600) }]),
      },
      {
        operation: "issues",
        value: JSON.stringify([{ ...issue, reason: "😀".repeat(601) }]),
      },
      { operation: "length", value: "é😀\ud800" },
    ],
  });
  expect(response!.outcomes[0]!.result).toBe(
    '[{"capability":"' +
      "\\ud83d\\ude00".repeat(64) +
      '","reason":"\\ud800","severity":"warn","status":"unknown"}]',
  );
  expect(response!.outcomes[1]!.error).toContain("1 to 128 characters");
  expect(response!.outcomes[2]!.error).toBeUndefined();
  expect(response!.outcomes[3]!.error).toContain("1 to 1200 characters");
  expect(response!.outcomes[4]!.result).toBe(4);
});

test("preflight validation keeps shape and field failure order without limiting JSON bytes", () => {
  const [response] = run({
    actions: [
      { operation: "issues", value: "{" },
      { operation: "issues", value: JSON.stringify(Array(33).fill(issue)) },
      {
        operation: "issues",
        value: JSON.stringify([{ ...issue, extra: true, severity: [] }]),
      },
      {
        operation: "issues",
        value: JSON.stringify([{ ...issue, severity: [], status: {} }]),
      },
      {
        operation: "issues",
        value: JSON.stringify([{ ...issue, severity: "bad", status: {} }]),
      },
      {
        operation: "issues",
        value:
          '[{"capability":NaN,"reason":"x","severity":"warn","status":"fail"}]',
      },
      {
        operation: "issues",
        value: JSON.stringify(
          Array(32).fill({ ...issue, reason: "x".repeat(1200) }),
        ),
      },
    ],
  });
  expect(response!.outcomes.slice(0, 6).map((value) => value.error)).toEqual([
    "Preflight issues must be valid JSON.",
    "Preflight issues must be an array of at most 32 objects.",
    "Preflight issue 1 must contain capability, reason, severity, and status.",
    "unhashable type: 'list'",
    "Preflight issue 1 has an invalid severity or status.",
    "Preflight issue 1 capability must be text.",
  ]);
  expect(JSON.parse(response!.outcomes[6]!.result as string)).toHaveLength(32);
});

test("preflight receipts persist when phase-specific counters reset and discovery counts clear", () => {
  const [response] = run({
    actions: [
      {
        operation: "progress",
        args: {
          phaseItemsTotal: 4,
          phaseItemsCompleted: 3,
          phaseProgressUnit: "checks",
          preflightIssuesJson: JSON.stringify([issue]),
        },
      },
      {
        operation: "progress",
        args: { phaseItemsCompleted: 4, preflightIssuesJson: "[]" },
      },
      { operation: "progress", args: { phase: "threat_model" } },
      { operation: "progress", args: { phase: "validation" } },
      { operation: "progress", args: { preflightIssuesJson: "[]" } },
    ],
  });
  expect(response!.outcomes[0]!.snapshot.progress[0]).toMatchObject({
    preflight_checks_total: 4,
    preflight_checks_completed: 3,
  });
  expect(response!.outcomes[2]!.snapshot.progress[0]).toMatchObject({
    phase_items_total: 0,
    phase_items_completed: 0,
    phase_progress_unit: null,
    preflight_checks_total: 4,
    preflight_checks_completed: 4,
    preflight_issues_json: "[]",
    reportable_findings_count: 8,
  });
  expect(response!.outcomes[3]!.snapshot.progress[0]).toMatchObject({
    reportable_findings_count: 0,
  });
  expect(response!.outcomes[4]!.error).toContain(
    "only be updated during preflight",
  );
});

test("phase counters reject regression, changed units and completed counts above totals", () => {
  const [response] = run({
    scan: { phase: "validation" },
    progress: {
      phase_items_total: 5,
      phase_items_completed: 3,
      phase_progress_unit: "candidate_findings",
    },
    actions: [
      { operation: "progress", args: { phase: "discovery" } },
      { operation: "progress", args: { phaseItemsTotal: 4 } },
      { operation: "progress", args: { phaseItemsCompleted: 2 } },
      { operation: "progress", args: { phaseProgressUnit: "checks" } },
      { operation: "progress", args: { phaseItemsCompleted: 6 } },
      {
        operation: "progress",
        args: { phase: "reporting", phaseItemsTotal: 1 },
      },
    ],
  });
  expect(response!.outcomes.map((value) => value.error)).toEqual([
    "Scan progress cannot move to an earlier phase.",
    "Phase item total cannot decrease within a phase.",
    "Completed phase items cannot decrease within a phase.",
    "Phase progress unit cannot change within a phase.",
    "Completed phase items cannot exceed total phase items.",
    "Phase progress with a nonzero total requires a progress unit.",
  ]);
  expect(response!.snapshot.scans[0]).toMatchObject({
    phase: "validation",
    updated_at: "original",
  });
});

test("deep review passes reset completed counts and preserve within-pass monotonicity", () => {
  const [response] = run({
    scan: { mode: "deep" },
    progress: {
      deep_review_pass: 1,
      review_items_total: 10,
      review_items_completed: 7,
    },
    actions: [
      {
        operation: "progress",
        args: { deepReviewPass: 2, reviewItemsTotal: 3 },
      },
      {
        operation: "progress",
        args: {
          deepReviewPass: 2,
          reviewItemsTotal: 3,
          reviewItemsCompleted: 0,
        },
      },
      { operation: "progress", args: { reviewItemsCompleted: 2 } },
      { operation: "progress", args: { reviewItemsCompleted: 1 } },
      { operation: "progress", args: { deepReviewPass: 1 } },
      { operation: "progress", args: { reviewItemsCompleted: 4 } },
    ],
  });
  expect(response!.outcomes.map((value) => value.error ?? null)).toEqual([
    "A new Deep Scan review pass must start with zero completed items.",
    null,
    null,
    "Completed review items cannot decrease within a review pass.",
    "Deep Scan progress cannot move to an earlier review pass.",
    "Completed review items cannot exceed total review items.",
  ]);
  expect(response!.snapshot.progress[0]).toMatchObject({
    deep_review_pass: 2,
    review_items_total: 3,
    review_items_completed: 2,
  });
});

test("coordinator leases distinguish unclaimed, missing and superseded generations", () => {
  const [legacy, claimed, terminal, standard] = run(
    {
      scan: { mode: "deep" },
      coordinator: { coordinator_generation: 1 },
      actions: [
        { operation: "progress" },
        { operation: "progress", args: { coordinatorGeneration: 1 } },
      ],
    },
    {
      scan: { mode: "deep" },
      coordinator: { coordinator_generation: 3 },
      actions: [
        { operation: "progress" },
        { operation: "progress", args: { coordinatorGeneration: 2 } },
        { operation: "progress", args: { coordinatorGeneration: 3 } },
        {
          operation: "progress",
          args: { coordinatorGeneration: 3, preflightIssuesJson: "[]" },
        },
      ],
    },
    {
      scan: { mode: "deep" },
      coordinator: { coordinator_generation: 3, status: "succeeded" },
      actions: [{ operation: "progress" }],
    },
    {
      actions: [
        { operation: "progress", args: { coordinatorGeneration: 1 } },
        { operation: "progress", args: { deepReviewPass: 1 } },
      ],
    },
  );
  expect(legacy!.outcomes.map((value) => value.error ?? null)).toEqual([
    null,
    "Deep Scan coordinator lease has not been claimed.",
  ]);
  expect(claimed!.outcomes.map((value) => value.error ?? null)).toEqual([
    "Deep Scan mutation requires the current coordinator lease.",
    "Deep Scan coordinator lease belongs to a newer generation.",
    null,
    "Deep Scan preflight progress is owned by its coordinator.",
  ]);
  expect(terminal!.outcomes[0]!.error).toBeUndefined();
  expect(standard!.outcomes.map((value) => value.error)).toEqual([
    "Coordinator leases apply only to Deep Scan progress.",
    "Only Deep Scan can record a deep review pass.",
  ]);
});

test("workspace context changes update both records while continuation updates retain saved context", () => {
  const [workspace, thread] = run(
    {
      actions: [
        {
          operation: "update",
          args: { command: "update-scan-context", userContextStdin: true },
          stdin: "  context😀\n",
        },
      ],
    },
    {
      scan: {
        handoff_claim_token: token,
        continuation_thread_id: "continuation",
      },
      actions: [
        {
          operation: "context",
          args: {
            workspaceId: null,
            threadId: "workspace-thread",
            claimToken: token,
          },
        },
        {
          operation: "context",
          args: {
            workspaceId: null,
            threadId: "continuation",
            claimToken: null,
          },
        },
        {
          operation: "context",
          args: {
            workspaceId: null,
            threadId: " continuation ",
            claimToken: token,
          },
        },
      ],
    },
  );
  expect(workspace!.snapshot.scans[0]).toMatchObject({
    user_context: "context😀",
  });
  expect(workspace!.snapshot.workspaces[0]).toMatchObject({
    user_context: "context😀",
  });
  expect(names(workspace!.outcomes[0]!)).toEqual([
    "stdin:false",
    "BEGIN IMMEDIATE:false",
    "scan:true",
    "workspace:true",
    "now:true",
    "COMMIT:true",
    "context:false",
  ]);
  expect(thread!.outcomes.slice(0, 2).map((value) => value.error)).toEqual([
    "This scan does not belong to the current Codex thread.",
    "Scan context updates are owned by another continuation.",
  ]);
  expect(thread!.snapshot.scans[0]).toMatchObject({
    user_context: "replacement",
  });
  expect(thread!.snapshot.workspaces[0]).toMatchObject({
    user_context: "saved",
    updated_at: "2026-01-02T00:00:00Z",
  });
});

test("late progress and context updates reject canceled scans before other ownership checks", () => {
  const [response] = run({
    scan: {
      status: "canceled",
      canceled_at: "2026-01-01T00:00:00Z",
      mode: "deep",
    },
    actions: [
      {
        operation: "progress",
        args: { coordinatorGeneration: 9, claimToken: "invalid" },
      },
      {
        operation: "context",
        args: { workspaceId: "invalid", claimToken: "invalid" },
      },
    ],
  });
  expect(response!.outcomes.map((value) => value.error)).toEqual([
    "Only a running scan can update progress.",
    "Only a running scan can update context.",
  ]);
  expect(names(response!.outcomes[0]!)).toEqual([
    "BEGIN IMMEDIATE:false",
    "now:true",
    "scan:true",
    "ROLLBACK:true",
  ]);
  expect(names(response!.outcomes[1]!)).toEqual([
    "BEGIN IMMEDIATE:false",
    "scan:true",
    "ROLLBACK:true",
  ]);
});

test("validation and lazy stdin precede BEGIN without consuming input on earlier failures", () => {
  const [response] = run({
    actions: [
      {
        operation: "progress",
        args: { model: "😀".repeat(201), preflightIssuesJsonStdin: true },
        failAt: "stdin",
      },
      {
        operation: "context",
        args: { scanId: "invalid", userContextStdin: true },
        failAt: "stdin",
      },
      {
        operation: "progress",
        args: { preflightIssuesJsonStdin: true },
        stdin: "{",
      },
      {
        operation: "progress",
        args: {
          model: "😀".repeat(200),
          reasoningEffort: "\u001c high ",
          phase: "discovery",
        },
      },
    ],
  });
  expect(response!.outcomes.slice(0, 2).map((value) => value.events)).toEqual([
    [],
    [],
  ]);
  expect(names(response!.outcomes[2]!)).toEqual(["stdin:false"]);
  expect(response!.outcomes[2]!.error).toBe(
    "Preflight issues must be valid JSON.",
  );
  expect(response!.snapshot.scans[0]).toMatchObject({
    model: "😀".repeat(200),
    reasoning_effort: "high",
    phase: "discovery",
  });
});

test("callback and SQL failures roll back both progress writes and context changes", () => {
  const [clock, progressWrite, workspaceWrite, changed] = run(
    { actions: [{ operation: "progress", failAt: "now", writeAt: "now" }] },
    {
      setupSql: [
        "CREATE TRIGGER fail_phase BEFORE UPDATE OF phase_items_total ON scan_progress BEGIN SELECT RAISE(ABORT, 'phase failed'); END",
      ],
      actions: [
        {
          operation: "progress",
          args: {
            model: "new",
            preflightIssuesJson: JSON.stringify([issue]),
            phaseItemsTotal: 4,
            phaseProgressUnit: "checks",
          },
        },
      ],
    },
    {
      setupSql: [
        "CREATE TRIGGER fail_workspace BEFORE UPDATE ON workspaces BEGIN SELECT RAISE(ABORT, 'workspace failed'); END",
      ],
      actions: [{ operation: "context" }],
    },
    {
      actions: [
        {
          operation: "progress",
          afterReadSql: "UPDATE scans SET status = 'canceled'",
        },
      ],
    },
  );
  expect(
    [clock!, progressWrite!, workspaceWrite!, changed!].map(
      (value) => value.outcomes[0]!.error,
    ),
  ).toEqual([
    "now failed",
    "phase failed",
    "workspace failed",
    "Only a running scan can update progress.",
  ]);
  for (const value of [clock!, progressWrite!, workspaceWrite!, changed!]) {
    expect(value.outcomes[0]!.inTransaction).toBe(false);
    expect(value.snapshot.audit).toEqual([]);
    expect(value.snapshot.scans[0]).toMatchObject({
      updated_at: "original",
      status: "running",
      user_context: "scan context",
    });
  }
});

test("failed commit rolls back and post-commit context exceptions retain the committed mutation", () => {
  const [commit, callback, nested] = run(
    {
      setupSql: [
        "PRAGMA foreign_keys=ON",
        "CREATE TABLE parent (id INTEGER PRIMARY KEY)",
        "CREATE TABLE child (id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER fail_commit AFTER UPDATE ON scans BEGIN INSERT INTO child VALUES (1); END",
      ],
      actions: [{ operation: "progress" }],
    },
    {
      actions: [
        { operation: "context", failAt: "context", writeAt: "context" },
        { operation: "rollback" },
      ],
    },
    { actions: [{ operation: "progress", beginExisting: true }] },
  );
  expect(commit!.outcomes[0]!.error).toBe("FOREIGN KEY constraint failed");
  expect(commit!.outcomes[0]!.inTransaction).toBe(false);
  expect(commit!.snapshot.scans[0]).toMatchObject({ updated_at: "original" });
  expect(callback!.outcomes[0]!.inTransaction).toBe(true);
  expect(callback!.snapshot.scans[0]).toMatchObject({
    user_context: "replacement",
  });
  expect(callback!.snapshot.audit).toEqual([]);
  expect(nested!.outcomes[0]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(nested!.snapshot.audit).toEqual([{ event: "existing" }]);
  expect(nested!.outcomes[0]!.inTransaction).toBe(true);
});

test("workspace selection validates claim conflicts and UUID ownership before the clock", () => {
  const [response] = run({
    actions: [
      {
        operation: "context",
        args: { workspaceId: "invalid", claimToken: token },
      },
      { operation: "context", args: { workspaceId: "invalid" } },
      { operation: "context", args: { workspaceId: token } },
      {
        operation: "context",
        args: { workspaceId: "{" + workspaceId + "}", userContext: " \u001c " },
      },
    ],
  });
  expect(response!.outcomes.map((value) => value.error ?? null)).toEqual([
    "claim-token is only valid with thread-id.",
    "workspace-id must be a UUID.",
    "This scan does not belong to the selected workspace.",
    null,
  ]);
  expect(
    response!.outcomes
      .slice(0, 3)
      .every((value) => !value.events.some((event) => event.event === "now")),
  ).toBe(true);
  expect(response!.snapshot.scans[0]).toMatchObject({ user_context: null });
});
