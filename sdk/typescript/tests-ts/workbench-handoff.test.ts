import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  Action,
  Outcome,
  Request,
  Response,
} from "./support/workbench-handoff-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-handoff-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const token = "11111111-1111-4111-8111-111111111111";
const other = "22222222-2222-4222-8222-222222222222";
const env = { ...process.env, PATH: "", PYTHON: "/unavailable/python" };
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-handoff-fixture.ts", import.meta.url),
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
    env,
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = JSON.parse(child.stdout) as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
const names = (outcome: Outcome) =>
  outcome.events.map((event) => `${event.event}:${event.inTransaction}`);

test("normalizes recovery tokens and preserves legacy delivered continuation access", () => {
  const responses = run(
    {
      actions: [
        {
          operation: "token",
          claimToken: "recovery_{" + token.toUpperCase() + "}",
        },
        { operation: "token", claimToken: "recovery_recovery_" + token },
        { operation: "current", claimToken: null },
      ],
    },
    {
      scan: { handoff_status: "delivered" },
      actions: [{ operation: "current", claimToken: null }],
    },
    {
      scan: { handoff_claim_token: "recovery_" + token },
      actions: [
        { operation: "current", claimToken: "recovery_{" + token + "}" },
        { operation: "current", claimToken: token },
        { operation: "current", claimToken: "invalid" },
      ],
    },
  );
  expect(
    responses[0]!.outcomes.map((item) => item.result ?? item.error),
  ).toEqual([
    "recovery_" + token,
    "claim-token must be a UUID.",
    "continuation rejected",
  ]);
  expect(responses[1]!.outcomes[0]!.result).toBeNull();
  expect(
    responses[2]!.outcomes.map((item) => item.error ?? item.result),
  ).toEqual([null, "continuation rejected", "claim-token must be a UUID."]);
});

test("claims one lease and only resets continuation owners on a stale takeover", () => {
  const initial = {
    handoff_claim_token: token,
    handoff_claimed_at: "2026-01-01T23:00:01Z",
    continuation_thread_id: "old-thread",
    deep_scan_owner_thread_id: "old-thread",
  };
  const [fresh, stale, empty] = run(
    {
      scan: initial,
      actions: [{ operation: "claim", claimToken: other, takeOverStale: true }],
    },
    {
      scan: { ...initial, handoff_claimed_at: "2026-01-01T23:00:00Z" },
      actions: [{ operation: "claim", claimToken: other, takeOverStale: true }],
    },
    {
      scan: {
        continuation_thread_id: "retained",
        deep_scan_owner_thread_id: "retained",
      },
      actions: [{ operation: "claim" }],
    },
  );
  expect(fresh!.snapshot.scans[0]).toMatchObject(initial);
  expect(stale!.snapshot.scans[0]).toMatchObject({
    handoff_claim_token: other,
    continuation_thread_id: null,
    deep_scan_owner_thread_id: null,
  });
  expect(empty!.snapshot.scans[0]).toMatchObject({
    handoff_claim_token: token,
    continuation_thread_id: "retained",
    deep_scan_owner_thread_id: "retained",
  });
  expect(names(fresh!.outcomes[0]!)).toEqual([
    "now:false",
    "scan:false",
    "stale:false",
    "BEGIN:false",
    "state:true",
    "COMMIT:true",
  ]);
  expect(names(stale!.outcomes[0]!)).toEqual([
    "now:false",
    "scan:false",
    "stale:false",
    "BEGIN:false",
    "COMMIT:true",
    "state:false",
  ]);
});

test("releasing the matching pending lease clears both owners and rejects tokenless writes", () => {
  const [response] = run({
    scan: {
      mode: "deep",
      handoff_claim_token: token,
      continuation_thread_id: "old",
      deep_scan_owner_thread_id: "old",
    },
    actions: [
      { operation: "release", claimToken: other },
      { operation: "release" },
      { operation: "current", claimToken: null },
    ],
  });
  expect(response!.outcomes[0]!.snapshot.scans[0]).toMatchObject({
    handoff_claim_token: token,
    continuation_thread_id: "old",
    deep_scan_owner_thread_id: "old",
  });
  expect(response!.outcomes[1]!.snapshot.scans[0]).toMatchObject({
    handoff_claim_token: null,
    continuation_thread_id: null,
    deep_scan_owner_thread_id: null,
  });
  expect(response!.outcomes[2]!.error).toBe("continuation rejected");
});

test("attaches one continuation and gives deep scans the same owner", () => {
  const [response] = run({
    scan: { mode: "deep", handoff_claim_token: token },
    actions: [
      { operation: "attach", threadId: " continuation😀\n" },
      { operation: "attach", threadId: "continuation😀" },
      { operation: "attach", threadId: "other" },
      { operation: "attach", threadId: "continuation😀", claimToken: other },
    ],
  });
  expect(response!.snapshot.scans[0]).toMatchObject({
    continuation_thread_id: "continuation😀",
    deep_scan_owner_thread_id: "continuation😀",
  });
  expect(response!.outcomes.map((item) => item.error ?? null)).toEqual([
    null,
    null,
    "Codex Security scan continuation is owned by another continuation.",
    "Codex Security continuation thread claim token does not match.",
  ]);
  expect(response!.outcomes.every((item) => !item.inTransaction)).toBe(true);
});

test("delivery checks the owning thread, retains its token and only clears standard progress", () => {
  const [standard, deep, recovery] = run(
    {
      scan: {
        handoff_claim_token: token,
        continuation_thread_id: "continuation",
      },
      actions: [
        { operation: "deliver", threadId: "workspace-thread" },
        { operation: "deliver", threadId: "continuation" },
        { operation: "deliver", threadId: "continuation", claimToken: other },
      ],
    },
    {
      scan: { mode: "deep", handoff_claim_token: token },
      actions: [{ operation: "deliver" }],
    },
    {
      scan: { handoff_claim_token: "recovery_" + token },
      actions: [
        {
          operation: "deliver",
          claimToken: "recovery_" + token,
          threadId: "recovery-thread",
        },
      ],
    },
  );
  expect(standard!.outcomes[0]!.error).toContain("owning Codex thread");
  expect(standard!.outcomes[2]!.error).toContain(
    "owned by another continuation",
  );
  expect(standard!.snapshot.scans[0]).toMatchObject({
    handoff_status: "delivered",
    handoff_claim_token: token,
    handoff_claimed_at: null,
  });
  expect(standard!.snapshot.progress[0]).toMatchObject({
    phase_items_total: 0,
    phase_items_completed: 0,
    phase_progress_unit: "checks",
    preflight_checks_total: 0,
    preflight_checks_completed: 0,
  });
  expect(deep!.snapshot.progress[0]).toMatchObject({
    phase_items_total: 9,
    phase_items_completed: 4,
    phase_progress_unit: "files",
    preflight_checks_total: 7,
    preflight_checks_completed: 3,
  });
  expect(recovery!.outcomes[0]!.error).toBeUndefined();
});

test("validates identifiers and thread length before invoking callbacks or transactions", () => {
  const [response] = run({
    actions: [
      { operation: "claim", scanId: "bad", claimToken: "bad" },
      { operation: "deliver", claimToken: "bad", threadId: "😀".repeat(513) },
      { operation: "attach", threadId: " \u001c" },
      { operation: "attach", threadId: "😀".repeat(513) },
    ],
  });
  expect(response!.outcomes.map((item) => item.error)).toEqual([
    "scan-id must be a UUID.",
    "claim-token must be a UUID.",
    "Codex Security continuation thread ID is required.",
    "Text value must be no longer than 512 characters.",
  ]);
  expect(response!.outcomes.every((item) => item.events.length === 0)).toBe(
    true,
  );
});

test("claim state failures roll back no-ops while successful claims commit before state reads", () => {
  const [same, changed] = run(
    {
      scan: { handoff_claim_token: token },
      actions: [{ operation: "claim", writeAt: "state", failAt: "state" }],
    },
    {
      actions: [
        { operation: "claim", writeAt: "state", failAt: "state" },
        { operation: "rollback" },
      ],
    },
  );
  expect(same!.outcomes[0]!.error).toBe("state failed");
  expect(same!.outcomes[0]!.inTransaction).toBe(false);
  expect(same!.snapshot.audit).toEqual([]);
  expect(changed!.outcomes[0]!.inTransaction).toBe(true);
  expect(changed!.outcomes[0]!.snapshot.audit).toEqual([{ event: "state" }]);
  expect(changed!.snapshot.audit).toEqual([]);
  expect(changed!.snapshot.scans[0]).toMatchObject({
    handoff_claim_token: token,
  });
});

test("attachment and delivery keep their idempotent state callbacks inside the rollback handler", () => {
  const requests: Request[] = [];
  for (const operation of ["attach", "deliver"] as const) {
    const action: Action = {
      operation,
      threadId: "continuation",
      writeAt: "state",
      failAt: "state",
    };
    const scan = {
      handoff_claim_token: token,
      continuation_thread_id: "continuation",
    };
    requests.push({
      scan: {
        ...scan,
        ...(operation === "deliver" ? { handoff_status: "delivered" } : {}),
      },
      actions: [action],
    });
    requests.push({
      scan: {
        ...scan,
        ...(operation === "attach" ? { continuation_thread_id: null } : {}),
      },
      actions: [action, { operation: "rollback" }],
    });
  }
  const results = run(...requests);
  for (const index of [0, 2]) {
    expect(results[index]!.outcomes[0]!.inTransaction).toBe(false);
    expect(results[index]!.snapshot.audit).toEqual([]);
  }
  for (const index of [1, 3]) {
    expect(results[index]!.outcomes[0]!.inTransaction).toBe(true);
    expect(results[index]!.snapshot.audit).toEqual([]);
  }
  expect(results[1]!.snapshot.scans[0]).toMatchObject({
    continuation_thread_id: "continuation",
  });
  expect(results[3]!.snapshot.scans[0]).toMatchObject({
    handoff_status: "delivered",
  });
});

test("callback failures and a rejected nested BEGIN preserve the original transaction boundaries", () => {
  const [clock, lookup, stale, attach, nested] = run(
    { actions: [{ operation: "claim", beginExisting: true, failAt: "now" }] },
    {
      actions: [{ operation: "release", beginExisting: true, failAt: "scan" }],
    },
    { actions: [{ operation: "claim", writeAt: "stale", failAt: "stale" }] },
    {
      actions: [
        { operation: "attach", threadId: "continuation", failAt: "now" },
      ],
    },
    {
      actions: [
        { operation: "attach", threadId: "continuation", beginExisting: true },
      ],
    },
  );
  expect(clock!.outcomes[0]!.inTransaction).toBe(true);
  expect(clock!.snapshot.audit).toEqual([{ event: "existing" }]);
  for (const result of [lookup!, stale!, attach!]) {
    expect(result.outcomes[0]!.inTransaction).toBe(false);
    expect(result.snapshot.audit).toEqual([]);
  }
  expect(nested!.outcomes[0]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(nested!.outcomes[0]!.inTransaction).toBe(true);
  expect(names(nested!.outcomes[0]!)).toEqual([
    "BEGIN:false",
    "BEGIN IMMEDIATE:true",
  ]);
});

test("zero-row updates, progress errors and deferred commit failures roll back atomically", () => {
  const [ignored, progress, commit] = run(
    {
      scan: { handoff_claim_token: token },
      setupSql: [
        "CREATE TRIGGER skip_attach BEFORE UPDATE OF continuation_thread_id ON scans BEGIN SELECT RAISE(IGNORE); END",
      ],
      actions: [{ operation: "attach", threadId: "continuation" }],
    },
    {
      scan: { handoff_claim_token: token },
      setupSql: [
        "CREATE TRIGGER fail_progress BEFORE UPDATE ON scan_progress BEGIN SELECT RAISE(ABORT, 'progress failed'); END",
      ],
      actions: [{ operation: "deliver" }],
    },
    {
      setupSql: [
        "PRAGMA foreign_keys=ON",
        "CREATE TABLE parent (id INTEGER PRIMARY KEY)",
        "CREATE TABLE child (id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER fail_commit AFTER UPDATE ON scans BEGIN INSERT INTO child VALUES (1); END",
      ],
      actions: [{ operation: "claim" }],
    },
  );
  expect(ignored!.outcomes[0]!.error).toBe(
    "Codex Security continuation thread could not be attached.",
  );
  expect(progress!.outcomes[0]!.error).toBe("progress failed");
  expect(commit!.outcomes[0]!.error).toBe("FOREIGN KEY constraint failed");
  for (const result of [ignored!, progress!, commit!]) {
    expect(result.outcomes[0]!.inTransaction).toBe(false);
    expect(result.snapshot.scans[0]).toMatchObject({
      handoff_status: "pending",
      updated_at: "original",
    });
  }
  expect(names(commit!.outcomes[0]!).slice(-2)).toEqual([
    "COMMIT:true",
    "ROLLBACK:true",
  ]);
});

async function concurrent(request: Request): Promise<Response> {
  return new Promise((resolve, reject) => {
    const child = spawn(node, [fixture], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0 || stderr)
        reject(new Error(`Node failed (${code}): ${stderr}`));
      else resolve((JSON.parse(stdout) as Response[])[0]!);
    });
    child.stdin.end(JSON.stringify([request]));
  });
}

test("concurrent connections retain one claim owner and serialize repeated delivery", async () => {
  const database = join(directory, "concurrent.sqlite3");
  run({ database, actions: [] });
  const claims = await Promise.all(
    [token, other].map((claimToken) =>
      concurrent({
        database,
        initialize: false,
        actions: [{ operation: "claim", claimToken }],
      }),
    ),
  );
  const owners = new Set(
    claims.map(
      (response) => response.snapshot.scans[0]!["handoff_claim_token"],
    ),
  );
  expect(owners.size).toBe(1);
  const claimToken = [...owners][0] as string;
  const delivered = await Promise.all(
    [0, 1].map(() =>
      concurrent({
        database,
        initialize: false,
        actions: [{ operation: "deliver", claimToken }],
      }),
    ),
  );
  for (const response of delivered) {
    expect(response.node).toBe(nodeVersion);
    expect(response.outcomes[0]!.error).toBeUndefined();
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(response.snapshot.scans[0]).toMatchObject({
      handoff_status: "delivered",
      handoff_claim_token: claimToken,
    });
  }
});
