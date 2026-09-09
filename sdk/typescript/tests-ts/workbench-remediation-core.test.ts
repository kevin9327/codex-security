import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
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
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-remediation-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-remediation-")),
);
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const scanId = "11111111-1111-4111-8111-111111111111";
const requestId = "33333333-3333-4333-8333-333333333333";
const token = "44444444-4444-4444-8444-444444444444";
const other = "55555555-5555-4555-8555-555555555555";
const older = "66666666-6666-4666-8666-666666666666";
const now = 1786795200123456n;
const updatedAt = "2026-08-15T12:00:00.123456Z";
const cancel: Action = { operation: "cancel" };
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-remediation-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(root, { recursive: true, force: true }));
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
const attempts = (response: Response) =>
  response.snapshot["finding_remediation_attempts"]!;
const scan = (response: Response) => response.snapshot["scans"]![0]!;
const error = (response: Response, index = 0) =>
  response.outcomes[index]!.error ?? null;

test("availability checks the occurrence and completed scan only for remediation commands", () => {
  const responses = run(
    ...["complete", "running", "failed"].map(
      (status): Request => ({
        scan: { status },
        actions: [
          { operation: "available", command: "request-finding-remediation" },
        ],
      }),
    ),
    {
      occurrences: [],
      actions: [
        {
          operation: "available",
          command: "get-scan",
          occurrenceId: null,
          scanError: "must not run",
        },
      ],
    },
    {
      occurrences: [],
      actions: [{ operation: "available", command: "set-finding-remediation" }],
    },
    {
      scan: { canceled_at: "canceled" },
      actions: [{ operation: "available", command: "set-finding-remediation" }],
    },
  );
  expect(responses.map((response) => error(response))).toEqual([
    null,
    "Remediation is available only for successfully completed scans.",
    "Remediation is available only for successfully completed scans.",
    null,
    "Codex Security finding occurrence not found.",
    null,
  ]);
  expect(responses[0]!.outcomes[0]!.events).toEqual([
    ["query", "SELECT * FROM finding_occurrences WHERE id = ?", false],
    ["scan", scanId, false],
    ["query", "SELECT * FROM scans WHERE id = ?", false],
  ]);
  expect(responses[3]!.outcomes[0]!.events).toEqual([]);
  expect(responses[4]!.outcomes[0]!.events).toHaveLength(1);
});

test("claim and delivery leases expire at the exact microsecond cutoff in every offset", () => {
  const values: Record<string, string>[] = [
    { pending_action_claimed_at: "2026-08-15T11:58:00.123455Z" },
    { pending_action_claimed_at: "2026-08-15T11:58:00.123456z" },
    { pending_action_claimed_at: "2026-08-15T11:58:00.123457Z" },
    { pending_action_claimed_at: "2026-08-15T17:28:00.123456+05:30" },
    { pending_action_claimed_at: "2026-08-15T11:58:17.358023+00:00:17.234567" },
    {
      pending_action_claimed_at: "2026-08-15T10:00:00Z",
      pending_action_delivered_at: "2026-08-15T11:45:00.123456Z",
    },
    {
      pending_action_claimed_at: "2026-08-15T10:00:00Z",
      pending_action_delivered_at: "2026-08-15T11:45:00.123457Z",
    },
  ];
  const responses = run(
    ...values.map(
      (row): Request => ({ actions: [{ operation: "lease", values: row }] }),
    ),
  );
  expect(responses.map((response) => response.outcomes[0]!.value)).toEqual([
    false,
    false,
    true,
    false,
    false,
    false,
    true,
  ]);
  for (const response of responses)
    expect(response.outcomes[0]!.events).toEqual([["now", false]]);
});

test("invalid or naive claim times remain active without consulting the clock", () => {
  const responses = run(
    ...["invalid", "2026-08-15T11:00:00", "2026-02-29T11:00:00Z", null].map(
      (claimedAt): Request => ({
        actions: [
          {
            operation: "lease",
            values: { pending_action_claimed_at: claimedAt },
            nowError: "clock failed",
          },
        ],
      }),
    ),
    {
      actions: [
        {
          operation: "lease",
          values: { pending_action_claim_token: null },
          nowError: "clock failed",
        },
      ],
    },
    { actions: [{ operation: "lease", nowError: "clock failed" }] },
    {
      actions: [
        {
          operation: "lease",
          values: { pending_action_claimed_at: "2026-08-15T11:00:00Z" },
          blobs: { pending_action_delivered_at: "" },
        },
      ],
    },
  );
  expect(
    responses.slice(0, 5).map((response) => response.outcomes[0]!.value),
  ).toEqual([true, true, true, true, false]);
  for (const response of responses.slice(0, 5))
    expect(response.outcomes[0]!.events).toEqual([]);
  expect(error(responses[5]!)).toBe("clock failed");
  expect(responses[6]!.outcomes[0]!.value).toBe(false);
});

test("transition guards retain retries and pending actions prevent skipping work", () => {
  const actions: Action[] = [
    { operation: "transition", current: "requested", requested: "generated" },
    { operation: "transition", current: "failed", requested: "verified" },
    { operation: "transition", current: "verified", requested: "verifying" },
    { operation: "transition", current: "verified", requested: "failed" },
    { operation: "transition", current: "idle", requested: "requested" },
    {
      operation: "pending",
      current: "requested",
      requested: "generated",
      pending: null,
    },
    {
      operation: "pending",
      current: "generated",
      requested: "applied",
      pending: "generate",
    },
    {
      operation: "pending",
      current: "generated",
      requested: "applied",
      pending: "apply",
    },
    {
      operation: "pending",
      current: "failed",
      requested: "verified",
      pending: "verify",
    },
    {
      operation: "pending",
      current: "verified",
      requested: "verified",
      pending: null,
    },
  ];
  const [response] = run({ actions });
  expect(response!.outcomes.map((outcome) => outcome.error ?? null)).toEqual([
    null,
    null,
    null,
    "Finding remediation cannot move from verified to failed.",
    "Finding remediation cannot move from idle to requested.",
    "Request generate before recording remediation state generated.",
    "Pending remediation action generate cannot record state applied.",
    null,
    null,
    null,
  ]);
});

test("canceling generation restores the last superseded request and preserves repeat cancellation", () => {
  const [response] = run({
    attempts: [
      {
        request_id: other,
        state: "superseded",
        version: 9007199254740993n,
        pending_action: null,
        created_at: "before",
        patch_path: "patch.diff",
        patch_digest: "sha256:synthetic",
      },
      { created_at: "current" },
    ],
    actions: [cancel, cancel],
  });
  expect(attempts(response!)).toHaveLength(1);
  expect(attempts(response!)[0]).toMatchObject({
    request_id: other,
    state: "generated",
    version: 9007199254740994n,
    patch_path: "patch.diff",
    patch_digest: "sha256:synthetic",
    updated_at: updatedAt,
  });
  expect(scan(response!)["updated_at"]).toBe(updatedAt);
  expect(response!.outcomes.map((outcome) => outcome.value)).toEqual([
    scanId,
    scanId,
  ]);
  expect(
    response!.outcomes[0]!.events.filter(
      (event) => (event as string[])[0] === "now",
    ),
  ).toEqual([["now", true]]);
  expect(
    response!.outcomes[1]!.events.some(
      (event) => (event as string[])[0] === "now",
    ),
  ).toBe(false);
  expect(response!.outcomes.every((outcome) => !outcome.inTransaction)).toBe(
    true,
  );
});

test("restoration selects the latest row and treats an empty applied digest as applied", () => {
  const [tied, failed] = run(
    {
      attempts: [
        {
          request_id: older,
          state: "superseded",
          created_at: "same",
          applied_content_digest: null,
        },
        {
          request_id: other,
          state: "superseded",
          created_at: "same",
          applied_content_digest: "",
        },
        { created_at: "current" },
      ],
      actions: [cancel],
    },
    {
      attempts: [
        { request_id: older, state: "superseded", created_at: "before" },
        { request_id: other, state: "failed", created_at: "latest" },
        { created_at: "current" },
      ],
      actions: [cancel],
    },
  );
  expect(
    attempts(tied!).map((row) => [
      row["request_id"],
      row["state"],
      row["version"],
    ]),
  ).toEqual([
    [older, "superseded", 1n],
    [other, "applied", 2n],
  ]);
  expect(attempts(failed!).map((row) => row["state"])).toEqual([
    "superseded",
    "failed",
  ]);
});

test("canceling apply or verify clears pending ownership and advances only the attempt version", () => {
  const responses = run(
    ...[
      ["generated", "apply"],
      ["applied", "verify"],
    ].map(
      ([state, pending_action]): Request => ({
        attempts: [
          {
            state: state!,
            pending_action: pending_action!,
            pending_action_delivered_at: "delivered",
            version: 7n,
          },
        ],
        actions: [cancel],
      }),
    ),
  );
  for (const [index, response] of responses.entries()) {
    expect(attempts(response)[0]).toMatchObject({
      state: index ? "applied" : "generated",
      version: 8n,
      pending_action: null,
      pending_action_claim_token: null,
      pending_action_claimed_at: null,
      pending_action_delivered_at: null,
      updated_at: updatedAt,
    });
    expect(scan(response)["updated_at"]).toBe("updated");
  }
});

test("canceling a failed retry preserves pending work and its version while releasing the claim", () => {
  const [response] = run({
    attempts: [
      {
        state: "failed",
        pending_action: "generate",
        pending_action_delivered_at: "delivered",
        version: 9n,
      },
    ],
    actions: [cancel, { operation: "cancel", args: { actionToken: other } }],
  });
  expect(attempts(response!)[0]).toMatchObject({
    state: "failed",
    pending_action: "generate",
    version: 9n,
    updated_at: updatedAt,
    pending_action_claim_token: null,
    pending_action_claimed_at: null,
    pending_action_delivered_at: null,
  });
  expect(response!.outcomes[1]!.value).toBe(scanId);
  expect(
    response!.outcomes[1]!.events.some(
      (event) => (event as string[])[0] === "now",
    ),
  ).toBe(false);
  expect(scan(response!)["updated_at"]).toBe("updated");
});

test("cancellation checks finding ownership before no-op branches and rejects another action token", () => {
  const responses = run(
    {
      occurrences: [{}, {}],
      attempts: [
        { occurrence_id: "synthetic-occurrence-1", pending_action: null },
      ],
      actions: [cancel],
    },
    {
      attempts: [{}],
      actions: [{ operation: "cancel", args: { actionToken: other } }],
    },
    {
      attempts: [{ pending_action: null }],
      actions: [
        {
          operation: "cancel",
          args: { actionToken: other },
          nowError: "must not run",
        },
      ],
    },
    { actions: [{ operation: "cancel", nowError: "must not run" }] },
  );
  expect(responses.map((response) => error(response))).toEqual([
    "This remediation request belongs to a different finding.",
    "This remediation host request is owned by a different action token.",
    null,
    null,
  ]);
  for (const response of responses) {
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(
      response.outcomes[0]!.events.some(
        (event) => (event as string[])[0] === "now",
      ),
    ).toBe(false);
  }
});

test("UUID validation precedes BEGIN and a failed BEGIN leaves the caller transaction intact", () => {
  const [response] = run({
    attempts: [{}],
    actions: [
      { operation: "sql", sql: "UPDATE scans SET updated_at='caller'" },
      {
        operation: "cancel",
        args: {
          requestId: "invalid",
          actionToken: "invalid",
          occurrenceId: null,
        },
      },
      cancel,
      { operation: "rollback" },
    ],
  });
  expect(response!.outcomes[1]).toMatchObject({
    error: "request-id must be a UUID.",
    inTransaction: true,
  });
  expect(response!.outcomes[1]!.events).toEqual([]);
  expect(response!.outcomes[2]).toMatchObject({
    error: "cannot start a transaction within a transaction",
    inTransaction: true,
  });
  expect(response!.outcomes[2]!.events).toEqual([
    ["query", "BEGIN IMMEDIATE", true],
    ["transaction", "BEGIN IMMEDIATE", true],
  ]);
  expect(scan(response!)["updated_at"]).toBe("updated");
  expect(attempts(response!)).toHaveLength(1);
});

test("generation validation and clock failure roll back without losing the active request", () => {
  const [generated, clock] = run(
    { attempts: [{ state: "generated" }], actions: [cancel] },
    {
      attempts: [{}],
      actions: [
        {
          operation: "cancel",
          nowError: "clock failed",
          nowSql: "INSERT INTO synthetic_audit VALUES ('clock')",
        },
      ],
    },
  );
  expect(error(generated!)).toBe(
    "Only a requested patch generation can be canceled.",
  );
  expect(generated!.outcomes[0]!.events).toContainEqual(["now", true]);
  expect(error(clock!)).toBe("clock failed");
  expect(clock!.snapshot["synthetic_audit"]).toEqual([]);
  for (const response of [generated!, clock!]) {
    expect(response.outcomes[0]!.events.at(-1)).toEqual([
      "transaction",
      "ROLLBACK",
      true,
    ]);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(attempts(response)[0]).toMatchObject({
      request_id: requestId,
      pending_action_claim_token: token,
      updated_at: "updated",
    });
  }
});

test("restoration and deferred commit failures roll back the deleted generation", () => {
  const responses = run(
    ...[
      [
        "CREATE TRIGGER reject_restore BEFORE UPDATE ON finding_remediation_attempts BEGIN SELECT RAISE(ABORT, 'restore rejected'); END",
      ],
      [
        "CREATE TABLE deferred_audit(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER deferred_failure AFTER DELETE ON finding_remediation_attempts BEGIN INSERT INTO deferred_audit VALUES ('missing'); END",
      ],
    ].map(
      (setupSql): Request => ({
        attempts: [
          { request_id: other, state: "superseded", created_at: "before" },
          {},
        ],
        actions: [cancel],
        setupSql,
      }),
    ),
  );
  expect(responses.map((response) => error(response))).toEqual([
    "restore rejected",
    "FOREIGN KEY constraint failed",
  ]);
  for (const response of responses) {
    expect(attempts(response).map((row) => row["state"])).toEqual([
      "superseded",
      "requested",
    ]);
    expect(scan(response)["updated_at"]).toBe("updated");
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(response.outcomes[0]!.events.at(-1)).toEqual([
      "transaction",
      "ROLLBACK",
      true,
    ]);
  }
});

test("cancellation timestamps retain six-digit precision and omit empty fractions", () => {
  const responses = run(
    ...[now, now - (now % 1_000_000n), -1n].map(
      (instant): Request => ({
        attempts: [{ pending_action: "apply" }],
        actions: [{ operation: "cancel", now: instant }],
      }),
    ),
  );
  expect(
    responses.map((response) => attempts(response)[0]!["updated_at"]),
  ).toEqual([updatedAt, "2026-08-15T12:00:00Z", "1969-12-31T23:59:59.999999Z"]);
});
