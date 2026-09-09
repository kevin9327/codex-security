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
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-remediation-requests-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-remediation-requests-")),
);
const target = join(root, "target"),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const requestId = "33333333-3333-4333-8333-333333333333",
  token = "44444444-4444-4444-8444-444444444444",
  other = "55555555-5555-4555-8555-555555555555";
const now = 1786795200123456n,
  updatedAt = "2026-08-15T12:00:00.123456Z";
const generated = {
  state: "generated",
  pending_action: null,
  pending_action_claim_token: null,
  patch_path: "remediation.patch",
  patch_digest: "sha256:" + "1".repeat(64),
};
const close =
  "INSERT INTO finding_triage(occurrence_id,status,close_reason,updated_at) VALUES ('synthetic-occurrence','closed','wont_fix','closed')";
beforeAll(() => {
  mkdirSync(target);
  writeFileSync(join(target, "source.txt"), "synthetic source\n");
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL(
          "./support/workbench-remediation-requests-fixture.ts",
          import.meta.url,
        ),
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
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
function run(...requests: Omit<Request, "targetPath">[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(
      requests.map((request) => ({ targetPath: target, ...request })),
    ),
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
const error = (response: Response, index = 0) =>
  response.outcomes[index]!.error ?? null;
const phase = (response: Response, name: string, index = 0) =>
  response.outcomes[index]!.events.filter(
    (event) => Array.isArray(event) && event[0] === name,
  );
const sql = (text: string): Action => ({ operation: "sql", sql: text });

test("generation snapshots the current target and replays its request without another write", () => {
  const [result] = run({
    actions: [
      { operation: "request" },
      { operation: "request", hooks: { now: { error: "must not run" } } },
    ],
  });
  expect(result!.outcomes.map((outcome) => outcome.error ?? null)).toEqual([
    null,
    null,
  ]);
  expect(attempts(result!)).toHaveLength(1);
  expect(attempts(result!)[0]).toMatchObject({
    request_id: requestId,
    state: "requested",
    version: 1n,
    base_revision: "unversioned",
    pending_action: "generate",
    pending_action_claim_token: token,
    pending_action_claimed_at: updatedAt,
    created_at: updatedAt,
    updated_at: updatedAt,
  });
  expect(attempts(result!)[0]!["base_content_digest"]).toMatch(
    /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
  );
  expect(phase(result!, "now", 1)).toEqual([]);
  expect(result!.snapshot["scans"]![0]!["updated_at"]).toBe("updated");
});

test("generation checks target identity only after the request replay lookup", () => {
  const results = run(
    ...[null, -1n].map((target_inode) => ({
      scan: { target_inode },
      actions: [{ operation: "request" as const }],
    })),
    {
      scan: { target_inode: null, target_path: "missing" },
      attempts: [{}],
      actions: [{ operation: "request" }],
    },
    {
      scan: { target_revision: "another revision" },
      actions: [{ operation: "request" }],
    },
  );
  expect(error(results[0]!)).toContain("does not record checkout identity");
  expect(error(results[1]!)).toContain("checkout path was replaced");
  expect(error(results[2]!)).toBeNull();
  expect(error(results[3]!)).toContain("Repository HEAD changed");
  for (const result of results) expect(phase(result, "now")).toEqual([]);
});

test("new generation supersedes only the latest completed patch and keeps exact versions", () => {
  const [result] = run({
    attempts: [
      {
        request_id: other,
        state: "generated",
        pending_action: null,
        version: 9007199254740993n,
      },
    ],
    actions: [{ operation: "request" }],
  });
  expect(error(result!)).toBeNull();
  expect(attempts(result!)[0]).toMatchObject({
    state: "superseded",
    version: 9007199254740994n,
    pending_action: null,
    pending_action_claim_token: null,
    updated_at: updatedAt,
  });
  expect(attempts(result!)[1]).toMatchObject({
    state: "requested",
    version: 1n,
  });
  const [blocked] = run({
    attempts: [
      { request_id: other, state: "generated", pending_action: "apply" },
    ],
    actions: [{ operation: "request" }],
  });
  expect(error(blocked!)).toContain("active remediation operation");
  expect(attempts(blocked!)[0]!["state"]).toBe("generated");
});

test("failed requests regenerate at the lease boundary and release their pending action", () => {
  const responses = run(
    ...[
      "2026-08-15T11:58:00.123455Z",
      "2026-08-15T11:58:00.123456Z",
      "2026-08-15T11:58:00.123457Z",
    ].map((pending_action_claimed_at) => ({
      attempts: [
        {
          request_id: other,
          state: "failed",
          pending_action_claimed_at,
          version: 7n,
        },
      ],
      actions: [{ operation: "request" as const, now }],
    })),
  );
  expect(responses.map((result) => error(result))).toEqual([
    null,
    null,
    "Finish or retry the active remediation operation before regenerating.",
  ]);
  for (const result of responses.slice(0, 2))
    expect(attempts(result)[0]).toMatchObject({
      state: "failed",
      version: 7n,
      pending_action: null,
      pending_action_claim_token: null,
    });
  expect(phase(responses[0]!, "microseconds")).toEqual([
    ["microseconds", true],
  ]);
});

test("action requests verify the patch and checkout before acquiring the transaction", () => {
  const [apply, verify] = run(
    {
      attempts: [generated],
      actions: [{ operation: "action" }, { operation: "action" }],
    },
    {
      attempts: [{ ...generated, state: "applied" }],
      actions: [{ operation: "action", args: { action: "verify" } }],
    },
  );
  expect(error(apply!)).toBeNull();
  expect(error(apply!, 1)).toBeNull();
  expect(attempts(apply!)[0]).toMatchObject({
    state: "generated",
    version: 2n,
    pending_action: "apply",
    pending_action_claim_token: token,
    updated_at: updatedAt,
  });
  expect((phase(apply!, "patch")[0] as unknown[]).at(-1)).toBe(false);
  expect((phase(apply!, "checkout")[0] as unknown[]).slice(-2)).toEqual([
    { requireBaseContent: true, requireAppliedContent: false },
    false,
  ]);
  expect((phase(verify!, "checkout")[0] as unknown[]).slice(-2)).toEqual([
    { requireBaseContent: false, requireAppliedContent: true },
    false,
  ]);
  expect(phase(apply!, "patch", 1)).toEqual([]);
  expect(phase(apply!, "now", 1)).toEqual([]);
});

test("action validation preserves pending ownership and version precedence", () => {
  const results = run(
    {
      attempts: [
        {
          ...generated,
          pending_action: "apply",
          pending_action_claim_token: other,
        },
      ],
      actions: [{ operation: "action", args: { expectedVersion: 0n } }],
    },
    {
      attempts: [{ ...generated, state: "failed" }],
      actions: [{ operation: "action", args: { expectedVersion: 0n } }],
    },
    {
      attempts: [{ ...generated, patch_path: null }],
      actions: [{ operation: "action" }],
    },
    {
      attempts: [{ ...generated, version: 9007199254740993n }],
      actions: [
        { operation: "action", args: { expectedVersion: 9007199254740993n } },
      ],
    },
  );
  expect(error(results[0]!)).toContain("already pending");
  expect(error(results[1]!)).toContain("changed. Refresh");
  expect(error(results[2]!)).toContain("scan-local patch path and digest");
  expect(error(results[3]!)).toBeNull();
  expect(attempts(results[3]!)[0]!["version"]).toBe(9007199254740994n);
});

test("guard and transaction-time races roll back the complete action request", () => {
  const [guard, closure, version] = run(
    {
      attempts: [generated],
      actions: [
        {
          operation: "action",
          hooks: {
            patch: {
              sql: "INSERT INTO synthetic_audit VALUES ('patch')",
              error: "patch changed",
              systemExit: true,
            },
          },
        },
      ],
    },
    {
      attempts: [generated],
      actions: [{ operation: "action", hooks: { now: { sql: close } } }],
    },
    {
      attempts: [generated],
      actions: [
        {
          operation: "action",
          hooks: {
            now: { sql: "UPDATE finding_remediation_attempts SET version=2" },
          },
        },
      ],
    },
  );
  expect(error(guard!)).toBe("patch changed");
  expect(phase(guard!, "checkout")).toEqual([]);
  expect(guard!.snapshot["synthetic_audit"]).toEqual([]);
  expect(error(closure!)).toContain("Reopen this finding");
  expect(closure!.snapshot["finding_triage"]).toEqual([]);
  expect(error(version!)).toContain("changed. Refresh");
  for (const result of [guard!, closure!, version!]) {
    expect(attempts(result)[0]!["version"]).toBe(1n);
    expect(result.outcomes[0]!.inTransaction).toBe(false);
  }
});

test("resending uses inclusive host and worker lease cutoffs", () => {
  const deadlines: Record<string, string>[] = [
    { pending_action_claimed_at: "2026-08-15T11:58:00.123456Z" },
    { pending_action_claimed_at: "2026-08-15T11:58:00.123457Z" },
    { pending_action_delivered_at: "2026-08-15T11:45:00.123456Z" },
    { pending_action_delivered_at: "2026-08-15T11:45:00.123457Z" },
  ];
  const responses = run(
    ...deadlines.map((values) => ({
      attempts: [{ ...values, pending_action_claim_token: other }],
      actions: [{ operation: "claim" as const }],
    })),
  );
  expect(error(responses[0]!)).toBeNull();
  expect(error(responses[1]!)).toContain("owned by another panel");
  expect(error(responses[2]!)).toBeNull();
  expect(error(responses[3]!)).toContain("execution lease");
  expect(phase(responses[0]!, "stale")).toEqual([["stale", [], true]]);
  expect(phase(responses[2]!, "stale")).toEqual([["stale", [900n], true]]);
  for (const result of [responses[0]!, responses[2]!]) {
    expect(attempts(result)[0]).toMatchObject({
      pending_action_claim_token: token,
      pending_action_delivered_at: null,
      version: 1n,
    });
    expect(result.outcomes[0]!.value).toHaveProperty("actionToken", token);
  }
});

test("resend replays its owner and treats an empty delivery timestamp as delivered", () => {
  const [replay, noOwner] = run(
    {
      attempts: [{ pending_action_delivered_at: updatedAt }],
      actions: [
        { operation: "claim", hooks: { stale: { error: "must not run" } } },
      ],
    },
    {
      attempts: [
        { pending_action_claim_token: null, pending_action_delivered_at: "" },
      ],
      actions: [{ operation: "claim" }],
    },
  );
  expect(error(replay!)).toBeNull();
  expect(phase(replay!, "stale")).toEqual([]);
  expect(attempts(replay!)[0]!["pending_action_delivered_at"]).toBe(updatedAt);
  expect(error(noOwner!)).toContain("execution lease");
});

test("delivery requires ownership while release permits an obsolete token", () => {
  const [wrongDelivery, wrongRelease, recovery] = run(
    {
      attempts: [{}],
      actions: [{ operation: "deliver", args: { actionToken: other } }],
    },
    {
      attempts: [{}],
      actions: [{ operation: "release", args: { actionToken: other } }],
    },
    {
      attempts: [{}],
      setupSql: [close],
      actions: [{ operation: "deliver" }, { operation: "release" }],
    },
  );
  expect(error(wrongDelivery!)).toContain("no longer owned");
  expect(error(wrongRelease!)).toBeNull();
  expect(attempts(wrongRelease!)[0]!["pending_action_claim_token"]).toBe(token);
  expect(recovery!.outcomes.map((outcome) => outcome.error ?? null)).toEqual([
    null,
    null,
  ]);
  expect(attempts(recovery!)[0]).toMatchObject({
    pending_action: "generate",
    pending_action_claimed_at: null,
    pending_action_claim_token: null,
    pending_action_delivered_at: null,
    updated_at: updatedAt,
    version: 1n,
  });
});

test("request validation precedes clocks and leaves a caller transaction intact", () => {
  const responses = run(
    ...["request", "action", "claim", "deliver", "release"].map(
      (operation) => ({
        attempts: [generated],
        actions: [
          sql("UPDATE scans SET updated_at='caller'"),
          {
            operation,
            args: { requestId: "bad", actionToken: "bad" },
          } as Action,
        ],
      }),
    ),
  );
  for (const result of responses) {
    expect(error(result, 1)).toContain("request-id");
    expect(result.outcomes[1]!.events).toEqual([]);
    expect(result.outcomes[1]!.inTransaction).toBe(true);
    expect(result.snapshot["scans"]![0]!["updated_at"]).toBe("caller");
  }
});

test("nested transaction failures preserve the original per-operation rollback boundary", () => {
  const [request, action, claim, delivered] = run(
    {
      actions: [
        sql("UPDATE scans SET updated_at='caller'"),
        { operation: "request" },
      ],
    },
    {
      attempts: [generated],
      actions: [
        sql("UPDATE scans SET updated_at='caller'"),
        { operation: "action" },
      ],
    },
    {
      attempts: [{}],
      actions: [
        sql("UPDATE scans SET updated_at='caller'"),
        { operation: "claim" },
      ],
    },
    {
      attempts: [{}],
      actions: [
        sql("UPDATE scans SET updated_at='caller'"),
        { operation: "deliver" },
      ],
    },
  );
  for (const result of [request!, action!, claim!])
    expect(error(result, 1)).toContain(
      "cannot start a transaction within a transaction",
    );
  expect(request!.outcomes[1]!.inTransaction).toBe(false);
  expect(action!.outcomes[1]!.inTransaction).toBe(false);
  expect(claim!.outcomes[1]!.inTransaction).toBe(true);
  expect(error(delivered!, 1)).toBeNull();
  expect(delivered!.outcomes[1]!.inTransaction).toBe(false);
  expect(delivered!.snapshot["scans"]![0]!["updated_at"]).toBe("caller");
});

test("render failures retain committed work and preserve replay rollback behavior", () => {
  const hooks = {
    render: {
      sql: "INSERT INTO synthetic_audit VALUES ('render')",
      error: "render failed",
    },
  };
  const [created, replay] = run(
    { actions: [{ operation: "request", hooks }] },
    { attempts: [{}], actions: [{ operation: "request", hooks }] },
  );
  expect(error(created!)).toBe("render failed");
  expect(attempts(created!)).toHaveLength(1);
  expect(created!.outcomes[0]!.inTransaction).toBe(true);
  expect(created!.snapshot["synthetic_audit"]).toEqual([{ value: "render" }]);
  expect(error(replay!)).toBe("render failed");
  expect(replay!.outcomes[0]!.inTransaction).toBe(false);
  expect(replay!.snapshot["synthetic_audit"]).toEqual([]);
});

test("commit-time foreign key errors roll back generation, action and delivery writes", () => {
  const responses = run(
    ...["request", "action", "claim", "deliver", "release"].map(
      (operation) => ({
        attempts:
          operation === "request"
            ? []
            : [
                operation === "action"
                  ? generated
                  : {
                      pending_action_claim_token:
                        operation === "claim" ? null : token,
                    },
              ],
        setupSql: [
          "CREATE TABLE deferred_audit(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
          `CREATE TRIGGER deferred_failure AFTER ${operation === "request" ? "INSERT" : "UPDATE"} ON finding_remediation_attempts BEGIN INSERT INTO deferred_audit VALUES ('missing'); END`,
        ],
        actions: [{ operation } as Action],
      }),
    ),
  );
  for (const result of responses) {
    expect(error(result)).toBe("FOREIGN KEY constraint failed");
    expect(result.outcomes[0]!.inTransaction).toBe(false);
    expect(phase(result, "render")).toEqual([]);
    for (const attempt of attempts(result))
      expect(attempt["updated_at"]).toBe("updated");
  }
  expect(attempts(responses[0]!)).toEqual([]);
});
