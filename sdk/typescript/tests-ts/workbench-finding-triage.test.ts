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
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { FindingTriageArguments } from "../../../plugins/codex-security/mcp-app/src/workbench-finding-triage";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-remediation-requests-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-finding-triage-")),
);
const target = join(root, "target"),
  scan = join(root, "scan"),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() => {
  mkdirSync(target);
  mkdirSync(scan, { mode: 0o700 });
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
const triage = (args: Partial<FindingTriageArguments> = {}): Action => ({
  operation: "triage",
  args,
});
const close = (): Action =>
  triage({ status: "closed", closeReason: "already_fixed" });
function run(...requests: Omit<Request, "targetPath">[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(
      requests.map((value) => ({
        targetPath: target,
        scan: { scan_dir: scan },
        ...value,
      })),
    ),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return parseJson(child.stdout) as unknown as Response[];
}
const decision = (response: Response) =>
  response.snapshot["finding_decisions"]!;
const current = (response: Response) =>
  response.snapshot["finding_triage"]![0]!;
const error = (response: Response) => response.outcomes[0]!.error;

test("unchanged decisions refresh the timestamp without adding history or drawing a UUID", () => {
  const [unchanged, changed] = run(
    {
      actions: [
        triage(),
        {
          ...triage(),
          now: 1786795200123457n,
          hooks: { uuid: { error: "must not run" } },
        },
      ],
    },
    {
      actions: [
        triage(),
        triage({ note: " checked " }),
        triage({ note: "checked" }),
        close(),
        triage(),
      ],
    },
  );
  expect(
    unchanged!.outcomes.every((outcome) => outcome.error === undefined),
  ).toBe(true);
  expect(decision(unchanged!)).toHaveLength(1);
  expect(decision(unchanged!)[0]).toMatchObject({
    status: "open",
    created_at: "2026-08-15T12:00:00.123456Z",
  });
  expect(current(unchanged!)).toMatchObject({
    status: "open",
    close_reason: null,
    note: null,
    updated_at: "2026-08-15T12:00:00.123457Z",
  });
  expect(
    decision(changed!).map((row) => [
      row["status"],
      row["close_reason"],
      row["note"],
    ]),
  ).toEqual([
    ["open", null, null],
    ["open", null, "checked"],
    ["closed", "already_fixed", null],
    ["open", null, null],
  ]);
});

test("invalid close reasons and notes fail before mutating triage", () => {
  const results = run(
    { actions: [triage({ closeReason: "already_fixed" })] },
    { actions: [triage({ status: "closed" })] },
    {
      actions: [
        triage({ status: "closed", closeReason: "false_positive", note: "  " }),
      ],
    },
    { actions: [triage({ status: "closed", closeReason: "wont_fix" })] },
    { actions: [triage({ note: "😀".repeat(2401) })] },
    { actions: [triage({ occurrenceId: "missing" })] },
  );
  expect(results.map(error)).toEqual([
    "An open finding cannot keep a close reason.",
    "Choose why this finding is being closed.",
    "Explain why this finding is a false positive.",
    "Explain why this finding will not be fixed.",
    "Text value must be no longer than 2400 characters.",
    "Codex Security finding occurrence not found.",
  ]);
  for (const result of results) {
    expect(decision(result)).toEqual([]);
    expect(result.snapshot["finding_triage"]).toEqual([]);
    expect(result.outcomes[0]!.inTransaction).toBe(false);
  }
});

test("closing waits for pending operations except failed attempts whose lease expired", () => {
  const results = run(
    { actions: [close()], attempts: [{}] },
    {
      actions: [close()],
      attempts: [{ state: "failed", pending_action_claim_token: null }],
    },
    {
      actions: [close()],
      attempts: [
        {
          state: "failed",
          pending_action_claimed_at: "2026-08-15T11:58:00.123456Z",
        },
      ],
    },
    {
      actions: [close()],
      attempts: [
        {
          state: "failed",
          pending_action_claimed_at: "2026-08-15T11:58:00.123457Z",
        },
      ],
    },
    {
      actions: [close()],
      attempts: [
        {
          state: "failed",
          pending_action_delivered_at: "2026-08-15T11:45:00.123456Z",
        },
      ],
    },
    {
      actions: [close()],
      attempts: [
        {
          state: "failed",
          pending_action_delivered_at: "2026-08-15T11:45:00.123457Z",
        },
      ],
    },
  );
  expect(results.map((result) => error(result) === undefined)).toEqual([
    false,
    true,
    true,
    false,
    true,
    false,
  ]);
  expect(error(results[0]!)).toBe(
    "Wait for the pending remediation operation to finish before closing this finding.",
  );
});

test("the newest remediation attempt controls closure, including equal timestamps", () => {
  const earlier = {
    request_id: "55555555-5555-4555-8555-555555555555",
    pending_action: "generate",
    created_at: "same",
  };
  const [allowed, blocked] = run(
    {
      actions: [close()],
      attempts: [earlier, { pending_action: null, created_at: "same" }],
    },
    {
      actions: [close()],
      attempts: [
        { ...earlier, created_at: "z" },
        { pending_action: null, created_at: "a" },
      ],
    },
  );
  expect(error(allowed!)).toBeUndefined();
  expect(error(blocked!)).toContain("pending remediation operation");
});

test("already-fixed closure checks the verified checkout before writing the decision", () => {
  const verified = { state: "verified", pending_action: null };
  const [allowed, changed, otherReason, wrongRevision] = run(
    { actions: [close()], attempts: [verified] },
    {
      actions: [close()],
      attempts: [{ ...verified, applied_content_digest: "changed" }],
    },
    {
      actions: [
        triage({ status: "closed", closeReason: "wont_fix", note: "accepted" }),
      ],
      attempts: [{ ...verified, applied_content_digest: "changed" }],
    },
    {
      actions: [close()],
      attempts: [{ ...verified, base_revision: "changed" }],
    },
  );
  expect(error(allowed!)).toBeUndefined();
  expect(error(changed!)).toContain("Working-tree contents changed.");
  expect(decision(changed!)).toEqual([]);
  expect(error(otherReason!)).toBeUndefined();
  expect(error(wrongRevision!)).toContain("Repository HEAD changed.");
});

test("a caller-owned transaction survives BEGIN failure and later triage write failures roll back", () => {
  const [caller, rejected] = run(
    {
      actions: [
        { operation: "sql", sql: "UPDATE scans SET updated_at='caller'" },
        triage(),
      ],
    },
    {
      actions: [triage()],
      setupSql: [
        "CREATE TRIGGER reject_triage BEFORE INSERT ON finding_triage BEGIN SELECT RAISE(ABORT, 'blocked'); END",
      ],
    },
  );
  expect(caller!.outcomes[1]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(caller!.outcomes[1]!.inTransaction).toBe(true);
  expect(caller!.snapshot["scans"]![0]!["updated_at"]).toBe("caller");
  expect(error(rejected!)).toBe("blocked");
  expect(decision(rejected!)).toEqual([]);
  expect(rejected!.snapshot["finding_triage"]).toEqual([]);
  expect(rejected!.outcomes[0]!.inTransaction).toBe(false);
});

test("clock and UUID failures roll back while rendering happens after commit", () => {
  const results = run(
    ...(["now", "uuid", "render"] as const).map((phase) => ({
      actions: [
        { ...triage(), hooks: { [phase]: { error: "synthetic failure" } } },
      ],
    })),
  );
  expect(results.map(error)).toEqual([
    "synthetic failure",
    "synthetic failure",
    "synthetic failure",
  ]);
  expect(results.map((result) => decision(result).length)).toEqual([0, 0, 1]);
  expect(results.map((result) => result.outcomes[0]!.inTransaction)).toEqual([
    false,
    false,
    false,
  ]);
});
