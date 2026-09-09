import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
import type { RemediationUpdateArguments } from "../../../plugins/codex-security/mcp-app/src/workbench-remediation-state";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-remediation-requests-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-remediation-state-")),
);
const target = join(root, "target"),
  scan = join(root, "scan"),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const patch = Buffer.from("synthetic patch\0\xff", "latin1"),
  digest = `sha256:${createHash("sha256").update(patch).digest("hex")}`;
const token = "44444444-4444-4444-8444-444444444444";
const close =
  "INSERT INTO finding_triage(occurrence_id,status,close_reason,updated_at) VALUES ('synthetic-occurrence','closed','wont_fix','closed')";
beforeAll(() => {
  mkdirSync(target);
  mkdirSync(scan, { mode: 0o700 });
  writeFileSync(join(target, "source.txt"), "synthetic source\n");
  writeFileSync(join(scan, "patch.diff"), patch);
  writeFileSync(join(scan, "other.diff"), "other patch");
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
const record = (args: Partial<RemediationUpdateArguments> = {}): Action => ({
  operation: "record",
  args: { baseRevision: "unversioned", ...args },
});
const attempt = (values: NonNullable<Request["attempts"]>[number] = {}) => ({
  patch_path: "patch.diff",
  patch_digest: digest,
  summary: "old summary",
  verification_summary: "old verification",
  ...values,
});
function run(...requests: Omit<Request, "targetPath">[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(
      requests.map((value) => ({
        targetPath: target,
        scan: { scan_dir: scan },
        attempts: [attempt()],
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
const row = (response: Response) =>
  response.snapshot["finding_remediation_attempts"]![0]!;
const error = (response: Response) => response.outcomes[0]!.error;

test("generated updates preserve reviewed patch identity and release host ownership", () => {
  const [result] = run({
    actions: [
      record({
        patchPath: " ./patch.diff ",
        patchDigest: ` ${digest} `,
        summary: " updated ",
      }),
    ],
  });
  expect(error(result!)).toBeUndefined();
  expect(row(result!)).toMatchObject({
    state: "generated",
    version: 2n,
    patch_path: "patch.diff",
    patch_digest: digest,
    summary: "updated",
    verification_summary: "old verification",
    pending_action: null,
    pending_action_claimed_at: null,
    pending_action_claim_token: null,
    pending_action_delivered_at: null,
  });
  expect(
    result!.outcomes[0]!.events.filter(
      (event) => (event as unknown[])[0] === "render",
    ),
  ).toEqual([["render", "11111111-1111-4111-8111-111111111111", false]]);
  const [replaced, changed, missing] = run(
    { actions: [record({ patchPath: "other.diff" })] },
    { actions: [record({ patchDigest: "sha256:" + "a".repeat(64) })] },
    { actions: [record()], attempts: [attempt({ patch_digest: null })] },
  );
  expect(error(replaced!)).toBe(
    "A remediation attempt cannot replace its reviewed patch path.",
  );
  expect(error(changed!)).toBe(
    "A remediation attempt cannot replace its reviewed patch digest.",
  );
  expect(error(missing!)).toBe(
    "Generated remediation states require a scan-local patch path and digest.",
  );
});

test("applied updates check the reviewed patch before beginning the write transaction", () => {
  const action = {
    ...record({ state: "applied" }),
    appliedDigest: "applied-content",
  };
  const [result, rejected] = run(
    {
      actions: [action],
      attempts: [attempt({ state: "generated", pending_action: "apply" })],
    },
    {
      actions: [
        {
          ...action,
          hooks: {
            applied: { error: "reviewed patch is absent", systemExit: true },
          },
        },
      ],
      attempts: [attempt({ state: "generated", pending_action: "apply" })],
    },
  );
  expect(error(result!)).toBeUndefined();
  expect(row(result!)).toMatchObject({
    state: "applied",
    applied_content_digest: "applied-content",
    pending_action: null,
  });
  const events = result!.outcomes[0]!.events as unknown[][];
  expect(events.find((event) => event[0] === "applied")?.at(-1)).toBe(false);
  expect(events.findIndex((event) => event[0] === "applied")).toBeLessThan(
    events.findIndex((event) => event[0] === "now"),
  );
  expect(error(rejected!)).toBe("reviewed patch is absent");
  expect(row(rejected!)).toMatchObject({
    state: "generated",
    version: 1n,
    pending_action_claim_token: token,
  });
});

test("verification retains its claim until completion and requires a summary", () => {
  const base = attempt({
    state: "applied",
    pending_action: "verify",
    pending_action_delivered_at: "delivered",
  });
  const [verifying, missing, verified] = run(
    { attempts: [base], actions: [record({ state: "verifying" })] },
    {
      attempts: [attempt({ state: "verifying", pending_action: "verify" })],
      actions: [record({ state: "verified" })],
    },
    {
      attempts: [attempt({ state: "verifying", pending_action: "verify" })],
      actions: [
        record({ state: "verified", verificationSummary: " checked " }),
      ],
    },
  );
  expect(row(verifying!)).toMatchObject({
    state: "verifying",
    pending_action: "verify",
    pending_action_claim_token: token,
    pending_action_delivered_at: "delivered",
  });
  expect(error(missing!)).toBe(
    "Verified remediation requires a verification summary.",
  );
  expect(row(verified!)).toMatchObject({
    state: "verified",
    verification_summary: "checked",
    pending_action: null,
    pending_action_claim_token: null,
  });
});

test("failed retry summaries and pending-action fields retain their distinct update rules", () => {
  const [failed, retry, replacement] = run(
    { actions: [record({ state: "failed" })] },
    { attempts: [attempt({ state: "failed" })], actions: [record()] },
    {
      attempts: [attempt({ state: "failed" })],
      actions: [record({ summary: "new" })],
    },
  );
  expect(row(failed!)).toMatchObject({
    state: "failed",
    summary: "old summary",
    pending_action: "generate",
    pending_action_claim_token: null,
  });
  expect(row(retry!)).toMatchObject({ state: "generated", summary: null });
  expect(row(replacement!)).toMatchObject({
    state: "generated",
    summary: "new",
  });
});

test("guard, ownership and compare-and-swap failures leave remediation state unchanged", () => {
  const requests: Omit<Request, "targetPath">[] = [
    {
      actions: [record()],
      attempts: [attempt({ pending_action_claim_token: null })],
    },
    { actions: [record({ expectedVersion: 2n })] },
    {
      actions: [record()],
      attempts: [attempt({ patch_digest: "sha256:" + "0".repeat(64) })],
    },
    {
      actions: [record()],
      attempts: [attempt({ base_content_digest: "different" })],
    },
    {
      actions: [
        {
          ...record(),
          hooks: {
            now: { sql: "UPDATE finding_remediation_attempts SET version=2" },
          },
        },
      ],
    },
    { actions: [{ ...record(), hooks: { now: { sql: close } } }] },
  ];
  const results = run(...requests);
  for (const result of results) {
    expect(error(result)).toBeDefined();
    expect(row(result)).toMatchObject({ state: "requested", version: 1n });
    expect(result.outcomes[0]!.inTransaction).toBe(false);
  }
  expect(error(results[2]!)).toBe(
    "Patch digest does not match the scan-local patch file.",
  );
  expect(error(results[3]!)).toBe(
    "Working-tree contents changed. Regenerate the remediation patch against the current checkout.",
  );
  expect(results[5]!.snapshot["finding_triage"]).toEqual([]);
  const [wide] = run({
    attempts: [attempt({ version: 9007199254740993n })],
    actions: [record({ expectedVersion: 9007199254740993n })],
  });
  expect(row(wide!)["version"]).toBe(9007199254740994n);
});

test("input errors preserve caller transactions while failed writes roll them back", () => {
  const edit: Action = {
    operation: "sql",
    sql: "UPDATE scans SET updated_at='caller'",
  };
  const [input, begin, commit] = run(
    { actions: [edit, record({ summary: "x".repeat(2401) })] },
    { actions: [edit, record()] },
    {
      actions: [record()],
      setupSql: [
        "CREATE TABLE deferred_check(id TEXT REFERENCES finding_occurrences(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER deferred_record AFTER UPDATE ON finding_remediation_attempts BEGIN INSERT INTO deferred_check VALUES ('missing'); END",
      ],
    },
  );
  expect(input!.outcomes[1]!.inTransaction).toBe(true);
  expect(input!.snapshot["scans"]![0]!["updated_at"]).toBe("caller");
  expect(begin!.outcomes[1]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(begin!.snapshot["scans"]![0]!["updated_at"]).toBe("updated");
  expect(error(commit!)).toBe("FOREIGN KEY constraint failed");
  expect(row(commit!)).toMatchObject({ state: "requested", version: 1n });
});

test("rendering failure happens after committed updates", () => {
  const [result] = run({
    actions: [
      {
        ...record(),
        hooks: {
          render: {
            error: "render failed",
            sql: "INSERT INTO synthetic_audit VALUES ('render')",
          },
        },
      },
    ],
  });
  expect(error(result!)).toBe("render failed");
  expect(row(result!)).toMatchObject({ state: "generated", version: 2n });
  expect(result!.outcomes[0]!.inTransaction).toBe(true);
  expect(result!.snapshot["synthetic_audit"]).toEqual([{ value: "render" }]);
});
