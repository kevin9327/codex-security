import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Operation } from "./support/navigation-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-finding-command-")),
);
const node = Bun.which("node")!,
  fixture = join(root, "fixture.cjs");
const workspace = "11111111-1111-4111-8111-111111111111";
const environment = { ...process.env, PATH: "", PYTHON: "/unavailable/python" };
const nodeMajor = Number(
  spawnSync(node, ["-p", "process.versions.node.split('.')[0]"], {
    encoding: "utf8",
  }).stdout,
);
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/navigation-fixture.ts", import.meta.url),
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
function setup() {
  const directory = mkdtempSync(join(root, "case-")),
    target = join(directory, "target"),
    state = join(directory, "state"),
    scanRoot = join(directory, "outputs");
  mkdirSync(target);
  writeFileSync(join(target, "source.ts"), "synthetic source\n");
  return { directory, target, state, scanRoot };
}
type Setup = ReturnType<typeof setup>;
function helper(
  args: string[],
  s: Setup,
  input?: string | Buffer,
  env = environment,
) {
  return spawnSync(node, [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args], {
    input,
    encoding: "utf8",
    env: {
      ...env,
      CODEX_SECURITY_STATE_DIR: s.state,
      CODEX_HOME: join(s.directory, "codex"),
      CODEX_SQLITE_HOME: join(s.directory, "sqlite"),
    },
  });
}
function result(
  args: string[],
  s: Setup,
  input?: string,
  env = environment,
): Record<string, unknown> {
  const child = helper(args, s, input, env);
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Record<string, unknown>;
}
function snapshot(s: Setup) {
  const child = spawnSync(node, [fixture, join(s.state, "workbench.sqlite3")], {
    input: stringifyJson({ operations: [{ snapshot: true }] }),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  return (
    JSON.parse(child.stdout) as {
      value: Record<string, Record<string, unknown>[]>;
    }[]
  )[0]!.value;
}
const current = (s: Setup) => snapshot(s)["scans"]![0]!;
const workspaceArgs = (s: Setup) => [
  "--workspace-id",
  workspace,
  "--target-path",
  s.target,
  "--scope",
  ".",
  "--mode",
  "standard",
];
const token = "22222222-2222-4222-8222-222222222222";
const cost = JSON.stringify({
  model: "synthetic",
  inputTokens: 10,
  cachedInputTokens: 0,
  cacheWriteInputTokens: 0,
  outputTokens: 2,
  estimatedUsd: 0.25,
});
function startScan(s: Setup) {
  result(
    ["create-workspace", "--workspace-id", workspace, "--thread-id", "owner"],
    s,
  );
  result(["save-workspace", ...workspaceArgs(s)], s);
  const started = result(
    ["start-scan", "--workspace-id", workspace, "--scan-root", s.scanRoot],
    s,
  );
  const scanId = (started["results"] as Record<string, unknown>)[
    "scanId"
  ] as string;
  result(
    ["claim-handoff-delivery", "--scan-id", scanId, "--claim-token", token],
    s,
  );
  result(
    [
      "mark-handoff-delivered",
      "--scan-id",
      scanId,
      "--claim-token",
      token,
      "--thread-id",
      "owner",
    ],
    s,
  );
  return scanId;
}
type Table = Record<string, unknown>;
function draft(s: Setup) {
  const scan = current(s),
    directory = scan["scan_dir"] as string;
  const read = (name: string) =>
    JSON.parse(
      readFileSync(join(PLUGIN_ROOT, "examples/completed-scan", name), "utf8"),
    ) as Table;
  const manifest = read("scan-manifest.json"),
    manifestScan = manifest["scan"] as Table;
  delete manifestScan["sealedAt"];
  delete manifestScan["artifacts"];
  manifestScan["target"] = {
    kind: "directory_snapshot",
    snapshotDigest: scan["target_snapshot_digest"],
  };
  const findings = read("findings.json"),
    coverage = read("coverage.json");
  for (const finding of findings["findings"] as Table[])
    for (const key of ["findingId", "occurrenceId", "fingerprints"])
      delete finding[key];
  const path = join(directory, "drafts", "a-b.json");
  mkdirSync(join(directory, "drafts"), { recursive: true });
  writeFileSync(path, JSON.stringify({ manifest, findings, coverage }));
  return { path, directory };
}
const requestId = "33333333-3333-4333-8333-333333333333";
const actionToken = "44444444-4444-4444-8444-444444444444";
const patch =
  "--- a/source.ts\n+++ b/source.ts\n@@ -1 +1 @@\n-synthetic source\n+changed source\n";
const patchDigest = `sha256:${createHash("sha256").update(patch).digest("hex")}`;
function completed() {
  const s = setup(),
    scanId = startScan(s),
    staged = draft(s);
  result(
    [
      "write-scan-draft",
      "--scan-id",
      scanId,
      "--claim-token",
      token,
      "--draft-path",
      staged.path,
    ],
    s,
  );
  result(
    [
      "complete-scan",
      "--scan-id",
      scanId,
      "--claim-token",
      token,
      "--cost-json",
      cost,
    ],
    s,
  );
  const occurrenceId = snapshot(s)["finding_occurrences"]![0]!["id"] as string;
  writeFileSync(join(staged.directory, "reviewed.patch"), patch);
  return { ...s, scanId, occurrenceId };
}
function finding(value: Table, occurrenceId: string) {
  return ((value["scan"] as Table)["findings"] as Table[]).find(
    (item) => item["occurrenceId"] === occurrenceId,
  )!;
}
const identity = (s: { occurrenceId: string }) => [
  "--occurrence-id",
  s.occurrenceId,
  "--request-id",
  requestId,
  "--action-token",
  actionToken,
];
const generatedArgs = (s: { occurrenceId: string }) => [
  "set-finding-remediation",
  ...identity(s),
  "--expected-version",
  "1",
  "--state",
  "generated",
  "--patch-path",
  "reviewed.patch",
  "--patch-digest",
  patchDigest,
  "--base-revision",
  "unversioned",
  "--summary",
  "Reviewed change",
];

test("finding triage and remediation commands retain claim and patch ownership without Python", () => {
  const s = completed(),
    args = identity(s);
  let value = result(["request-finding-remediation", ...args], s);
  expect(finding(value, s.occurrenceId)["remediationState"]).toMatchObject({
    state: "requested",
    version: 1,
    actionClaimToken: actionToken,
  });
  result(["release-finding-remediation-claim", ...args], s);
  value = result(["claim-finding-remediation-resend", ...args], s);
  expect(finding(value, s.occurrenceId)["remediationState"]).toMatchObject({
    actionClaimToken: actionToken,
  });
  result(["mark-finding-remediation-delivered", ...args], s);
  const invalidDigest = helper(
    [...generatedArgs(s), "--patch-digest", "sha256:" + "0".repeat(64)],
    s,
  );
  expect(invalidDigest.status).toBe(1);
  expect(invalidDigest.stderr).toContain("Patch digest does not match");
  value = result(generatedArgs(s), s);
  expect(finding(value, s.occurrenceId)["remediationState"]).toMatchObject({
    state: "generated",
    version: 2,
    pendingAction: null,
    patchDigest,
  });
  value = result(
    [
      "request-finding-remediation-action",
      ...args,
      "--expected-version",
      "2",
      "--action",
      "apply",
    ],
    s,
  );
  expect(finding(value, s.occurrenceId)["remediationState"]).toMatchObject({
    version: 3,
    pendingAction: "apply",
  });
  const unchanged = helper(
    [
      "set-finding-remediation",
      ...args,
      "--expected-version",
      "3",
      "--state",
      "applied",
      "--base-revision",
      "unversioned",
    ],
    s,
  );
  expect(unchanged.status).toBe(1);
  expect(unchanged.stderr).toContain("checkout is unchanged");
  result(["cancel-finding-remediation-request", ...args], s);
  value = result(
    [
      "set-finding-triage",
      "--occurrence-id",
      s.occurrenceId,
      "--status",
      "closed",
      "--close-reason",
      "false_positive",
      "--note",
      "Source flow is bounded.",
    ],
    s,
  );
  expect(finding(value, s.occurrenceId)["triage"]).toMatchObject({
    status: "closed",
    closeReason: "false_positive",
    note: "Source flow is bounded.",
  });
  const closed = helper(["request-finding-remediation", ...args], s);
  expect(closed.status).toBe(1);
  expect(closed.stderr).toContain("Reopen this finding");
  value = result(
    [
      "set-finding-triage",
      "--occurrence-id",
      s.occurrenceId,
      "--status",
      "open",
    ],
    s,
  );
  expect(finding(value, s.occurrenceId)["triage"]).toMatchObject({
    status: "open",
    closeReason: null,
  });
});

test("reviewed patches proceed through apply, verification and triage with persisted checkout guards", () => {
  const s = completed(),
    args = identity(s),
    git = Bun.which("git")!;
  const env = { ...environment, PATH: dirname(git) };
  const run = (command: string[]) => result(command, s, undefined, env);
  run(["request-finding-remediation", ...args]);
  run(generatedArgs(s));
  run([
    "request-finding-remediation-action",
    ...args,
    "--expected-version",
    "2",
    "--action",
    "apply",
  ]);
  const applied = spawnSync(
    git,
    [
      "apply",
      "--no-index",
      join(current(s)["scan_dir"] as string, "reviewed.patch"),
    ],
    { cwd: s.target, encoding: "utf8" },
  );
  expect(applied.status, applied.stderr).toBe(0);
  const setState = (version: number, state: string) => [
    "set-finding-remediation",
    ...args,
    "--expected-version",
    String(version),
    "--state",
    state,
    "--base-revision",
    "unversioned",
  ];
  const unrelated = join(s.target, "unrelated.txt");
  writeFileSync(unrelated, "outside the reviewed patch\n");
  const extraChanges = helper(setState(3, "applied"), s, undefined, env);
  expect(extraChanges.status).toBe(1);
  expect(extraChanges.stderr).toContain("changes outside the reviewed patch");
  rmSync(unrelated);
  expect(
    finding(run(setState(3, "applied")), s.occurrenceId)["remediationState"],
  ).toMatchObject({ state: "applied", version: 4 });
  run([
    "request-finding-remediation-action",
    ...args,
    "--expected-version",
    "4",
    "--action",
    "verify",
  ]);
  expect(
    finding(run(setState(5, "verifying")), s.occurrenceId)["remediationState"],
  ).toMatchObject({ state: "verifying", version: 6, pendingAction: "verify" });
  expect(
    finding(
      run([
        ...setState(6, "verified"),
        "--verification-summary",
        "Focused regression tests passed.",
      ]),
      s.occurrenceId,
    )["remediationState"],
  ).toMatchObject({ state: "verified", version: 7, pendingAction: null });
  const close = [
    "set-finding-triage",
    "--occurrence-id",
    s.occurrenceId,
    "--status",
    "closed",
    "--close-reason",
    "already_fixed",
  ];
  writeFileSync(join(s.target, "source.ts"), "changed after verification\n");
  const stale = helper(close, s, undefined, env);
  expect(stale.status).toBe(1);
  expect(stale.stderr).toContain("Working-tree contents changed");
  writeFileSync(join(s.target, "source.ts"), "changed source\n");
  expect(finding(run(close), s.occurrenceId)["triage"]).toMatchObject({
    status: "closed",
    closeReason: "already_fixed",
  });
  expect(
    finding(run(["get-scan", "--scan-id", s.scanId]), s.occurrenceId),
  ).toMatchObject({
    triage: { status: "closed" },
    remediationState: { state: "verified", version: 7 },
  });
});

test("finding commands reject invalid arguments and remediation on stopped scans", () => {
  const s = setup();
  for (const args of [
    ["request-finding-remediation"],
    ["set-finding-triage", "--occurrence-id", "synthetic", "--status", "other"],
    [
      "request-finding-remediation-action",
      ...identity({ occurrenceId: "synthetic" }),
      "--expected-version",
      "0",
      "--action",
      "apply",
    ],
    [
      "set-finding-remediation",
      ...identity({ occurrenceId: "synthetic" }),
      "--expected-version",
      "1",
      "--state",
      "requested",
    ],
  ])
    expect(helper(args, s).status).toBe(2);
  expect(existsSync(s.state)).toBe(false);
  const stopped = completed();
  const operations: Operation[] = [
    {
      sql: "UPDATE scans SET status='failed' WHERE id=?",
      parameters: [stopped.scanId],
    },
    { sql: "COMMIT" },
  ];
  const child = spawnSync(
    node,
    [fixture, join(stopped.state, "workbench.sqlite3")],
    {
      input: stringifyJson({ operations }),
      encoding: "utf8",
      env: environment,
    },
  );
  expect(child.status, child.stderr).toBe(0);
  const unavailable = helper(
    ["request-finding-remediation", ...identity(stopped)],
    stopped,
  );
  expect(unavailable.status).toBe(1);
  expect(unavailable.stderr).toContain(
    "Remediation is available only for successfully completed scans",
  );
});

test.skipIf(nodeMajor < 22)(
  "SDK routes all eight finding commands through Node",
  () => {
    const s = completed(),
      args = identity(s);
    const commands = [
      ["request-finding-remediation", ...args],
      ["release-finding-remediation-claim", ...args],
      ["claim-finding-remediation-resend", ...args],
      ["mark-finding-remediation-delivered", ...args],
      generatedArgs(s),
      [
        "request-finding-remediation-action",
        ...args,
        "--expected-version",
        "2",
        "--action",
        "apply",
      ],
      ["cancel-finding-remediation-request", ...args],
      [
        "set-finding-triage",
        "--occurrence-id",
        s.occurrenceId,
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "The residual risk is accepted.",
      ],
    ];
    const operations: Operation[] = commands.map((sdk) => ({
      sdk,
      pluginRoot: PLUGIN_ROOT,
      stateDir: s.state,
    }));
    const child = spawnSync(node, [fixture], {
      input: stringifyJson({ operations }),
      encoding: "utf8",
      env: environment,
    });
    expect(child.status, child.stderr).toBe(0);
    const responses = JSON.parse(child.stdout) as {
      error?: string;
      value: Table;
    }[];
    expect(responses).toHaveLength(commands.length);
    for (const response of responses) expect(response.error).toBeUndefined();
    expect(finding(responses.at(-1)!.value, s.occurrenceId)).toMatchObject({
      triage: { status: "closed" },
      remediationState: { state: "generated", pendingAction: null, version: 4 },
    });
  },
);
