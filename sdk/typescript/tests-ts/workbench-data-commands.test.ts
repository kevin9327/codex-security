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
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Operation } from "./support/navigation-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-data-command-")),
);
const node = Bun.which("node")!,
  fixture = join(root, "fixture.cjs");
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
function helper(args: string[], s: Setup, input?: string | Buffer) {
  return spawnSync(node, [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args], {
    input,
    encoding: "utf8",
    env: {
      ...environment,
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
): Record<string, unknown> {
  const child = helper(args, s, input);
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
type Table = Record<string, unknown>;
function draft(s: Setup, scanId: string) {
  const scan = snapshot(s)["scans"]!.find((row) => row["id"] === scanId)!,
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

function register(s: Setup) {
  const scanDir = mkdtempSync(join(s.directory, "scan-"));
  const recipe = {
    repository: s.target,
    mode: "standard",
    maxCostUsd: 0.5,
    config: {},
    target: { kind: "repository", paths: [] },
  };
  return result(
    [
      "register-cli-scan",
      "--repository",
      s.target,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify(recipe),
    ],
    s,
  )["scanId"] as string;
}
function complete(s: Setup) {
  const scanId = register(s),
    staged = draft(s, scanId);
  result(
    ["write-scan-draft", "--scan-id", scanId, "--draft-path", staged.path],
    s,
  );
  result(["complete-scan", "--scan-id", scanId], s);
  return { scanId, scanDirectory: staged.directory };
}
function sdk(s: Setup, commands: { args: string[]; input?: string }[]) {
  const operations: Operation[] = commands.map(({ args, input }) => ({
    sdk: args,
    ...(input === undefined ? {} : { input }),
    pluginRoot: PLUGIN_ROOT,
    stateDir: s.state,
  }));
  const child = spawnSync(node, [fixture], {
    input: stringifyJson({ operations }),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  return JSON.parse(child.stdout) as { error?: string; value: Table }[];
}
const matches = JSON.stringify({ matches: [], uncertain: [] });

test("comparison, exports and publication receipts use sealed scans without Python", () => {
  const s = setup(),
    before = complete(s),
    after = complete(s);
  const pair = [
    "--before-scan-id",
    before.scanId,
    "--after-scan-id",
    after.scanId,
  ];
  expect(
    result(["list-unmatched-scan-pairs", "--repository", s.target], s)[
      "scanCount"
    ],
  ).toBe(2);
  expect(
    result(["compare-scans", ...pair, "--include-matching-inputs"], s),
  ).toMatchObject({
    beforeScanId: before.scanId,
    afterScanId: after.scanId,
    matchingInputs: { before: expect.any(Array) },
  });
  const missing = helper(["compare-scans", ...pair, "--require-matches"], s);
  expect(missing.status).toBe(1);
  expect(missing.stderr).toContain("No saved matches");
  result(["save-scan-comparison", ...pair, "--matches-json", matches], s);
  result(["save-scan-comparison", ...pair, "--matches-json-stdin"], s, matches);
  const conflicting = helper(
    [
      "save-scan-comparison",
      ...pair,
      "--matches-json",
      matches,
      "--matches-json-stdin",
    ],
    s,
    matches,
  );
  expect(conflicting.status).toBe(2);
  expect(conflicting.stderr).toContain("not allowed with argument");
  const occurrence = (scanId: string) =>
    snapshot(s)["finding_occurrences"]!.find(
      (row) => row["scan_id"] === scanId,
    )!["id"] as string;
  const reason = "Synthetic comparison 🙂 " + "x".repeat(64 * 1024);
  const oversized = JSON.stringify({
    matches: [
      {
        beforeOccurrenceIds: [occurrence(before.scanId)],
        afterOccurrenceIds: [occurrence(after.scanId)],
        confidence: "high",
        reason,
      },
    ],
    uncertain: [],
  });
  result(
    ["save-scan-comparison", ...pair, "--matches-json-stdin"],
    s,
    oversized,
  );
  expect(
    (
      JSON.parse(
        snapshot(s)["scan_comparisons"]![0]!["result_json"] as string,
      ) as {
        matches: { reason: string }[];
      }
    ).matches[0]!.reason,
  ).toBe(reason);
  result(["compare-scans", ...pair, "--require-matches"], s);
  expect(snapshot(s)["scan_comparisons"]).toHaveLength(1);
  for (const format of ["json", "csv", "sarif"]) {
    const exported = result(
      ["export-findings", "--scan-id", after.scanId, "--format", format],
      s,
    )["export"] as Table;
    expect(exported["format"]).toBe(format);
    expect(
      readFileSync(exported["path"] as string, "utf8").length,
    ).toBeGreaterThan(0);
  }
  const findings = (
    JSON.parse(
      readFileSync(join(after.scanDirectory, "findings.json"), "utf8"),
    ) as { findings: Table[] }
  ).findings;
  const payload = {
    ...after,
    destination: { type: "linear", teamId: "synthetic-team" },
    findings: findings.map((f) => ({
      findingId: f["findingId"],
      occurrenceId: f["occurrenceId"],
    })),
  };
  const path = join(s.directory, "publication.json"),
    args = ["--input-file", path];
  writeFileSync(path, JSON.stringify(payload));
  expect(
    result(["inspect-linear-publication", ...args], s)["recorded"],
  ).toEqual([]);
  expect(
    result(["prepare-linear-publication", ...args], s)["findingCount"],
  ).toBe(findings.length);
  const publications = payload.findings.map((f, i) => ({
    ...f,
    issueIdentifier: `SYNTHETIC-${i + 1}`,
  }));
  writeFileSync(path, JSON.stringify({ ...payload, publications }));
  expect(
    result(["record-linear-publications", ...args], s)["created"],
  ).toHaveLength(findings.length);
  expect(result(["record-linear-publications", ...args], s)["created"]).toEqual(
    publications,
  );
  writeFileSync(path, JSON.stringify(payload));
  expect(
    result(["inspect-linear-publication", ...args], s)["recorded"],
  ).toEqual(publications);
  if (nodeMajor >= 22) {
    const recordedPath = join(s.directory, "recorded.json");
    writeFileSync(recordedPath, JSON.stringify({ ...payload, publications }));
    for (const response of sdk(s, [
      { args: ["compare-scans", ...pair] },
      {
        args: [
          "list-unmatched-scan-pairs",
          "--repository",
          s.target,
          "--force",
        ],
      },
      {
        args: ["save-scan-comparison", ...pair, "--matches-json-stdin"],
        input: matches,
      },
      {
        args: [
          "export-findings",
          "--scan-id",
          after.scanId,
          "--format",
          "json",
        ],
      },
      { args: ["inspect-linear-publication", ...args] },
      { args: ["prepare-linear-publication", ...args] },
      { args: ["record-linear-publications", "--input-file", recordedPath] },
    ]))
      expect(response.error).toBeUndefined();
  }
});

const finding = (id: string) => ({
  findingId: id,
  fingerprints: { primary: `fingerprint-${id}` },
  ruleId: "synthetic",
  identity: { anchor: "source.ts" },
  title: "Original title",
});
const assessment = (id: string) => ({
  findingId: id,
  occurrenceId: `occurrence-${id}`,
  inputSha256: "input",
  rubricSha256: "rubric",
  knowledgeBaseSha256: "knowledge",
  assessedAt: "ignored",
  source: "rubric",
  decision: "assessed",
  level: "high",
  rubricLabel: "High",
  rationale: "Evidence",
  confidence: "high",
  reviewTrigger: null,
});

test("severity checkpoints preserve selections, existing findings and transaction rollback", () => {
  const s = setup(),
    command = ["severity-classification"];
  const begin = {
    action: "begin",
    scanId: "selection",
    findingIds: ["b", "a", "b", "missing"],
    assessedAt: "2026-01-01T00:00:00Z",
    rubricSha256: "rubric",
    knowledgeBaseSha256: "knowledge",
  };
  expect(result(command, s, JSON.stringify(begin))).toEqual({
    assessments: [],
  });
  for (const id of ["a", "b"])
    result(
      command,
      s,
      JSON.stringify({
        action: "save",
        finding: finding(id),
        assessment: assessment(id),
      }),
    );
  const original = snapshot(s)["findings"];
  result(
    command,
    s,
    JSON.stringify({
      action: "save",
      finding: { ...finding("a"), title: "Changed title" },
      assessment: { ...assessment("a"), level: "low" },
    }),
  );
  expect(snapshot(s)["findings"]).toEqual(original);
  const saved = result(
    ["read-severity-classification", "--scan-id", "selection"],
    s,
  );
  const selection: Table = { ...begin };
  delete selection["action"];
  expect(saved).toMatchObject(selection);
  const rows = saved["assessments"] as Table[];
  expect(rows.map((row) => row["findingId"])).toEqual(["b", "a", "b"]);
  expect(rows[1]!["level"]).toBe("low");
  expect(rows[0]!["assessedAt"]).toMatch(/^\d{4}-.*Z$/);
  expect(result(command, s, JSON.stringify(begin))["assessments"]).toEqual(
    rows,
  );
  const incomplete: Table = assessment("rollback");
  delete incomplete["rationale"];
  expect(
    helper(
      command,
      s,
      JSON.stringify({
        action: "save",
        finding: finding("rollback"),
        assessment: incomplete,
      }),
    ).status,
  ).toBe(1);
  expect(snapshot(s)["findings"]).toEqual(original);
  expect(helper(command, s, '{"action":"unknown"}').stderr.trim()).toBe(
    "Unknown severity checkpoint action.",
  );
  expect(
    result(["read-severity-classification", "--scan-id", "absent"], s),
  ).toEqual({});
  if (nodeMajor >= 22) {
    const responses = sdk(s, [
      { args: command, input: JSON.stringify(begin) },
      { args: ["read-severity-classification", "--scan-id", "selection"] },
    ]);
    expect(responses.map((r) => r.error)).toEqual([undefined, undefined]);
    expect(responses[1]!.value).toEqual(saved);
  }
});

test("severity inspection does not create databases or initialize legacy schemas", () => {
  const s = setup(),
    args = ["read-severity-classification", "--scan-id", "absent"];
  expect(helper(args, s).status).toBe(1);
  expect(existsSync(s.state)).toBe(false);
  mkdirSync(s.state, { mode: 0o700 });
  const database = join(s.state, "workbench.sqlite3");
  const child = spawnSync(node, [fixture, database], {
    input: stringifyJson({
      operations: [{ sql: "CREATE TABLE legacy (id TEXT)" }],
    }),
    encoding: "utf8",
    env: environment,
  });
  expect(child.status, child.stderr).toBe(0);
  const before = readFileSync(database);
  expect(result(args, s)).toEqual({});
  expect(readFileSync(database)).toEqual(before);
});

test("workflow state and cost-limit conversions retain their command behavior", () => {
  const s = setup(),
    scanId = register(s),
    command = ["finding-workflow"];
  const binding = { repositoryPath: s.target, scanId };
  result(
    command,
    s,
    JSON.stringify({ id: "workflow", action: "bind", binding }),
  );
  result(
    command,
    s,
    JSON.stringify({ id: "workflow", action: "begin", stage: "scan" }),
  );
  const completed = result(
    command,
    s,
    JSON.stringify({
      id: "workflow",
      action: "complete",
      stage: "scan",
      result: { scanId },
    }),
  );
  expect(completed["workflow"]).toMatchObject({
    id: "workflow",
    ...binding,
    stages: { scan: { status: "completed", result: { scanId } } },
  });
  expect(
    result(command, s, JSON.stringify({ id: "workflow", action: "get" })),
  ).toEqual(completed);
  const conflict = helper(
    command,
    s,
    JSON.stringify({
      id: "workflow",
      action: "bind",
      binding: { scanId: "other" },
    }),
  );
  expect(conflict.status).toBe(1);
  expect(conflict.stderr).toContain("already bound");
  const args = ["set-scan-cost-limit", "--scan-id", scanId];
  expect(result([...args, "--max-cost-usd", "١_٠.٥"], s)).toEqual({
    scanId,
    maxCostUsd: 10.5,
  });
  for (const value of ["nan", "inf", "0", "-0", "10.5"])
    expect(helper([...args, `--max-cost-usd=${value}`], s).status).toBe(1);
  for (const value of ["bad", "1__2", "0x10", "\ufeff12"])
    expect(helper([...args, "--max-cost-usd", value], s).status).toBe(2);
  if (nodeMajor >= 22) {
    const responses = sdk(s, [
      {
        args: command,
        input: JSON.stringify({ id: "workflow", action: "get" }),
      },
      { args: [...args, "--max-cost-usd", "2e1"] },
    ]);
    expect(responses.map((r) => r.error)).toEqual([undefined, undefined]);
    expect(responses[0]!.value).toEqual(completed);
    expect(responses[1]!.value).toEqual({ scanId, maxCostUsd: 20 });
  }
});
