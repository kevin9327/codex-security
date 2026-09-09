import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { cleanWorktreeContentDigest } from "../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import type { Request, Response } from "./support/workbench-results-fixture";

const scanId = "11111111-1111-4111-8111-111111111111";
const workspaceId = "22222222-2222-4222-8222-222222222222";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-results-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-results-fixture.ts", import.meta.url),
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
    input: stringifyJson(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as unknown as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
const value = (response: Response, index = 0) =>
  response.outcomes[index]!.result as Record<string, unknown>;
const occurrence = (index: number) =>
  `${index.toString(16).padStart(8, "0")}-3333-4333-8333-333333333333`;
test("scan results retain JSON stored as UTF-8 or UTF-16 SQLite blobs", () => {
  const documents: Record<string, unknown> = {
    recipe_json: { target: { kind: "paths", paths: ["src", "lib"] } },
    preflight_issues_json: [{ title: "é🧭", count: 9007199254740993n }],
    completion_warnings_json: ["é🧭"],
    cost_json: {
      usage: { inputTokens: 9007199254740993n },
      cost: { usd: new JsonFloat("1.0") },
    },
  };
  const responses = run(
    ...(["utf8", "utf16le"] as const).map(
      (encoding): Request => ({
        setupSql: Object.entries(documents).map(([field, document]) => {
          const bytes = Buffer.from(stringifyJson(document), encoding);
          const table =
            field === "preflight_issues_json" ? "scan_progress" : "scans";
          return `UPDATE ${table} SET ${field} = x'${bytes.toString("hex")}'`;
        }),
        actions: [{ operation: "scan" }, { operation: "coverage" }],
      }),
    ),
  );
  for (const response of responses) {
    expect(response.outcomes[0]!.error).toBeUndefined();
    expect(value(response)).toMatchObject({
      progress: { preflightIssues: documents["preflight_issues_json"] },
      warnings: documents["completion_warnings_json"],
      usage: { inputTokens: 9007199254740993n },
      cost: { usd: new JsonFloat("1.0") },
      contract: { scope: { requiredIncludePaths: ["src", "lib"] } },
    });
    expect(response.outcomes[1]!.result).toBe("scoped_path");
  }
});
function records(count: number) {
  return {
    finding_occurrences: Array.from({ length: count }, (_, index) => ({
      id: occurrence(index),
      finding_id: `finding-${index}`,
      scan_id: scanId,
      title: `Title ${index}`,
      summary: `Summary ${index}`,
      severity: "high",
      confidence: "high",
      remediation: "fix",
      created_at: String(index).padStart(2, "0"),
      details_json: "{}",
    })),
  };
}
test("selected findings beyond the first page appear in scan context without changing the workspace page", () => {
  const [response] = run({
    records: records(23),
    actions: [{ operation: "context", occurrenceId: occurrence(22) }],
  });
  expect(response!.outcomes[0]!.error).toBeUndefined();
  const context = value(response!),
    scan = context["scan"] as Record<string, unknown>,
    workspace = context["workspace"] as Record<string, unknown>;
  const findings = scan["findings"] as Record<string, unknown>[];
  expect(findings).toHaveLength(21);
  expect(findings.at(-1)).toMatchObject({
    id: occurrence(22),
    scan_id: scanId,
  });
  expect(findings[0]).not.toHaveProperty("scan_id");
  expect(scan["findingCount"]).toBe(23n);
  expect(scan["findingsTruncated"]).toBe(true);
  expect(
    (workspace["results"] as Record<string, unknown>)["findings"],
  ).toHaveLength(20);
  expect(workspace["userContext"]).toBe("scan context");
  expect(
    response!.outcomes[0]!.events.filter(
      (event) => (event as unknown[])[0] === "backfill",
    ),
  ).toHaveLength(2);
});
test("pagination shares severity, triage and location filtering while retaining the page maximum", () => {
  const items = records(23);
  items.finding_occurrences[0]!.title = "STRASSE";
  const [response] = run({
    records: {
      ...items,
      finding_triage: [
        {
          occurrence_id: occurrence(1),
          status: "closed",
          close_reason: "already_fixed",
          updated_at: "updated",
        },
      ],
      finding_locations: [
        {
          occurrence_id: occurrence(2),
          sort_order: 0n,
          relative_path: "src/target.ts",
          start_line: 1n,
          end_line: 2n,
          role: "primary",
        },
      ],
    },
    actions: [
      { operation: "list", limit: 100n },
      { operation: "list", offset: 20n },
      { operation: "list", query: " \u001cStraße\u2000" },
      { operation: "list", status: "closed", severity: "high" },
      { operation: "list", query: "src/target" },
      { operation: "list", query: "%" },
    ],
  });
  const page = (index: number) =>
    value(response!, index)["findingsPage"] as Record<string, unknown>;
  expect(page(0)).toMatchObject({
    limit: 20n,
    nextOffset: 20n,
    offset: 0n,
    scanId,
    total: 23n,
  });
  expect(page(1)).toMatchObject({ nextOffset: null, total: 23n });
  expect(page(1)["findings"]).toHaveLength(3);
  for (const [index, id] of [
    [2, 0],
    [3, 1],
    [4, 2],
  ]) {
    expect(page(index!)["total"]).toBe(1n);
    expect(page(index!)["findings"]).toMatchObject([{ id: occurrence(id!) }]);
  }
  expect(page(5)["total"]).toBe(0n);
});
test("progress combines precise deep review counts, cancellation and management timestamps", () => {
  const [response] = run({
    scan: {
      mode: "deep",
      canceled_at: "canceled",
      cost_json:
        '{"usage":{"inputTokens":9007199254740993},"cost":{"usd":1.0}}',
    },
    progress: {
      reportable_findings_count: 9007199254740993n,
      scope_file_count: 9007199254740994n,
    },
    records: {
      ...records(1),
      deep_scan_runs: [
        {
          scan_id: scanId,
          schema_version: 1n,
          workflow_version: "deep-security-scan/v1",
          status: "running",
          phase: "reducing",
          workers: 4n,
          subagents: 1n,
          stop_after_no_new: 4n,
          stop_after_consecutive_errors: 3n,
          max_discovery_runs: 9007199254740995n,
          max_time_hours: 2,
          completion_sequence: 9007199254740992n,
          created_at: "created",
          updated_at: "z-review",
        },
      ],
      deep_scan_workers: [
        {
          id: occurrence(0),
          scan_id: scanId,
          kind: "discovery",
          status: "queued",
          prompt_path: "/prompt",
          artifact_dir: "/artifacts",
          created_at: "created",
          updated_at: "updated",
        },
      ],
      finding_triage: [
        {
          occurrence_id: occurrence(0),
          status: "closed",
          close_reason: "wont_fix",
          note: "reason",
          updated_at: "zz-triage",
        },
      ],
    },
    actions: [
      { operation: "scan" },
      { operation: "triage", occurrenceId: occurrence(0) },
      { operation: "triage", occurrenceId: "unknown" },
    ],
  });
  const scan = value(response!);
  expect(scan["progress"]).toMatchObject({
    status: "canceled",
    candidates: { reportable: 9007199254740993n },
    coverage: { filesTotal: 9007199254740994n },
    independentReviews: {
      active: 1n,
      completed: 9007199254740992n,
      maximum: 9007199254740995n,
      consolidating: true,
    },
  });
  expect(scan["updatedAt"]).toBe("zz-triage");
  expect(scan["usage"]).toEqual({ inputTokens: 9007199254740993n });
  expect((scan["cost"] as Record<string, unknown>)["usd"]).toBeInstanceOf(
    JsonFloat,
  );
  expect(stringifyJson(scan["cost"], { compact: true })).toBe('{"usd": 1.0}');
  expect(value(response!, 1)).toMatchObject({
    status: "closed",
    closeReason: "wont_fix",
    note: "reason",
  });
  expect(value(response!, 2)).toEqual({ status: "open" });
});
test("artifact availability and callback failures preserve cursor and transaction ownership", () => {
  const report = join("/scan", "REPORT.md"),
    sarif = join("/scan", "exports", "results.sarif");
  const [response, missing] = run(
    {
      records: {
        scan_artifacts: [
          {
            scan_id: scanId,
            kind: "coverage",
            path: join("/scan", "coverage.json"),
            created_at: "created",
          },
          {
            scan_id: scanId,
            kind: "markdownReport",
            path: report,
            created_at: "created",
          },
        ],
      },
      actions: [
        {
          operation: "scan",
          artifacts: {
            [report]: report,
            [sarif]: sarif,
          },
        },
        {
          operation: "scan",
          callbackSql: { artifact: "DROP TABLE scan_artifacts" },
        },
        {
          operation: "scan",
          callbackSql: {
            backfill: "UPDATE scan_progress SET updated_at = 'zz-backfill'",
          },
          fail: "remediation",
        },
        { operation: "rollback" },
        { operation: "scan" },
      ],
    },
    { progress: null, actions: [{ operation: "scan" }] },
  );
  expect(value(response!)).toMatchObject({
    reportAvailable: true,
    artifacts: {
      markdownReport: report,
      sarifReport: sarif,
    },
  });
  expect(response!.outcomes[1]!.error).toBe("database table is locked");
  expect(response!.outcomes[2]).toMatchObject({
    error: "remediation failed",
    systemExit: true,
    inTransaction: true,
  });
  expect(value(response!, 4)["updatedAt"]).toBe("scan-updated");
  expect(missing!.outcomes[0]!.error).toBe(
    "'NoneType' object is not subscriptable",
  );
  expect((missing!.outcomes[0]!.events.at(-1) as unknown[])[0]).toBe(
    "remediation",
  );
});

test("artifact cursors prefetch the next path before checking availability", () => {
  const coverage = join("/scan", "coverage.json"),
    findings = join("/scan", "findings.json");
  const [response] = run({
    records: {
      scan_artifacts: [
        {
          scan_id: scanId,
          kind: "coverage",
          path: coverage,
          created_at: "created",
        },
        {
          scan_id: scanId,
          kind: "findings",
          path: findings,
          created_at: "created",
        },
      ],
    },
    actions: [
      {
        operation: "scan",
        artifacts: { [coverage]: coverage, [findings]: findings },
        callbackSql: {
          artifact: "UPDATE scan_artifacts SET path = path || '.updated'",
        },
      },
    ],
  });
  expect(response!.outcomes[0]!.error).toBeUndefined();
  expect(value(response!)["artifacts"]).toEqual({ coverage, findings });
  expect(
    response!.outcomes[0]!.events.filter(
      (event) => (event as unknown[])[0] === "artifact",
    )
      .slice(0, 2)
      .map((event) => (event as unknown[])[2]),
  ).toEqual([coverage, findings]);
});
test("workspace overrides still validate scan ownership and preserve selected user context", () => {
  const [response, unselected] = run(
    {
      actions: [
        {
          operation: "workspace",
          options: { threadId: " owner\u001c", resultScan: { supplied: true } },
        },
        {
          operation: "workspace",
          options: { threadId: "other", resultScan: { supplied: true } },
        },
        {
          operation: "workspace",
          options: {
            resultScanId: "44444444-4444-4444-8444-444444444444",
            resultScan: { supplied: true },
          },
        },
      ],
    },
    {
      workspace: { active_scan_id: null },
      actions: [{ operation: "workspace" }],
    },
  );
  expect(value(response!)).toMatchObject({
    id: workspaceId,
    results: { supplied: true },
    userContext: "scan context",
  });
  expect(response!.outcomes[1]!.error).toBe(
    "Codex Security workspace not found in this thread.",
  );
  expect(response!.outcomes[2]!.error).toContain("scan not found");
  expect(value(unselected!)).toMatchObject({
    setupValidation: { error: null, valid: false },
    userContext: "workspace context",
  });
  expect(value(unselected!)).not.toHaveProperty("results");
});
test("scan contracts distinguish snapshots and requested paths, and reject malformed recipes at their original boundary", () => {
  const [clean, snapshot, malformed, scoped] = run(
    {
      scan: {
        target_snapshot_digest: cleanWorktreeContentDigest(),
        target_path: "/target/repository/",
        recipe_json: '{"target":{"kind":"paths","paths":["src","lib"]}}',
      },
      actions: [{ operation: "contract" }, { operation: "coverage" }],
    },
    {
      scan: {
        target_revision: "unversioned",
        target_snapshot_digest: "digest",
      },
      actions: [{ operation: "contract" }],
    },
    {
      scan: { recipe_json: '{"target":{"kind":"paths","paths":[NaN]}}' },
      actions: [{ operation: "paths" }, { operation: "coverage" }],
    },
    {
      scan: { scope: "src", recipe_json: "malformed" },
      actions: [{ operation: "coverage" }],
    },
  );
  expect(value(clean!)).toMatchObject({
    scope: { requestedPath: ".", requiredIncludePaths: ["src", "lib"] },
    target: { displayName: "repository", allowedKinds: ["git_revision"] },
  });
  expect(value(clean!)["target"]).not.toHaveProperty("requiredSnapshotDigest");
  expect(clean!.outcomes[1]!.result).toBe("scoped_path");
  expect(value(snapshot!)["target"]).toMatchObject({
    allowedKinds: ["directory_snapshot"],
    requiredSnapshotDigest: "digest",
  });
  expect(malformed!.outcomes[0]!.error).toBe(
    "non-finite JSON number 'NaN' is not supported",
  );
  expect(malformed!.outcomes[1]!.result).toBe("scoped_path");
  expect(scoped!.outcomes[0]!.result).toBe("scoped_path");
});

test("stored progress, warning, cost and recipe JSON retain integer conversion failures", () => {
  const integer = "9".repeat(4301),
    json = `{"count":${integer}}`;
  const responses = run(
    {
      progress: { preflight_issues_json: json },
      actions: [{ operation: "scan" }],
    },
    {
      scan: { completion_warnings_json: json },
      actions: [{ operation: "scan" }],
    },
    { scan: { cost_json: json }, actions: [{ operation: "scan" }] },
    {
      scan: { recipe_json: `{"target":{"kind":"paths","paths":[${integer}]}}` },
      actions: [{ operation: "scan" }],
    },
  );
  for (const response of responses)
    expect(response.outcomes[0]).toMatchObject({
      error:
        "Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use sys.set_int_max_str_digits() to increase the limit",
      systemExit: false,
      inTransaction: false,
    });
});

test("related findings reach selected scan and paginated renderers and exclude confirmed matches", () => {
  const otherScan = "44444444-4444-4444-8444-444444444444";
  const items = records(23);
  const linked = {
    ...items.finding_occurrences[0]!,
    id: occurrence(99),
    finding_id: "related-finding",
    scan_id: otherScan,
    title: "Related finding",
  };
  const [response] = run({
    records: {
      finding_occurrences: [...items.finding_occurrences, linked],
      scan_comparisons: [
        {
          before_scan_id: scanId,
          after_scan_id: otherScan,
          result_json: JSON.stringify({
            related: [
              {
                beforeOccurrenceId: occurrence(22),
                afterOccurrenceId: occurrence(99),
                reason: "Shared behavior",
              },
            ],
          }),
          created_at: "created",
          updated_at: "updated",
        },
      ],
    },
    actions: [
      { operation: "context", occurrenceId: occurrence(22) },
      { operation: "list", offset: 20n },
      {
        operation: "sql",
        sql: "INSERT INTO scan_comparison_matches (before_scan_id, after_scan_id, before_occurrence_id, after_occurrence_id, reason) VALUES (?, ?, ?, ?, ?)",
        parameters: [
          scanId,
          otherScan,
          occurrence(22),
          occurrence(99),
          "Same finding",
        ],
      },
      { operation: "list", offset: 20n },
      { operation: "rollback" },
      { operation: "list", offset: 20n },
    ],
  });
  expect(
    response!.outcomes.every((outcome) => outcome.error === undefined),
  ).toBe(true);
  const expected = [
    {
      findingId: "related-finding",
      occurrenceId: occurrence(99),
      reason: "Shared behavior",
      scanId: otherScan,
      title: "Related finding",
    },
  ];
  const context = value(response!);
  const scan = context["scan"] as Record<string, unknown>;
  expect(
    (scan["findings"] as Record<string, unknown>[]).at(-1)!["related"],
  ).toEqual(expected);
  const workspace = context["workspace"] as Record<string, unknown>;
  const workspaceScan = workspace["results"] as Record<string, unknown>;
  expect(
    (workspaceScan["findings"] as Record<string, unknown>[]).every(
      (item) => (item["related"] as unknown[]).length === 0,
    ),
  ).toBe(true);
  const related = (index: number) =>
    (
      (value(response!, index)["findingsPage"] as Record<string, unknown>)[
        "findings"
      ] as Record<string, unknown>[]
    ).at(-1)!["related"];
  expect(related(1)).toEqual(expected);
  expect(related(3)).toEqual([]);
  expect(response!.outcomes[3]!.inTransaction).toBe(true);
  expect(related(5)).toEqual(expected);
});
