import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { NavigationQuery } from "../../../plugins/codex-security/mcp-app/src/workbench-navigation";
import type { Operation, Request } from "./support/navigation-fixture";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directory = mkdtempSync(join(tmpdir(), "navigation-indexes-"));
const fixture = join(directory, "fixture.cjs");
const node = Bun.which("node")!;
let counter = 0;
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
interface Result {
  value: {
    findings: Record<string, unknown>[];
    repositories: {
      latestScan: Record<string, unknown>;
      [key: string]: unknown;
    }[];
    [key: string]: unknown;
  };
  error?: string;
  inTransaction: boolean;
}
function run(
  operations: Operation[],
  filename = join(directory, `${counter++}.sqlite3`),
): Result[] {
  const request: Request = { initialize: true, operations };
  const result = spawnSync(node, [fixture, filename], {
    input: stringifyJson(request),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "missing-navigation-python" },
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as Result[];
}
const sql = (
  sql: string,
  parameters?: (string | number | null)[],
): Operation => ({ sql, ...(parameters === undefined ? {} : { parameters }) });
const time = (day: number) =>
  `2026-01-${String(day).padStart(2, "0")}T00:00:00Z`;
function target(id: string, path = `/${id}`): Operation[] {
  return [
    sql(
      "INSERT INTO security_targets(id,current_path,display_name,created_at,updated_at) VALUES(?,?,?,?,?)",
      [id, path, id, time(1), time(1)],
    ),
    sql(
      "INSERT INTO workspaces(id,target_id,target_path,created_at,updated_at) VALUES(?,?,?,?,?)",
      [id, id, path, time(1), time(1)],
    ),
  ];
}
function scan(id: string, target: string, day: number): Operation[] {
  return [
    sql(
      `INSERT INTO scans(id,workspace_id,target_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at)
    SELECT ?,id,target_id,target_path,'revision','repository','standard',target_path || '/scan-' || ?,'complete','reporting',?,?,? FROM workspaces WHERE id=?`,
      [id, id, time(day), time(day), time(day), target],
    ),
    sql(
      "INSERT INTO scan_progress(scan_id,updated_at,scope_file_count,review_items_total,review_items_completed,reportable_findings_count) VALUES(?,?,8,6,3,2)",
      [id, time(day)],
    ),
  ];
}
function finding(
  id: string,
  finding: string,
  scan: string,
  level = "high",
): Operation[] {
  return [
    sql(
      "INSERT OR IGNORE INTO findings(id,fingerprint,rule_id,identity_anchor,created_at,updated_at) VALUES(?,?, 'rule','anchor',?,?)",
      [finding, `fingerprint:${finding}`, time(1), time(1)],
    ),
    sql(
      `INSERT INTO finding_occurrences(id,finding_id,scan_id,title,summary,severity,confidence,remediation,created_at,details_json)
      SELECT ?,?,id,?,'Summary',?,'high','Fix',started_at,'{}' FROM scans WHERE id=?`,
      [id, finding, finding, level, scan],
    ),
    sql(
      "INSERT INTO finding_locations(occurrence_id,relative_path,start_line,end_line,role,sort_order) VALUES(?,'src/auth.py',1,1,'root_control',0)",
      [id],
    ),
  ];
}
function match(before: string, after: string): Operation[] {
  return [
    sql(
      `INSERT OR IGNORE INTO scan_comparisons SELECT b.scan_id,a.scan_id,'{}',?,? FROM finding_occurrences b,finding_occurrences a WHERE b.id=? AND a.id=?`,
      [time(1), time(1), before, after],
    ),
    sql(
      `INSERT INTO scan_comparison_matches SELECT b.scan_id,a.scan_id,b.id,a.id,'Same cause' FROM finding_occurrences b,finding_occurrences a WHERE b.id=? AND a.id=?`,
      [before, after],
    ),
  ];
}
const page = (options: Partial<NavigationQuery> = {}): Operation => ({
  command: "list-global-findings",
  options: { offset: 0n, ...options },
});
const repos = (options?: Partial<NavigationQuery>): Operation => ({
  command: "list-repositories",
  ...(options === undefined ? {} : { options: { offset: 0n, ...options } }),
});
const snapshot: Operation = { snapshot: true };
const commit = sql("COMMIT");

test("combines repository findings without reviving dismissed aliases", () => {
  const operations: Operation[] = [...target("first"), ...target("second")];
  for (const [id, target, day] of [
    ["old", "first", 1],
    ["same", "first", 2],
    ["renamed", "first", 3],
    ["latest", "first", 4],
    ["other", "second", 4],
  ] as const)
    operations.push(...scan(id, target, day));
  for (const [id, findingId, scanId] of [
    ["old-occurrence", "dismissed", "old"],
    ["same-occurrence", "dismissed", "same"],
    ["renamed-occurrence", "renamed", "renamed"],
    ["latest-occurrence", "renamed-again", "latest"],
    ["historical-occurrence", "historical", "old"],
    ["other-occurrence", "dismissed", "other"],
  ])
    operations.push(...finding(id!, findingId!, scanId!));
  operations.push(
    ...match("same-occurrence", "renamed-occurrence"),
    ...match("renamed-occurrence", "latest-occurrence"),
    ...match("latest-occurrence", "other-occurrence"),
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,updated_at,close_reason) VALUES('old-occurrence','closed',?,'false_positive')",
      ["2026-01-01T12:00:00Z"],
    ),
    commit,
  );
  const indexes: Record<string, number> = {};
  const findings = (name: string, targetId = "first", status?: string) => {
    indexes[name] = operations.length;
    operations.push(
      page({ targetId, ...(status === undefined ? {} : { status }) }),
    );
  };
  findings("dismissed", "first", "open");
  findings("other", "second", "open");
  findings("closed");
  operations.push(
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,updated_at) VALUES('latest-occurrence','open',?)",
      [time(6)],
    ),
  );
  findings("reopened", "first", "open");
  operations.push(...scan("clean", "first", 7));
  findings("not_revalidated", "first", "open");
  operations.push(
    sql(
      "UPDATE finding_triage SET close_reason='wont_fix',updated_at=? WHERE occurrence_id='old-occurrence'",
      [time(8)],
    ),
  );
  findings("wont_fix", "first", "open");
  operations.push(
    sql(
      "UPDATE finding_triage SET close_reason='already_fixed',updated_at=? WHERE occurrence_id='old-occurrence'",
      [time(9)],
    ),
    ...scan("rediscovered", "first", 10),
    ...finding("rediscovered-occurrence", "renamed-again", "rediscovered"),
  );
  findings("rediscovered", "first", "open");
  operations.push(
    ...scan("tied", "first", 11),
    ...finding("z-occurrence", "z-finding", "tied"),
    ...finding("a-occurrence", "a-finding", "tied"),
    sql(
      "UPDATE finding_occurrences SET severity='critical' WHERE id='historical-occurrence'",
    ),
  );
  findings("ordered", "first", "open");
  const results = run(operations);
  expect(results.filter((result) => result.error)).toEqual([]);
  const result = Object.fromEntries(
    Object.entries(indexes).map(([name, index]) => [
      name,
      results[index]!.value.findings,
    ]),
  );
  expect(result).toMatchObject({
    dismissed: [
      {
        findingId: "historical",
        confirmedInLatestScan: false,
        knownScanIds: ["old"],
      },
    ],
    other: [{ findingId: "dismissed", targetId: "second", status: "open" }],
    closed: [
      { findingId: "historical", status: "open" },
      { findingId: "renamed-again", status: "closed" },
    ],
    wont_fix: [{ findingId: "historical" }],
  });
  expect(result["reopened"]![0]).toMatchObject({
    findingId: "renamed-again",
    status: "open",
    confirmedInLatestScan: true,
    knownSince: time(1),
    knownScanIds: ["old", "same", "renamed", "latest"],
    matchedFindingIds: ["dismissed", "renamed", "renamed-again"],
    occurrenceCount: 4,
  });
  expect(result["not_revalidated"]![0]).toMatchObject({
    findingId: "renamed-again",
    status: "open",
    confirmedInLatestScan: false,
  });
  expect(result["rediscovered"]![0]).toMatchObject({
    findingId: "renamed-again",
    status: "open",
    confirmedInLatestScan: true,
    occurrenceCount: 5,
  });
  expect(result["ordered"]!.map((finding) => finding["findingId"])).toEqual([
    "historical",
    "a-finding",
    "z-finding",
    "renamed-again",
  ]);
});

test("filters full Unicode text before byte-bounded output and preserves stable pagination", () => {
  const operations = [...target("first"), ...scan("scan", "first", 1)];
  for (let i = 0; i < 23; i++)
    operations.push(
      ...finding(`occ-${String(i).padStart(2, "0")}`, `finding-${i}`, "scan"),
    );
  operations.push(
    sql("UPDATE finding_occurrences SET title=?, summary=?", [
      "界".repeat(180) + "STRASSE",
      "😀".repeat(501) + "Kelvin",
    ]),
    commit,
    snapshot,
    page({ query: "\u001c straße \u001f" }),
    page({ query: "kelvin", offset: 20n, limit: 40n }),
    page({ severity: "critical" }),
    page({ targetId: "other" }),
    snapshot,
    sql("BEGIN IMMEDIATE"),
    page({ limit: 1n }),
    repos(),
    snapshot,
    sql("ROLLBACK"),
  );
  const results = run(operations).slice(-11);
  expect(results.filter((result) => result.error)).toEqual([]);
  const first = results[1]!.value;
  expect(first.findings).toHaveLength(20);
  expect(first.findings[0]).toMatchObject({
    title: "界".repeat(170),
    summary: "😀".repeat(500),
    occurrenceId: "occ-00",
  });
  expect(first).toMatchObject({ limit: 20, offset: 0, nextOffset: 20 });
  expect(results[2]!.value).toMatchObject({
    limit: 20,
    offset: 20,
    nextOffset: null,
  });
  expect(results[2]!.value.findings.map((row) => row["occurrenceId"])).toEqual([
    "occ-20",
    "occ-21",
    "occ-22",
  ]);
  expect(results[3]!.value.findings).toEqual([]);
  expect(results[4]!.value.findings).toEqual([]);
  expect(results[5]!.value).toEqual(results[0]!.value);
  expect(results[7]!.inTransaction).toBe(true);
  expect(results[8]!.inTransaction).toBe(true);
  expect(results[9]!.value).toEqual(results[0]!.value);
});

test("repository summaries use scan chronology and retain cost, warnings, cancellation and page envelopes", () => {
  const checkout = join(directory, "checkout");
  mkdirSync(checkout);
  const linked = join(directory, "linked");
  symlinkSync(
    checkout,
    linked,
    process.platform === "win32" ? "junction" : "dir",
  );
  const absent = join(directory, "missing");
  const results = run([
    ...target("first", linked),
    ...target("second", absent),
    ...target("unscanned"),
    ...scan("older", "first", 1),
    ...scan("newest", "first", 2),
    ...scan("second-scan", "second", 2),
    ...finding("old", "finding", "older"),
    ...finding("new", "finding", "newest"),
    sql("UPDATE scans SET status='running',updated_at=? WHERE id='older'", [
      time(9),
    ]),
    sql(
      "UPDATE scans SET canceled_at=?,recipe_json='{}',cost_json=?,completion_warnings_json=? WHERE id='newest'",
      [
        time(4),
        '{"usage":{"totalTokens":12},"cost":{"estimate":1.0}}',
        '["Saved findings"]',
      ],
    ),
    sql("UPDATE scan_progress SET updated_at=? WHERE scan_id='newest'", [
      time(5),
    ]),
    commit,
    repos(),
    repos({ limit: 1n }),
    repos({ offset: 1n }),
    repos({ query: "FIRST" }),
    repos({ status: "not_scanned" }),
    repos({ status: "open_findings" }),
  ]).slice(-6);
  expect(results.filter((result) => result.error)).toEqual([]);
  expect(Object.keys(results[0]!.value)).toEqual(["repositories"]);
  const repositories = results[0]!.value.repositories;
  expect(repositories.map((row) => row["targetId"])).toEqual([
    "second",
    "first",
  ]);
  expect(repositories[0]).toMatchObject({
    checkoutAvailable: false,
    openFindingsCount: 0,
    scanCount: 1,
  });
  expect(repositories[1]).toMatchObject({
    checkoutAvailable: true,
    openFindingsCount: 1,
    scanCount: 2,
    latestScan: {
      scanId: "newest",
      recipeAvailable: true,
      usage: { totalTokens: 12 },
      cost: { estimate: 1 },
      warnings: ["Saved findings"],
      updatedAt: time(5),
      progress: {
        status: "canceled",
        coverage: { closedRows: 3, filesTotal: 8, worklistRows: 6 },
      },
    },
  });
  expect(results[1]!.value).toMatchObject({
    limit: 1,
    offset: 0,
    nextOffset: 1,
  });
  expect(results[2]!.value).toMatchObject({
    limit: 20,
    offset: 1,
    nextOffset: null,
  });
  expect(results[3]!.value.repositories).toHaveLength(1);
  expect(results[4]!.value.repositories).toEqual([]);
  expect(results[5]!.value.repositories.map((row) => row["targetId"])).toEqual([
    "first",
  ]);
});

test("cost JSON rejects overwritten nonstandard numbers and accepts duplicate warning keys", () => {
  const results = run([
    ...target("first"),
    ...scan("scan", "first", 1),
    sql("UPDATE scans SET cost_json=?", ['{"x":NaN,"x":1}']),
    repos(),
    sql("UPDATE scans SET cost_json=?,completion_warnings_json=?", [
      '{"usage":null,"cost":false}',
      '[{"x":1,"x":2}]',
    ]),
    repos(),
    sql("UPDATE scans SET cost_json='null'"),
    repos(),
    sql("UPDATE scans SET cost_json='{'"),
    repos(),
  ]).slice(-8);
  expect(results[1]!.error).toBe("invalid JSON number NaN");
  expect(results[3]!.value.repositories[0]!.latestScan).toMatchObject({
    usage: null,
    warnings: [{ x: 2 }],
  });
  expect(results[5]!.value.repositories[0]!.latestScan).not.toHaveProperty(
    "cost",
  );
  expect(results[7]!.error).toContain(
    "Expecting property name enclosed in double quotes",
  );
});

test("finding and repository filters apply before pagination across targets", () => {
  const operations: Operation[] = [];
  for (const [id, day] of [
    ["needle-first", 1],
    ["needle-second", 2],
    ["unrelated", 3],
  ] as const)
    operations.push(
      ...target(id),
      ...scan(id, id, day),
      ...finding(id, id, id),
    );
  const filters = {
    query: "NeEdLe",
    severity: "high",
    status: "open",
    limit: 1n,
  };
  operations.push(
    commit,
    page(filters),
    page({ ...filters, offset: 1n }),
    page({ ...filters, targetId: "needle-first" }),
    repos({ query: "needle", status: "scanned", limit: 1n }),
    repos({ query: "needle", status: "scanned", limit: 1n, offset: 1n }),
    repos({ query: "needle", targetId: "needle-first" }),
    page(),
    repos(),
  );
  const results = run(operations).slice(-8);
  expect(results.filter((result) => result.error)).toEqual([]);
  expect(results[0]!.value["nextOffset"]).toBe(1);
  expect(results[1]!.value["nextOffset"]).toBeNull();
  expect(
    new Set([
      results[0]!.value.findings[0]!["targetId"],
      results[1]!.value.findings[0]!["targetId"],
    ]),
  ).toEqual(new Set(["needle-first", "needle-second"]));
  expect(results[2]!.value.findings.map((row) => row["targetId"])).toEqual([
    "needle-first",
  ]);
  expect(results[3]!.value["nextOffset"]).toBe(1);
  expect(results[4]!.value["nextOffset"]).toBeNull();
  expect(
    new Set([
      results[3]!.value.repositories[0]!["targetId"],
      results[4]!.value.repositories[0]!["targetId"],
    ]),
  ).toEqual(new Set(["needle-first", "needle-second"]));
  expect(results[5]!.value.repositories.map((row) => row["targetId"])).toEqual([
    "needle-first",
  ]);
  expect(results[6]!.value.findings).toHaveLength(3);
  expect(results[7]!.value.repositories).toHaveLength(3);
});

test("actual SDK workbench routes run both index commands without Python", () => {
  const state = join(directory, `sdk-${counter++}`);
  mkdirSync(state);
  const results = run(
    [
      ...target("first"),
      ...scan("scan", "first", 1),
      ...finding("occurrence", "finding", "scan"),
      commit,
      {
        sdk: ["list-global-findings", "--target-id", "first"],
        pluginRoot: PLUGIN_ROOT,
        stateDir: state,
      },
      { sdk: ["list-repositories"], pluginRoot: PLUGIN_ROOT, stateDir: state },
    ],
    join(state, "workbench.sqlite3"),
  ).slice(-2);
  expect(results.filter((result) => result.error)).toEqual([]);
  expect(results[0]!.value.findings[0]).toMatchObject({
    findingId: "finding",
    targetId: "first",
  });
  expect(results[1]!.value.repositories[0]).toMatchObject({
    targetId: "first",
    scanCount: 1,
    openFindingsCount: 1,
  });
});

test("command argument errors preserve validation order, accepted aliases and large offsets", () => {
  const state = join(directory, `cli-${counter++}`);
  const run = (args: string[]) =>
    spawnSync(node, [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: "",
        PYTHON: "missing-navigation-python",
        CODEX_SECURITY_STATE_DIR: state,
      },
    });
  for (const command of ["list-global-findings", "list-repositories"]) {
    expect(run([command, "--offset=-1", "--offset=0", "--help"]).status).toBe(
      2,
    );
    expect(run([command, "--limit=0", "--limit=1"]).stderr).toContain(
      "expected a positive integer",
    );
    expect(run([command, "--lim=١", "--off=０"]).status).toBe(0);
    expect(run([command, "--status=invalid"]).status).toBe(2);
  }
  expect(
    run(["list-global-findings", "--offset=9223372036854775807"]).stderr,
  ).toContain("Stop argument for islice()");
  expect(
    JSON.parse(
      run(["list-repositories", "--offset=9223372036854775807"]).stdout,
    )["repositories"],
  ).toEqual([]);
});
