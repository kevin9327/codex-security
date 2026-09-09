import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type {
  Operation,
  Request,
  Response,
  Sql,
} from "./support/scan-comparison-core-fixture";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directory = mkdtempSync(join(tmpdir(), "scan-comparison-core-")),
  fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
let sequence = 0;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-comparison-core-fixture.ts", import.meta.url),
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
function run(operations: Operation[], git?: Request["git"]): Response {
  const child = spawnSync(
    node,
    [fixture, join(directory, `${sequence++}.sqlite3`)],
    {
      input: stringifyJson({
        operations,
        ...(git === undefined ? {} : { git }),
      }),
      encoding: "utf8",
      env: { ...process.env, PATH: "", PYTHON: "missing-comparison-python" },
      maxBuffer: Infinity,
    },
  );
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response;
}
const id = (number: number) =>
  `00000000-0000-4000-8000-${String(number).padStart(12, "0")}`;
const sql = (text: string, ...parameters: (string | number | null)[]): Sql => ({
  sql: text,
  parameters,
});
const commit: Sql = { sql: "COMMIT" },
  snapshot: Operation = { snapshot: true };
function target(name = "target", path = join(directory, name)): Operation[] {
  return [
    sql(
      "INSERT INTO security_targets(id,current_path,display_name,created_at,updated_at) VALUES(?,?,?,'1','1')",
      name,
      path,
      name,
    ),
    sql(
      "INSERT INTO workspaces(id,target_id,target_path,created_at,updated_at) VALUES(?,?,?,'1','1')",
      name,
      name,
      path,
    ),
  ];
}
function scan(
  number: number,
  target = "target",
  scanId = id(number),
): Operation[] {
  const time = `2026-01-${String(number).padStart(2, "0")}T00:00:00Z`;
  return [
    sql(
      "INSERT INTO scans(id,workspace_id,target_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) SELECT ?,id,target_id,target_path,'revision','.','standard',target_path || '/scan-' || ?,'complete','reporting',?,?,? FROM workspaces WHERE id=?",
      scanId,
      scanId,
      time,
      time,
      time,
      target,
    ),
    sql(
      "INSERT INTO scan_progress(scan_id,updated_at) VALUES(?,?)",
      scanId,
      time,
    ),
  ];
}
function finding(number: number, name = "a", severity = "high"): Operation[] {
  const occurrence = `${number}-${name}`,
    finding = `finding-${number}-${name}`;
  return [
    sql(
      "INSERT INTO findings(id,fingerprint,rule_id,identity_anchor,created_at,updated_at) VALUES(?,?,'rule','anchor','1','1')",
      finding,
      finding,
    ),
    sql(
      "INSERT INTO finding_occurrences(id,finding_id,scan_id,title,summary,severity,confidence,remediation,created_at,details_json) VALUES(?,?,?,?,'Summary',?,'high','Fix','1','{}')",
      occurrence,
      finding,
      id(number),
      finding,
      severity,
    ),
    sql(
      "INSERT INTO finding_locations(occurrence_id,relative_path,start_line,end_line,role,sort_order) VALUES(?,'src/file.ts',1,1,'root_control',0)",
      occurrence,
    ),
  ];
}
function seed(count = 2, names = ["a"]): Operation[] {
  const operations = target();
  for (let number = 1; number <= count; number++) {
    operations.push(...scan(number));
    for (const name of names) operations.push(...finding(number, name));
  }
  return [...operations, commit];
}
const pair = (before = 1, after = 2) => ({
  beforeScanId: id(before),
  afterScanId: id(after),
});
const compare = (before = 1, after = 2, options = {}): Operation => ({
  compare: { ...pair(before, after), ...options },
});
const match = (before: string[], after: string[], reason = "same") => ({
  beforeOccurrenceIds: before,
  afterOccurrenceIds: after,
  reason,
  confidence: "high",
});
const save = (
  matches: unknown[] = [],
  uncertain: unknown[] = [],
  before = 1,
  after = 2,
): Operation => ({
  save: pair(before, after),
  source: JSON.stringify({ matches, uncertain }),
});
interface Comparison {
  summary: Record<string, number>;
  findings: Record<string, unknown>[];
  matchingCached?: boolean;
  matchingInputs?: {
    before: Record<string, unknown>[];
    after: Record<string, unknown>[];
    knownFindingGroups?: string[][];
  };
}
function value<T = Comparison>(row: Response["results"][number]): T {
  expect(row.error).toBeUndefined();
  return row.value as T;
}
const callbacks = (row: Response["results"][number]) =>
  row.events.map((event) => event.callback);
type Snapshot = Record<string, Record<string, unknown>[]>;

test("comparison is read-only and requires saved matches in the requested direction", () => {
  const base = seed(),
    result = run([
      ...base,
      snapshot,
      compare(),
      compare(1, 2, { requireMatches: true }),
      save(),
      compare(1, 2, { requireMatches: true }),
      compare(2, 1, { requireMatches: true }),
      compare(1, 1),
      snapshot,
    ]).results.slice(base.length);
  expect(value(result[1]!).summary).toEqual({
    new: 1,
    persisting: 0,
    resolved: 1,
    reopened: 0,
    unknown: 0,
  });
  expect(result[2]!.error).toContain(
    "Run 'codex-security scans match BEFORE AFTER' first",
  );
  expect(callbacks(result[2]!)).toEqual(["require", "require"]);
  expect(value(result[4]!).summary).toEqual(value(result[1]!).summary);
  expect(result[5]!.error).toBe(
    `These scans are in the wrong order. Run 'codex-security scans compare ${id(1)} ${id(2)}'.`,
  );
  expect(result[6]!.error).toBe("Select two different scans to compare.");
  const before = value<Snapshot>(result[0]!),
    after = value<Snapshot>(result[7]!);
  expect(after["finding_occurrences"]).toEqual(before["finding_occurrences"]);
  expect(after["scan_comparisons"]).toHaveLength(1);
});

test("many-to-many groups preserve severity, occurrence ordering, uncertainty and reopening", () => {
  const base = seed(2, ["a", "b", "c", "d"]);
  const result = run([
    ...base,
    sql("UPDATE finding_occurrences SET severity='critical' WHERE id='2-b'"),
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,close_reason,updated_at) VALUES('1-a','closed','already_fixed','1')",
    ),
    sql(
      "INSERT INTO finding_triage(occurrence_id,status,close_reason,updated_at) VALUES('2-b','closed','false_positive','1')",
    ),
    commit,
    save(
      [match(["1-a", "1-b"], ["2-a", "2-b"], "shared cause")],
      [
        {
          beforeOccurrenceId: "1-c",
          afterOccurrenceId: "2-c",
          reason: "possibly related",
        },
      ],
    ),
    snapshot,
  ]).results.slice(-2);
  const comparison = value(result[0]!);
  expect(comparison.summary).toEqual({
    new: 1,
    persisting: 0,
    resolved: 1,
    reopened: 1,
    unknown: 2,
  });
  expect(
    comparison.findings.find((row) => row["status"] === "reopened"),
  ).toMatchObject({
    findingId: "finding-2-b",
    severity: "critical",
    beforeOccurrenceIds: ["1-a", "1-b"],
    afterOccurrenceIds: ["2-a", "2-b"],
    matchReason: "shared cause",
    triage: { status: "closed", closeReason: "false_positive" },
  });
  expect(
    comparison.findings
      .filter((row) => row["status"] === "unknown")
      .map((row) => row["reason"]),
  ).toEqual(["possibly related", "possibly related"]);
  expect(value<Snapshot>(result[1]!)["scan_comparison_matches"]).toHaveLength(
    4,
  );
});

test("saved replacement rolls back late insertions and caller transactions exactly", () => {
  const base = seed(2, ["a", "b"]),
    original = save([match(["1-a"], ["2-a"], "original")]);
  const result = run([
    ...base,
    original,
    snapshot,
    sql(
      "CREATE TRIGGER fail_match BEFORE INSERT ON scan_comparison_matches WHEN NEW.before_occurrence_id='1-b' BEGIN SELECT RAISE(ABORT,'synthetic insertion failure'); END",
    ),
    save([match(["1-a", "1-b"], ["2-b"])]),
    snapshot,
    sql("DROP TRIGGER fail_match"),
    save([{ beforeOccurrenceIds: ["1-a"], afterOccurrenceIds: ["2-b"] }]),
    snapshot,
    sql("BEGIN IMMEDIATE"),
    sql("UPDATE finding_occurrences SET summary='pending' WHERE id='1-a'"),
    save(),
    snapshot,
  ]).results.slice(base.length);
  const initial = value<Snapshot>(result[1]!);
  expect(result[3]!.error).toBe("synthetic insertion failure");
  expect(result[3]!.inTransaction).toBe(false);
  expect(value<Snapshot>(result[4]!)).toEqual(initial);
  expect(result[6]!.error).toBe(
    "Scan comparison matches must have high confidence and a reason.",
  );
  expect(value<Snapshot>(result[7]!)).toEqual(initial);
  expect(result[10]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(result[10]!.inTransaction).toBe(false);
  expect(value<Snapshot>(result[11]!)).toEqual(initial);
});

test("invalid match groups are rejected before replacing a saved comparison", () => {
  const base = seed(2, ["a", "b"]),
    invalid = [
      "{",
      "null",
      '{"matches":[]}',
      '{"matches":null,"uncertain":[]}',
      JSON.stringify({ matches: [match(["missing"], ["2-a"])], uncertain: [] }),
      JSON.stringify({
        matches: [match(["1-a", "1-a"], ["2-a"])],
        uncertain: [],
      }),
      JSON.stringify({
        matches: [match(["1-a"], ["2-a"]), match(["1-a"], ["2-b"])],
        uncertain: [],
      }),
      JSON.stringify({
        matches: [match(["1-a"], ["2-a"])],
        uncertain: [
          {
            beforeOccurrenceId: "1-a",
            afterOccurrenceId: "2-b",
            reason: "maybe",
          },
        ],
      }),
    ];
  const result = run([
    ...base,
    save([match(["1-a"], ["2-a"])]),
    snapshot,
    ...invalid.flatMap((source): Operation[] => [
      { save: pair(), source },
      snapshot,
    ]),
  ]).results.slice(base.length);
  const original = value<Snapshot>(result[1]!);
  for (let index = 2; index < result.length; index += 2) {
    expect(result[index]!.kind).toBe("ScanComparisonError");
    expect(callbacks(result[index]!)).toEqual([
      "require",
      "require",
      "coverage",
      "input",
    ]);
    expect(result[index]!.inTransaction).toBe(false);
    expect(value<Snapshot>(result[index + 1]!)).toEqual(original);
  }
  const legacy = run([
    ...base,
    save([match(["1-a"], ["2-a"])]),
    sql(
      "UPDATE scan_comparisons SET result_json=?",
      JSON.stringify({
        matches: [match(["1-a"], ["2-a"], 0 as unknown as string)],
        uncertain: [],
      }),
    ),
    commit,
    compare(),
  ]).results.at(-1)!;
  expect(legacy.error).toBe(
    "sequence item 0: expected str instance, int found",
  );
  expect(legacy.inTransaction).toBe(false);
});

test("callback failures retain input ordering and keep already committed matches", () => {
  const base = seed(),
    args = save([match(["1-a"], ["2-a"])]);
  const result = run([
    ...base,
    { ...args, failure: { callback: "input", message: "input read failed" } },
    snapshot,
    { ...args, failure: { callback: "now", message: "clock failed" } },
    snapshot,
    {
      ...args,
      failure: {
        callback: "coverage",
        at: 2,
        message: "after commit",
        domain: true,
      },
    },
    snapshot,
  ]).results.slice(base.length);
  expect(result[0]!.error).toBe("input read failed");
  expect(callbacks(result[0]!)).toEqual([
    "require",
    "require",
    "coverage",
    "input",
  ]);
  expect(value<Snapshot>(result[1]!)["scan_comparisons"]).toEqual([]);
  expect(result[2]!.error).toBe("clock failed");
  expect(value<Snapshot>(result[3]!)["scan_comparisons"]).toEqual([]);
  expect(result[4]!.error).toBe("after commit");
  expect(callbacks(result[4]!)).toEqual([
    "require",
    "require",
    "coverage",
    "input",
    "now",
    "require",
    "require",
    "coverage",
  ]);
  expect(
    result[4]!.events.every((event) => event.inTransaction === false),
  ).toBe(true);
  expect(value<Snapshot>(result[5]!)["scan_comparisons"]).toHaveLength(1);
  expect(value<Snapshot>(result[5]!)["scan_comparison_matches"]).toHaveLength(
    1,
  );
});

test("matching input backfill runs before coverage and leaves callback transactions owned by the caller", () => {
  const base = seed(),
    update = sql(
      "UPDATE finding_occurrences SET details_json=? WHERE id='1-a'",
      '{"severity":{"level":"low","description":"stored"},"summary":"stored summary","keep":true}',
    );
  const result = run([
    ...base,
    {
      compare: { ...pair(), includeMatchingInputs: true },
      backfill: { [id(1)]: [update] },
    },
    snapshot,
    sql("ROLLBACK"),
    {
      compare: { ...pair(), includeMatchingInputs: true },
      backfill: { [id(1)]: [update] },
      failure: {
        callback: "backfill",
        at: 2,
        message: "later backfill failed",
      },
    },
    snapshot,
    sql("ROLLBACK"),
    snapshot,
  ]).results.slice(base.length);
  expect(callbacks(result[0]!)).toEqual([
    "require",
    "require",
    "backfill",
    "backfill",
    "coverage",
  ]);
  expect(result[0]!.inTransaction).toBe(true);
  expect(value(result[0]!).matchingInputs!.before[0]).toMatchObject({
    severity: { level: "low", description: "stored" },
    summary: "Summary",
    title: "finding-1-a",
    keep: true,
  });
  expect(result[3]!.error).toBe("later backfill failed");
  expect(result[3]!.inTransaction).toBe(true);
  expect(
    value<Snapshot>(result[4]!)["finding_occurrences"]![0]!["details_json"],
  ).toContain("stored");
  expect(
    value<Snapshot>(result[6]!)["finding_occurrences"]![0]!["details_json"],
  ).toBe("{}");
});

test("pair plans skip saved or unavailable scans and cache backfills once", () => {
  const base = seed(3),
    plan = { plan: { repository: join(directory, "target") } };
  const result = run([
    ...base,
    save([match(["1-a"], ["2-a"])]),
    plan,
    { plan: { ...plan.plan, force: true } },
    {
      ...plan,
      failure: {
        callback: "coverage",
        at: 2,
        message: "unavailable",
        domain: true,
      },
    },
    {
      ...plan,
      failure: { callback: "coverage", at: 2, message: "unexpected failure" },
    },
    compare(1, 2, { includeMatchingInputs: true }),
    compare(2, 3, { includeMatchingInputs: true }),
  ]).results.slice(base.length);
  interface Plan {
    batches: {
      afterScanId: string;
      beforeScans: { scanId: string }[];
      knownFindingGroups?: string[][];
    }[];
    scanCount: number;
    unavailableScans: number;
    skippedPairs: number;
  }
  const first = value<Plan>(result[1]!);
  expect(first).toMatchObject({
    scanCount: 3,
    unavailableScans: 0,
    skippedPairs: 1,
  });
  expect(
    first.batches.map((row) => [
      row.afterScanId,
      row.beforeScans.map((scan) => scan.scanId),
    ]),
  ).toEqual([[id(3), [id(1), id(2)]]]);
  expect(
    result[1]!.events
      .filter((event) => event.callback === "backfill")
      .map((event) => event.id),
  ).toEqual([id(1), id(2), id(3)]);
  expect(value<Plan>(result[2]!).batches).toHaveLength(2);
  expect(first.batches[0]!.knownFindingGroups).toEqual([
    ["finding-1-a", "finding-2-a"],
  ]);
  expect(
    value<Plan>(result[2]!).batches.every(
      (batch) => batch.knownFindingGroups === undefined,
    ),
  ).toBe(true);
  expect(value(result[5]!).matchingInputs!.knownFindingGroups).toBeUndefined();
  expect(value(result[6]!).matchingInputs!.knownFindingGroups).toEqual([
    ["finding-1-a", "finding-2-a"],
  ]);
  expect(value<Plan>(result[3]!)).toMatchObject({
    scanCount: 3,
    unavailableScans: 1,
    skippedPairs: 0,
  });
  expect(result[4]!.error).toBe("unexpected failure");
  expect(callbacks(result[4]!)).toEqual(["coverage", "coverage"]);
});

test("scan IDs retain UUID spellings, Unicode digits and prefix ambiguity", () => {
  const base = [...seed(), ...scan(11), commit];
  const forms = [
    id(1),
    id(1).replaceAll("-", ""),
    `{${id(1)}}`,
    `urn:uuid:${id(1)}`,
    id(11).slice(0, -1),
  ];
  const result = run([
    ...base,
    ...forms.map((resolve) => ({ resolve })),
    { resolve: id(1).slice(0, 8) },
    { resolve: "missing" },
    { resolve: "unknown-id" },
    { resolve: "١".repeat(32) },
  ]).results.slice(base.length);
  expect(
    result.slice(0, forms.length).map((row) => value<string>(row)),
  ).toEqual([id(1), id(1), id(1), id(1), id(11)]);
  expect(result[5]!.error).toContain("matches multiple scans");
  expect(result[6]!.error).toBe(
    "Scan ID prefixes must be at least eight characters.",
  );
  expect(result[7]!.error).toBe("Codex Security scan not found.");
  expect(value<string>(result[8]!)).toBe(
    "11111111-1111-1111-1111-111111111111",
  );
});

test("coverage keeps POSIX anchors and fnmatch semantics on every platform", () => {
  const cases: [string, string[], string[], boolean][] = [
    ["src/file.ts", ["src"], [], true],
    ["src2/file.ts", ["src"], [], false],
    ["src/tests/file.ts", ["src"], ["src/*"], false],
    ["//src", ["/"], [], false],
    ["//src", ["//"], [], true],
    ["/src", ["//"], [], false],
    ["a", ["."], ["[z-a]"], true],
    ["a", ["."], ["[!z-a]"], false],
    ["]", ["."], ["[]]"], false],
    ["a\nb", ["."], ["a?b"], false],
    ["😀", ["."], ["[😀-🙏]"], false],
  ];
  const result = run(
    cases.map(([path, includePaths, excludePaths]) => ({
      cover: {
        scan: { status: "complete", target_id: "target" },
        targetId: "target",
        path,
        coverage: {
          completeness: "complete",
          includePaths,
          excludePaths,
          explicitExclusions: [],
        },
      },
    })),
  ).results;
  expect(result.map((row) => value<boolean>(row))).toEqual(
    cases.map((row) => row[3]),
  );
});

test("comparison identity shares Git common directories and retains lazy origin probes", () => {
  const before = join(directory, "before"),
    after = join(directory, "after"),
    common = join(directory, "common.git");
  const base = [
    ...target("before", before),
    ...target("after", after),
    ...scan(1, "before"),
    ...scan(2, "after"),
    ...finding(1),
    ...finding(2),
    commit,
    compare(),
  ];
  const first = run(base, { [before]: { common }, [after]: { common } });
  expect(value(first.results.at(-1)!).summary["new"]).toBe(1);
  expect(first.probes.map((probe) => [probe.target, probe.args[0]])).toEqual([
    [before, "rev-parse"],
    [after, "rev-parse"],
  ]);
  const second = run(base, {
    [before]: { origin: "https://EXAMPLE.test/team/project.git" },
    [after]: { origin: "git@example.test:team/project" },
  });
  expect(second.results.at(-1)!.error).toBeUndefined();
  expect(second.probes.map((probe) => [probe.target, probe.args[0]])).toEqual([
    [before, "rev-parse"],
    [after, "rev-parse"],
    [before, "remote"],
    [after, "remote"],
  ]);
  const third = run(base, {
    [before]: {},
    [after]: { origin: "https://example.test/team/project" },
  });
  expect(third.results.at(-1)!.error).toContain("same repository target");
  expect(third.probes).toHaveLength(3);
  const withoutIds = [
    ...base.slice(0, -1),
    sql("UPDATE scans SET target_id=NULL"),
    commit,
  ];
  const different = run([...withoutIds, compare()], {
    [before]: {},
    [after]: {},
  });
  expect(different.results.at(-1)!.error).toContain("same repository target");
  const equal = run([
    ...withoutIds,
    sql("UPDATE scans SET target_path=?", before),
    commit,
    compare(),
  ]);
  expect(equal.results.at(-1)!.error).toBeUndefined();
  expect(equal.probes).toEqual([]);
});

test("confirmed aliases use every previous path and uncertainty from any group member", () => {
  const base = seed(3, ["a", "b"]);
  const result = run([
    ...base,
    sql("UPDATE finding_occurrences SET severity='critical' WHERE id='1-b'"),
    sql(
      "UPDATE finding_locations SET relative_path='outside.ts' WHERE occurrence_id='1-a'",
    ),
    commit,
    save([match(["1-a", "1-b"], ["2-a", "2-b"])]),
    {
      compare: pair(1, 3),
      coverage: {
        [id(3)]: {
          completeness: "complete",
          includePaths: ["src"],
          excludePaths: [],
          explicitExclusions: [],
        },
      },
    },
    save(
      [],
      [
        {
          beforeOccurrenceId: "1-a",
          afterOccurrenceId: "3-a",
          reason: "Uncertain group member.",
        },
      ],
      1,
      3,
    ),
  ]).results.slice(-2);
  expect(
    value(result[0]!).findings.find((row) => row["beforeOccurrenceIds"]),
  ).toMatchObject({
    findingId: "finding-1-b",
    severity: "critical",
    beforeOccurrenceIds: ["1-a", "1-b"],
    status: "unknown",
    reason: "The affected path was excluded or outside the later scope.",
  });
  expect(
    value(result[1]!).findings.find((row) => row["beforeOccurrenceIds"]),
  ).toMatchObject({ status: "unknown", reason: "Uncertain group member." });
});

test("related findings remain separate until another saved comparison confirms their identity", () => {
  const base = seed(3, ["a", "b"]);
  const related = {
    beforeOccurrenceId: "1-b",
    afterOccurrenceId: "2-b",
    reason: "Separate controls.",
  };
  const request: Operation = {
    save: pair(),
    source: JSON.stringify({
      matches: [match(["1-a"], ["2-a"])],
      uncertain: [],
      related: [related],
    }),
  };
  const result = run([
    ...base,
    request,
    snapshot,
    save([match(["1-b"], ["3-b"])], [], 1, 3),
    save([match(["2-b"], ["3-b"])], [], 2, 3),
    compare(),
    snapshot,
  ]).results.slice(base.length);
  expect(value<{ related: unknown[] }>(result[0]!).related).toEqual([
    { ...related, beforeTitle: "finding-1-b", afterTitle: "finding-2-b" },
  ]);
  expect(value(result[4]!)).not.toHaveProperty("related");
  expect(
    value<Snapshot>(result[5]!)["scan_comparisons"]![0]!["result_json"],
  ).toBe(value<Snapshot>(result[1]!)["scan_comparisons"]![0]!["result_json"]);
});
