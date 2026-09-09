import assert from "node:assert/strict";
import { join } from "node:path";
import {
  Connection,
  type Parameter,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  compareScans,
  saveScanComparison,
  listUnmatchedScanPairs,
  ScanComparisonError,
  type ComparisonScan,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-scan-comparison";
import {
  savedFindingLinks,
  confirmedFindingAliases,
  findingRelations,
  findingMatches,
  rowsForIds,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-finding-links";
import { MIGRATIONS } from "../../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import { applyMigrations } from "../../../../plugins/codex-security/mcp-app/src/workbench-schema";
import { derivedFindingIdentityRows } from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-validation";
import { stringifyJson } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export type Scenario =
  | "unrelated"
  | "validation"
  | "indexes"
  | "matching"
  | "cached"
  | "relations"
  | "recurring";
const native = sqliteBinding(),
  connection = new Connection(native, ":memory:");
const repository = process.argv[3]!;
const execute = (sql: string, parameters: Parameter[] = []) =>
  connection.prepare(sql).run(parameters);
const rows = (sql: string, parameters: Parameter[] = []) =>
  connection
    .prepare(sql)
    .all(parameters)
    .map((row) => row.toObject());
const requireScan = (db: Connection, id: string) =>
  db
    .prepare("SELECT * FROM scans WHERE id = ?")
    .get([id])!
    .toObject() as ComparisonScan;
const pairArgs = { beforeScanId: "before", afterScanId: "after" };
const completeCoverage = () => ({
  completeness: "complete",
  includePaths: ["src"],
  excludePaths: [] as string[],
  explicitExclusions: [],
});
const pair = (before: string, after: string) => ({
  beforeOccurrenceId: before,
  afterOccurrenceId: after,
  reason: "Separate synthetic controls.",
});
const group = (before: string[], after: string[]) => ({
  beforeOccurrenceIds: before,
  afterOccurrenceIds: after,
  confidence: "high",
  reason: "The same synthetic control.",
});
function trace() {
  const queries: string[] = [],
    prepare = connection.raw.prepare.bind(connection.raw);
  connection.raw.prepare = (sql) => {
    queries.push(sql);
    return prepare(sql);
  };
  return queries;
}
function run(scenario: Scenario): unknown {
  switch (scenario) {
    case "unrelated": {
      connection.exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, started_at TEXT);
CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);`);
      for (const [index, [scan, target]] of [
        ["unrelated-before", "unrelated"],
        ["unrelated-after", "unrelated"],
        ["before", "selected"],
        ["after", "selected"],
      ].entries())
        execute("INSERT INTO scans VALUES (?, NULL, ?, ?, ?)", [
          scan!,
          join(repository, target!),
          "complete",
          String(index),
        ]);
      for (const value of [
        ["unrelated-first", "unrelated-identity-a", "unrelated-before"],
        ["unrelated-second", "unrelated-identity-b", "unrelated-after"],
      ])
        execute("INSERT INTO finding_occurrences VALUES (?, ?, ?)", value);
      execute("INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)", [
        "unrelated-before",
        "unrelated-after",
        "unrelated-first",
        "unrelated-second",
      ]);
      return compareScans(
        connection,
        { ...pairArgs, includeMatchingInputs: true },
        { requireScan, readCoverage: completeCoverage },
      )["matchingInputs"];
    }
    case "validation": {
      connection.exec(`PRAGMA foreign_keys = ON;
CREATE TABLE scans (id TEXT PRIMARY KEY, target_path TEXT, target_id TEXT, status TEXT);
CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT, severity TEXT
);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparisons (
    before_scan_id TEXT, after_scan_id TEXT, result_json TEXT, created_at TEXT, updated_at TEXT,
    PRIMARY KEY(before_scan_id, after_scan_id)
);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT,
    reason TEXT,
    FOREIGN KEY(before_scan_id, after_scan_id)
        REFERENCES scan_comparisons(before_scan_id, after_scan_id) ON DELETE CASCADE
);
CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);`);
      for (const [scan, names] of [
        ["before", ["a1", "a2", "b", "c"]],
        ["after", ["x1", "x2", "y", "z"]],
      ] as const) {
        execute("INSERT INTO scans VALUES (?, ?, ?, ?)", [
          scan,
          repository,
          "target",
          "complete",
        ]);
        for (const name of names) {
          execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?)", [
            name,
            name,
            scan,
            name,
            "high",
          ]);
          execute("INSERT INTO finding_locations VALUES (?, ?, ?, ?)", [
            name,
            "src/example.py",
            "root_control",
            0,
          ]);
        }
      }
      connection.commit();
      const payload = {
        matches: [group(["a1", "a2"], ["x1", "x2"]), group(["b"], ["y"])],
        uncertain: [] as ReturnType<typeof pair>[],
        related: [pair("a2", "y"), pair("c", "z")],
      };
      const save = (value: typeof payload) =>
        saveScanComparison(connection, pairArgs, {
          requireScan,
          readCoverage: completeCoverage,
          now: () => "2026-01-01T00:00:00Z",
          readMatches: () => JSON.stringify(value),
        });
      const snapshot = () => ({
        result: rows("SELECT result_json FROM scan_comparisons"),
        pairs: rows(
          "SELECT * FROM scan_comparison_matches ORDER BY before_occurrence_id, after_occurrence_id",
        ),
      });
      const accepted = save(payload),
        original = snapshot();
      for (const value of [
        { ...payload, related: [pair("a2", "x2")] },
        { ...payload, related: [pair("b", "y")] },
        { ...payload, related: [pair("a2", "y"), pair("a2", "y")] },
        { ...payload, related: [pair("outside", "z")] },
        { ...payload, uncertain: [pair("c", "z")] },
        { ...payload, uncertain: [pair("a1", "z")] },
        { ...payload, uncertain: [pair("c", "y")] },
        {
          ...payload,
          matches: [payload.matches[0]!, group(["b", "a1"], ["y"])],
        },
      ]) {
        assert.throws(() => save(value), ScanComparisonError);
        assert.deepEqual(snapshot(), original);
      }
      return {
        summary: accepted["summary"],
        related: (accepted["related"] as ReturnType<typeof pair>[]).map(
          (item) => [item.beforeOccurrenceId, item.afterOccurrenceId],
        ),
        savedPairs: original.pairs.length,
      };
    }
    case "indexes": {
      execute("PRAGMA foreign_keys = ON");
      const timestamp = "2026-01-01T00:00:00Z";
      const migrate = (migrations: typeof MIGRATIONS) =>
        applyMigrations(
          native,
          connection,
          migrations,
          () => timestamp,
          () => {},
        );
      migrate(MIGRATIONS.filter(([version]) => version < 31));
      execute("INSERT INTO security_targets VALUES (?, ?, ?, ?, ?)", [
        "target",
        repository,
        "Synthetic target",
        timestamp,
        timestamp,
      ]);
      execute(
        "INSERT INTO workspaces (id, target_id, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ["workspace", "target", timestamp, timestamp],
      );
      const scanId = (index: number) =>
        `scan-${String(index).padStart(3, "0")}`;
      for (let index = 0; index < 200; index++)
        execute(
          `INSERT INTO scans (
        id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir,
        status, phase, started_at, created_at, updated_at
      ) VALUES (?, 'workspace', 'target', ?, 'unversioned', '.', 'standard', ?, 'complete', 'reporting', ?, ?, ?)`,
          [
            scanId(index),
            repository,
            join(repository, scanId(index)),
            timestamp,
            timestamp,
            timestamp,
          ],
        );
      for (let after = 0; after < 200; after++)
        for (let before = 0; before < after; before++)
          execute("INSERT INTO scan_comparisons VALUES (?, ?, ?, ?, ?)", [
            scanId(before),
            scanId(after),
            JSON.stringify({ matches: [], uncertain: [] }),
            timestamp,
            timestamp,
          ]);
      const snapshot = () =>
        rows(
          "SELECT * FROM scan_comparisons ORDER BY before_scan_id, after_scan_id",
        );
      const original = snapshot();
      migrate(MIGRATIONS);
      migrate(MIGRATIONS);
      const plan = rows(
        `EXPLAIN QUERY PLAN SELECT before_scan_id, after_scan_id, result_json FROM scan_comparisons
        WHERE before_scan_id = ? OR after_scan_id = ? ORDER BY before_scan_id, after_scan_id`,
        ["scan-100", "scan-100"],
      ).map((row) => row["detail"]);
      const identityPlan = rows(
        "EXPLAIN QUERY PLAN SELECT id FROM finding_occurrences WHERE finding_id = ?",
        ["synthetic-finding"],
      ).map((row) => row["detail"]);
      const indexes = Object.fromEntries(
        [
          "finding_occurrences_by_finding",
          "scan_comparisons_by_after_scan",
        ].map((name) => [
          name,
          rows(`PRAGMA index_info(${name})`).map((row) => row["name"]),
        ]),
      );
      const identity = (target: string, scan: string) =>
        derivedFindingIdentityRows(
          { scan: { id: scan, target: { targetId: target } } },
          {
            scanId: scan,
            findings: [
              {
                ruleId: "synthetic-control",
                identity: { anchor: "synthetic-control" },
              },
            ],
          },
        )[0]!.slice(2, 4);
      const first = identity("target", "first"),
        recurring = identity("target", "second"),
        other = identity("another-target", "third");
      return {
        unchanged: stringifyJson(snapshot()) === stringifyJson(original),
        comparisons: original.length,
        plan,
        identityPlan,
        indexes,
        stableIdentity: first[0] === recurring[0],
        distinctOccurrences: first[1] !== recurring[1],
        targetScopedIdentity: first[0] !== other[0],
        foreignKeyErrors: rows("PRAGMA foreign_key_check").length,
      };
    }
    case "matching": {
      connection.exec(`CREATE TABLE security_targets (id TEXT, current_path TEXT);
CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, started_at TEXT);
CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);
CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);
CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);`);
      const finding = (id: string, identity = id) =>
        execute(
          "INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          [id, identity, id, "{}", "fix", "high", "summary", "title"],
        );
      const scan = (index: number, identity?: string) => {
        const id = `scan-${index}`;
        execute("INSERT INTO scans VALUES (?, ?, NULL, ?, ?)", [
          id,
          repository,
          "complete",
          String(index),
        ]);
        finding(id, identity);
      };
      for (let index = 0; index < 3; index++) scan(index);
      const queries = trace(),
        backfilled: string[] = [];
      const result = listUnmatchedScanPairs(
        connection,
        { repository },
        {
          backfillFindingDetails: (_, scan) => {
            backfilled.push(scan.id);
          },
          readCoverage: () => ({}),
        },
      );
      const findingQueries = queries.filter((query) =>
        query.includes("FROM finding_occurrences AS occurrences"),
      ).length;
      for (const value of [
        ["scan-0", "scan-1"],
        ["scan-0", "scan-2"],
        ["scan-1", "scan-2"],
      ])
        execute("INSERT INTO scan_comparisons VALUES (?, ?)", value);
      queries.length = 0;
      const cached = listUnmatchedScanPairs(
        connection,
        { repository },
        { backfillFindingDetails: () => {}, readCoverage: () => ({}) },
      );
      const cachedLinkQueries = queries.filter((query) =>
        query.includes("FROM scan_comparison_matches"),
      ).length;
      for (const name of ["foreign-a", "foreign-b"]) finding(name);
      for (const value of [
        ["scan-0", "scan-1", "scan-0", "scan-1"],
        ["foreign-a", "foreign-b", "foreign-a", "foreign-b"],
      ])
        execute(
          "INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)",
          value,
        );
      queries.length = 0;
      const scoped = savedFindingLinks(
        connection,
        new Set(["scan-0", "scan-1"]),
      );
      const linkQueries = queries.filter((query) =>
        query.includes("FROM scan_comparison_matches"),
      );
      for (const index of [3, 4]) scan(index, `scan-${index - 3}`);
      const readCoverage = (scan: ComparisonScan) => {
        if (["scan-0", "scan-1", "scan-2"].includes(scan.id))
          throw new ScanComparisonError("Synthetic unavailable artifacts");
        return {};
      };
      const callbacks = { readCoverage, backfillFindingDetails: () => {} };
      const unavailable = listUnmatchedScanPairs(
        connection,
        { repository },
        callbacks,
      );
      const forced = listUnmatchedScanPairs(
        connection,
        { repository, force: true },
        callbacks,
      );
      for (const value of [
        ["scan-1", "scan-2", "scan-1", "scan-2"],
        ["scan-2", "scan-0", "scan-2", "scan-0"],
        ["scan-0", "foreign-a", "scan-0", "foreign-a"],
        ["foreign-a", "scan-1", "foreign-a", "scan-1"],
      ])
        execute(
          "INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)",
          value,
        );
      const oldLimit = connection.raw.limit(9, 2);
      queries.length = 0;
      const batched = savedFindingLinks(
          connection,
          new Set(["scan-2", "scan-0", "scan-1"]),
        ),
        batchedQueryCount = queries.length;
      connection.raw.limit(9, oldLimit);
      queries.length = 0;
      const empty = savedFindingLinks(connection, new Set());
      return {
        result,
        backfilled,
        findingQueries,
        cached,
        cachedLinkQueries,
        scopedLinks: scoped.map(({ before_finding_id, after_finding_id }) => ({
          before_finding_id,
          after_finding_id,
        })),
        scopedQueryCount: linkQueries.length,
        unscopedQueries: linkQueries.filter(
          (query) => !query.includes("WHERE matches.before_scan_id"),
        ).length,
        unavailable,
        forcedKnownGroups: forced.batches.map(
          (batch) => batch["knownFindingGroups"] ?? null,
        ),
        batchedLinks: batched.map((row) => [
          row.before_scan_id,
          row.after_scan_id,
        ]),
        batchedQueryCount,
        expectedBatchedQueryCount: 2,
        emptyLinks: empty,
        emptyQueryCount: queries.length,
      };
    }
    case "cached": {
      connection.exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, target_path TEXT, target_id TEXT, status TEXT);
CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT, severity TEXT
);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparisons (
    before_scan_id TEXT, after_scan_id TEXT, result_json TEXT,
    PRIMARY KEY(before_scan_id, after_scan_id)
);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT
);
CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);`);
      for (const scan of ["before", "after", "later", "latest"])
        execute("INSERT INTO scans VALUES (?, ?, ?, ?)", [
          scan,
          repository,
          "target",
          "complete",
        ]);
      for (const [scan, names] of [
        ["before", ["a1", "a2"]],
        ["after", ["b1", "b2"]],
        ["later", ["c1", "c2"]],
        ["latest", ["d1"]],
      ] as const)
        for (const name of names) {
          execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?)", [
            name,
            name,
            scan,
            name,
            name.endsWith("1") ? "low" : "high",
          ]);
          execute("INSERT INTO finding_locations VALUES (?, ?, ?, ?)", [
            name,
            name === "a1" ? "src/excluded.py" : "src/covered.py",
            "root_control",
            0,
          ]);
        }
      const link = (before: string, after: string) =>
        execute(
          `INSERT INTO scan_comparison_matches
        SELECT previous.scan_id, current.scan_id, previous.id, current.id FROM finding_occurrences AS previous, finding_occurrences AS current
        WHERE previous.id = ? AND current.id = ?`,
          [before, after],
        );
      for (const [before, after] of [
        ["a1", "c1"],
        ["a2", "c1"],
        ["b1", "c2"],
        ["b2", "c2"],
      ] as const)
        link(before, after);
      const payload = {
        matches: [],
        uncertain: [{ ...pair("a1", "b1"), reason: "Synthetic uncertainty." }],
        related: [pair("a2", "b2")],
      };
      const cache = () =>
        execute("INSERT OR REPLACE INTO scan_comparisons VALUES (?, ?, ?)", [
          "before",
          "after",
          JSON.stringify(payload),
        ]);
      const coverage = {
        ...completeCoverage(),
        excludePaths: ["src/excluded.py"],
      };
      const compare = () =>
        compareScans(
          connection,
          { ...pairArgs, requireMatches: true },
          { requireScan, readCoverage: () => coverage },
        );
      cache();
      const uncertain = compare();
      payload.uncertain = [];
      cache();
      const excluded = compare();
      coverage.excludePaths = [];
      const resolved = compare();
      execute("INSERT INTO finding_triage VALUES (?, ?, ?)", [
        "a1",
        "closed",
        "already_fixed",
      ]);
      link("c1", "d1");
      link("c2", "d1");
      const linked = compare();
      const unchanged =
        rows("SELECT result_json FROM scan_comparisons")[0]!["result_json"] ===
        JSON.stringify(payload);
      execute(
        "DELETE FROM scan_comparison_matches WHERE after_scan_id = 'latest'",
      );
      return {
        uncertain,
        excluded,
        resolved,
        linked,
        unchanged,
        restored: compare(),
      };
    }
    case "relations": {
      connection.exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT);
CREATE INDEX scans_by_target ON scans(target_id, id);
CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT,
    UNIQUE(scan_id, finding_id)
);
CREATE INDEX occurrences_by_finding ON finding_occurrences(finding_id, id);
CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT
);
CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);`);
      for (const value of [
        ["one", "target"],
        ["two", "target"],
        ["three", "clone"],
        ["four", "clone"],
        ["foreign-one", "unrelated-target"],
        ["foreign-two", "unrelated-target"],
      ])
        execute("INSERT INTO scans VALUES (?, ?)", value);
      for (let index = 0; index < 10_000; index++)
        for (const [side, scan] of [
          ["left", "one"],
          ["right", "two"],
        ] as const)
          execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)", [
            `${side}-${index}`,
            `${side}-identity-${index}`,
            scan,
            `Synthetic ${side} ${index}`,
          ]);
      const payload = JSON.stringify({
        matches: [],
        uncertain: [],
        related: Array.from({ length: 10_000 }, (_, index) =>
          pair(`left-${index}`, `right-${index}`),
        ),
      });
      execute("INSERT INTO scan_comparisons VALUES (?, ?, ?)", [
        "one",
        "two",
        payload,
      ]);
      const queries = trace();
      const scoped = findingRelations(connection, "one", ["left-0"]),
        scopedQueries = queries.length;
      queries.length = 0;
      const empty = findingRelations(connection, "one", []),
        emptyQueries = queries.length;
      for (const value of [
        ["recurring-left", "left-identity-0", "four", "Recurring control"],
        ["bridge", "bridge-identity", "three", "Renamed control"],
        ["foreign-a", "foreign-identity-a", "foreign-one", "Unrelated A"],
        ["foreign-b", "foreign-identity-b", "foreign-two", "Unrelated B"],
      ])
        execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)", value);
      for (const value of [
        ["four", "three", "recurring-left", "bridge"],
        ["two", "three", "right-0", "bridge"],
        ["foreign-one", "foreign-two", "foreign-a", "foreign-b"],
      ])
        execute(
          "INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)",
          value,
        );
      const aliases = confirmedFindingAliases(connection, ["left-0"]);
      const forward = findingRelations(connection, "one", ["left-0"]),
        reverse = findingRelations(connection, "two", ["right-0"]),
        remaining = findingRelations(connection, "one", ["left-1"]);
      const unchanged =
        rows("SELECT result_json FROM scan_comparisons")[0]!["result_json"] ===
        payload;
      execute(
        "DELETE FROM scan_comparison_matches WHERE before_occurrence_id = ?",
        ["right-0"],
      );
      const restoredAfterUnlink =
        stringifyJson(findingRelations(connection, "one", ["left-0"])) ===
        stringifyJson(scoped);
      const oldLimit = connection.raw.limit(9, 8);
      queries.length = 0;
      const batched = findingRelations(
          connection,
          "one",
          Array.from({ length: 10 }, (_, index) => `left-${index + 1}`),
        ),
        batchedQueries = queries.length;
      connection.raw.limit(9, 999);
      queries.length = 0;
      const legacyRows = [
        ...rowsForIds(
          connection,
          "SELECT id FROM finding_occurrences WHERE id IN ({placeholders})",
          Array.from({ length: 1001 }, (_, index) => `left-${index}`),
        ),
      ];
      connection.raw.limit(9, oldLimit);
      return {
        scoped,
        scopedQueries,
        empty,
        emptyQueries,
        aliases: [...aliases.keys()].sort(),
        forward,
        reverse,
        remaining: Object.keys(remaining).sort(),
        unchanged,
        restoredAfterUnlink,
        batchedCount: Object.keys(batched).length,
        batchedQueries,
        expectedBatchedQueries: 6,
        legacyCount: legacyRows.length,
        legacyQueries: queries.length,
      };
    }
    case "recurring": {
      connection.exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT);
CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT, reason TEXT
);`);
      const scans = [
        ["a", "a"],
        ["b", "b"],
        ["c", "c"],
        ["a-repeat", "a"],
        ["c-repeat", "c"],
        ["unlinked", "unlinked"],
      ] as const;
      for (const [index, [scan, finding]] of scans.entries()) {
        execute("INSERT INTO scans VALUES (?, ?)", [scan, String(index)]);
        execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)", [
          scan,
          finding,
          scan,
          scan,
        ]);
      }
      for (const value of [
        ["a", "b", "a", "b", "First confirmed link."],
        ["b", "c", "b", "c", "Second confirmed link."],
      ])
        execute(
          "INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?, ?)",
          value,
        );
      const collect = () =>
        Object.fromEntries(
          scans.map(([scan], index) => {
            const [matches, first, bounds] = findingMatches(
              connection,
              scan,
              scan,
              String(index),
            );
            for (const match of matches) {
              assert.ok(match["reason"]);
              if (scan === "a" && match["occurrenceId"] === "b")
                assert.equal(match["reason"], "First confirmed link.");
            }
            return [
              scan,
              {
                linked: matches.map((match) => match["occurrenceId"]),
                first,
                bounds,
              },
            ];
          }),
        );
      const withLinks = collect();
      execute("DELETE FROM scan_comparison_matches");
      return { withLinks, withoutLinks: collect() };
    }
  }
}
try {
  process.stdout.write(stringifyJson(run(process.argv[2] as Scenario)));
} finally {
  connection.close();
}
