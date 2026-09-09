import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { buildSync } from "esbuild";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { Scenario } from "./support/legacy-history-fixture";

const root = mkdtempSync(join(tmpdir(), "history-fixture-"));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/legacy-history-fixture.ts", import.meta.url),
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
function runScenario(scenario: Scenario): Record<string, unknown> {
  const child = spawnSync(node, [fixture, scenario, root], {
    encoding: "utf8",
    env: { ...process.env, PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Record<string, unknown>;
}

test("keeps unrelated legacy repositories out of matching inputs", () => {
  const observed = runScenario("unrelated");
  expect(observed).toEqual({ before: [], after: [] });
});

test("validates related pairs by confirmed group without replacing saved results", () => {
  expect(runScenario("validation")).toEqual({
    summary: { new: 1, persisting: 2, reopened: 0, resolved: 1, unknown: 0 },
    related: [
      ["a2", "y"],
      ["c", "z"],
    ],
    savedPairs: 5,
  });
});

test("upgrades existing history with indexed identity and reverse comparison lookups", () => {
  const observed = runScenario("indexes") as {
    plan: string[];
    identityPlan: string[];
  };
  expect(observed).toMatchObject({
    unchanged: true,
    comparisons: 19_900,
    foreignKeyErrors: 0,
    stableIdentity: true,
    distinctOccurrences: true,
    targetScopedIdentity: true,
    indexes: {
      finding_occurrences_by_finding: ["finding_id", "id"],
      scan_comparisons_by_after_scan: ["after_scan_id", "before_scan_id"],
    },
  });
  expect(observed.plan.some((step) => step.includes("before_scan_id=?"))).toBe(
    true,
  );
  expect(observed.plan.some((step) => step.includes("after_scan_id=?"))).toBe(
    true,
  );
  expect(
    observed.plan.some((step) => step.startsWith("SCAN scan_comparisons")),
  ).toBe(false);
  expect(
    observed.identityPlan.some((step) =>
      step.includes("finding_occurrences_by_finding"),
    ),
  ).toBe(true);
});

test("loads each scan once and scopes saved links to uncached history", () => {
  const observed = runScenario("matching");
  expect(observed).toMatchObject({
    backfilled: ["scan-0", "scan-1", "scan-2"],
    findingQueries: 3,
    cached: { batches: [], skippedPairs: 3 },
    cachedLinkQueries: 0,
    scopedLinks: [{ before_finding_id: "scan-0", after_finding_id: "scan-1" }],
    scopedQueryCount: 1,
    unscopedQueries: 0,
    batchedLinks: [
      ["scan-0", "scan-1"],
      ["scan-1", "scan-2"],
      ["scan-2", "scan-0"],
    ],
    emptyLinks: [],
    emptyQueryCount: 0,
    unavailable: {
      scanCount: 5,
      unavailableScans: 3,
      batches: [
        {
          afterScanId: "scan-4",
          beforeScans: [{ scanId: "scan-3" }],
          knownFindingGroups: [["scan-0", "scan-1"]],
        },
      ],
    },
    forcedKnownGroups: [null],
    result: {
      scanCount: 3,
      batches: [
        { afterScanId: "scan-1", beforeScans: [{ scanId: "scan-0" }] },
        {
          afterScanId: "scan-2",
          beforeScans: [{ scanId: "scan-0" }, { scanId: "scan-1" }],
        },
      ],
    },
  });
  expect(observed["batchedQueryCount"]).toBe(
    observed["expectedBatchedQueryCount"],
  );
});

test("reconciles cached statuses without losing grouped coverage or uncertainty", () => {
  const observed = runScenario("cached");
  expect(observed).toMatchObject({
    uncertain: {
      summary: { new: 0, resolved: 0, unknown: 2 },
      findings: [
        {
          findingId: "a2",
          beforeOccurrenceIds: ["a1", "a2"],
          severity: "high",
          status: "unknown",
          reason: "Synthetic uncertainty.",
        },
        {
          findingId: "b2",
          afterOccurrenceIds: ["b1", "b2"],
          status: "unknown",
          reason: "Synthetic uncertainty.",
        },
      ],
    },
    excluded: { summary: { new: 1, resolved: 0, unknown: 1 } },
    resolved: { summary: { new: 1, resolved: 1, unknown: 0 } },
    linked: {
      summary: { new: 0, persisting: 0, reopened: 1, resolved: 0, unknown: 0 },
      findings: [
        {
          beforeOccurrenceIds: ["a1", "a2"],
          afterOccurrenceIds: ["b1", "b2"],
          matchReason: expect.any(String),
          status: "reopened",
        },
      ],
    },
    unchanged: true,
  });
  expect(observed["linked"]).not.toHaveProperty("related");
  expect(observed["restored"]).toEqual(observed["resolved"]);
});

test("loads displayed relations in bulk and follows current confirmed identities", () => {
  const observed = runScenario("relations");
  expect(observed).toMatchObject({
    scoped: {
      "left-0": [{ occurrenceId: "right-0", scanId: "two" }],
    },
    scopedQueries: 3,
    empty: {},
    emptyQueries: 0,
    aliases: ["bridge-identity", "left-identity-0", "right-identity-0"],
    forward: {},
    reverse: {},
    remaining: ["left-1"],
    unchanged: true,
    restoredAfterUnlink: true,
    batchedCount: 10,
    legacyCount: 1001,
    legacyQueries: 2,
  });
  expect(observed["batchedQueries"]).toBe(observed["expectedBatchedQueries"]);
});

test("includes recurring stable identities in confirmed finding history", () => {
  const observed = runScenario("recurring");
  expect(observed).toEqual({
    withLinks: {
      a: {
        linked: ["a-repeat", "b", "c", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      b: {
        linked: ["a", "a-repeat", "c", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      c: {
        linked: ["a", "a-repeat", "b", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      "a-repeat": {
        linked: ["a", "b", "c", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      "c-repeat": {
        linked: ["a", "a-repeat", "b", "c"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      unlinked: { linked: [], first: "5", bounds: ["unlinked"] },
    },
    withoutLinks: {
      a: { linked: ["a-repeat"], first: "0", bounds: ["a", "a-repeat"] },
      "a-repeat": { linked: ["a"], first: "0", bounds: ["a", "a-repeat"] },
      b: { linked: [], first: "1", bounds: ["b"] },
      c: { linked: ["c-repeat"], first: "2", bounds: ["c", "c-repeat"] },
      "c-repeat": { linked: ["c"], first: "2", bounds: ["c", "c-repeat"] },
      unlinked: { linked: [], first: "5", bounds: ["unlinked"] },
    },
  });
});
