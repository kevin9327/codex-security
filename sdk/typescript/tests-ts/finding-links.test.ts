import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { Operation, Response } from "./support/finding-links-fixture";

const root = mkdtempSync(join(tmpdir(), "finding-links-"));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/finding-links-fixture.ts", import.meta.url),
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
function run(
  operations: Operation[],
  allowErrors = false,
): Response["results"] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(operations),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const results = (JSON.parse(child.stdout) as Response).results;
  expect(results).toHaveLength(operations.length);
  if (!allowErrors)
    for (const result of results) expect(result.error).toBeUndefined();
  return results;
}
const sql = (sql: string, ...parameters: (string | null)[]): Operation => ({
  sql,
  parameters,
});
function occurrence(id: string, identity = id, stamp = id): Operation[] {
  return [
    sql("INSERT INTO scans VALUES (?, ?)", id, stamp),
    sql(
      "INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)",
      id,
      identity,
      id,
      "Title " + id,
    ),
  ];
}
const link = (before: string, after: string, reason = "Confirmed.") =>
  sql(
    "INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?, ?)",
    before,
    after,
    before,
    after,
    reason,
  );
const relation = (before: string, after: string) =>
  sql(
    "INSERT INTO scan_comparisons VALUES (?, ?, ?)",
    before,
    after,
    JSON.stringify({
      matches: [],
      uncertain: [],
      related: [
        {
          beforeOccurrenceId: before,
          afterOccurrenceId: after,
          reason: "Separate controls.",
        },
      ],
    }),
  );
const matches = (id: string, stamp = id): Operation => ({
  matches: { occurrenceId: id, scanId: id, startedAt: stamp },
});

test("finding aliases preserve union order and sort known groups by Python code points", () => {
  const result = run([
    {
      aliases: [
        ["b", "c"],
        ["a", "b"],
        ["c", "a"],
        ["__proto__", "constructor"],
        ["alone", "alone"],
      ],
    },
    {
      groups: {
        links: [
          {
            before_scan_id: "one",
            after_scan_id: "two",
            before_finding_id: "😀",
            after_finding_id: "a",
          },
          {
            before_scan_id: "one",
            after_scan_id: "two",
            before_finding_id: "\ue000",
            after_finding_id: "z",
          },
          {
            before_scan_id: "two",
            after_scan_id: "outside",
            before_finding_id: "a",
            after_finding_id: "z",
          },
        ],
        scanIds: ["one", "two"],
      },
    },
  ]);
  expect(Object.entries(result[0]!.value as object)).toEqual([
    ["b", "a"],
    ["c", "a"],
    ["a", "a"],
    ["__proto__", "__proto__"],
    ["constructor", "__proto__"],
    ["alone", "alone"],
  ]);
  expect(result[1]!.value).toEqual([
    ["a", "😀"],
    ["z", "\ue000"],
  ]);
  expect(result.map((row) => row.queries)).toEqual([0, 0]);
});

test("finding history includes recurring identities, cycles and confirmed reasons without writes", () => {
  const seed = [
    ...occurrence("a", "a", "0"),
    ...occurrence("b", "b", "1"),
    ...occurrence("c", "c", "2"),
    ...occurrence("a-repeat", "a", "3"),
    ...occurrence("c-repeat", "c", "4"),
    ...occurrence("unlinked", "unlinked", "5"),
    link("a", "b", "First link."),
    link("b", "c"),
    link("c", "a"),
    sql("COMMIT"),
  ];
  const result = run([
    ...seed,
    matches("a", "0"),
    matches("a-repeat", "3"),
    matches("unlinked", "5"),
    sql("DELETE FROM scan_comparison_matches"),
    sql("COMMIT"),
    matches("a", "0"),
    matches("c", "2"),
  ]).slice(seed.length);
  const first = result[0]!.value as [
    Record<string, string>[],
    string,
    string[],
  ];
  expect(first[0].map((row) => row["occurrenceId"])).toEqual([
    "a-repeat",
    "b",
    "c",
    "c-repeat",
  ]);
  expect(first[0].find((row) => row["occurrenceId"] === "b")?.["reason"]).toBe(
    "First link.",
  );
  expect(first.slice(1)).toEqual(["0", ["a", "c-repeat"]]);
  expect((result[1]!.value as unknown[]).slice(1)).toEqual([
    "0",
    ["a", "c-repeat"],
  ]);
  expect(result[2]!.value).toEqual([[], "5", ["unlinked"]]);
  expect((result[5]!.value as unknown[]).slice(1)).toEqual([
    "0",
    ["a", "a-repeat"],
  ]);
  expect((result[6]!.value as unknown[]).slice(1)).toEqual([
    "2",
    ["c", "c-repeat"],
  ]);
  expect(
    result.filter((_, i) => i !== 3).every((row) => !row.inTransaction),
  ).toBe(true);
});

test("related findings traverse only selected components and disappear after confirmation", () => {
  const seed = [
    ...occurrence("left", "left-id"),
    ...occurrence("right", "right-id"),
    ...occurrence("repeat", "left-id"),
    ...occurrence("bridge"),
    ...occurrence("other-left"),
    ...occurrence("other-right"),
    relation("left", "right"),
    link("other-left", "other-right"),
    sql("COMMIT"),
  ];
  const query: Operation = { relations: { scanId: "left", ids: ["left"] } };
  const result = run([
    ...seed,
    query,
    { relations: { scanId: "left", ids: [] } },
    link("repeat", "bridge"),
    link("right", "bridge"),
    sql("COMMIT"),
    { confirmed: ["left"] },
    query,
    { relations: { scanId: "right", ids: ["right"] } },
    sql(
      "DELETE FROM scan_comparison_matches WHERE before_occurrence_id = 'right'",
    ),
    sql("COMMIT"),
    query,
  ]).slice(seed.length);
  expect(result[0]!.value).toEqual({
    left: [
      {
        findingId: "right-id",
        occurrenceId: "right",
        reason: "Separate controls.",
        scanId: "right",
        title: "Title right",
      },
    ],
  });
  expect(result[0]!.queries).toBe(3);
  expect(result[1]!.value).toEqual({});
  expect(result[1]!.queries).toBe(0);
  expect(Object.keys(result[5]!.value as object).sort()).toEqual([
    "bridge",
    "left-id",
    "right-id",
  ]);
  expect(result[6]!.value).toEqual({});
  expect(result[7]!.value).toEqual({});
  expect(result[10]!.value).toEqual(result[0]!.value);
});

test("finding queries respect the live SQLite variable limit and deduplicate input IDs", () => {
  const seed = Array.from({ length: 11 }, (_, i) =>
    occurrence(`id-${i}`),
  ).flat();
  const links = Array.from({ length: 10 }, (_, i) =>
    link(`id-${i}`, `id-${i + 1}`),
  );
  const ids = Array.from({ length: 11 }, (_, i) => `id-${i}`);
  const result = run([
    ...seed,
    ...links,
    sql("COMMIT"),
    { limit: 2 },
    { rows: [...ids, ...ids] },
    { saved: ids },
    { confirmed: ids },
    { rows: [] },
  ]).slice(-5);
  expect(result[1]!.queries).toBe(6);
  expect((result[1]!.value as string[]).sort()).toEqual([...ids].sort());
  expect(result[2]!.queries).toBe(6);
  expect(result[2]!.value).toHaveLength(10);
  expect(result[3]!.queries).toBe(6);
  expect(Object.keys(result[3]!.value as object).sort()).toEqual(
    [...ids].sort(),
  );
  expect(new Set(Object.values(result[3]!.value as object)).size).toBe(1);
  expect(result[4]!.queries).toBe(0);
  expect(result.every((row) => !row.inTransaction)).toBe(true);
});

test("related findings omit stale occurrence IDs and preserve prototype-shaped keys", () => {
  const seed = [
    ...occurrence("__proto__"),
    ...occurrence("constructor"),
    relation("__proto__", "constructor"),
    sql("COMMIT"),
  ];
  const query: Operation = {
    relations: { scanId: "__proto__", ids: ["__proto__"] },
  };
  const result = run([
    ...seed,
    query,
    sql(
      "UPDATE finding_occurrences SET scan_id='moved' WHERE id='constructor'",
    ),
    sql("COMMIT"),
    query,
    sql("DELETE FROM finding_occurrences WHERE id='constructor'"),
    sql("COMMIT"),
    query,
  ]).slice(seed.length);
  expect(Object.keys(result[0]!.value as object)).toEqual(["__proto__"]);
  expect(result[3]!.value).toEqual({});
  expect(result[6]!.value).toEqual({});
});

test("a zero SQLite variable limit preserves the original batch error", () => {
  const results = run(
    [{ limit: 0 }, { rows: ["missing"] }, { rows: [] }],
    true,
  );
  expect(results.slice(1)).toEqual([
    {
      error: "range() arg 3 must not be zero",
      queries: 0,
      inTransaction: false,
    },
    {
      error: "range() arg 3 must not be zero",
      queries: 0,
      inTransaction: false,
    },
  ]);
});
