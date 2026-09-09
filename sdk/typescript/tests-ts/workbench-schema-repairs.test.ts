import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { ScenarioResult, Snapshot } from "./support/schema-repair-fixture";

const node = Bun.which("node")!;
const directory = mkdtempSync(join(tmpdir(), "schema-repairs-"));
const fixture = join(directory, "fixture.mjs");
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/schema-repair-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(name: string): ScenarioResult {
  const result = spawnSync(node, [fixture, PLUGIN_ROOT, name], {
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
    maxBuffer: Infinity,
  });
  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as ScenarioResult;
}
const names = (snapshot: Snapshot) => snapshot.schema.map((row) => row["name"]);
const owners = (snapshot: Snapshot) =>
  snapshot.tables["scans"]!.map((row) => [
    row["id"],
    row["deep_scan_owner_thread_id"],
  ]);

describe("native SQLite schema repairs", () => {
  test("splits Python line boundaries and whitespace without splitting quoted statements or triggers", () => {
    const result = spawnSync(node, [fixture, PLUGIN_ROOT, "statements"], {
      encoding: "utf8",
      env: { ...process.env, PATH: "" },
    });
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const results = JSON.parse(result.stdout) as {
      statements: string[] | null;
      error: string | null;
    }[];
    expect(results[0]!.statements).toEqual([]);
    expect(results[2]!.statements).toEqual(["SELECT 1;", "SELECT 2;"]);
    expect(results[3]!.statements).toEqual(["SELECT 1; SELECT 2;"]);
    expect(results[4]!.statements).toEqual(["SELECT 1;"]);
    expect(results[6]!.statements).toEqual([
      "SELECT\n1;",
      "SELECT\n2;",
      "SELECT\n3;",
      "SELECT\n4;",
    ]);
    expect(results[8]!.statements).toHaveLength(1);
    expect(results[10]!.error).toBe("Incomplete SQLite migration statement.");
    expect(results[13]!.error).toBe("Incomplete SQLite migration statement.");
    expect(results[15]!.statements).toEqual(["SELECT 'x\u001fy';"]);
  });
  test("adds missing columns and thread indexes without changing existing rows or opening a transaction", () => {
    const added = run("column").snapshots;
    expect(added[1]!.tables["things"]).toEqual([
      { id: "41", value: "kept", extra: "added" },
    ]);
    expect(added[2]).toEqual(added[1]);
    expect(added[1]!.inTransaction).toBe(false);
    const thread = run("thread").snapshots;
    expect(thread[1]!.tables["workspaces"]).toEqual([
      { id: "kept", updated_at: "t", thread_id: null },
    ]);
    expect(names(thread[1]!)).toContain("workspaces_by_thread_and_updated_at");
    expect(thread[2]).toEqual(thread[1]);
    expect(run("column-missing-table").snapshots[1]!.error!.message).toContain(
      "no such table",
    );
  });
  test("backfills failure thresholds once and preserves an existing threshold", () => {
    const snapshots = run("counter").snapshots;
    expect(snapshots[1]!.tables["deep_scan_runs"]).toEqual([
      {
        scan_id: "a",
        stop_after_no_new: "2",
        stop_after_consecutive_errors: "2",
        consecutive_errors: "0",
      },
      {
        scan_id: "b",
        stop_after_no_new: "7",
        stop_after_consecutive_errors: "7",
        consecutive_errors: "0",
      },
    ]);
    expect(snapshots[1]!.inTransaction).toBe(true);
    expect(
      snapshots
        .at(-1)!
        .tables[
          "deep_scan_runs"
        ]!.map((row) => [row["stop_after_consecutive_errors"], row["consecutive_errors"]]),
    ).toEqual([
      ["9", "3"],
      ["9", "3"],
    ]);
    expect(snapshots.at(-1)!.inTransaction).toBe(false);
    const partial = run("counter-partial").snapshots[1]!;
    expect(
      partial.tables["deep_scan_runs"]![0]!["stop_after_consecutive_errors"],
    ).toBe("9");
    expect(partial.inTransaction).toBe(false);
    const failed = run("counter-error").snapshots;
    expect(failed[1]!.error!.code).toBe(19);
    expect(failed[1]!.inTransaction).toBe(true);
    expect(failed[2]!.inTransaction).toBe(false);
    expect(failed[2]!.tables["deep_scan_runs"]![0]).toEqual({
      scan_id: "invalid",
      stop_after_no_new: "0",
      stop_after_consecutive_errors: "1",
    });
  });
  test("repairs missing deep-scan objects while preserving owner assignments and caller rollback", () => {
    const repaired = run("deep-owners").snapshots;
    expect(owners(repaired[1]!)).toEqual([
      ["scan-a", "owner-a"],
      ["scan-b", null],
      ["scan-c", "continuation-c"],
      ["scan-d", null],
      ["scan-e", null],
    ]);
    expect(repaired[1]!.inTransaction).toBe(true);
    expect(repaired[3]).toEqual(repaired[2]);
    const partial = run("deep-partial").snapshots[1]!;
    expect(owners(partial)[0]).toEqual(["scan-a", "custom-a"]);
    expect(owners(partial)[2]).toEqual(["scan-c", null]);
    expect(names(partial)).toContain("deep_scan_dedup_inputs");
    expect(partial.inTransaction).toBe(false);
    const rollback = run("deep-rollback").snapshots;
    expect(rollback[2]!.error).toBe(null);
    expect(rollback[3]).toEqual(rollback[0]);
    const injected = run("deep-injected").snapshots[1]!;
    expect(names(injected)).toContain("deep_scan_injected");
    expect(names(injected)).not.toContain("deep_scan_runs");
    expect(owners(injected).every(([, owner]) => owner === "injected")).toBe(
      true,
    );
  });
  test("returns whether stable targets needed repair, cleans only orphan scan references, and honors rollback", () => {
    const repaired = run("targets").snapshots;
    expect(repaired[1]!.value).toBe(true);
    expect(repaired[1]!.inTransaction).toBe(true);
    expect(repaired[3]!.value).toBe(false);
    expect(repaired[3]!.inTransaction).toBe(false);
    const partial = run("targets-partial").snapshots;
    expect(partial[1]!.tables["scans"]!.map((row) => row["target_id"])).toEqual(
      ["kept-target", null, null, null, null],
    );
    expect(
      partial[1]!.tables["workspaces"]!.every(
        (row) => row["target_id"] === "orphan",
      ),
    ).toBe(true);
    expect(partial[3]!.value).toBe(false);
    const rollback = run("targets-rollback").snapshots;
    expect(rollback[2]!.value).toBe(true);
    expect(rollback[3]).toEqual(rollback[0]);
    expect(names(run("targets-injected").snapshots[1]!)).toContain(
      "injected_marker",
    );
  });
});
