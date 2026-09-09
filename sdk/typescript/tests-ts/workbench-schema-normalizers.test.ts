import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type {
  ScenarioResult,
  Snapshot,
} from "./support/schema-normalizer-fixture";

const node = Bun.which("node")!;
const directory = mkdtempSync(join(tmpdir(), "schema-normalizers-"));
const fixture = join(directory, "fixture.mjs");
const timestamp = "2026-07-04T12:00:00Z";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/schema-normalizer-fixture.ts", import.meta.url),
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
function run(name: string): Snapshot[] {
  const result = spawnSync(node, [fixture, PLUGIN_ROOT, name], {
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
    maxBuffer: Infinity,
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return (JSON.parse(result.stdout) as ScenarioResult).snapshots;
}
const history = (snapshot: Snapshot) =>
  Object.fromEntries(
    snapshot.tables["schema_migrations"]!.map((row) => [
      row["version"],
      [row["name"], row["applied_at"]],
    ]),
  );
const objects = (snapshot: Snapshot) =>
  snapshot.schema.map((row) => row["name"]);
function rejectedWithoutWrites(
  name: string,
  kind: string,
  inTransaction = false,
) {
  const snapshots = run(name);
  expect(snapshots[1]!.error!.message).toContain(
    `unsupported ${kind} migration history`,
  );
  const withoutError: Snapshot = { ...snapshots[1]!, error: null };
  expect(withoutError).toEqual({ ...snapshots[0]!, inTransaction });
}

describe("native SQLite historical schema normalization", () => {
  test("retains the current schema and unrelated history without inventing newer migrations", () => {
    const current = run("current");
    expect(current[1]).toEqual({ ...current[0]!, inTransaction: true });
    expect(current[1]!.tables["schema_migrations"]).toHaveLength(41);
    const unrelated = run("unrelated-history");
    expect(unrelated[1]).toEqual({ ...unrelated[0]!, inTransaction: true });
    expect(history(unrelated[1]!).hasOwnProperty("9007199254740993")).toBe(
      true,
    );
    expect(history(unrelated[1]!)["33"]).toEqual([
      "unrelated migration",
      "applied-33",
    ]);
  });
  test("moves the historical finding index after mirror validation and preserves caller rollback", () => {
    const migrated = run("finding-index-history");
    expect(history(migrated[1]!)).toEqual({
      40: ["index finding identity and comparison history", "applied-33"],
    });
    expect(migrated[1]!.inTransaction).toBe(true);
    expect(migrated[3]).toEqual({ ...migrated[2]!, inTransaction: true });
    const conflict = run("finding-index-conflict");
    expect(conflict[1]!.error!.code).toBe(19);
    expect(conflict[1]!.tables).toEqual(conflict[0]!.tables);
    expect(conflict[1]!.inTransaction).toBe(true);
    expect(conflict[2]).toEqual(conflict[0]);
    const rollback = run("finding-index-rollback");
    expect(rollback[2]!.error).toBe(null);
    expect(rollback[3]).toEqual(rollback[0]);
    const warning = run("finding-index-before-warning-error");
    expect(warning[1]!.error!.message).toContain("unsupported pre-release");
    expect(history(warning[1]!)["40"]).toEqual([
      "index finding identity and comparison history",
      "applied-33",
    ]);
    expect(warning[2]).toEqual(warning[0]);
    rejectedWithoutWrites("finding-index-after-mirror-error", "mirror");
  });
  test("renumbers the exact mirror lineage, preserving timestamps and caller rollback", () => {
    const snapshots = run("mirror");
    expect(history(snapshots[1]!)).toEqual({
      31: ["freeze stopped scan source digests", "applied-29"],
      32: ["separate deep scan publication failures", "applied-30"],
    });
    expect(snapshots[1]!.inTransaction).toBe(true);
    expect(snapshots[3]).toEqual(snapshots[2]);
    rejectedWithoutWrites("mirror-partial", "mirror");
    rejectedWithoutWrites("mirror-conflict", "mirror");
    const rollback = run("mirror-rollback");
    expect(rollback[3]).toEqual(rollback[0]);
    const failure = run("mirror-before-warning-error");
    expect(failure[1]!.error!.message).toContain("unsupported pre-release");
    expect(history(failure[1]!)["31"]).toEqual([
      "freeze stopped scan source digests",
      "applied-29",
    ]);
    expect(failure[1]!.inTransaction).toBe(true);
    expect(failure[2]).toEqual(failure[0]);
  });
  test("preserves populated legacy execution settings and constraints across supported histories", () => {
    for (const suffix of [
      "v11",
      "v12-static",
      "v12-dynamic",
      "v13",
      "v22",
      "v25",
    ]) {
      const snapshots = run(`profiles-${suffix}`);
      expect(snapshots[1]!.error).toBe(null);
      expect(
        snapshots[1]!.tables["scans"]!.map((row) => [
          row["id"],
          row["legacy_execution_model"],
          row["legacy_reasoning_effort"],
          row["model"],
          row["reasoning_effort"],
        ]),
      ).toEqual([
        ["a", "legacy-model", "medium", "legacy-model", "medium"],
        [
          "b",
          "alternate",
          "high",
          suffix === "v13" ? "chosen" : "alternate",
          "high",
        ],
        ["c", null, null, null, null],
      ]);
      expect(history(snapshots[1]!)["25"]).toEqual([
        "persist scan model settings",
        suffix === "v25" ? "applied-25" : timestamp,
      ]);
      expect(snapshots[1]!.inTransaction).toBe(true);
      expect(snapshots[3]).toEqual({ ...snapshots[2]!, inTransaction: true });
    }
    const constraints = run("execution-constraints");
    expect(constraints[3]!.error!.code).toBe(19);
    expect(constraints[4]).toEqual(constraints[2]);
    const columnsOnly = run("execution-columns-only");
    expect(history(columnsOnly[1]!)["25"]).toEqual([
      "persist scan model settings",
      timestamp,
    ]);
    expect(columnsOnly[3]).toEqual(columnsOnly[2]);
    const historyOnly = run("execution-renames-history-only");
    expect(history(historyOnly[1]!)["25"]).toEqual([
      "persist scan model settings",
      "applied-25",
    ]);
    expect(historyOnly[1]!.schema).toEqual(historyOnly[0]!.schema);
    const stray = run("execution-stray-scan-effort");
    expect(stray[1]).toEqual(stray[0]);
  });
  test("rejects unsupported profiles and retains original partial-failure transaction behavior", () => {
    for (const name of [
      "execution-unknown-11",
      "execution-unknown-12",
      "execution-unknown-25",
      "execution-partial-columns",
      "execution-renamed-collision",
    ])
      rejectedWithoutWrites(name, "execution-profile");
    const missing = run("execution-missing-columns");
    expect(missing[1]!.error!.message).toContain(
      "unsupported execution-profile",
    );
    expect(history(missing[1]!)["25"]).toEqual([
      "persist scan model settings",
      "applied-25",
    ]);
    expect(missing[1]!.inTransaction).toBe(true);
    expect(missing[2]).toEqual(missing[0]);
    const backfill = run("execution-backfill-error");
    expect(backfill[1]!.error!.code).toBe(19);
    expect(backfill[1]!.inTransaction).toBe(true);
    expect(backfill[2]!.tables["scans"]![0]).toMatchObject({
      legacy_execution_model: "legacy-model",
      legacy_reasoning_effort: "medium",
      model: null,
      reasoning_effort: null,
    });
    expect(history(backfill[2]!)).toEqual({});
    expect(backfill[2]!.inTransaction).toBe(false);
    const rollback = run("execution-rollback");
    expect(rollback[2]!.error).toBe(null);
    expect(rollback[3]).toEqual(rollback[0]);
  });
  test("moves old warning and progress versions and reconciles sparse legacy history", () => {
    for (const [oldVersion, newVersion, name] of [
      [25, 26, "persist scan completion warnings"],
      [12, 20, "phase-specific scan progress"],
      [13, 21, "current scan preflight state"],
    ] as const) {
      const snapshots = run(`remap-${oldVersion}`);
      expect(history(snapshots[1]!)).toEqual({
        [newVersion]: [name, `applied-${oldVersion}`],
      });
      expect(snapshots[3]).toEqual({ ...snapshots[2]!, inTransaction: true });
      rejectedWithoutWrites(
        `remap-conflict-${oldVersion}`,
        "pre-release",
        true,
      );
    }
    const legacy = run("legacy-versions");
    expect(history(legacy[1]!)).toEqual({
      2: ["persist capability preflight summaries", timestamp],
      3: ["finding management schema", "applied-2"],
      4: ["scan handoff delivery claims", "applied-3"],
      5: ["finding remediation action claims", "applied-4"],
    });
    expect(
      legacy[1]!.tables["workspaces"]![0]!["capability_preflight_json"],
    ).toBe(null);
    expect(legacy[1]!.tables["scans"]![0]!["target_snapshot_digest"]).toBe(
      null,
    );
    expect(legacy[3]).toEqual({ ...legacy[2]!, inTransaction: true });
    const partial = run("legacy-partial");
    expect(history(partial[1]!)["4"]).toBeUndefined();
    expect(history(partial[1]!)["5"]).toEqual([
      "finding remediation action claims",
      "applied-4",
    ]);
    rejectedWithoutWrites("legacy-conflict", "pre-release", true);
    const existing = run("legacy-existing-columns")[1]!;
    expect(
      existing.tables["workspaces"]![0]!["capability_preflight_json"],
    ).toBe("kept");
    expect(existing.tables["scans"]![0]!["target_snapshot_digest"]).toBe(
      "digest",
    );
    const rollback = run("legacy-rollback");
    expect(rollback[3]).toEqual(rollback[0]);
  });
  test("repairs shadowed setup preferences from supplied migration SQL and preserves existing rows", () => {
    expect(run("setup-0")[1]!.tables["setup_preferences"]).toEqual([]);
    expect(run("setup-1")[1]!.tables["setup_preferences"]).toEqual([
      { singleton: "1", skip_setup_ui: "1", updated_at: "kept" },
    ]);
    const injected = run("setup-injected");
    expect(injected[1]!.tables["injected_settings"]).toEqual([
      { value: "kept" },
    ]);
    expect(objects(injected[1]!)).not.toContain("setup_preferences");
    expect(history(injected[1]!)["19"]).toEqual([
      "persist setup workspace preference",
      "applied-19",
    ]);
    expect(injected[3]).toEqual({ ...injected[2]!, inTransaction: true });
    const failed = run("setup-injected-error");
    expect(failed[1]!.error!.message).toContain(
      "no such table: missing_settings",
    );
    expect(objects(failed[1]!)).toContain("partial_settings");
    expect(failed[1]!.inTransaction).toBe(true);
    expect(failed[2]).toEqual(failed[0]);
    expect(history(failed[2]!)["19"]).toEqual([
      "structured scan guidance context",
      "applied-19",
    ]);
    const rollback = run("setup-injected-rollback");
    expect(rollback[3]).toEqual(rollback[0]);
  });
  test("retains partial progress, recipe data, and newly delivered claims on a second normalization", () => {
    for (const index of [0, 1]) {
      const phase = run(`phase-${index}`);
      expect(phase[1]!.tables["scan_progress"]![0]).toEqual({
        scan_id: "delivered",
        reviewed: "7",
        phase_items_total: index === 0 ? "0" : "3",
        phase_items_completed: "0",
        phase_progress_unit: null,
      });
      expect(phase[3]).toEqual({ ...phase[2]!, inTransaction: true });
      const preflight = run(`preflight-${index}`);
      expect(preflight[1]!.tables["scan_progress"]![0]).toEqual({
        scan_id: "delivered",
        reviewed: "7",
        preflight_issues_json: index === 0 ? "[]" : '["kept"]',
        preflight_checks_total: "0",
        preflight_checks_completed: "0",
      });
      expect(preflight[3]).toEqual({ ...preflight[2]!, inTransaction: true });
    }
    const failed = run("phase-constraint-error");
    expect(failed[1]!.error).toEqual({
      code: 1,
      message: "CHECK constraint failed",
    });
    expect(failed[2]).toEqual(failed[0]);
    const recipe = run("recipe");
    expect(recipe[1]!.tables["scans"]![0]).toMatchObject({
      recipe_json: null,
      parent_scan_id: null,
    });
    expect(
      recipe[1]!.schema.find((row) => row["name"] === "scans")!["sql"],
    ).toContain("REFERENCES scans(id) ON DELETE SET NULL");
    expect(run("recipe-existing")[1]!.tables["scans"]![0]!["recipe_json"]).toBe(
      "kept",
    );
    const claims = run("claims");
    expect(
      claims[1]!.tables["scans"]!.map((row) => [
        row["handoff_claimed_at"],
        row["handoff_claim_token"],
      ]),
    ).toEqual([
      [null, null],
      ["pending-time", "pending-token"],
    ]);
    expect(claims[5]).toEqual({ ...claims[4]!, inTransaction: true });
    expect(claims[5]!.tables["scans"]![0]!["handoff_claim_token"]).toBe(
      "new-token",
    );
  });
  test("orders mirror, warning, profile, and shadowed repairs as one historical normalization", () => {
    const snapshots = run("ordered-combination");
    expect(snapshots[1]!.error).toBe(null);
    expect(history(snapshots[1]!)).toMatchObject({
      2: ["persist capability preflight summaries", timestamp],
      19: ["persist setup workspace preference", "applied-19"],
      20: ["phase-specific scan progress", "applied-12"],
      21: ["current scan preflight state", "applied-13"],
      22: ["replayable scan launch recipes", "applied-22"],
      25: ["persist scan model settings", timestamp],
      26: ["persist scan completion warnings", "applied-25"],
      31: ["freeze stopped scan source digests", "applied-29"],
      32: ["separate deep scan publication failures", "applied-30"],
    });
    expect(history(snapshots[1]!)["11"]).toBeUndefined();
    expect(snapshots[1]!.tables["scans"]![0]).toMatchObject({
      model: "legacy-model",
      reasoning_effort: "medium",
      handoff_claim_token: null,
    });
    expect(snapshots[3]).toEqual({ ...snapshots[2]!, inTransaction: true });
  });
});
