import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { ScenarioResult, Snapshot } from "./support/schema-runner-fixture";

const node = Bun.which("node")!;
const directory = mkdtempSync(join(tmpdir(), "schema-runner-"));
const fixture = join(directory, "fixture.mjs");
let serial = 0;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/schema-runner-fixture.ts", import.meta.url),
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
  const result = spawnSync(
    node,
    [
      fixture,
      PLUGIN_ROOT,
      name,
      join(directory, `database-${serial++}.sqlite3`),
    ],
    {
      encoding: "utf8",
      env: { ...process.env, PATH: "" },
      maxBuffer: Infinity,
    },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return (JSON.parse(result.stdout) as ScenarioResult).snapshots;
}
const database = ({
  schema,
  tables,
  foreignKeys,
  inTransaction,
}: Snapshot) => ({ schema, tables, foreignKeys, inTransaction });
const history = (snapshot: Snapshot) => snapshot.tables["schema_migrations"]!;
const table = (snapshot: Snapshot, name: string) =>
  snapshot.schema.find(
    (row) => row["type"] === "table" && row["name"] === name,
  );
const backfills = (snapshot: Snapshot) =>
  snapshot.events.filter((event) => event.startsWith("backfill:"));

describe("native SQLite schema runner", () => {
  test("initializes the full schema once and keeps transaction and callback order", () => {
    const snapshots = run("fresh");
    expect(snapshots[1]!.error).toBe(null);
    expect(history(snapshots[1]!).map((row) => row["version"])).toEqual(
      Array.from({ length: 41 }, (_, index) => String(index + 1)),
    );
    expect(history(snapshots[1]!)[0]!["applied_at"]).toBe("tick-2");
    expect(history(snapshots[1]!).at(-1)!["applied_at"]).toBe("tick-42");
    expect(snapshots[1]!.events[0]).toBe("now:1:true");
    expect(backfills(snapshots[1]!)).toHaveLength(1);
    expect(backfills(snapshots[1]!)[0]).toContain("39,40,41:");
    expect(snapshots[1]!.tables["callback_receipts"]).toEqual([
      { value: "called" },
    ]);
    expect(snapshots[1]!.inTransaction).toBe(false);
    expect(database(snapshots[2]!)).toEqual(database(snapshots[1]!));
    expect(snapshots[2]!.events.at(-1)).toBe("now:43:true");
    const empty = run("empty-sequence")[1]!;
    expect(history(empty)).toEqual([]);
    expect(empty.events).toEqual(["now:1:true"]);
    expect(empty.inTransaction).toBe(false);
  });
  test("repairs recorded versions and uses canonical SQL for special new migrations", () => {
    const snapshots = run("partial-recorded");
    expect(snapshots[1]!.error).toBe(null);
    expect(snapshots[1]!.tables["workspaces"]![0]).toMatchObject({
      capability_preflight_json: null,
      thread_id: null,
    });
    expect(snapshots[1]!.tables["scans"]![0]).toMatchObject({
      deep_scan_owner_thread_id: null,
      continuation_thread_id: null,
      completion_warnings_json: "[]",
      retained_source_digests_json: null,
    });
    expect(
      snapshots[1]!.tables["deep_scan_runs"]!.map((row) => [
        row["stop_after_consecutive_errors"],
        row["consecutive_errors"],
        row["max_time_hours"],
        row["publication_error_message"],
      ]),
    ).toEqual([
      ["2", "0", { real: "0000000000005840" }, null],
      ["7", "0", { real: "0000000000005840" }, null],
    ]);
    expect(backfills(snapshots[1]!)[0]).toEndWith(":2,7");
    expect(database(snapshots[2]!)).toEqual(database(snapshots[1]!));
    expect(backfills(snapshots[2]!)).toHaveLength(1);
    const counter = run("recorded-counter-with-empty-sequence")[1]!;
    expect(
      counter.tables["deep_scan_runs"]!.map(
        (row) => row["stop_after_consecutive_errors"],
      ),
    ).toEqual(["2", "7"]);
    expect(backfills(counter)).toEqual([]);
    const thread = run("new-special-repairs");
    expect(thread[1]!.error).toBe(null);
    expect(history(thread[1]!).at(-1)!["name"]).toBe("injected thread");
    expect(database(thread[2]!)).toEqual(database(thread[1]!));
    const target = run("new-target-repair")[1]!;
    expect(target.error).toBe(null);
    expect(table(target, "security_targets")).toBeDefined();
    expect(backfills(target)).toHaveLength(1);
    const duplicateTarget = run("last-target-result")[1]!;
    expect(duplicateTarget.error).toBe(null);
    expect(backfills(duplicateTarget)).toEqual([]);
  });
  test("normalizes history before selecting missing migrations", () => {
    const snapshots = run("legacy-normalization");
    expect(snapshots[1]!.error).toBe(null);
    expect(history(snapshots[1]!)[1]).toEqual({
      version: "2",
      name: "persist capability preflight summaries",
      applied_at: "tick-1",
    });
    expect(history(snapshots[1]!)[2]).toEqual({
      version: "3",
      name: "finding management schema",
      applied_at: "original-2",
    });
    expect(history(snapshots[1]!)).toHaveLength(41);
    expect(database(snapshots[2]!)).toEqual(database(snapshots[1]!));
  });
  test("upgrades historical finding indexes and retains severity checkpoints on reopen", () => {
    const indexes = run("legacy-finding-indexes");
    expect(indexes[1]!.error).toBe(null);
    expect(history(indexes[1]!).find((row) => row["version"] === "40")).toEqual(
      {
        version: "40",
        name: "index finding identity and comparison history",
        applied_at: "original-33",
      },
    );
    expect(history(indexes[1]!)).toHaveLength(41);
    expect(table(indexes[1]!, "finding_severity_assessments")).toBeDefined();
    expect(database(indexes[2]!)).toEqual(database(indexes[1]!));
    const failed = run("legacy-finding-indexes-later-error");
    expect(failed[1]!.error!.message).toContain("synthetic_missing_table");
    expect(database(failed[1]!)).toEqual(database(failed[0]!));
    const checkpoints = run("current-severity-checkpoints");
    expect(checkpoints[1]!.error).toBe(null);
    expect(database(checkpoints[1]!)).toEqual(database(checkpoints[0]!));
    expect(database(checkpoints[2]!)).toEqual(database(checkpoints[0]!));
    expect(database(checkpoints[3]!)).toEqual(database(checkpoints[0]!));
  });
  test("rolls back schema, data and callbacks on errors while preserving preceding pending work", () => {
    for (const name of [
      "later-error",
      "backfill-error",
      "normalization-error",
      "clock-first-error",
      "clock-later-error",
      "duplicate-unapplied-version",
    ]) {
      const snapshots = run(name);
      expect(snapshots[1]!.error).not.toBe(null);
      expect(database(snapshots[1]!)).toEqual(database(snapshots[0]!));
      expect(snapshots[1]!.inTransaction).toBe(false);
      if (name === "later-error")
        expect(snapshots[1]!.error!.message).toContain(
          "synthetic_missing_table",
        );
      if (name === "backfill-error")
        expect(backfills(snapshots[1]!)).toHaveLength(1);
      else expect(backfills(snapshots[1]!)).toHaveLength(0);
    }
    const snapshots = run("initial-commit");
    expect(snapshots[1]!.inTransaction).toBe(true);
    expect(snapshots[2]!.error!.message).toContain("synthetic_missing_table");
    expect(snapshots[2]!.tables["preceding_work"]).toEqual([
      { value: "must commit" },
    ]);
    expect(table(snapshots[2]!, "schema_migrations")).toBeUndefined();
    expect(snapshots[2]!.inTransaction).toBe(false);
  });
  test("preserves workflow resume state, JSON bytes, and review references across reopen", () => {
    const snapshots = run("workflows");
    expect(snapshots[1]!.error).toBe(null);
    expect(snapshots[1]!.foreignKeys).toEqual([]);
    const workflows = Object.fromEntries(
      snapshots[1]!.tables["finding_workflows"]!.map((row) => [row["id"], row]),
    );
    expect(workflows["complete"]).toMatchObject({
      repository_path: "/synthetic/repository",
      scan_request_digest: "request",
      scope_repository_id: "repository",
      scope_all_repositories: null,
      scan_status: "completed",
      created_at: "created",
      updated_at: "updated",
    });
    expect(workflows["complete"]!["results_json"]).toBe(
      '{"scan": null, "publish": {"findingIds": []}, "dedupe": {"duplicateGroups": []}}',
    );
    expect(workflows["unfinished"]).toMatchObject({
      scope_all_repositories: "1",
      scan_status: "failed",
      scan_error: "interrupted",
      publish_status: "running",
      dedupe_error: "lost acknowledgement",
    });
    expect(workflows["unfinished"]!["results_json"]).toBe(
      '{"dedupe": {"duplicateGroups": [["a", "b"]]}, "dedupePendingWrite": {"groups": [["a", "b"]]}}',
    );
    expect(workflows["pending"]!["results_json"]).toBe("{}");
    expect(workflows["duplicates"]!["results_json"]).toBe(
      '{"2": "last", "1": 1}',
    );
    expect(workflows["numeric"]!["results_json"]).toBe(
      String.raw`{"10": 0, "2": [9007199254740993, 1.0, -0.0, 1e+16, 1e-07, 5e-324, "caf\u00e9 \ud83d\udd10", "\u007f", "\ud800"], "scan": null, "dedupePendingWrite": {"groups": [["a", "b"]]}, "publish": {"2": 1, "1": 2, "__proto__": 3}, "dedupe": {"groups": []}}`,
    );
    expect(workflows["numeric"]).toMatchObject({
      repository_path: "7",
      scope_all_repositories: "2",
      scan_status: "1",
    });
    expect(workflows["blob"]!["results_json"]).toBe(
      workflows["complete"]!["results_json"],
    );
    const reviews = Object.fromEntries(
      snapshots[1]!.tables["finding_workflow_reviews"]!.map((row) => [
        row["review_key"],
        row,
      ]),
    );
    expect(reviews["review"]).toMatchObject({
      prompt_digest: "prompt",
      contract_digest: "contract",
      review_contract_version: "1",
      settings_digest: null,
      result_json: '{ "kept": 1 }\n',
      created_at: "review-created",
    });
    expect(reviews["numeric"]).toMatchObject({
      review_contract_version: "9007199254740993",
      codex_version: "2.0",
      scope_all_repositories: "1",
      source_repository_path: "/café/🔐",
    });
    expect(reviews["nonfinite"]).toMatchObject({
      review_contract_version: null,
      codex_version: "Inf",
    });
    expect(database(snapshots[2]!)).toEqual(database(snapshots[1]!));
    expect(database(snapshots[3]!)).toEqual(database(snapshots[1]!));
    expect(snapshots[5]!.tables["finding_workflow_reviews"]).toEqual([]);
    expect(snapshots[5]!.tables["workflow_references"]).toEqual([]);
    const recorded = run("recorded-backfill-not-replayed");
    expect(database(recorded[1]!)).toEqual(database(recorded[0]!));
  });
  test("rejects malformed stored state without losing prior rows or partially renamed schemas", () => {
    for (const name of [
      "syntax",
      "root-list",
      "root-null",
      "missing-stages",
      "scope-null",
      "stages-list",
      "stage-null",
      "stage-index",
      "missing-dedupe",
      "missing-status",
      "null-status",
      "nonfinite-nan",
      "nonfinite-infinity",
    ]) {
      const snapshots = run(`malformed-workflow-${name}`);
      expect(snapshots[1]!.error).not.toBe(null);
      expect(database(snapshots[1]!)).toEqual(database(snapshots[0]!));
    }
    for (const name of [
      "syntax",
      "root-list",
      "source-null",
      "scope-null",
      "missing-version",
    ]) {
      const snapshots = run(`malformed-review-${name}`);
      expect(snapshots[1]!.error).not.toBe(null);
      expect(database(snapshots[1]!)).toEqual(database(snapshots[0]!));
    }
    const workflows = run("workflow-partial-direct");
    expect(workflows[1]!.inTransaction).toBe(true);
    expect(workflows[1]!.error!.message).toBe("'stages'");
    expect(workflows[1]!.tables["finding_workflows"]![0]!["scan_status"]).toBe(
      "completed",
    );
    expect(database(workflows[2]!)).toEqual(database(workflows[0]!));
    const reviews = run("review-partial-direct");
    expect(reviews[1]!.inTransaction).toBe(true);
    expect(reviews[1]!.error!.message).toBe("'source'");
    expect(
      reviews[1]!.tables["finding_workflow_reviews"]![0]!["prompt_digest"],
    ).toBe("prompt");
    expect(database(reviews[2]!)).toEqual(database(reviews[0]!));
  });
  test("supports compact persisted JSON without changing existing pretty-print defaults", () => {
    const child = spawnSync(node, [fixture, PLUGIN_ROOT, "json"], {
      encoding: "utf8",
      env: { ...process.env, PATH: "" },
    });
    expect(child.status, child.stderr).toBe(0);
    const results = JSON.parse(child.stdout) as {
      pretty: string;
      compact: string | null;
      error: string | null;
    }[];
    expect(results[2]!.compact).toBe(
      String.raw`{"2": 3, "1": 2, "\u00e9": "\ud83d\udd10\u007f\ud800"}`,
    );
    expect(results[3]!.compact).toBe(
      "[1.0, -0.0, 0.0001, 1e+16, 1e-07, 5e-324, 9007199254740993]",
    );
    expect(results[4]!.pretty).toBe('{\n  "a": NaN\n}');
    expect(results[4]!.error).toBe(
      "Out of range float values are not JSON compliant: nan",
    );
    expect(results[5]!.pretty).toBe(
      '{\n  "a": [\n    Infinity,\n    -Infinity\n  ]\n}',
    );
    expect(results[5]!.error).toBe(
      "Out of range float values are not JSON compliant: inf",
    );
    expect(results[7]!.compact).toBe(
      '{"s": "a  b\\n\\t", "empty": {}, "nested": [{"0": true, "-1": null}]}',
    );
  });
  test("serializes two native processes opening the same fresh database", async () => {
    const filename = join(directory, "concurrent.sqlite3");
    const workers = Array.from({ length: 2 }, () => {
      const child = spawn(
        node,
        [fixture, PLUGIN_ROOT, "concurrent", filename],
        { env: { ...process.env, PATH: "" }, timeout: 15_000 },
      );
      let output = "";
      let errors = "";
      const ready = once(child.stdout, "data");
      child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
        output += chunk;
      });
      child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
        errors += chunk;
      });
      const finished = once(child, "close").then(([code]) => {
        expect(code, errors).toBe(0);
        expect(errors).toBe("");
        return JSON.parse(output.slice(output.indexOf("\n") + 1)) as {
          clock: number;
          snapshot: Snapshot;
        };
      });
      return { child, ready, finished };
    });
    try {
      await Promise.all(workers.map(({ ready }) => ready));
      for (const { child } of workers) child.stdin.end("start\n");
      const results = await Promise.all(
        workers.map(({ finished }) => finished),
      );
      expect(results.map(({ clock }) => clock).sort((a, b) => a - b)).toEqual([
        1, 42,
      ]);
      for (const { snapshot } of results) {
        expect(history(snapshot)).toHaveLength(41);
        expect(snapshot.tables["callback_receipts"]).toEqual([
          { value: "called" },
        ]);
        expect(snapshot.foreignKeys).toEqual([]);
        expect(snapshot.inTransaction).toBe(false);
      }
      expect(database(results[0]!.snapshot)).toEqual(
        database(results[1]!.snapshot),
      );
    } finally {
      for (const { child } of workers)
        if (child.exitCode === null) child.kill();
    }
  });
});
