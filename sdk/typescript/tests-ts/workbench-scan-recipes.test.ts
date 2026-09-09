import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Action } from "./support/scan-start-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-scan-recipes-")),
);
const target = join(root, "target"),
  outside = join(root, "outside"),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const scanId = "11111111-1111-4111-8111-111111111111",
  workspaceId = "22222222-2222-4222-8222-222222222222";
beforeAll(() => {
  mkdirSync(target);
  mkdirSync(outside);
  mkdirSync(join(target, "nested"));
  writeFileSync(join(target, "nested", "file.txt"), "synthetic\n");
  symlinkSync(
    join(target, "nested"),
    join(target, "alias"),
    process.platform === "win32" ? "junction" : "dir",
  );
  symlinkSync(
    outside,
    join(target, "escape"),
    process.platform === "win32" ? "junction" : "dir",
  );
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-start-fixture.ts", import.meta.url),
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
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
interface Outcome {
  value?: unknown;
  error?: string;
  kind?: string;
  inTransaction: boolean;
}
function run(actions: Action[]): Outcome[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson({ actions }),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const outcomes = parseJson(child.stdout) as unknown as Outcome[];
  actions.forEach((action, index) => {
    if (action.kind === "sql" || action.kind === "query")
      expect(outcomes[index]!.error, action.sql).toBeUndefined();
  });
  return outcomes;
}
const recipe = (changes: Record<string, unknown> = {}) => ({
  repository: target,
  mode: "standard",
  config: {},
  target: { kind: "repository", paths: [] },
  ...changes,
});
const parse = (value: unknown): Action => ({
  kind: "parseRecipe",
  value: stringifyJson(value),
  repository: target,
});
const sql = (statement: string, ...parameters: (string | null)[]): Action => ({
  kind: "sql",
  sql: statement,
  parameters,
});
const query = (statement: string): Action => ({
  kind: "query",
  sql: statement,
});
const seed = (): Action[] => [
  sql(
    "INSERT INTO workspaces(id,created_at,updated_at) VALUES (?, 'before', 'before')",
    workspaceId,
  ),
  sql(
    "INSERT INTO scans(id,workspace_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES (?,?,'/synthetic','unversioned','.','standard','/synthetic-scan','complete','reporting','before','before','before')",
    scanId,
    workspaceId,
  ),
  { kind: "commit" },
];

test("recipes preserve their config and extra fields while validating target identity", () => {
  const value = recipe({
    mode: "deep",
    config: { integer: 9007199254740993n },
    extra: "kept",
    target: {
      kind: "paths",
      paths: ["nested//file.txt", "alias"],
      extra: true,
    },
  });
  const [accepted, mismatch, relative] = run([
    parse(value),
    parse(recipe({ repository: outside })),
    parse(recipe({ repository: "relative" })),
  ]);
  expect(accepted!.value).toEqual(value);
  expect(mismatch!.error).toBe(
    "Scan launch recipe repository must match the scanned repository.",
  );
  expect(relative!.error).toBe(
    "Scan target must be an absolute local directory path.",
  );
});

test("scoped recipes reject missing or escaping paths and retain contained directory links", () => {
  const paths = [
    "nested/file.txt",
    "alias/file.txt",
    "escape",
    "../outside",
    "nested/../nested/file.txt",
    "missing",
    "",
    "nested\\file.txt",
    "nul\0name",
  ];
  const results = run(
    paths.map((path) =>
      parse(recipe({ target: { kind: "paths", paths: [path] } })),
    ),
  );
  expect(results.map((result) => result.error === undefined)).toEqual([
    true,
    true,
    false,
    false,
    false,
    false,
    false,
    false,
    false,
  ]);
  for (const result of results.slice(2))
    expect(result.error).toBe(
      "Scan launch recipe target paths must exist inside the repository.",
    );
});

test("recipe kinds retain their path and revision requirements", () => {
  const results = run([
    parse(recipe({ target: { kind: "paths", paths: [] } })),
    parse(recipe({ target: { kind: "repository", paths: ["nested"] } })),
    parse(recipe({ target: { kind: "refs", paths: [] } })),
    parse(
      recipe({
        target: { kind: "working_tree", paths: [], base: "", head: "" },
      }),
    ),
    parse(recipe({ mode: [] })),
  ]);
  expect(results.map((result) => result.error)).toEqual([
    "A scoped scan launch recipe must include at least one target path.",
    "Only scoped scan launch recipes can include target paths.",
    "Diff scan launch recipes require resolved base and head revisions.",
    undefined,
    "unhashable type: 'list'",
  ]);
});

test("recipe JSON retains the byte limit and non-finite number rejection", () => {
  const results = run(
    [" ".repeat(262144), " ".repeat(262145), "null", "{", '{"number":NaN}'].map(
      (value): Action => ({ kind: "parseRecipe", value, repository: target }),
    ),
  );
  expect(results.map((result) => result.error)).toEqual([
    "Scan launch recipe must be a valid JSON object.",
    "Scan launch recipe must be no larger than 256 KiB.",
    "Scan launch recipe must be a JSON object.",
    "Scan launch recipe must be a valid JSON object.",
    "Scan launch recipe must be a valid JSON object.",
  ]);
});

test("saved recipes return stored JSON and parent identity without reopening recipe validation", () => {
  const results = run([
    ...seed(),
    { kind: "getRecipe", scanId },
    sql(
      "UPDATE scans SET recipe_json = ?, parent_scan_id = ?",
      '{"integer":9007199254740993}',
      scanId,
    ),
    { kind: "getRecipe", scanId },
    sql("UPDATE scans SET recipe_json = ?", '{"number":NaN}'),
    { kind: "getRecipe", scanId },
    query("SELECT parent_scan_id FROM scans"),
  ]);
  expect(results[3]!.error).toBe(
    "This scan does not have a saved launch recipe.",
  );
  expect(results[5]!.value).toEqual({
    parentScanId: scanId,
    recipe: { integer: 9007199254740993n },
    scanId,
  });
  expect(results[7]!.error).toBe(
    "non-finite JSON number 'NaN' is not supported",
  );
  expect(results[7]!.inTransaction).toBe(true);
});

test("thread updates commit with caller changes and roll back if their clock or write fails", () => {
  const results = run([
    ...seed(),
    sql("UPDATE scans SET scope='caller'"),
    { kind: "setThread", scanId, threadId: "next" },
    query("SELECT continuation_thread_id,scope,updated_at FROM scans"),
    sql("UPDATE scans SET scope='uncommitted'"),
    { kind: "setThread", scanId, threadId: "failed", failNow: "clock failed" },
    query("SELECT continuation_thread_id,scope FROM scans"),
    sql(
      "CREATE TRIGGER reject_thread BEFORE UPDATE ON scans BEGIN SELECT RAISE(ABORT, 'blocked'); END",
    ),
    { kind: "setThread", scanId, threadId: "blocked" },
    query("SELECT continuation_thread_id,scope FROM scans"),
  ]);
  expect(results[4]!.value).toEqual({ scanId, threadId: "next" });
  expect(results[4]!.inTransaction).toBe(false);
  expect(results[5]!.value).toEqual([
    {
      continuation_thread_id: "next",
      scope: "caller",
      updated_at: "2026-08-15T12:00:00.123456Z",
    },
  ]);
  expect(results[7]!.error).toBe("clock failed");
  expect(results[7]!.inTransaction).toBe(false);
  expect(results[8]!.value).toEqual([
    { continuation_thread_id: "next", scope: "caller" },
  ]);
  expect(results[10]!.error).toBe("blocked");
  expect(results[11]!.value).toEqual(results[8]!.value);
});
