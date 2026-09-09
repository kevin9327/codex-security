import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Action, Request } from "./support/scan-start-fixture";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";

const root = realpathSync(mkdtempSync(join(tmpdir(), "workbench-scan-start-")));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-start-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(root, { recursive: true, force: true }));
type Response = {
  value?: unknown;
  error?: string;
  kind?: string;
  inTransaction: boolean;
};
function run(actions: Action[], migrate = true): Response[] {
  const request: Request = { actions, migrate };
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(request),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
const sql = (
  sql: string,
  ...parameters: (string | number | null)[]
): Action => ({ kind: "sql", sql, parameters });
const query = (sql: string): Action => ({ kind: "query", sql });
function setup(mode = "standard"): Action[] {
  return [
    sql(
      "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES ('target', '/target', 'target', 'before', 'before')",
    ),
    sql(
      "INSERT INTO workspaces (id, target_id, target_path, default_mode, user_context, thread_id, created_at, updated_at) VALUES ('workspace', 'target', '/target', ?, '  user context  ', 'owner', 'before', 'before')",
      mode,
    ),
  ];
}
function savedScan(
  id = "old",
  scanDir = join(root, "scan"),
  status = "complete",
  targetId = "target",
): Action {
  return sql(
    `INSERT INTO scans (id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, handoff_status, started_at, completed_at, created_at, updated_at)
    VALUES (?, 'workspace', ?, '/target', 'revision', '.', 'standard', ?, ?, 'reporting', 'delivered', 'before', '2026-01-01', 'before', 'before')`,
    id,
    targetId,
    scanDir,
    status,
  );
}
function start(
  scanId: string,
  targetRoot: string,
  scanDir: string | null = null,
): Extract<Action, { kind: "insert" }> {
  return {
    kind: "insert",
    workspaceId: "workspace",
    options: {
      scanId,
      target: "/target",
      scope: "src",
      diffTarget: null,
      targetIdentity: ["revision", "digest", 1n, "stat:10000000000000000"],
      targetRoot,
      targetSummary: "summary",
      scopeFileCount: 17n,
      timestamp: "after",
      scanDir,
    },
  };
}
function finding(
  id: string,
  scanId = "old",
  note: string | null = "Reviewed control",
  updatedAt = "2026-01-02",
): Action[] {
  return [
    sql(
      "INSERT OR IGNORE INTO findings (id, fingerprint, rule_id, identity_anchor, identity_instance, created_at, updated_at) VALUES (?, ?, 'rule', ?, 'instance', 'before', 'before')",
      id,
      id,
      id,
    ),
    sql(
      "INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, confidence, remediation, created_at) VALUES (?, ?, ?, 'Title', 'Summary', 'high', 'high', 'Fix', 'before')",
      `${scanId}-${id}`,
      id,
      scanId,
    ),
    sql(
      "INSERT INTO finding_locations (occurrence_id, relative_path, start_line, end_line, role, sort_order) VALUES (?, 'src/sink.ts', 1, 2, 'sink', 0)",
      `${scanId}-${id}`,
    ),
    sql(
      "INSERT INTO finding_locations (occurrence_id, relative_path, start_line, end_line, role, sort_order) VALUES (?, 'src/control.ts', 3, 4, 'root_control', 1)",
      `${scanId}-${id}`,
    ),
    sql(
      "INSERT INTO finding_triage (occurrence_id, status, close_reason, note, updated_at) VALUES (?, 'closed', 'false_positive', ?, ?)",
      `${scanId}-${id}`,
      note,
      updatedAt,
    ),
  ];
}

test("Windows temporary-directory creation is exclusive and existing callers retain native recursion", () => {
  const responses = run(
    [
      { kind: "windowsMkdir", errors: [183], recursive: false },
      { kind: "windowsMkdir", errors: [3], recursive: false },
      { kind: "windowsMkdir", errors: [0] },
      { kind: "windowsMkdir", errors: [3] },
    ],
    false,
  );
  const child = "\\\\?\\C:\\parent\\child";
  expect(responses.map((response) => response.value)).toEqual([
    { calls: [{ path: child, recursive: false }], error: 183 },
    { calls: [{ path: child, recursive: false }], error: 3 },
    { calls: [{ path: child, recursive: true }], error: null },
    { calls: [{ path: child, recursive: true }], error: 3 },
  ]);
});

test("retains Unicode directory segments and diff identity fields", () => {
  const values = run(
    [
      {
        kind: "safe",
        values: ["é中𐐀Ⅳ²", " _a😀b/ ", "---", "...", "a\u0301b"],
      },
      { kind: "diff", value: null },
      {
        kind: "diff",
        value: {
          kind: "working_tree",
          baseRevision: "base",
          headRevision: "head",
          contentDigest: "",
        },
      },
      { kind: "timestamp" },
    ],
    false,
  );
  expect(values[0]?.value).toEqual(["é中𐐀Ⅳ²", "_a-b", "scan", "...", "a-b"]);
  expect(values[1]?.value).toEqual([null, null, null, null]);
  expect(values[2]?.value).toEqual(["working_tree", "base", "head", ""]);
  expect(values[3]?.value).toMatch(/^\d{8}T\d{6}Z$/u);
});

test("archives all recorded artifact paths while retaining external paths", () => {
  const scanDir = join(root, "archived-scan"),
    archivedScanDir = `${scanDir}.previous-20260729T000000Z`;
  mkdirSync(scanDir);
  mkdirSync(archivedScanDir);
  const names = {
    coverage: "sub/../coverage.json",
    findings: "findings.json",
    markdownReport: "report.md",
  };
  const values = run([
    ...setup(),
    savedScan("old", scanDir),
    ...Object.entries(names).map(([kind, path]) =>
      sql(
        "INSERT INTO scan_artifacts VALUES ('old', ?, ?, 'before')",
        kind,
        `${scanDir}/${path}`,
      ),
    ),
    sql(
      "INSERT INTO scan_artifacts VALUES ('old', 'manifest', ?, 'before')",
      join(root, "outside.json"),
    ),
    { kind: "commit" },
    { kind: "archive", scanDir, archivedScanDir, archiveExisting: true },
    query("SELECT scan_dir, updated_at FROM scans"),
    query("SELECT kind, path FROM scan_artifacts ORDER BY kind"),
  ]);
  expect(values.some((value) => value.error)).toBe(false);
  expect(values.at(-2)?.value).toEqual([
    { scan_dir: archivedScanDir, updated_at: "after" },
  ]);
  expect(values.at(-1)?.value).toEqual(
    Object.entries({ ...names, manifest: "" })
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([kind, path]) => ({
        kind,
        path:
          kind === "manifest"
            ? join(root, "outside.json")
            : `${archivedScanDir}/${path}`.replaceAll("/", sep),
      })),
  );
});

test("rejects missing archive paths before changing existing artifacts or creating directories", () => {
  const parent = mkdtempSync(join(root, "archive-error-")),
    scanDir = join(parent, "scan");
  mkdirSync(scanDir);
  const values = run([
    ...setup(),
    savedScan("old", scanDir),
    sql(
      "INSERT INTO scan_artifacts VALUES ('old', 'coverage', ?, 'before')",
      join(scanDir, "coverage.json"),
    ),
    { kind: "commit" },
    { kind: "archive", scanDir, archivedScanDir: null, archiveExisting: true },
    query("SELECT scan_dir, updated_at FROM scans"),
    query("SELECT path FROM scan_artifacts"),
  ]);
  expect(values.at(-3)).toEqual({
    error:
      "The archived scan directory is required to preserve existing scan artifacts.",
    kind: "WorkbenchValidationError",
    inTransaction: false,
  });
  expect(values.at(-2)?.value).toEqual([
    { scan_dir: scanDir, updated_at: "before" },
  ]);
  expect(values.at(-1)?.value).toEqual([
    { path: join(scanDir, "coverage.json") },
  ]);
  expect(readdirSync(parent)).toEqual(["scan"]);
});

test("creates an archive only for stopped scans without artifacts and preserves rejection order", () => {
  const parent = mkdtempSync(join(root, "archive-empty-")),
    scanDir = join(parent, "scan");
  mkdirSync(scanDir);
  const values = run([
    ...setup(),
    savedScan("old", scanDir, "running"),
    { kind: "commit" },
    { kind: "archive", scanDir, archivedScanDir: null, archiveExisting: false },
    { kind: "archive", scanDir, archivedScanDir: null, archiveExisting: true },
    sql("UPDATE scans SET status = 'failed'"),
    { kind: "commit" },
    { kind: "archive", scanDir, archivedScanDir: null, archiveExisting: true },
    query("SELECT scan_dir FROM scans"),
  ]);
  expect(values[4]?.error).toContain("Use --archive-existing");
  expect(values[5]?.error).toBe("Cannot archive the output of a running scan.");
  const directory = (values.at(-1)?.value as { scan_dir: string }[])[0]!
    .scan_dir;
  expect(directory).toMatch(/scan\.previous-[a-z0-9_]{8}$/u);
  expect(statSync(directory).isDirectory()).toBe(true);
  if (process.platform !== "win32")
    expect(statSync(directory).mode & 0o777).toBe(0o700);
});

test("inserts a native scan and progress atomically in its caller's transaction", () => {
  const parent = mkdtempSync(join(root, "native-"));
  const insert = start("new", parent);
  insert.options.diffTarget = {};
  const values = run([
    ...setup("deep"),
    { kind: "commit" },
    insert,
    query("SELECT * FROM scans"),
    query("SELECT * FROM scan_progress"),
    query("SELECT active_scan_id, user_context FROM workspaces"),
    { kind: "rollback" },
    query("SELECT id FROM scans"),
  ]);
  expect(values[3]).toEqual({ value: "new", inTransaction: true });
  const scan = (values[4]?.value as Record<string, unknown>[])[0]!;
  expect(scan).toMatchObject({
    id: "new",
    target_revision: "revision",
    target_snapshot_digest: "digest",
    target_device: 1,
    target_inode: "stat:10000000000000000",
    scope: "src",
    status: "running",
    phase: "preflight",
    handoff_status: "pending",
    user_context: "user context",
    deep_scan_owner_thread_id: "owner",
    diff_target_kind: null,
    model: null,
    reasoning_effort: null,
    started_at: "after",
  });
  expect(values[5]?.value).toMatchObject([
    {
      scope_file_count: 17,
      review_items_total: 0,
      review_items_completed: 0,
      reportable_findings_count: 0,
    },
  ]);
  expect(values[6]?.value).toEqual([
    { active_scan_id: "new", user_context: "  user context  " },
  ]);
  expect(values[8]?.value).toEqual([]);
  expect(readdirSync(scan["scan_dir"] as string)).toEqual([]);
});

test("keeps externally supplied scans free of native feedback files and stores diff options", () => {
  const scanDir = join(root, "external-scan");
  mkdirSync(scanDir);
  const insert = start("new", root, scanDir);
  Object.assign(insert.options, {
    diffTarget: {
      kind: "range",
      baseRevision: "base",
      headRevision: "head",
      contentDigest: "digest",
    },
    handoffStatus: "delivered",
    model: " model ",
    reasoningEffort: " high ",
  });
  const values = run([
    ...setup(),
    savedScan(),
    ...finding("f"),
    insert,
    { kind: "stored", scanId: "new" },
    query(
      "SELECT model, reasoning_effort, deep_scan_owner_thread_id FROM scans WHERE id = 'new'",
    ),
  ]);
  expect(values.at(-3)?.value).toBe("new");
  expect(values.at(-2)?.value).toEqual({
    baseRevision: "base",
    headRevision: "head",
    kind: "range",
    contentDigest: "digest",
  });
  expect(values.at(-1)?.value).toEqual([
    {
      model: "model",
      reasoning_effort: "high",
      deep_scan_owner_thread_id: null,
    },
  ]);
  expect(readdirSync(scanDir)).toEqual([]);
});

test("materializes reviewed feedback with exact JSON bytes and private file mode", () => {
  const parent = mkdtempSync(join(root, "feedback-file-"));
  const values = run([
    ...setup(),
    savedScan(),
    ...finding("f"),
    start("new", parent),
    { kind: "feedback", scanId: "new" },
    query("SELECT scan_dir FROM scans WHERE id = 'new'"),
  ]);
  expect(values.at(-3)?.value).toBe("new");
  const feedback = (values.at(-2)?.value as { falsePositives: unknown[] })
    .falsePositives;
  const scanDir = (values.at(-1)?.value as { scan_dir: string }[])[0]!.scan_dir;
  const file = join(
    scanDir,
    "artifacts/01_context/false_positive_feedback.json",
  );
  expect(readFileSync(file, "utf8")).toBe(
    stringifyJson(feedback, { compact: true }) + "\n",
  );
  expect(feedback).toMatchObject([
    {
      identity: { anchor: "f", instance: "instance" },
      reason: "Reviewed control",
      locations: [
        {
          path: "src/control.ts",
          role: "root_control",
          startLine: 3,
          endLine: 4,
        },
      ],
    },
  ]);
  if (process.platform !== "win32")
    expect(statSync(file).mode & 0o777).toBe(0o600);
});

test("selects latest explained decisions and excludes current, reopened, failed and other-target findings", () => {
  const values = run([
    ...setup(),
    savedScan(),
    ...finding("keep"),
    ...finding("reopen"),
    ...finding("no-note", "old", null),
    ...finding("empty-note", "old", " "),
    savedScan("later", join(root, "later")),
    sql("UPDATE scans SET completed_at = '2026-01-03' WHERE id = 'later'"),
    ...finding("reopen", "later"),
    sql("DELETE FROM finding_triage WHERE occurrence_id = 'later-reopen'"),
    savedScan("failed", join(root, "failed"), "failed"),
    ...finding("failed", "failed"),
    sql(
      "INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES ('other', '/other', 'other', 'before', 'before')",
    ),
    savedScan("other", join(root, "other"), "complete", "other"),
    ...finding("other", "other"),
    savedScan("current", join(root, "current")),
    ...finding("current", "current"),
    { kind: "feedback", scanId: "current" },
  ]);
  expect(values.some((value) => value.error)).toBe(false);
  const feedback = values.at(-1)?.value as {
    falsePositives: { findingId: string }[];
  };
  expect(feedback.falsePositives.map((value) => value.findingId)).toEqual([
    "keep",
  ]);
});

test("limits ordered feedback to fifty decisions and truncates Unicode by UTF-8 bytes", () => {
  const records = Array.from({ length: 55 }, (_, index) =>
    finding(
      `f${index.toString().padStart(2, "0")}`,
      "old",
      "reason",
      `2026-01-${index.toString().padStart(2, "0")}`,
    ),
  ).flat();
  const values = run([
    ...setup(),
    savedScan(),
    ...records,
    savedScan("current", join(root, "limit-current")),
    sql(
      "UPDATE finding_occurrences SET title = ?, summary = ?",
      "😀".repeat(130),
      "é".repeat(1001),
    ),
    sql("UPDATE finding_locations SET relative_path = ?", "中".repeat(684)),
    { kind: "feedback", scanId: "current" },
  ]);
  expect(values.some((value) => value.error)).toBe(false);
  const feedback = (
    values.at(-1)?.value as {
      falsePositives: {
        findingId: string;
        title: string;
        summary: string;
        locations: { path: string }[];
      }[];
    }
  ).falsePositives;
  expect(feedback.map((value) => value.findingId)).toEqual(
    Array.from(
      { length: 50 },
      (_, index) => `f${(54 - index).toString().padStart(2, "0")}`,
    ),
  );
  expect(feedback[0]).toMatchObject({
    title: "😀".repeat(128),
    summary: "é".repeat(1000),
    locations: [{ path: "中".repeat(682) }],
  });
});
