import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { ScanQuery } from "../../../plugins/codex-security/mcp-app/src/workbench-scan-history";
import type {
  Operation,
  Request,
  Response,
} from "./support/list-scans-fixture";
import { PLUGIN_ROOT } from "./plugin-root.js";

const root = realpathSync(mkdtempSync(join(tmpdir(), "list-scans-")));
const fixture = join(root, "fixture.cjs"),
  cli = join(root, "cli.mjs");
const node = Bun.which("node")!;
let next = 0;
beforeAll(() => {
  symlinkSync(
    fileURLToPath(new URL("../node_modules/", import.meta.url)),
    join(root, "node_modules"),
    process.platform === "win32" ? "junction" : "dir",
  );
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/list-scans-fixture.ts", import.meta.url),
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
  buildSync({
    stdin: {
      contents:
        'import {main} from "./cli.js"; void main().then(status => {process.exitCode=status});',
      resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
      loader: "ts",
    },
    outfile: cli,
    bundle: true,
    packages: "external",
    platform: "node",
    format: "esm",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        new URL("../src/cli.ts", import.meta.url).href,
      ),
    },
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
function run(
  operations: Operation[],
  settings: { filename?: string; git?: Request["git"]; path?: string } = {},
): Response {
  const child = spawnSync(
    node,
    [fixture, settings.filename ?? join(root, `${next++}.sqlite3`)],
    {
      input: stringifyJson({
        initialize: true,
        operations,
        ...(settings.git === undefined ? {} : { git: settings.git }),
      }),
      encoding: "utf8",
      maxBuffer: Infinity,
      env: {
        ...process.env,
        PYTHON: "missing-list-scans-python",
        PATH: settings.path ?? "",
      },
    },
  );
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response;
}
function sql(sql: string, parameters?: (string | number | null)[]): Operation {
  return { sql, ...(parameters ? { parameters } : {}) };
}
function target(id: string, path = join(root, id)): Operation[] {
  return [
    sql(
      "INSERT INTO security_targets(id,current_path,display_name,created_at,updated_at) VALUES(?,?,?,'1','1')",
      [id, path, id],
    ),
    sql(
      "INSERT INTO workspaces(id,target_id,target_path,created_at,updated_at) VALUES(?,?,?,'1','1')",
      [id, id, path],
    ),
  ];
}
function scan(id: string, target: string, day: number): Operation[] {
  const time = `2026-01-${String(day).padStart(2, "0")}T00:00:00Z`;
  return [
    sql(
      `INSERT INTO scans(id,workspace_id,target_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at)
    SELECT ?,id,target_id,target_path,'revision','src/','standard',target_path || '/scan-' || ?,'complete','reporting',?,?,? FROM workspaces WHERE id=?`,
      [id, id, time, time, time, target],
    ),
    sql(
      "INSERT INTO scan_progress(scan_id,updated_at,scope_file_count,review_items_total,review_items_completed,reportable_findings_count) VALUES(?,?,8,6,3,2)",
      [id, time],
    ),
  ];
}
const query = (options: Partial<ScanQuery> = {}): Operation => ({
  query: { offset: 0n, ...options },
});
const commit = sql("COMMIT");
interface Listing {
  scans: { scanId: string; [key: string]: unknown }[];
  limit?: number;
  offset?: number;
  nextOffset?: number | null;
}
function listing(response: Response, index: number): Listing {
  expect(response.results[index]?.error).toBeUndefined();
  return response.results[index]!.value as Listing;
}
const ids = (value: Listing) => value.scans.map((scan) => scan.scanId);

test("scan history reads legacy cost and warning JSON from SQLite blobs", () => {
  const cost = Buffer.from(
    '{"usage":{"inputTokens":7},"cost":{"usd":1.0}}',
    "utf16le",
  ).toString("hex");
  const warnings = Buffer.from('["é🧭"]', "utf8").toString("hex");
  const response = run([
    ...target("target"),
    ...scan("scan", "target", 1),
    sql(
      `UPDATE scans SET cost_json=x'${cost}',completion_warnings_json=x'${warnings}'`,
    ),
    query(),
  ]);
  expect(listing(response, response.results.length - 1).scans[0]).toMatchObject(
    {
      usage: { inputTokens: 7 },
      cost: { usd: 1 },
      warnings: ["é🧭"],
    },
  );
});

test("filters before pagination and preserves unpaginated envelopes and the existing page cap", () => {
  const operations: Operation[] = [...target("needle"), ...target("other")];
  for (let i = 0; i < 24; i++)
    operations.push(
      ...scan(
        `scan-${String(i).padStart(2, "0")}`,
        i === 23 ? "other" : "needle",
        i + 1,
      ),
    );
  operations.push(
    sql(
      "UPDATE scans SET status='running',phase='preflight' WHERE id='scan-00'",
    ),
    sql("UPDATE scans SET canceled_at=updated_at WHERE id='scan-01'"),
    sql("UPDATE scans SET mode='deep' WHERE id='scan-02'"),
    commit,
    query(),
    query({
      query: " NeEdLe ",
      status: "complete",
      mode: "standard",
      limit: 1n,
    }),
    query({ targetId: "needle", status: "canceled" }),
    query({ status: "running" }),
    query({ limit: 99n }),
    query({ offset: 20n }),
    query({ query: "NO MATCH", offset: 1n }),
    query({ query: "\u0085\u001c" }),
    { snapshot: true },
    sql("BEGIN IMMEDIATE"),
    query(),
    { snapshot: true },
    sql("ROLLBACK"),
  );
  const result = run(operations).results.slice(-13);
  const values = result.map((item) => item.value as Listing);
  expect(Object.keys(values[0]!)).toEqual(["scans"]);
  expect(ids(values[0]!)[0]).toBe("scan-00");
  expect(values[0]!.scans).toHaveLength(24);
  expect(ids(values[1]!)).toEqual(["scan-22"]);
  expect(values[1]).toMatchObject({ limit: 1, offset: 0, nextOffset: 1 });
  expect(ids(values[2]!)).toEqual(["scan-01"]);
  expect(ids(values[3]!)).toEqual(["scan-00"]);
  expect(values[4]).toMatchObject({ limit: 20, offset: 0, nextOffset: 20 });
  expect(values[4]!.scans).toHaveLength(20);
  expect(values[5]).toMatchObject({ limit: 20, offset: 20, nextOffset: null });
  expect(values[5]!.scans).toHaveLength(4);
  expect(values[6]).toEqual({
    scans: [],
    limit: 20,
    offset: 1,
    nextOffset: null,
  });
  expect(values[7]).toEqual(values[0]);
  expect(result[10]!.inTransaction).toBe(true);
  expect(result[11]!.value).toEqual(result[8]!.value);
});

test("retains summary fields, measured usage, warnings and repository-navigation reuse", () => {
  const result = run([
    ...target("target"),
    ...scan("older", "target", 1),
    ...scan("newest", "target", 2),
    sql(
      "UPDATE scans SET status='running',updated_at='later' WHERE id='older'",
    ),
    sql(
      "UPDATE scans SET canceled_at='canceled',recipe_json='{}',cost_json=?,completion_warnings_json=?,target_summary='Summary',model='model',reasoning_effort='high',continuation_thread_id='thread' WHERE id='newest'",
      [
        '{"usage":{"totalTokens":12},"cost":{"estimate":1.0}}',
        '["Saved results"]',
      ],
    ),
    sql(
      "UPDATE scan_progress SET updated_at='progress' WHERE scan_id='newest'",
    ),
    commit,
    query(),
    { repositories: true },
  ]);
  const scans = listing(result, result.results.length - 2).scans;
  expect(scans[1]).toMatchObject({
    scanId: "newest",
    targetSummary: "Summary",
    model: "model",
    reasoningEffort: "high",
    continuationThreadId: "thread",
    recipeAvailable: true,
    cost: { estimate: 1 },
    usage: { totalTokens: 12 },
    warnings: ["Saved results"],
    updatedAt: "progress",
    progress: {
      status: "canceled",
      phase: "reporting",
      candidates: { reportable: 2 },
      coverage: { closedRows: 3, filesTotal: 8, worklistRows: 6 },
    },
  });
  expect(scans[1]).not.toHaveProperty("artifacts");
  expect(scans[1]).not.toHaveProperty("findings");
  expect(
    (
      result.results.at(-1)!.value as {
        repositories: { latestScan: unknown }[];
      }
    ).repositories[0]!.latestScan,
  ).toEqual(scans[1]);
});

test("decodes only selected rows and keeps SQLite lower search semantics", () => {
  const result = run([
    ...target("target"),
    ...scan("old", "target", 1),
    ...scan("new", "target", 2),
    sql("UPDATE scans SET cost_json='{' WHERE id='old'"),
    sql("UPDATE scans SET target_summary='STRASSE Straße' WHERE id='new'"),
    commit,
    query({ limit: 1n }),
    query({ query: "STRASSE" }),
    query({ query: "straße" }),
    query({ query: "NO MATCH" }),
    query({ offset: 1n, limit: 1n }),
    sql(
      "UPDATE scans SET cost_json='null',target_summary='Äpfel' WHERE id='old'",
    ),
    query({ query: "ÄPFEL" }),
    query({ query: "äpfel" }),
    query({ offset: 9223372036854775808n }),
  ]);
  const rows = result.results.slice(-9);
  for (const index of [0, 1, 2])
    expect(ids(rows[index]!.value as Listing)).toEqual(["new"]);
  expect((rows[3]!.value as Listing).scans).toEqual([]);
  expect(rows[4]!.error).toContain(
    "Expecting property name enclosed in double quotes",
  );
  expect((rows[6]!.value as Listing).scans).toEqual([]);
  expect((rows[7]!.value as Listing).scans).toEqual([]);
  expect(rows[8]!.error).toBe(
    "Python int too large to convert to SQLite INTEGER",
  );
});

test("normalizes repository origins without changing accepted URL or SCP identities", () => {
  const origins: [string, [string, string] | null][] = [
    [
      "https://user:synthetic@EXAMPLE.test:443/Team/Project.git",
      ["example.test", "Team/Project"],
    ],
    [
      "ssh://user@EXAMPLE.test:22/Team/Project.git",
      ["example.test", "Team/Project"],
    ],
    ["git@EXAMPLE.test:Team/Project", ["example.test", "Team/Project"]],
    [
      "ssh://EXAMPLE.test:2222/Team/Project.git",
      ["example.test:2222", "Team/Project"],
    ],
    [
      "https://例え.テスト/Team/%2FProject.git?#",
      ["例え.テスト", "Team/%2FProject"],
    ],
    ["https://AΣ/Team/../Project.GIT", ["aς", "Team/../Project.GIT"]],
    ["https://\ua7cb.example/Project", ["\ua7cb.example", "Project"]],
    ["https://[fe80::1%tESt]/Project", ["fe80::1%test", "Project"]],
    ["https://[fe80::1%😀]/Project", ["fe80::1%😀", "Project"]],
    ["https://[v1.future]/Project", ["v1.future", "Project"]],
    ...[
      "https://example.test:65536/Project",
      "https://example.test:+22/Project",
      "https://[127.0.0.1]/Project",
      "https://example\uff0ftest/Project",
      "https://example.test/Project?query",
      "https://example.test/Project#fragment",
      "https://[::1]extra/Project",
      "file:///Project",
      "relative/path",
    ].map((value): [string, null] => [value, null]),
  ];
  const git = Object.fromEntries(
    origins.map(([origin], index) => [`origin-${index}`, { origin }]),
  );
  const response = run(
    origins.map((_, index) => ({ origin: `origin-${index}` })),
    { git },
  );
  expect(
    response.results.map((result) => result.error ?? result.value),
  ).toEqual(origins.map(([, expected]) => expected));
});

test("uses exact target history and related Git identities while probing the requested checkout once", () => {
  const requested = join(root, "requested"),
    linked = join(root, "worktree"),
    clone = join(root, "clone"),
    other = join(root, "unrelated"),
    common = join(root, "shared.git");
  const response = run(
    [
      ...target("requested", requested),
      ...target("linked", linked),
      ...target("clone", clone),
      ...target("other", other),
      ...scan("original", "requested", 1),
      ...scan("worktree", "linked", 2),
      ...scan("clone", "clone", 3),
      ...scan("unrelated", "other", 4),
      sql("UPDATE scans SET target_path=? WHERE id='original'", [
        join(root, "old-requested"),
      ]),
      commit,
      query({ repository: requested }),
    ],
    {
      git: {
        [requested]: {
          common,
          origin: "https://EXAMPLE.test/team/project.git",
        },
        [linked]: { common, origin: "ignored" },
        [clone]: {
          common: join(root, "clone.git"),
          origin: "git@example.test:team/project",
        },
        [other]: {
          common: join(root, "other.git"),
          origin: "https://example.test/team/other",
        },
      },
    },
  );
  expect(ids(listing(response, response.results.length - 1))).toEqual([
    "clone",
    "worktree",
    "original",
  ]);
  expect(
    response.probes
      .filter((probe) => probe.target === requested)
      .map((probe) => probe.args),
  ).toEqual([
    ["rev-parse", "--path-format=absolute", "--git-common-dir"],
    ["remote", "get-url", "origin"],
  ]);
  expect(
    response.probes.filter((probe) => probe.target === linked),
  ).toHaveLength(1);
});

test("matches checkout aliases before Git probes when recorded paths have moved", () => {
  const checkout = join(root, "plain-checkout"),
    alias = join(root, "plain-alias");
  mkdirSync(checkout);
  symlinkSync(
    checkout,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  const response = run([
    ...target("plain", alias),
    ...scan("plain-scan", "plain", 1),
    sql("UPDATE scans SET target_path=? WHERE id='plain-scan'", [
      join(root, "previous-plain-checkout"),
    ]),
    commit,
    query({ repository: checkout }),
  ]);
  expect(ids(listing(response, response.results.length - 1))).toEqual([
    "plain-scan",
  ]);
  expect(response.probes.filter((probe) => probe.target === alias)).toEqual([]);
});

test("related history follows real worktrees, moved clones and requested symlink paths", () => {
  const parent = join(root, "real-git"),
    repository = join(parent, "repository"),
    worktree = join(parent, "worktree"),
    clone = join(parent, "clone"),
    moved = join(parent, "moved"),
    alias = join(parent, "alias"),
    unrelated = join(parent, "unrelated");
  mkdirSync(parent);
  const git = Bun.which("git")!;
  const command = (args: string[]) => {
    const env = { ...process.env };
    for (const key of [
      "GIT_DIR",
      "GIT_WORK_TREE",
      "GIT_INDEX_FILE",
      "GIT_COMMON_DIR",
    ])
      delete env[key];
    const child = spawnSync(
      git,
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        ...args,
      ],
      { env, encoding: "utf8" },
    );
    expect(child.status, child.stderr).toBe(0);
  };
  command(["init", "-q", repository]);
  writeFileSync(join(repository, "file"), "synthetic");
  command(["-C", repository, "add", "file"]);
  command(["-C", repository, "commit", "-qm", "Synthetic fixture"]);
  command([
    "-C",
    repository,
    "remote",
    "add",
    "origin",
    "https://example.test/team/project.git",
  ]);
  command(["-C", repository, "worktree", "add", "-q", "--detach", worktree]);
  command(["clone", "-q", repository, clone]);
  command([
    "-C",
    clone,
    "remote",
    "set-url",
    "origin",
    "git@example.test:team/project",
  ]);
  command(["init", "-q", unrelated]);
  command([
    "-C",
    unrelated,
    "remote",
    "add",
    "origin",
    "https://example.test/team/unrelated",
  ]);
  renameSync(clone, moved);
  symlinkSync(moved, alias, process.platform === "win32" ? "junction" : "dir");
  const response = run(
    [
      ...target("repo", repository),
      ...target("worktree", worktree),
      ...target("clone", moved),
      ...target("other", unrelated),
      ...scan("original", "repo", 1),
      ...scan("linked", "worktree", 2),
      ...scan("cloned", "clone", 3),
      ...scan("unrelated", "other", 4),
      sql("UPDATE scans SET target_path=? WHERE id='cloned'", [clone]),
      commit,
      query({ repository: alias }),
      query({ repository: repository, offset: 1n, limit: 1n }),
      query({ repository: moved, query: "clone" }),
      query({ repository: unrelated }),
    ],
    { path: dirname(git) },
  );
  const values = response.results
    .slice(-4)
    .map((result) => result.value as Listing);
  expect(ids(values[0]!)).toEqual(["cloned", "linked", "original"]);
  expect(ids(values[1]!)).toEqual(["linked"]);
  expect(values[1]).toMatchObject({ nextOffset: 2 });
  expect(ids(values[2]!)).toEqual(["cloned"]);
  expect(ids(values[3]!)).toEqual(["unrelated"]);
});

test("scan-root matching is contained and preserves platform path aliases", () => {
  const scans = join(root, "Scan History"),
    alias = join(root, "History Alias");
  mkdirSync(scans);
  symlinkSync(scans, alias, process.platform === "win32" ? "junction" : "dir");
  const response = run([
    ...target("target"),
    ...scan("inside", "target", 1),
    ...scan("sibling", "target", 2),
    sql("UPDATE scans SET scan_dir=? WHERE id='inside'", [
      join(scans, "child"),
    ]),
    sql("UPDATE scans SET scan_dir=? WHERE id='sibling'", [
      scans + " Other/child",
    ]),
    commit,
    query({ scanRoot: alias }),
    query({
      scanRoot: process.platform === "win32" ? scans.toUpperCase() : scans,
    }),
    sql("UPDATE scans SET scan_dir=? WHERE id='inside'", [scans]),
    query({ scanRoot: scans }),
  ]);
  for (const index of [
    response.results.length - 4,
    response.results.length - 3,
    response.results.length - 1,
  ])
    expect(ids(listing(response, index))).toEqual(["inside"]);
});

test("SDK scan-list helper retains output and validation without requiring Python", () => {
  const state = join(root, "state"),
    repository = join(root, "cli-repository");
  mkdirSync(state);
  mkdirSync(repository);
  const filename = join(state, "workbench.sqlite3");
  const response = run(
    [
      ...target("cli-target", repository),
      ...scan("saved", "cli-target", 1),
      commit,
      {
        sdk: ["list-scans", "--repository", repository, "--limit", "1"],
        state,
        plugin: PLUGIN_ROOT,
      },
    ],
    { filename },
  );
  expect(ids(listing(response, response.results.length - 1))).toEqual([
    "saved",
  ]);
  for (const args of [
    ["--limit", "0"],
    ["--offset", "-1"],
    ["--mode", "unsupported"],
  ]) {
    const child = spawnSync(
      node,
      [join(PLUGIN_ROOT, "mcp/helpers.mjs"), "list-scans", ...args],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: "",
          PYTHON: "missing-list-scans-python",
          CODEX_SECURITY_STATE_DIR: state,
        },
      },
    );
    expect(child.status).toBe(2);
    expect(child.stderr).toContain("list-scans: error:");
  }
});

test("public scan-list CLI retains output without requiring Python", () => {
  const state = join(root, "public-cli-state"),
    repository = join(root, "public-cli-repository");
  mkdirSync(state);
  mkdirSync(repository);
  run(
    [
      ...target("cli-target", repository),
      ...scan("saved", "cli-target", 1),
      commit,
    ],
    { filename: join(state, "workbench.sqlite3") },
  );
  for (const args of [
    ["scans", "--json"],
    ["scans", "list", repository, "--json"],
    ["scans", "list", "--scan-root", repository, "--json"],
  ]) {
    const child = spawnSync(node, [cli, ...args], {
      cwd: repository,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: "",
        PYTHON: "missing-list-scans-python",
        CODEX_SECURITY_STATE_DIR: state,
      },
      maxBuffer: Infinity,
    });
    expect(child.status, child.stderr).toBe(0);
    expect(child.stderr).toBe("");
    expect(ids(JSON.parse(child.stdout) as Listing)).toEqual(["saved"]);
  }
});
