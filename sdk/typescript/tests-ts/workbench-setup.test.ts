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
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Action, Response } from "./support/workbench-setup-fixture";
import type {
  CreateWorkspaceArguments,
  DiffTarget,
  SetupArguments,
} from "../../../plugins/codex-security/mcp-app/src/workbench-setup";
import { stringifyJson } from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";

const root = realpathSync(mkdtempSync(join(tmpdir(), "workbench-setup-")));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const environment: NodeJS.ProcessEnv = {
  ...process.env,
  PYTHON: "/unavailable/python",
};
for (const key of [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
])
  delete environment[key];
Object.assign(environment, {
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "Fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
  CODEX_SECURITY_STATE_DIR: join(root, "state"),
});
let childPath = environment["PATH"];
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-setup-fixture.ts", import.meta.url),
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
  });
  if (process.platform !== "win32") {
    childPath = join(root, "bin");
    mkdirSync(childPath);
    symlinkSync(Bun.which("git")!, join(childPath, "git"));
  }
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
function run(actions: Action[], migrate = false): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson({ actions, migrate }),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...environment, PATH: childPath },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
function value(action: Action) {
  const response = run([action])[0]!;
  expect(response.error).toBeUndefined();
  return response.value;
}
function directory() {
  return realpathSync(mkdtempSync(join(root, "target Σ ")));
}
function write(target: string, path: string, contents = "contents\n") {
  const file = join(target, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, contents);
  return file;
}
function git(target: string, ...args: string[]) {
  const result = spawnSync(
    "git",
    ["-c", "protocol.file.allow=always", "-C", target, ...args],
    { env: environment, encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}
function repository(commit = true) {
  const target = directory();
  git(target, "init", "-q", "-b", "main");
  git(target, "config", "core.autocrlf", "false");
  write(target, "src/file.txt");
  if (commit) {
    git(target, "add", ".");
    git(target, "commit", "-qm", "Initial fixture");
  }
  return target;
}
function setup(targetPath: string, mode = "standard"): SetupArguments {
  return {
    targetPath,
    mode,
    scope: ".",
    diffTargetKind: null,
    diffBaseRevision: null,
    diffHeadRevision: null,
    diffContentDigest: null,
  };
}
const uuid = "11111111-2222-4333-8444-555555555555";
function create(
  targetPath: string | null = null,
  extra: Partial<CreateWorkspaceArguments> = {},
): Extract<Action, { kind: "create" }> {
  return {
    kind: "create",
    args: {
      ...setup(targetPath ?? ""),
      targetPath,
      workspaceId: uuid,
      threadId: null,
      targetTitle: null,
      targetSummary: null,
      userContext: null,
      ...extra,
    },
  };
}
function save(
  targetPath: string,
  extra: Partial<CreateWorkspaceArguments> = {},
): Extract<Action, { kind: "save" }> {
  return {
    kind: "save",
    args: {
      ...setup(targetPath),
      workspaceId: uuid,
      targetSummary: null,
      userContext: null,
      ...extra,
      targetPath,
      scope: extra.scope ?? ".",
    },
  };
}
const sql = (sql: string): Action => ({ kind: "sql", sql });
const query = (sql: string): Action => ({ kind: "query", sql });
const snapshot = () => [
  query("SELECT * FROM workspaces"),
  query("SELECT * FROM security_targets"),
];

test("target inspection resolves aliases and retains absolute-directory diagnostics", () => {
  const target = directory(),
    missing = join(target, "missing"),
    file = write(target, "file");
  const responses = run([
    { kind: "target", target },
    { kind: "target", target: "relative" },
    { kind: "target", target: missing },
    { kind: "target", target: file },
  ]);
  expect(responses[0]?.value).toBe(target);
  expect(responses[1]?.error).toBe(
    "Scan target must be an absolute local directory path.",
  );
  expect(responses[2]?.error).toBe(
    `Scan target is not a readable local directory: ${missing}`,
  );
  expect(responses[3]?.error).toBe(
    `Scan target is not a readable local directory: ${file}`,
  );
  if (process.platform !== "win32") {
    const alias = join(root, "alias"),
      loop = join(target, "loop");
    symlinkSync(target, alias, "dir");
    symlinkSync(loop, loop);
    expect(value({ kind: "target", target: alias })).toBe(target);
    const error = run([{ kind: "target", target: loop }])[0]!;
    expect(error.systemExit).toBe(false);
    expect(error.error).toBe(`Symlink loop from '${loop}'`);
  }
});

test("scope normalization preserves directory, traversal, symlink and mode checks", () => {
  const target = directory();
  mkdirSync(join(target, "src"));
  write(target, "file");
  const scopes = [
    "",
    "\u001c . \u2000",
    "src/./",
    join(target, "src"),
    join(target, "file"),
    "missing",
    "../outside",
    "src/..",
    "src\\child",
  ];
  const values = run(
    scopes.map((scope) => ({ kind: "scope", target, scope, mode: "standard" })),
  );
  expect(values.slice(0, 4).map((response) => response.value)).toEqual([
    ".",
    ".",
    "src",
    "src",
  ]);
  expect(
    values
      .slice(4, 6)
      .every((response) => response.error?.includes("existing directory")),
  ).toBe(true);
  expect(
    values
      .slice(6, 8)
      .every((response) => response.error?.includes("stay inside")),
  ).toBe(true);
  expect(values[8]?.error).toContain("repository-relative POSIX");
  expect(
    run([{ kind: "scope", target, scope: "missing", mode: "deep" }])[0]?.error,
  ).toContain("repository-wide");
  expect(
    run(
      ["standard", "deep", "diff"].map((mode) => ({
        kind: "scope",
        target,
        scope: "a\0b",
        mode,
      })),
    ).map((response) => response.error),
  ).toEqual(Array(3).fill("Scan scope must stay inside the scanned target."));
  if (process.platform !== "win32") {
    const outside = directory();
    symlinkSync(outside, join(target, "outside"), "dir");
    symlinkSync("src", join(target, "inside"), "dir");
    symlinkSync("loop", join(target, "loop"));
    const result = run(
      ["outside", "inside", "loop"].map((scope) => ({
        kind: "scope",
        target,
        scope,
        mode: "standard",
      })),
    );
    expect(result[0]?.error).toContain("stay inside");
    expect(result[1]?.value).toBe("src");
    expect(result[2]?.error).toContain("stay inside");
  }
});

test("setup permits plain and unborn targets while preserving diff rejection order", () => {
  const plain = directory(),
    unborn = repository(false),
    repositoryRoot = repository(),
    nested = join(repositoryRoot, "src"),
    bare = directory();
  git(bare, "init", "-q", "--bare");
  expect(value({ kind: "inspect", args: setup(plain) })).toMatchObject({
    scope: ".",
    diffTarget: null,
    target: { targetPath: plain, targetMetadata: { isGit: false } },
  });
  expect(value({ kind: "inspect", args: setup(unborn) })).toMatchObject({
    target: { targetMetadata: { isGit: true, hasHead: false } },
  });
  const results = run([
    { kind: "inspect", args: setup(bare) },
    { kind: "inspect", args: setup(unborn, "diff") },
    { kind: "inspect", args: setup(nested, "diff") },
    {
      kind: "inspect",
      args: { ...setup(repositoryRoot, "diff"), scope: "src" },
    },
    { kind: "inspect", args: { ...setup(plain), diffContentDigest: "" } },
  ]);
  expect(results.map((response) => response.error)).toEqual([
    "Codex Security requires a checked-out worktree, not a bare Git repository.",
    "Review changes requires a non-bare Git worktree with a resolvable HEAD.",
    "Review changes requires the checked-out Git repository root as the target.",
    "Review changes requires the whole target; use scope '.'.",
    "A Git diff target requires Review changes mode.",
  ]);
});

test("commit and range selections retain roots, parent validation and shallow errors", () => {
  const target = repository(),
    initial = git(target, "rev-parse", "HEAD");
  const selection = (head: string, base: string | null = null): Action => ({
    kind: "diff",
    args: {
      ...setup(target, "diff"),
      diffTargetKind: "commit",
      diffHeadRevision: head,
      diffBaseRevision: base,
    },
  });
  expect(value(selection("HEAD"))).toEqual({
    kind: "commit",
    baseRevision: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    headRevision: initial,
  });
  write(target, "src/file.txt", "second\n");
  git(target, "commit", "-qam", "Second fixture");
  const second = git(target, "rev-parse", "HEAD");
  expect(value(selection("HEAD"))).toEqual({
    kind: "commit",
    baseRevision: initial,
    headRevision: second,
  });
  expect(value(selection("HEAD", "HEAD~1"))).toMatchObject({
    baseRevision: initial,
  });
  expect(run([selection("HEAD", second)])[0]?.error).toContain(
    "must match the selected commit's parent",
  );
  const range = {
    ...setup(target, "diff"),
    diffTargetKind: "range",
    diffBaseRevision: initial,
    diffHeadRevision: second,
  };
  expect(value({ kind: "diff", args: range })).toEqual({
    kind: "range",
    baseRevision: initial,
    headRevision: second,
  });
  expect(
    run([{ kind: "diff", args: { ...range, diffBaseRevision: second } }])[0]
      ?.error,
  ).toBe("Base and head revisions must identify different commits.");
  const shallow = join(root, "shallow");
  git(root, "clone", "-q", "--depth", "1", pathToFileURL(target).href, shallow);
  expect(
    run([
      {
        kind: "diff",
        args: {
          ...range,
          targetPath: shallow,
          diffTargetKind: "commit",
          diffBaseRevision: null,
        },
      },
    ])[0]?.error,
  ).toContain("Commit parent does not resolve");
});

test("working-tree selections distinguish stale HEAD from stale contents", () => {
  const target = repository(),
    oldHead = git(target, "rev-parse", "HEAD");
  git(target, "commit", "--allow-empty", "-qm", "Next fixture");
  const args = { ...setup(target, "diff"), diffTargetKind: "working_tree" };
  const initial = value({ kind: "diff", args }) as DiffTarget;
  expect(initial.baseRevision).toBe(initial.headRevision);
  expect(initial.contentDigest).toMatch(
    /^codex-security-snapshot\/v1:sha256:/u,
  );
  write(target, "untracked");
  expect(
    run([
      {
        kind: "diff",
        args: { ...args, diffContentDigest: initial.contentDigest! },
      },
    ])[0]?.error,
  ).toContain("Working-tree contents changed");
  expect(
    run([
      {
        kind: "diff",
        args: {
          ...args,
          diffBaseRevision: oldHead,
          diffContentDigest: "stale",
        },
      },
    ])[0]?.error,
  ).toContain("Repository HEAD changed");
  expect(
    value({ kind: "diff", args: { ...args, diffContentDigest: "" } }),
  ).toMatchObject({ kind: "working_tree" });
});

test("revision lookup preserves argument handling and setup probe order", () => {
  const target = directory();
  const output = (text: string) => ({
    stdout: Buffer.from(text).toString("base64"),
  });
  const metadata = [
    ".git",
    "true",
    "head",
    target,
    "main",
    "subject",
    target,
  ].map(output);
  const results = run([
    { kind: "commit", target, revision: "", label: "Choice", git: [] },
    {
      kind: "commit",
      target,
      revision: "  --option  ",
      label: "Choice",
      git: [output("resolved")],
    },
    { kind: "diff", args: setup(target, "diff"), git: metadata },
  ]);
  expect(results[0]?.error).toBe("Choice is required.");
  expect(results[0]?.events).toEqual([]);
  expect(results[1]?.value).toBe("resolved");
  expect((results[1]?.events[0] as [string, string[]])[1].slice(-4)).toEqual([
    "rev-parse",
    "--verify",
    "--end-of-options",
    "--option^{commit}",
  ]);
  expect(results[2]?.events).toHaveLength(7);
  expect(results[2]?.error).toContain("Choose which Git changes");
  const badParent = Buffer.from("parent ", "ascii");
  const bad = run([
    {
      kind: "diff",
      args: {
        ...setup(target, "diff"),
        diffTargetKind: "commit",
        diffHeadRevision: "HEAD",
      },
      git: [
        ...metadata,
        output("head"),
        {
          stdout: Buffer.concat([badParent, Buffer.from([0xff])]).toString(
            "base64",
          ),
        },
      ],
    },
  ])[0]!;
  expect(bad.systemExit).toBe(false);
  expect(bad.error).toContain("'ascii' codec can't decode byte 0xff");
});

test("workspace creation retains invalid setup and discards diff fields outside diff mode", () => {
  const target = directory(),
    missing = join(target, "missing");
  const results = run(
    [
      create(missing, {
        scope: "src",
        userContext: "  context  ",
        diffTargetKind: "range",
        diffBaseRevision: "bad",
      }),
      ...snapshot(),
    ],
    true,
  );
  expect(results[0]?.value).toMatchObject({
    target_path: missing,
    default_scope: "src",
    user_context: "context",
    submitted: 0,
    diff_target_kind: null,
    diff_base_revision: null,
  });
  expect(results[0]?.events).toEqual([
    ["now", false],
    ["now", false],
    ["state", uuid, false],
  ]);
  expect(results[0]?.inTransaction).toBe(false);
  expect(results[2]?.value).toHaveLength(1);
  const invalidDeep = run(
    [create(target, { mode: "deep", scope: "src" })],
    true,
  )[0]!;
  expect(invalidDeep.value).toMatchObject({
    default_mode: "deep",
    default_scope: "src",
  });
});

test("workspace creation rolls back validation failures and commits before rendering state", () => {
  const target = directory();
  const badUuid = run([create(null, { workspaceId: "invalid" })], true)[0]!;
  expect(badUuid.events).toEqual([]);
  const tooLong = run(
    [create(target, { targetTitle: "x".repeat(201) }), ...snapshot()],
    true,
  );
  expect(tooLong[0]?.error).toContain("200 characters");
  expect(tooLong[1]?.value).toEqual([]);
  expect(tooLong[2]?.value).toEqual([]);
  expect(tooLong[0]?.inTransaction).toBe(false);
  const callbackFailure = { ...create(target), stateError: true };
  const committed = run([callbackFailure, ...snapshot()], true);
  expect(committed[0]?.error).toBe("state failed");
  expect(committed[1]?.value).toHaveLength(1);
  expect(committed[2]?.value).toHaveLength(1);
  if (process.platform !== "win32") {
    const loop = join(target, "loop");
    symlinkSync(loop, loop);
    const failed = run([create(loop), ...snapshot()], true);
    expect(failed[0]?.systemExit).toBe(false);
    expect(failed[1]?.value).toEqual([]);
    expect(failed[2]?.value).toEqual([]);
  }
});

test("saving setup preserves labels until the target changes and supplies diff summaries", () => {
  const target = directory(),
    replacement = repository();
  const results = run(
    [
      create(target, {
        targetTitle: "Friendly title",
        targetSummary: "Existing summary",
      }),
      save(target),
      save(replacement),
      save(replacement, {
        mode: "diff",
        diffTargetKind: "commit",
        diffHeadRevision: "HEAD",
        targetSummary: "",
      }),
    ],
    true,
  );
  expect(results[1]?.value).toMatchObject({
    target_title: "Friendly title",
    target_summary: "Existing summary",
    submitted: 1,
  });
  expect(results[2]?.value).toMatchObject({
    target_title: replacement.split(/[\\/]/u).at(-1),
    target_summary: null,
  });
  const selected = results[3]?.value as Record<string, unknown>;
  expect(selected["target_summary"]).toBe(
    `Commit ${(selected["diff_head_revision"] as string).slice(0, 7)}`,
  );
  expect(results.every((result) => !result.error)).toBe(true);
});

test("save checks active scans before inspection and retains the conditional update race guard", () => {
  const target = directory(),
    replacement = directory();
  const seedScan = sql(`INSERT INTO scans (
    id, workspace_id, target_id, target_path, target_revision, scope, mode,
    scan_dir, status, phase, handoff_status, started_at, created_at, updated_at
  ) SELECT 'active', id, target_id, target_path, 'revision', '.', 'standard',
    '/scan', 'running', 'preflight', 'pending', 'before', 'before', 'before'
    FROM workspaces`);
  const active = run(
    [
      create(target),
      seedScan,
      sql("UPDATE workspaces SET active_scan_id = 'active'"),
      { kind: "commitDb" },
      save("relative"),
    ],
    true,
  );
  expect(active.at(-1)?.error).toContain("already has a scan");
  expect(active.at(-1)?.events).toEqual([["require", uuid, false]]);
  const raced = run(
    [
      create(target),
      seedScan,
      { kind: "commitDb" },
      {
        ...save(replacement),
        afterReadSql: "UPDATE workspaces SET active_scan_id = 'active'",
      },
      ...snapshot(),
    ],
    true,
  );
  expect(raced[3]?.error).toContain("already has a scan");
  expect(raced[3]?.inTransaction).toBe(false);
  expect(raced[4]?.value).toMatchObject([
    { active_scan_id: "active", target_path: target },
  ]);
  expect(raced[5]?.value).toHaveLength(1);
});

test("workspace context stays unbounded and stdin failures roll back the caller transaction", () => {
  const target = directory(),
    context = "https://example.invalid/context\n" + "x".repeat(10001);
  const results = run(
    [
      create(target, { userContext: context }),
      {
        ...save(target, { userContextStdin: true }),
        stdin: "  replacement context  ",
      },
      query("SELECT user_context FROM workspaces"),
    ],
    true,
  );
  expect(results[0]?.value).toMatchObject({ user_context: context });
  expect(results[2]?.value).toEqual([{ user_context: "replacement context" }]);
  expect(results[1]?.events).toEqual([
    ["require", uuid, false],
    ["now", false],
    ["stdin", false],
    ["state", uuid, false],
  ]);
  const failed = run(
    [
      create(target),
      sql("UPDATE workspaces SET target_title = 'pending'"),
      { ...save(target, { userContextStdin: true }), stdinError: true },
      query("SELECT target_title FROM workspaces"),
    ],
    true,
  );
  expect(failed[2]?.error).toBe("stdin failed");
  expect(failed[2]?.inTransaction).toBe(false);
  expect(failed[3]?.value).toEqual([{ target_title: null }]);
});

test("scan roots stay outside selected targets and summaries truncate Unicode code points", () => {
  const target = join(root, "scan-target"),
    parent = dirname(target);
  mkdirSync(target);
  const results = run([
    { kind: "root", target, scanRoot: null },
    { kind: "root", target, scanRoot: parent },
    { kind: "root", target, scanRoot: target },
  ]);
  expect(results[0]?.value).toContain(join(root, "state", "scans"));
  expect(results[1]?.error).toContain("outside the selected target");
  expect(results[2]?.error).toContain("outside the selected target");
  expect(
    value({
      kind: "summary",
      target: {
        kind: "commit",
        baseRevision: "base",
        headRevision: "😀abcdefg",
      },
    }),
  ).toBe("Commit 😀abcdef");
  expect(
    value({
      kind: "summary",
      target: {
        kind: "range",
        baseRevision: "abcdefgh",
        headRevision: "12345678",
      },
    }),
  ).toBe("abcdefg…1234567");
});
