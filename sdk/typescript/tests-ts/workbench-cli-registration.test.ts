import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { RegisteredCliScan } from "../../../plugins/codex-security/mcp-app/src/workbench-cli-registration";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-cli-registration-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "cli-registration-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const scanId = "11111111-1111-4111-8111-111111111111",
  workspaceId = "22222222-2222-4222-8222-222222222222",
  parentId = "33333333-3333-4333-8333-333333333333",
  parentWorkspace = "44444444-4444-4444-8444-444444444444";
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL(
          "./support/workbench-cli-registration-fixture.ts",
          import.meta.url,
        ),
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function setup(name: string, paths?: string[], mode = "standard") {
  const root = join(directory, name),
    target = join(root, "target"),
    scan = join(root, "scan");
  mkdirSync(root);
  mkdirSync(target);
  mkdirSync(scan, { mode: 0o700 });
  mkdirSync(join(target, "nested"));
  writeFileSync(join(target, "main.ts"), "first\n");
  writeFileSync(join(target, "nested", "child.ts"), "child\n");
  const recipe = {
    repository: target,
    mode,
    config: {},
    target: { kind: paths ? "paths" : "repository", paths: paths ?? [] },
  };
  const action: Extract<Action, { operation: "register" }> = {
    operation: "register",
    args: {
      repository: target,
      scanDir: scan,
      recipeJson: stringifyJson(recipe),
      recipeJsonStdin: false,
      registrationJsonStdin: false,
      parentScanId: null,
      archivedScanDir: null,
      archiveExisting: false,
    },
  };
  const request: Request = { actions: [action] };
  return { root, target, scan, recipe, action, request };
}
type Setup = ReturnType<typeof setup>;
function envelope(value: Setup, fields: Record<string, unknown> = {}): void {
  value.action.args.recipeJson = null;
  value.action.args.registrationJsonStdin = true;
  value.action.stdin = stringifyJson({ recipe: value.recipe, ...fields });
}
function run(request: Request, path = ""): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: {
      ...process.env,
      PATH: path,
      PYTHON: "/unavailable/python",
      GIT_OPTIONAL_LOCKS: "0",
    },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return (parseJson(child.stdout) as unknown as Response[])[0]!;
}
const last = (response: Response) => response.outcomes.at(-1)!;
const result = (response: Response) =>
  last(response).value as RegisteredCliScan;
const rows = (response: Response, name: string) => response.snapshot[name]!;
const scan = (response: Response, id = scanId) =>
  rows(response, "scans").find((row) => row["id"] === id)!;
const phases = (response: Response, phase: string) =>
  last(response).events.filter((event) => (event as unknown[])[0] === phase);
const sql = (statement: string): Action => ({
  operation: "sql",
  sql: statement,
});
function previous(value: Setup, sameTarget = true): void {
  value.request.records = {
    security_targets: [
      {
        id: "previous-target",
        current_path: sameTarget ? value.target : join(value.root, "other"),
        display_name: "previous",
        created_at: "before",
        updated_at: "before",
      },
    ],
    workspaces: [
      {
        id: parentWorkspace,
        target_id: "previous-target",
        created_at: "before",
        updated_at: "before",
      },
    ],
    scans: [
      {
        id: parentId,
        workspace_id: parentWorkspace,
        target_id: "previous-target",
        target_path: value.target,
        target_revision: "previous",
        scope: ".",
        mode: "standard",
        scan_dir: value.scan,
        status: "complete",
        phase: "reporting",
        started_at: "before",
        created_at: "before",
        updated_at: "before",
      },
    ],
  };
}

test("registers standard and deep scans with their contract and external empty output", () => {
  for (const mode of ["standard", "deep"]) {
    const value = setup(mode, undefined, mode),
      response = run(value.request);
    expect(last(response).error).toBeUndefined();
    expect(result(response)).toMatchObject({
      scanId,
      scanDir: value.scan,
      scopeFileCount: 2n,
      targetRevision: "unversioned",
    });
    expect(scan(response)).toMatchObject({
      workspace_id: workspaceId,
      status: "running",
      phase: "preflight",
      mode,
      handoff_status: "delivered",
    });
    expect(result(response).contract["target"]).toMatchObject({
      allowedKinds: ["directory_snapshot"],
      targetId: result(response).targetId,
    });
    expect(rows(response, "workspaces")[0]).toMatchObject({
      active_scan_id: scanId,
      submitted: 1n,
    });
    expect(rows(response, "scan_progress")[0]!["scope_file_count"]).toBe(2n);
    expect(readdirSync(value.scan)).toEqual([]);
  }
});

test("preserves scoped paths and counts every selected file or directory", () => {
  for (const paths of [
    ["./main.ts"],
    ["nested"],
    ["main.ts", "nested"],
    ["main.ts", "main.ts"],
  ]) {
    const value = setup(
        `paths-${paths.join("-").replaceAll("/", "_")}`,
        paths,
        "deep",
      ),
      response = run(value.request);
    expect(last(response).error).toBeUndefined();
    expect(scan(response)["scope"]).toBe(paths.length === 1 ? paths[0] : ".");
    expect(result(response).scopeFileCount).toBe(paths.length === 1 ? 1n : 2n);
    expect(result(response).contract["scope"]).toMatchObject({
      requiredIncludePaths: paths,
    });
  }
});

test("recipe stdin and registration envelopes retain JSON and user context semantics", () => {
  const direct = setup("recipe-stdin");
  direct.action.args.recipeJsonStdin = true;
  direct.action.stdin = direct.action.args.recipeJson!;
  direct.action.args.recipeJson = null;
  const first = run(direct.request);
  expect(last(first).error).toBeUndefined();
  expect(phases(first, "stdin")).toHaveLength(1);
  const value = setup("registration-envelope");
  value.recipe.config = {
    text: "é".repeat(50_000),
    literal: "\\u00e9",
    wide: 9007199254740993n,
  };
  envelope(value, { userContext: "  Synthetic context  " });
  const response = run(value.request);
  expect(last(response).error).toBeUndefined();
  expect(parseJson(scan(response)["recipe_json"] as string)).toEqual(
    value.recipe,
  );
  expect(scan(response)["user_context"]).toBe("  Synthetic context  ");
  expect(rows(response, "workspaces")[0]!["user_context"]).toBeNull();
});

test("validates artifact containment and emptiness before reading stdin", () => {
  for (const variant of ["inside", "nonempty", "missing"]) {
    const value = setup(`output-${variant}`);
    if (variant === "inside") {
      const inside = join(value.target, "output");
      mkdirSync(inside, { mode: 0o700 });
      value.action.args.scanDir = inside;
    } else if (variant === "nonempty")
      writeFileSync(join(value.scan, "saved"), "saved bytes");
    else value.action.args.scanDir = join(value.root, "missing");
    envelope(value);
    value.action.hooks = [{ phase: "stdin", error: "must not read" }];
    const response = run(value.request);
    expect(last(response).error).toBeDefined();
    expect(phases(response, "stdin")).toEqual([]);
    expect(phases(response, "now")).toEqual([]);
    expect(rows(response, "scans")).toEqual([]);
    if (variant === "nonempty")
      expect(readFileSync(join(value.scan, "saved"), "utf8")).toBe(
        "saved bytes",
      );
  }
});

test("keeps separate scan and target creation clocks and skips the second for known targets", () => {
  const value = setup("clocks");
  value.action.times = ["2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z"];
  const response = run(value.request);
  expect(last(response).error).toBeUndefined();
  expect(scan(response)["created_at"]).toBe(value.action.times[0]);
  expect(rows(response, "security_targets")[0]!["created_at"]).toBe(
    value.action.times[1],
  );
  expect(
    phases(response, "now").map((event) => (event as unknown[])[2]),
  ).toEqual([false, true]);
  expect(phases(response, "uuid")).toHaveLength(2);
});

test("archives prior artifacts before registering a rerun under the same target", () => {
  const value = setup("archive");
  previous(value);
  const archived = join(value.root, "scan.previous-kept");
  mkdirSync(archived, { mode: 0o700 });
  writeFileSync(join(archived, "findings.json"), "prior bytes");
  value.request.records!["scan_artifacts"] = [
    {
      scan_id: parentId,
      kind: "findings",
      path: join(value.scan, "findings.json"),
      created_at: "before",
    },
  ];
  Object.assign(value.action.args, {
    archiveExisting: true,
    archivedScanDir: archived,
    parentScanId: parentId,
  });
  const response = run(value.request);
  expect(last(response).error).toBeUndefined();
  expect(result(response).targetId).toBe("previous-target");
  expect(scan(response, parentId)["scan_dir"]).toBe(archived);
  expect(rows(response, "scan_artifacts")[0]!["path"]).toBe(
    join(archived, "findings.json"),
  );
  expect(scan(response)["parent_scan_id"]).toBe(parentId);
  expect(phases(response, "now")).toHaveLength(1);
  expect(readFileSync(join(archived, "findings.json"), "utf8")).toBe(
    "prior bytes",
  );
  expect(readdirSync(value.scan)).toEqual([]);
});

test("creates an empty archive sibling and retains it if later registration rolls back", () => {
  for (const sameTarget of [true, false]) {
    const value = setup(`auto-archive-${sameTarget}`);
    previous(value, sameTarget);
    Object.assign(value.action.args, {
      archiveExisting: true,
      parentScanId: parentId,
    });
    const response = run(value.request),
      names = readdirSync(value.root).filter((name) =>
        name.startsWith("scan.previous-"),
      );
    expect(names).toHaveLength(1);
    expect(names[0]).toMatch(/^scan\.previous-[a-z0-9_]{8}$/);
    const archived = join(value.root, names[0]!);
    expect(readdirSync(archived)).toEqual([]);
    expect(readdirSync(value.scan)).toEqual([]);
    expect(scan(response, parentId)["scan_dir"]).toBe(
      sameTarget ? archived : value.scan,
    );
    expect(rows(response, "scans")).toHaveLength(sameTarget ? 2 : 1);
    if (sameTarget) expect(last(response).error).toBeUndefined();
    else
      expect(last(response).error).toBe(
        "A rerun must belong to the same repository as its parent scan.",
      );
  }
});

test("parent mismatch rolls back archive changes and newly created target records", () => {
  const value = setup("parent-mismatch");
  previous(value, false);
  const archived = join(value.root, "scan.previous-kept");
  mkdirSync(archived, { mode: 0o700 });
  Object.assign(value.action.args, {
    archiveExisting: true,
    archivedScanDir: archived,
    parentScanId: parentId,
  });
  const response = run(value.request);
  expect(last(response).error).toBe(
    "A rerun must belong to the same repository as its parent scan.",
  );
  expect(scan(response, parentId)["scan_dir"]).toBe(value.scan);
  expect(rows(response, "security_targets")).toHaveLength(1);
  expect(rows(response, "scans")).toHaveLength(1);
  expect(last(response).inTransaction).toBe(false);
});

test("registers the workflow atomically and rejects a completed workflow", () => {
  for (const status of ["pending", "completed"]) {
    const value = setup(`workflow-${status}`);
    envelope(value, { workflowId: "synthetic-workflow" });
    value.request.records = {
      finding_workflows: [
        {
          id: "synthetic-workflow",
          results_json: "{}",
          scan_status: status,
          created_at: "before",
          updated_at: "before",
        },
      ],
    };
    const response = run(value.request),
      workflow = rows(response, "finding_workflows")[0]!;
    if (status === "pending") {
      expect(last(response).error).toBeUndefined();
      expect(workflow).toMatchObject({
        scan_id: scanId,
        scan_dir: value.scan,
        scan_status: "pending",
      });
    } else {
      expect(last(response).error).toBe(
        "The workflow scan is already complete.",
      );
      expect(workflow["scan_id"]).toBeNull();
      expect(rows(response, "scans")).toEqual([]);
      expect(rows(response, "workspaces")).toEqual([]);
    }
  }
});

test("failed clocks and existing caller transactions retain their original rollback boundaries", () => {
  for (const call of [1, 2]) {
    const value = setup(`failed-clock-${call}`);
    value.action.hooks = [
      {
        phase: "now",
        call,
        sql: "INSERT INTO synthetic_audit VALUES ('clock')",
        error: "clock failed",
      },
    ];
    const response = run(value.request);
    expect(last(response).error).toBe("clock failed");
    expect(last(response).inTransaction).toBe(call === 1);
    expect(rows(response, "synthetic_audit")).toHaveLength(call === 1 ? 1 : 0);
    expect(rows(response, "scans")).toEqual([]);
  }
  const value = setup("caller");
  value.request.actions.unshift(
    sql("INSERT INTO synthetic_audit VALUES ('caller')"),
  );
  const response = run(value.request);
  expect(last(response).error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(last(response).inTransaction).toBe(true);
  expect(rows(response, "synthetic_audit")).toEqual([{ value: "caller" }]);
});

test("SQL, serialization and workflow failures leave no partial registration", () => {
  for (const failure of [
    "progress",
    "commit",
    "context",
    "overflow",
    "workflow",
  ]) {
    const value = setup(`rollback-${failure}`);
    if (failure === "progress")
      value.request.setupSql = [
        "CREATE TRIGGER reject_progress BEFORE INSERT ON scan_progress BEGIN SELECT RAISE(ABORT,'rejected'); END",
      ];
    if (failure === "commit")
      value.request.setupSql = [
        "CREATE TABLE deferred_check(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER defer_write AFTER INSERT ON scans BEGIN INSERT INTO deferred_check VALUES ('missing'); END",
      ];
    if (failure === "context") envelope(value, { userContext: [] });
    if (failure === "workflow") envelope(value, { workflowId: "missing" });
    if (failure === "overflow")
      value.action.args.recipeJson = value.action.args.recipeJson!.replace(
        '"config": {}',
        '"config": {"value": 1e9999}',
      );
    const response = run(value.request);
    expect(last(response).error).toBeDefined();
    expect(last(response).inTransaction).toBe(false);
    for (const table of [
      "security_targets",
      "workspaces",
      "scans",
      "scan_progress",
    ])
      expect(rows(response, table)).toEqual([]);
    expect(readdirSync(value.scan)).toEqual([]);
  }
});

test("a contract-rendering failure occurs after the registration commits", () => {
  const value = setup("postcommit");
  value.request.setupSql = [
    "CREATE TRIGGER corrupt_recipe AFTER UPDATE OF recipe_json ON scans BEGIN UPDATE scans SET recipe_json='{' WHERE id=NEW.id; END",
  ];
  const response = run(value.request);
  expect(last(response).error).toBeDefined();
  expect(last(response).inTransaction).toBe(false);
  expect(scan(response)).toMatchObject({ status: "running", recipe_json: "{" });
  expect(rows(response, "workspaces")[0]!["active_scan_id"]).toBe(scanId);
});

test("Git revision and working-tree recipes register diff identity using real Git", () => {
  const git = Bun.which("git")!;
  for (const kind of ["refs", "working_tree"]) {
    const value = setup(`git-${kind}`, undefined, "deep");
    const hooks = join(value.root, "hooks");
    mkdirSync(hooks);
    const gitEnvironment = {
      ...process.env,
      GIT_OPTIONAL_LOCKS: "0",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    };
    const command = (...args: string[]): string => {
      const child = spawnSync(
        git,
        [
          "-c",
          "user.name=Synthetic",
          "-c",
          "user.email=synthetic@example.test",
          "-c",
          `core.hooksPath=${hooks}`,
          ...args,
        ],
        {
          cwd: value.target,
          encoding: "utf8",
          env: gitEnvironment,
        },
      );
      expect(child.status, child.stderr).toBe(0);
      return child.stdout.trim();
    };
    command("init", "-q", "-b", "main");
    command("add", ".");
    command("commit", "-qm", "Synthetic first");
    const base = command("rev-parse", "HEAD");
    writeFileSync(join(value.target, "main.ts"), "second\n");
    command("add", ".");
    command("commit", "-qm", "Synthetic second");
    const head = command("rev-parse", "HEAD");
    if (kind === "working_tree")
      writeFileSync(join(value.target, "main.ts"), "uncommitted\n");
    const recipe = {
      ...value.recipe,
      target: { kind, paths: [], base: "HEAD~1", head: "HEAD" },
    };
    value.action.args.recipeJson = stringifyJson(recipe);
    const response = run(value.request, dirname(git));
    expect(last(response).error).toBeUndefined();
    expect(scan(response)).toMatchObject({
      mode: "diff",
      diff_target_kind: kind === "refs" ? "range" : "working_tree",
      diff_base_revision: base,
      diff_head_revision: head,
      target_revision: head,
      target_snapshot_digest: null,
    });
    expect(result(response).contract["target"]).toMatchObject({
      allowedKinds: ["git_diff"],
    });
    if (kind === "working_tree") {
      expect(scan(response)["diff_content_digest"]).toMatch(
        /^codex-security-snapshot\/v1:sha256:/,
      );
      value.action.args.recipeJson = stringifyJson({
        ...recipe,
        target: { ...recipe.target, head: "HEAD~1" },
      });
      const rejected = run(value.request, dirname(git));
      expect(last(rejected).error).toBe(
        "Working-tree HEAD changed before the scan started.",
      );
      expect(phases(rejected, "now")).toEqual([]);
    }
  }
});
