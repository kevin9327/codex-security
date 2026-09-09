import { createHash } from "node:crypto";
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
import { PLUGIN_ROOT } from "./plugin-root";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type {
  Action,
  Request,
  Response,
} from "./support/finding-workflows-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-finding-workflows-")),
);
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!,
  git = Bun.which("git")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const id = "synthetic-workflow",
  scanId = "11111111-1111-4111-8111-111111111111",
  workspaceId = "22222222-2222-4222-8222-222222222222";
const stages = ["scan", "publish", "dedupe"] as const;
const review = {
  version: 1n,
  codexVersion: "synthetic-version",
  source: {
    repository: "/synthetic/repository",
    revision: "synthetic-revision",
    refsDigest: "synthetic-refs",
    content: "synthetic-content",
  },
  scope: { repositoryId: "synthetic-repository" },
  model: "synthetic-model",
  effort: "high",
  settingsDigest: "synthetic-settings",
  promptDigest: "synthetic-prompt",
  contractDigest: "synthetic-contract",
};
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/finding-workflows-fixture.ts", import.meta.url),
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
function run(requests: Request[], path = ""): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(requests, { compact: true }),
    encoding: "utf8",
    env: { ...process.env, PATH: path, PYTHON: "/unavailable/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
function workflow(
  action: string,
  payload: Record<string, unknown> = {},
): Action {
  return { operation: "workflow", payload: { id, action, ...payload } };
}
const sql = (text: string): Action => ({ operation: "sql", sql: text });
const commit: Action = { operation: "commit" };
const rollback: Action = { operation: "rollback" };
const state = (response: Response, index: number) =>
  (response.outcomes[index]!.value as { workflow: Record<string, unknown> })
    .workflow;
const stageState = (response: Response, index: number, stage: string) =>
  (state(response, index)["stages"] as Record<string, unknown>)[stage];
const stored = (response: Response) =>
  response.snapshot["finding_workflows"]![0] as Record<string, unknown>;
const seedScan: Action[] = [
  sql(
    `INSERT INTO workspaces(id,created_at,updated_at) VALUES ('${workspaceId}','created','updated')`,
  ),
  sql(
    `INSERT INTO scans(id,workspace_id,target_path,target_revision,scope,mode,scan_dir,status,phase,started_at,created_at,updated_at) VALUES ('${scanId}','${workspaceId}','/target','revision','.','standard','/scan','running','discovery','started','created','updated')`,
  ),
  commit,
];

test("resumes failed stages and keeps completed stage results immutable", () => {
  const responses = run(
    stages.map((stage) => ({
      actions: [
        workflow("get"),
        workflow("bind"),
        workflow("begin", { stage }),
        workflow("fail", { stage, error: "Synthetic failure" }),
        workflow("begin", { stage }),
        workflow("complete", { stage, result: { findingIds: [] } }),
        workflow("begin", { stage }),
        workflow("fail", { stage, error: "Late failure" }),
        workflow("complete", { stage, result: { changed: true } }),
        workflow("unknown", { stage }),
        workflow("get"),
      ],
    })),
  );
  responses.forEach((response, index) => {
    const stage = stages[index]!;
    expect(response.outcomes[0]!.value).toEqual({ workflow: null });
    expect(stageState(response, 3, stage)).toEqual({
      status: "failed",
      error: "Synthetic failure",
    });
    expect(stageState(response, 4, stage)).toEqual({
      status: "running",
      error: "Synthetic failure",
    });
    expect(stageState(response, 5, stage)).toEqual({
      status: "completed",
      result: { findingIds: [] },
    });
    for (const outcome of response.outcomes.slice(6))
      expect(outcome.value).toEqual(response.outcomes[5]!.value);
    expect(response.outcomes.every((outcome) => !outcome.inTransaction)).toBe(
      true,
    );
  });
});

test("retains pending dedupe publication across retries and clears it on completion", () => {
  const [response] = run([
    {
      actions: [
        workflow("bind"),
        workflow("begin", { stage: "dedupe" }),
        workflow("prepare-dedupe", {
          stage: "dedupe",
          result: { duplicateGroups: [["a", "b"]] },
          pendingWrite: { groups: [["a", "b"]] },
        }),
        workflow("fail", { stage: "dedupe", error: "Lost acknowledgement" }),
        workflow("begin", { stage: "dedupe" }),
        workflow("complete", { stage: "dedupe", result: null }),
        workflow("get"),
      ],
    },
  ]);
  expect(stageState(response!, 4, "dedupe")).toEqual({
    status: "running",
    error: "Lost acknowledgement",
    result: { duplicateGroups: [["a", "b"]] },
    pendingWrite: { groups: [["a", "b"]] },
  });
  expect(stageState(response!, 6, "dedupe")).toEqual({
    status: "completed",
    result: null,
  });
  expect(stored(response!)["results_json"]).toBe('{"dedupe": null}');
});

test("keeps bindings immutable, rolls back partial changes, and separates identities", () => {
  const bindings = [
    ["repositoryPath", "/synthetic/one", "/synthetic/two"],
    ["scanRequestDigest", "one", "two"],
    ["scanId", "one", "two"],
    ["scanDir", "/synthetic/one", "/synthetic/two"],
    ["artifactDigest", "one", "two"],
    ["destination", "https://synthetic.invalid/", "https://other.invalid/"],
    ["scope", { repositoryId: "one" }, { allRepositories: true }],
  ] as const;
  const responses = run(
    bindings.map(([field, first, second]) => ({
      actions: [
        workflow("bind", { binding: { [field]: first } }),
        workflow("bind", { binding: { [field]: first } }),
        workflow("bind", { binding: { [field]: second } }),
        workflow("bind", { binding: { scanId: "partial", unknown: true } }),
        workflow("get"),
        workflow("bind", { id: "separate", binding: { [field]: second } }),
        workflow("get"),
      ],
    })),
  );
  responses.forEach((response, index) => {
    const [field, first, second] = bindings[index]!;
    expect(response.outcomes[2]!.error).toBe(
      `Workflow ${id} is already bound to a different ${field}. Use another --workflow-id.`,
    );
    expect(response.outcomes[2]!.systemExit).toBe(true);
    expect(response.outcomes[2]!.inTransaction).toBe(false);
    expect(state(response, 4)[field]).toEqual(first);
    expect(state(response, 5)[field]).toEqual(second);
    expect(response.outcomes[6]!.value).toEqual(response.outcomes[0]!.value);
  });
});

test("preserves original creation time and JSON numeric types through persistence", () => {
  const [response] = run([
    {
      actions: [
        workflow("bind", { binding: { scope: { allRepositories: true } } }),
        {
          ...workflow("complete", {
            stage: "scan",
            result: { integer: 9007199254740993n, real: new JsonFloat("1.0") },
          }),
          timestamp: "2026-08-02T00:00:00Z",
        },
        workflow("get"),
      ],
    },
  ]);
  expect(stored(response!)).toMatchObject({
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-02T00:00:00Z",
    scope_all_repositories: 1n,
    results_json: '{"scan": {"integer": 9007199254740993, "real": 1.0}}',
  });
  expect(stageState(response!, 2, "scan")).toEqual({
    status: "completed",
    result: { integer: 9007199254740993n, real: new JsonFloat("1.0") },
  });
});

test("review checkpoints enforce ownership and keep the first persisted result", () => {
  const [response] = run([
    {
      actions: [
        workflow("save-review", { key: "review", binding: review, result: {} }),
        workflow("bind"),
        workflow("get-review", { key: "review" }),
        workflow("save-review", {
          key: "review",
          binding: review,
          result: { decision: "DISTINCT" },
        }),
        workflow("save-review", {
          key: "review",
          binding: { ...review, settingsDigest: "changed" },
          result: { changed: true },
        }),
        workflow("get-review", { key: "review" }),
        workflow("get-review", { id: "another", key: "review" }),
      ],
    },
  ]);
  expect(response!.outcomes[0]!.error).toBe("FOREIGN KEY constraint failed");
  expect(response!.outcomes[0]!.inTransaction).toBe(false);
  expect(response!.outcomes[2]!.value).toEqual({ review: null });
  expect(response!.outcomes[5]!.value).toEqual({
    review: { decision: "DISTINCT" },
  });
  expect(response!.outcomes[6]!.value).toEqual({ review: null });
  expect(response!.snapshot["finding_workflow_reviews"]).toHaveLength(1);
  expect(response!.snapshot["finding_workflow_reviews"]![0]).toMatchObject({
    source_repository_path: review.source.repository,
    settings_digest: review.settingsDigest,
    result_json: '{"decision": "DISTINCT"}',
  });
});

test("reads workflow and review JSON stored as UTF-8 or UTF-16 SQLite blobs", () => {
  const document = { title: "é🧭", count: 9007199254740993n };
  const responses = run(
    (["utf8", "utf16le"] as const).map((encoding) => {
      const blob = (value: unknown) =>
        Buffer.from(stringifyJson(value, { compact: true }), encoding).toString(
          "hex",
        );
      return {
        actions: [
          workflow("bind"),
          workflow("save-review", {
            key: "review",
            binding: review,
            result: {},
          }),
          sql(
            `UPDATE finding_workflows SET results_json = x'${blob({ scan: document })}'`,
          ),
          sql(
            `UPDATE finding_workflow_reviews SET result_json = x'${blob(document)}'`,
          ),
          commit,
          workflow("get"),
          workflow("get-review", { key: "review" }),
        ],
      };
    }),
  );
  for (const response of responses) {
    expect(stageState(response, 5, "scan")).toEqual({
      status: "pending",
      result: document,
    });
    expect(response.outcomes[6]!.value).toEqual({ review: document });
  }
});

test("registers replacement scans inside the caller transaction and rejects completed scans", () => {
  const responses = run(
    ["running", "failed", "complete"].map((status) => ({
      actions: [
        ...seedScan,
        workflow("bind"),
        { operation: "register", id, scanId, scanDir: "/scan" },
        commit,
        sql(`UPDATE scans SET status = '${status}'`),
        commit,
        { operation: "register", id, scanId: "new", scanDir: "/new" },
        workflow("get"),
        rollback,
        workflow("get"),
      ],
    })),
  );
  responses.forEach((response, index) => {
    const replacement = response.outcomes[8]!;
    if (index === 2) {
      expect(replacement.error).toBe(
        "Reuse the workflow's completed scan instead of registering another.",
      );
      expect(replacement.inTransaction).toBe(false);
    } else {
      expect(replacement.error).toBeUndefined();
      expect(replacement.inTransaction).toBe(true);
      expect(state(response, 9)["scanId"]).toBe("new");
    }
    expect(state(response, 11)["scanId"]).toBe(scanId);
  });
  const [missing, completed] = run([
    { actions: [{ operation: "register", id, scanId, scanDir: "/scan" }] },
    {
      actions: [
        workflow("bind"),
        workflow("complete", { stage: "scan", result: {} }),
        { operation: "register", id, scanId, scanDir: "/scan" },
      ],
    },
  ]);
  expect(missing!.outcomes[0]!.error).toBe(
    "The workflow must be started before registering its scan.",
  );
  expect(completed!.outcomes[2]!.error).toBe(
    "The workflow scan is already complete.",
  );
});

test("retains caller transactions on read and pretransaction failure but rolls back review failures", () => {
  const requests = [
    workflow("get"),
    workflow("bind"),
    workflow("save-review", {
      key: "review",
      binding: { source: {} },
      result: {},
    }),
    workflow("save-review", { key: "review", binding: review }),
  ].map(
    (action): Request => ({
      actions: [
        workflow("bind"),
        sql("UPDATE finding_workflows SET destination = 'pending'"),
        action,
        workflow("get"),
        rollback,
        workflow("get"),
      ],
    }),
  );
  const responses = run(requests);
  expect(
    responses.map((response) => response.outcomes[2]!.inTransaction),
  ).toEqual([true, true, true, false]);
  expect(responses[1]!.outcomes[2]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(responses[2]!.outcomes[2]!.error).toBe("'scope'");
  expect(responses[3]!.outcomes[2]!.error).toBe("'result'");
  for (const response of responses)
    expect(state(response, 5)["destination"]).toBeUndefined();
});

test("reports unsupported SQL parameters in order after implicit BEGIN and preserves earlier errors", () => {
  const parameters = [
    [{}, []],
    [[], {}],
    [9223372036854775808n, {}],
    [{}, 9223372036854775808n],
    ["\ud800", {}],
    [{}, "\ud800"],
  ];
  const responses = run(
    parameters.map((values) => ({
      actions: [
        sql("CREATE TABLE synthetic_bindings(first,second)"),
        {
          operation: "sql",
          sql: "INSERT INTO synthetic_bindings VALUES (?,?)",
          parameters: values as never[],
        },
        {
          operation: "query",
          sql: "SELECT count(*) AS count FROM synthetic_bindings",
        },
        rollback,
      ],
    })),
  );
  expect(responses.map((response) => response.outcomes[1]!.error)).toEqual([
    "Error binding parameter 1: type 'dict' is not supported",
    "Error binding parameter 1: type 'list' is not supported",
    "Python int too large to convert to SQLite INTEGER",
    "Error binding parameter 1: type 'dict' is not supported",
    "SQLite strings must be valid UTF-8",
    "Error binding parameter 1: type 'dict' is not supported",
  ]);
  for (const response of responses) {
    expect(response.outcomes[1]!.inTransaction).toBe(true);
    expect(response.outcomes[1]!.events).toEqual([
      ["query", "INSERT INTO synthetic_bindings VALUES (?,?)", false],
      ["transaction", "BEGIN", false],
    ]);
    expect(response.outcomes[2]!.value).toEqual([{ count: 0n }]);
    expect(response.outcomes[3]!.inTransaction).toBe(false);
  }
  const [failedPrepare] = run([
    {
      actions: [
        {
          operation: "sql",
          sql: "INSERT INTO missing VALUES (?)",
          parameters: [{} as never],
        },
      ],
    },
  ]);
  expect(failedPrepare!.outcomes[0]!.error).toBe("no such table: missing");
  expect(failedPrepare!.outcomes[0]!.inTransaction).toBe(false);
});

test("rolls back nonfinite results and retains scalar JSON errors without rewriting them", () => {
  const [response] = run([
    {
      actions: [
        workflow("bind"),
        workflow("complete", { stage: "scan", result: new JsonFloat("NaN") }),
        workflow("get"),
        sql("UPDATE finding_workflows SET results_json = 'null'"),
        commit,
        workflow("get"),
      ],
    },
  ]);
  expect(response!.outcomes[1]!.error).toBe(
    "Out of range float values are not JSON compliant: nan",
  );
  expect(response!.outcomes[1]!.inTransaction).toBe(false);
  expect(stageState(response!, 2, "scan")).toEqual({ status: "pending" });
  expect(response!.outcomes[5]!.error).toBe(
    "argument of type 'NoneType' is not iterable",
  );
});

test("resolves source aliases and hashes plain directories without Git or Python", () => {
  const directory = join(root, "plain");
  mkdirSync(directory);
  writeFileSync(join(directory, "file.txt"), "synthetic content\n");
  const alias = join(root, "plain-alias");
  symlinkSync(
    directory,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  const [response] = run([
    {
      actions: [
        workflow("source", { repository: directory }),
        workflow("source", { repository: alias }),
      ],
    },
  ]);
  const result = response!.outcomes[0]!.value as {
    source: Record<string, unknown>;
  };
  expect(result.source).toMatchObject({
    repository: directory,
    revision: "unversioned",
    refsDigest: createHash("sha256").update("").digest("hex"),
  });
  expect(result.source["content"]).toMatch(
    /^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/u,
  );
  expect(response!.outcomes[1]!.value).toEqual(result);
});

test("includes ignored files in source identity and reads real Git revision and refs", () => {
  const directory = join(root, "git");
  mkdirSync(directory);
  const gitCommand = (...args: string[]) => {
    const child = spawnSync(git, ["-C", directory, ...args], {
      encoding: "utf8",
    });
    expect(child.status, child.stderr).toBe(0);
    return child.stdout.trim();
  };
  gitCommand("init", "-q");
  writeFileSync(join(directory, ".gitignore"), "ignored.txt\n");
  writeFileSync(join(directory, "tracked.txt"), "tracked\n");
  writeFileSync(join(directory, "ignored.txt"), "before\n");
  gitCommand("add", ".");
  gitCommand(
    "-c",
    "user.name=Synthetic Author",
    "-c",
    "user.email=synthetic@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "Synthetic fixture",
  );
  const gitOnly = join(root, "git-only");
  mkdirSync(gitOnly);
  symlinkSync(
    git,
    join(gitOnly, process.platform === "win32" ? "git.exe" : "git"),
  );
  const request: Request = {
    actions: [workflow("source", { repository: directory })],
  };
  const [before] = run([request], gitOnly);
  writeFileSync(join(directory, "ignored.txt"), "after\n");
  const [after] = run([request], gitOnly);
  const initial = (
    before!.outcomes[0]!.value as { source: Record<string, unknown> }
  ).source;
  const changed = (
    after!.outcomes[0]!.value as { source: Record<string, unknown> }
  ).source;
  expect(initial).toMatchObject({
    repository: directory,
    revision: gitCommand("rev-parse", "HEAD"),
    refsDigest: createHash("sha256")
      .update(gitCommand("show-ref"))
      .digest("hex"),
  });
  expect(initial["content"]).not.toBe(changed["content"]);
  expect(initial["revision"]).toBe(changed["revision"]);
  expect(initial["refsDigest"]).toBe(changed["refsDigest"]);
});
