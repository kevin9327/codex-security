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
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Request, Response } from "./support/workbench-scan-usage-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(mkdtempSync(join(tmpdir(), "scan-usage-"))),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-scan-usage-fixture.ts", import.meta.url),
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
function request(): Request {
  const path = mkdtempSync(join(root, "case-"));
  return {
    environment: {
      CODEX_STATE_DB: join(path, "state.sqlite"),
      CODEX_HOME: join(path, "home"),
      CODEX_SQLITE_HOME: join(path, "sqlite"),
    },
    actions: [{ operation: "collect" }],
    state: { path: join(path, "state.sqlite"), threads: [] },
  };
}
function run(input: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([input]),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const result = (parseJson(child.stdout) as unknown as Response[])[0]!;
  expect(result.node).toBe(nodeVersion);
  return result;
}
const value = (result: Response, index = 0) => {
  expect(result.outcomes[index]!.error).toBeUndefined();
  return result.outcomes[index]!.value as Record<string, unknown>;
};
function meta(id: string, parent?: string) {
  return {
    type: "session_meta",
    payload: {
      id,
      source: parent
        ? { subagent: { thread_spawn: { parent_thread_id: parent } } }
        : "cli",
    },
  };
}
function event(type: string, timestamp = "2026-01-01T00:01:00Z", fields = {}) {
  return { type: "event_msg", timestamp, payload: { type, ...fields } };
}
function tokens(
  input: bigint | number,
  output: bigint | number,
  timestamp?: string,
  extra = {},
) {
  return event("token_count", timestamp, {
    info: {
      total_token_usage: {
        input_tokens: input,
        output_tokens: output,
        total_tokens: BigInt(input) + BigInt(output),
        ...extra,
      },
    },
  });
}
const task = (timestamp?: string, turn = "turn") =>
  event("task_started", timestamp, { turn_id: turn });
function rollout(
  input: Request,
  id: string,
  events: unknown[],
  suffix = "",
): string {
  const path = join(
    input.environment["CODEX_HOME"]! + "-rollouts",
    id + ".jsonl",
  );
  mkdirSync(input.environment["CODEX_HOME"]! + "-rollouts", {
    recursive: true,
  });
  writeFileSync(
    path,
    events.map((entry) => stringifyJson(entry, { compact: true })).join("\n") +
      "\n" +
      suffix,
  );
  input.state!.threads.push([id, path]);
  return path;
}

test("usage attributes descendants after their own task boundary and avoids duplicate roots", () => {
  const input = request();
  input.scan = { mode: "deep", continuation_thread_id: "root" };
  input.workers = ["child", "child", "grandchild"];
  rollout(input, "root", [meta("root"), tokens(100, 10)]);
  rollout(input, "child", [
    meta("child", "root"),
    tokens(100, 10),
    task(),
    tokens(150, 15),
  ]);
  rollout(input, "grandchild", [
    meta("grandchild", "child"),
    task(),
    tokens(20, 2),
  ]);
  input.state!.edges = [
    ["root", "child"],
    ["child", "grandchild"],
  ];
  expect(value(run(input))).toMatchObject({
    coverage: "complete",
    inputTokens: 170n,
    outputTokens: 17n,
    totalTokens: 187n,
    threadCount: 3n,
  });
});

test("window filtering keeps the previous counter and counts resets and zero totals correctly", () => {
  const input = request();
  rollout(input, "root", [
    meta("root"),
    tokens(100, 10, "2025-12-31T23:59:00Z"),
    tokens(150, 15),
    tokens(20, 2),
    tokens(20, 2),
    tokens(1000, 100, "2026-01-01T00:11:00Z"),
  ]);
  expect(value(run(input))).toMatchObject({
    coverage: "complete",
    inputTokens: 70n,
    outputTokens: 7n,
    totalTokens: 77n,
  });
});

test("cache tokens retain legacy fallback, integer precision, and strict token types", () => {
  const input = request();
  const large = 9007199254740993n;
  rollout(input, "root", [
    meta("root"),
    tokens(large, 5n, undefined, {
      cached_input_tokens: 3n,
      cache_write_input_tokens: 0n,
      cache_write_tokens: 7n,
      reasoning_output_tokens: 2n,
    }),
  ]);
  expect(value(run(input))).toMatchObject({
    inputTokens: large,
    cachedInputTokens: 3n,
    cacheWriteInputTokens: 7n,
    reasoningOutputTokens: 2n,
    totalTokens: large + 5n,
  });
  const invalid = request();
  rollout(invalid, "root", [
    meta("root"),
    tokens(10, 1, undefined, { input_tokens: new JsonFloat("10.0") }),
    tokens(10, 1, undefined, {
      cached_input_tokens: 8,
      cache_write_tokens: 8,
      cache_write_input_tokens: 8,
    }),
    tokens(20, 2),
  ]);
  expect(value(run(invalid))).toMatchObject({
    coverage: "partial",
    inputTokens: 20n,
    totalTokens: 22n,
    warnings: ["token_record_invalid"],
  });
});

test("usage excludes an older worker and all descendants without marking them missing", () => {
  const input = request();
  rollout(input, "root", [meta("root"), tokens(10, 1)]);
  rollout(input, "old", [
    meta("old", "root"),
    task("2025-12-31T23:59:00Z"),
    tokens(1000, 100),
  ]);
  rollout(input, "child", [meta("child", "old"), task(), tokens(1000, 100)]);
  input.state!.edges = [
    ["root", "old"],
    ["old", "child"],
  ];
  expect(value(run(input))).toMatchObject({
    coverage: "complete",
    threadCount: 1n,
    totalTokens: 11n,
  });
});

test("missing parents, identity failures, and cycles produce partial attributable totals", () => {
  const input = request();
  rollout(input, "root", [meta("root"), tokens(10, 1)]);
  rollout(input, "mismatch", [
    meta("different", "root"),
    task(),
    tokens(1000, 100),
  ]);
  rollout(input, "orphan", [
    meta("orphan", "missing"),
    task(),
    tokens(1000, 100),
  ]);
  input.state!.edges = [
    ["root", "mismatch"],
    ["root", "missing"],
    ["missing", "orphan"],
    ["root", "root"],
  ];
  expect(value(run(input))).toMatchObject({
    coverage: "partial",
    threadCount: 1n,
    totalTokens: 11n,
    missingThreadCount: 4n,
    warnings: [
      "rollout_unavailable",
      "thread_identity_mismatch",
      "thread_lineage_cycle",
      "thread_lineage_incomplete",
    ],
  });
});

test("incomplete and invalid records add warnings only at the original ownership boundary", () => {
  const input = request();
  rollout(
    input,
    "root",
    [meta("root"), tokens(10, 1), null, event("token_count", "invalid", {})],
    "{unfinished",
  );
  expect(value(run(input))).toMatchObject({
    coverage: "partial",
    totalTokens: 11n,
    warnings: [
      "rollout_record_incomplete",
      "rollout_record_invalid",
      "token_record_invalid",
    ],
  });
  const bad = request();
  const path = rollout(bad, "root", []);
  writeFileSync(path, Buffer.from([255, 10]));
  expect(value(run(bad))).toEqual({
    coverage: "unavailable",
    source: "codex_rollout",
    threadCount: 0n,
    warnings: ["rollout_unavailable", "scan_thread_unavailable"],
  });
});

test("UUIDv7 ownership skips inherited turns until a turn belonging to the new thread", () => {
  const input = request(),
    id = "019a0000-0002-7000-8000-000000000000";
  input.workspaceThread = id;
  rollout(input, id, [
    meta(id, "parent"),
    task(undefined, "019a0000-0001-7000-8000-000000000000"),
    tokens(100, 10),
    task(undefined, "019a0000-0003-7000-8000-000000000000"),
    tokens(125, 15),
  ]);
  expect(value(run(input))).toMatchObject({
    coverage: "complete",
    threadCount: 1n,
    inputTokens: 25n,
    outputTokens: 5n,
  });
});

test("UUIDv7 ownership compares turns within the same millisecond", () => {
  const input = request(),
    id = "019a0000-0002-7001-8000-000000000002";
  input.workspaceThread = id;
  rollout(input, id, [
    meta(id, "parent"),
    task(undefined, "019a0000-0002-7001-8000-000000000001"),
    tokens(100, 10),
    task(undefined, "019a0000-0002-7001-8000-000000000003"),
    tokens(125, 15),
  ]);
  expect(value(run(input))).toMatchObject({
    coverage: "complete",
    threadCount: 1n,
    inputTokens: 25n,
    outputTokens: 5n,
  });
});

test("usage reports an unavailable rollout when its path is a symlink loop", () => {
  const input = request(),
    path = join(input.environment["CODEX_HOME"]! + "-loop");
  symlinkSync(path, path, "file");
  input.state!.threads = [["root", path]];
  expect(value(run(input))).toMatchObject({
    coverage: "unavailable",
    warnings: ["rollout_unavailable", "scan_thread_unavailable"],
  });
});

test("usage rejects an aliased rollout path and accepts its canonical file", () => {
  const input = request(),
    path = rollout(input, "root", [meta("root"), tokens(10, 1)]),
    alias = path + ".alias";
  symlinkSync(path, alias, "file");
  input.state!.threads = [["root", alias]];
  expect(value(run(input))).toMatchObject({
    coverage: "unavailable",
    warnings: ["rollout_unavailable", "scan_thread_unavailable"],
  });
});

test("unavailable roots, state, and scan windows report the original reason", () => {
  const inputs = [request(), request(), request()];
  inputs[0]!.workspaceThread = null;
  delete inputs[1]!.state;
  rollout(inputs[2]!, "root", [meta("root"), tokens(10, 1)]);
  inputs[2]!.scan = { started_at: "2026-01-01T00:00:00" };
  for (const [index, reason] of [
    "scan_thread_unavailable",
    "codex_state_unavailable",
    "scan_window_unavailable",
  ].entries())
    expect(value(run(inputs[index]!))["warnings"]).toEqual([reason]);
});

test("state discovery chooses the newest numeric version in the first configured root", () => {
  const input = request();
  rollout(input, "root", [meta("root"), tokens(10, 1)]);
  mkdirSync(input.environment["CODEX_SQLITE_HOME"]!);
  writeFileSync(
    join(input.environment["CODEX_SQLITE_HOME"]!, "state_2.sqlite"),
    "not sqlite",
  );
  input.state!.path = join(
    input.environment["CODEX_SQLITE_HOME"]!,
    "state_10.sqlite",
  );
  input.environment["CODEX_STATE_DB"] = "";
  expect(value(run(input))).toMatchObject({
    coverage: "complete",
    totalTokens: 11n,
  });
});

test("cost reconciliation retains measured usage and original JSON field order", () => {
  const input = request();
  delete input.state;
  input.scan = {
    cost_json:
      '{"2":"second","1":"first","usage":{"totalTokens":123},"cost":{"old":1}}',
  };
  input.actions = [
    { operation: "reconcile", costJson: '{"estimatedUsd":1.25}' },
  ];
  const result = run(input);
  expect(result.outcomes[0]).toEqual({ value: null, inTransaction: false });
  expect(result.rows[0]!["cost_json"]).toBe(
    '{"2":"second","1":"first","usage":{"totalTokens":123},"cost":{"estimatedUsd":1.25}}',
  );
  const legacy = request();
  delete legacy.state;
  legacy.actions = [
    { operation: "reconcile", costJson: ' { "estimatedUsd" : 2 } ' },
  ];
  expect(run(legacy).rows[0]!["cost_json"]).toBe(' { "estimatedUsd" : 2 } ');
});

test("cost reconciliation preserves the caller transaction when BEGIN fails and rolls back update errors", () => {
  const occupied = request();
  delete occupied.state;
  occupied.actions = [
    { operation: "sql", sql: "UPDATE scans SET cost_json='{}'" },
    { operation: "reconcile", costJson: "{}" },
    { operation: "rollback" },
  ];
  const result = run(occupied);
  expect(result.outcomes[1]!.error).toBe(
    "cannot start a transaction within a transaction",
  );
  expect(result.outcomes[1]!.inTransaction).toBe(true);
  expect(result.rows[0]!["cost_json"]).toBeNull();
  const rejected = request();
  delete rejected.state;
  rejected.setupSql = [
    "CREATE TRIGGER rejected BEFORE UPDATE ON scans BEGIN SELECT RAISE(ABORT,'rejected'); END",
  ];
  rejected.actions = [{ operation: "reconcile", costJson: "{}" }];
  const failure = run(rejected);
  expect(failure.outcomes[0]).toEqual({
    error: "rejected",
    inTransaction: false,
  });
  expect(failure.rows[0]!["cost_json"]).toBeNull();
});

test.skipIf(process.platform !== "darwin")(
  "usage accepts macOS system rollout aliases",
  () => {
    for (const temporaryRoot of [
      tmpdir().replace(/^\/private(?=\/var\/)/u, ""),
      "/tmp",
    ]) {
      const directory = mkdtempSync(join(temporaryRoot, "scan-usage-alias-"));
      try {
        const input = request();
        input.environment["CODEX_HOME"] = join(directory, "codex");
        const path = rollout(input, "root", [meta("root"), tokens(10, 3)]);
        expect(realpathSync(path)).toBe("/private" + path);
        expect(value(run(input))).toMatchObject({
          coverage: "complete",
          threadCount: 1n,
          totalTokens: 13n,
        });
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    }
  },
);
