import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/completion-binding-fixture";

type Table = Record<string, unknown>;
const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "completion-binding-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/completion-binding-fixture.ts", import.meta.url),
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
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/missing/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
const request = (
  operation: Request["operation"],
  payload: Table,
  options: Omit<Request, "operation" | "source"> = {},
): Request => ({ operation, source: JSON.stringify(payload), ...options });
function after(response: Response): Table {
  expect(response.error).toBeUndefined();
  return JSON.parse(response.after) as Table;
}
const binding = {
  scanId: "owned-scan",
  startedAt: "2026-01-01T00:00:00Z",
  completedAt: "2026-01-01T00:01:00Z",
  producer: { name: "synthetic", version: "1", custom: { values: [1] } },
  target: {
    targetId: "owned-target",
    snapshotDigest: "sha256:owned",
    remote: "https://example.test/repo",
  },
  scope: { includePaths: ["src"], excludePaths: ["vendor"] },
  coverageMode: "repository",
  allowedTargetKinds: ["git_worktree"],
  status: "interrupted",
};
function documents(): Table {
  return {
    manifest: {
      documentType: "draft",
      scan: {
        id: "draft",
        status: "draft",
        findingsRef: "other.json",
        coverageRef: "other.json",
        target: {
          kind: "git_worktree",
          targetId: "draft",
          revision: "old",
          baseRevision: "old",
          headRevision: "old",
          snapshotDigest: "old",
          displayName: "keep",
        },
        scope: { includePaths: ["draft"], excludePaths: [], note: "keep" },
      },
    },
    findings: { findings: [] },
    coverage: { mode: "draft", includePaths: ["draft"], excludePaths: [] },
    binding,
  };
}

test("completion fills workbench-owned fields while retaining draft choices and metadata", () => {
  const result = run([request("complete", documents())])[0]!;
  const output = after(result),
    manifest = output["manifest"] as Table,
    scan = manifest["scan"] as Table;
  expect(manifest["documentType"]).toBe("codex-security.scan-manifest");
  expect(scan).toMatchObject({
    id: "owned-scan",
    status: "interrupted",
    findingsRef: "findings.json",
    coverageRef: "coverage.json",
  });
  expect(scan["target"]).toEqual({
    kind: "git_worktree",
    ...binding.target,
    displayName: "keep",
  });
  expect(scan["scope"]).toEqual({ ...binding.scope, note: "keep" });
  expect(output["coverage"]).toMatchObject({
    documentType: "codex-security.coverage",
    schemaVersion: "1.0",
    scanId: "owned-scan",
    mode: "repository",
    ...binding.scope,
  });
  expect(result.events).toEqual([]);
});

test("bound producer, target, scope and coverage copies do not share mutable input", () => {
  const result = run([
    request("complete", documents(), {
      mutations: [
        {
          path: ["manifest", "scan", "producer", "custom", "values", 0],
          value: 2,
        },
        { path: ["manifest", "scan", "target", "remote"], value: "changed" },
        { path: ["coverage", "includePaths", 0], value: "changed" },
      ],
    }),
  ])[0]!;
  const output = after(result),
    scan = (output["manifest"] as Table)["scan"] as Table;
  expect(output["binding"]).toEqual(binding);
  expect(scan["scope"]).toEqual({ ...binding.scope, note: "keep" });
});

test("target coordinate cleanup retains only required draft coordinates and explicit binding values", () => {
  const cases = [
    "git_revision",
    "git_worktree",
    "git_diff",
    "directory_snapshot",
    "other",
  ].map((kind) =>
    request("target", {
      target: {
        kind,
        revision: "r",
        snapshotDigest: "s",
        baseRevision: "b",
        headRevision: "h",
      },
      binding: { targetId: "owned" },
    }),
  );
  const results = run(cases)
    .map(after)
    .map((value) => value["target"]);
  expect(results).toEqual([
    { kind: "git_revision", revision: "r", targetId: "owned" },
    ...["git_worktree", "git_diff", "directory_snapshot"].map((kind) => ({
      kind,
      snapshotDigest: "s",
      targetId: "owned",
    })),
    { kind: "other", targetId: "owned" },
  ]);
  const ordered = run([
    {
      operation: "target",
      source: '{"target":{"z":0,"2":0},"binding":{"1":1,"3":3}}',
    },
  ])[0]!;
  after(ordered);
  expect(ordered.after.indexOf('"2": 0')).toBeLessThan(
    ordered.after.indexOf('"1": 1'),
  );
  expect(ordered.after.indexOf('"1": 1')).toBeLessThan(
    ordered.after.indexOf('"3": 3'),
  );
});

test("unbound completion reads the start time only when present and preserves clock failure mutations", () => {
  const payload = {
    manifest: { scan: { startedAt: "draft", completedAt: "draft" } },
    binding: null,
  };
  const results = run([
    request("manifest", payload),
    request("manifest", payload, { startedAt: "2026-01-01T00:00:00Z" }),
    request("manifest", payload, { startedAt: "invalid", failClock: true }),
    request("manifest", payload, {
      startedAt: "2026-01-01T00:00:00Z",
      failClock: true,
    }),
    request("manifest", payload, {
      startedAt: "2026-01-01T00:00:00Z",
      microseconds: "0",
    }),
  ]);
  expect(
    ((after(results[0]!)["manifest"] as Table)["scan"] as Table)["completedAt"],
  ).toBe("draft");
  expect(
    ((after(results[1]!)["manifest"] as Table)["scan"] as Table)["completedAt"],
  ).toBe("2026-01-01T00:00:00.123456Z");
  expect(results[0]!.events).toEqual([]);
  expect(results[1]!.events).toEqual(["clock"]);
  expect(results[2]!.error).toBe(
    "CODEX_SECURITY_STARTED_AT: expected an RFC 3339 timestamp",
  );
  expect(results[2]!.events).toEqual([]);
  expect(results[3]!.error).toBe("synthetic clock failure");
  const failed = JSON.parse(results[3]!.after) as { manifest: { scan: Table } };
  expect(failed.manifest.scan["startedAt"]).toBe("2026-01-01T00:00:00Z");
  expect(failed.manifest.scan["completedAt"]).toBe("draft");
  expect(
    ((after(results[4]!)["manifest"] as Table)["scan"] as Table)["completedAt"],
  ).toBe("1970-01-01T00:00:00Z");
});

test("completion validation reports the first mismatched owner without changing documents", () => {
  const completed = after(run([request("complete", documents())])[0]!);
  const cases = [
    {
      path: ["manifest", "scan", "id"],
      error: "manifest.scan.id: must match the workbench scan",
    },
    {
      path: ["manifest", "scan", "status"],
      error: "manifest.scan.status: must match the workbench outcome",
    },
    {
      path: ["manifest", "scan", "target", "kind"],
      error: "scan.target.kind: must match the workbench target",
    },
    {
      path: ["findings", "scanId"],
      error: "findings.scanId: must match the workbench scan",
    },
    {
      path: ["coverage", "mode"],
      error: "coverage.mode: must match the workbench scan",
    },
  ];
  const requests = cases.map(({ path }) => {
    const copy = structuredClone(completed);
    let parent = copy;
    for (const key of path.slice(0, -1)) parent = parent[key] as Table;
    parent[path.at(-1)!] = "wrong";
    return request("validate", copy);
  });
  const results = run(requests);
  expect(results.map((result) => result.error)).toEqual(
    cases.map((item) => item.error),
  );
  expect(results.map((result) => JSON.parse(result.after))).toEqual(
    requests.map((item) => JSON.parse(item.source)),
  );
});

test("open-question and inventory normalization preserve supported optional fields", () => {
  const results = run([
    request("questions", {
      coverage: {
        openQuestions: [
          " \u0085 ",
          "  question  ",
          null,
          {
            question: " \u001c detail ",
            followUpPrompt: " follow up ",
            custom: 1,
          },
          { question: "next", followUpPrompt: " " },
        ],
      },
    }),
    request("questions", { coverage: { openQuestions: "invalid", keep: 1 } }),
    request("strategy", {
      coverage: { inventoryStrategy: "deep_repository_repeated_discovery" },
      expected: "deep_repository",
    }),
    request("strategy", {
      coverage: { inventoryStrategy: "deep_repository_repeated_discovery" },
      expected: "repository",
    }),
  ]).map(after);
  expect(results[0]!["coverage"]).toEqual({
    openQuestions: [
      { question: "question" },
      { question: "detail", followUpPrompt: " follow up ", custom: 1 },
      { question: "next" },
    ],
  });
  expect(results[1]!["coverage"]).toEqual({ keep: 1 });
  expect(results[2]!["coverage"]).toEqual({ inventoryStrategy: "repository" });
  expect(results[3]!["coverage"]).toEqual({
    inventoryStrategy: "deep_repository_repeated_discovery",
  });
});

test("selected Deep scans use repository inventory for missing or authored labels", () => {
  const coverage = [
    {},
    { inventoryStrategy: null },
    { inventoryStrategy: "unknown" },
    { inventoryStrategy: [] },
    { inventoryStrategy: "deep_repository_repeated_discovery" },
  ];
  for (const expected of ["deep_repository", "repository", null]) {
    const results = run(
      coverage.map((row) =>
        request("strategy", { coverage: { ...row, keep: true }, expected }),
      ),
    ).map(after);
    expect(results.map((row) => row["coverage"])).toEqual(
      coverage.map((row) => ({
        ...row,
        keep: true,
        ...(expected === "deep_repository"
          ? { inventoryStrategy: "repository" }
          : {}),
      })),
    );
  }
});
