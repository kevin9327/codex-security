import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-scan-completion-fixture";
import { buildReportFixture } from "./support/build-report-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

type Table = Record<string, unknown>;
const scanId = "11111111-1111-4111-8111-111111111111";
const root = realpathSync(mkdtempSync(join(tmpdir(), "scan-completion-"))),
  fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const version = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const cost = stringifyJson(
  {
    model: "fixture",
    inputTokens: 10,
    cachedInputTokens: 2,
    cacheWriteInputTokens: 1,
    outputTokens: 3,
    estimatedUsd: 0.25,
  },
  { compact: true },
);
beforeAll(() => {
  buildReportFixture(node, {
    entryPoints: [
      fileURLToPath(
        new URL(
          "./support/workbench-scan-completion-fixture.ts",
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
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

function setup(actions: Action[] = [{ operation: "complete" }]): {
  request: Request;
  directory: string;
} {
  const directory = mkdtempSync(join(root, "case-")),
    scanDir = join(directory, "scan");
  mkdirSync(scanDir, { mode: 0o700 });
  const read = (name: string) =>
    parseJson(
      readFileSync(join(PLUGIN_ROOT, "examples/completed-scan", name), "utf8"),
    ) as Table;
  const manifest = read("scan-manifest.json"),
    scan = manifest["scan"] as Table;
  scan["id"] = scanId;
  Object.assign(scan["target"] as Table, {
    targetId: "target-id",
    displayName: "target",
    revision: "revision",
  });
  delete scan["sealedAt"];
  delete scan["artifacts"];
  const findings = read("findings.json"),
    coverage = read("coverage.json");
  findings["scanId"] = scanId;
  coverage["scanId"] = scanId;
  for (const finding of findings["findings"] as Table[])
    for (const key of ["findingId", "occurrenceId", "fingerprints"])
      delete finding[key];
  for (const [name, value] of [
    ["scan-manifest.json", manifest],
    ["findings.json", findings],
    ["coverage.json", coverage],
  ] as const)
    writeFileSync(join(scanDir, name), stringifyJson(value));
  return {
    directory: scanDir,
    request: {
      environment: {
        CODEX_SECURITY_STATE_DIR: join(directory, "state"),
        CODEX_STATE_DB: join(directory, "missing.sqlite"),
        CODEX_HOME: join(directory, "codex"),
        CODEX_SQLITE_HOME: join(directory, "sqlite"),
      },
      scan: {
        scan_dir: scanDir,
        target_path: "/target",
        target_id: "target-id",
        target_revision: "revision",
        target_snapshot_digest: null,
      },
      actions,
    },
  };
}
function run(request: Request): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const result = (parseJson(child.stdout) as unknown as Response[])[0]!;
  expect(result.node).toBe(version);
  return result;
}
const scan = (response: Response) => response.snapshot["scans"]![0]!;
const outcome = (response: Response, index = 0) => {
  expect(response.outcomes[index]!.error).toBeUndefined();
  return response.outcomes[index]!;
};

test("completion seals the draft and records findings, progress and measured usage", () => {
  const input = setup(),
    response = run(input.request);
  expect(outcome(response).inTransaction).toBe(false);
  expect(scan(response)).toMatchObject({
    status: "complete",
    phase: "reporting",
    completed_at: "2026-01-02T00:00:00Z",
  });
  expect(response.snapshot["scan_artifacts"]!.length).toBe(4);
  expect(response.snapshot["finding_occurrences"]!.length).toBeGreaterThan(0);
  expect(response.snapshot["scan_progress"]![0]!["phase_progress_unit"]).toBe(
    "report_artifacts",
  );
  expect(parseJson(scan(response)["cost_json"] as string)).toMatchObject({
    usage: { coverage: "unavailable", warnings: ["codex_state_unavailable"] },
  });
  const manifest = parseJson(
    readFileSync(join(input.directory, "scan-manifest.json"), "utf8"),
  ) as Table;
  expect((manifest["scan"] as Table)["sealedAt"]).toBe("2026-01-02T00:00:00Z");
  expect(scan(response)["seal_manifest_digest"]).toMatch(
    /^sha256:[0-9a-f]{64}$/u,
  );
});

test("prepare seals files while leaving status, usage and finding indexes for completion", () => {
  const input = setup([
    { operation: "complete", prepareOnly: true, costJson: "{" },
  ]);
  const response = run(input.request);
  outcome(response);
  expect(scan(response)["status"]).toBe("running");
  expect(scan(response)["cost_json"]).toBeNull();
  expect(response.snapshot["scan_artifacts"]).toEqual([]);
  expect(response.snapshot["finding_occurrences"]).toEqual([]);
  expect(
    readFileSync(join(input.directory, "scan-manifest.json"), "utf8"),
  ).toContain('"sealedAt"');
});

test("a prepared recipe completes and accepts later authoritative cost without duplicating findings", () => {
  const input = setup([
    { operation: "complete", prepareOnly: true },
    { operation: "complete" },
    { operation: "complete", costJson: cost },
  ]);
  input.request.scan!["recipe_json"] = '{"target":{"kind":"repository"}}';
  const response = run(input.request);
  for (let index = 0; index < 3; index++) outcome(response, index);
  expect(scan(response)["status"]).toBe("complete");
  expect(response.snapshot["scan_artifacts"]!.length).toBe(4);
  expect(parseJson(scan(response)["cost_json"] as string)).toMatchObject({
    usage: { coverage: "unavailable" },
    cost: { model: "fixture" },
  });
});

test("completion rejects stale continuation claims before changing the draft", () => {
  const input = setup(),
    path = join(input.directory, "scan-manifest.json"),
    original = readFileSync(path);
  Object.assign(input.request.scan!, {
    handoff_status: "pending",
    handoff_claim_token: "33333333-3333-4333-8333-333333333333",
  });
  const response = run(input.request);
  expect(response.outcomes[0]!.error).toBe(
    "Scan completion is owned by another continuation.",
  );
  expect(readFileSync(path)).toEqual(original);
  expect(scan(response)["status"]).toBe("running");
});

test("completion rechecks continuation ownership after sealing and rolls back its database writes", () => {
  const input = setup([
    {
      operation: "complete",
      beforeBeginSql:
        "UPDATE scans SET handoff_status='pending', handoff_claim_token='33333333-3333-4333-8333-333333333333'",
    },
  ]);
  const response = run(input.request);
  expect(response.outcomes[0]!.error).toBe(
    "Scan completion is owned by another continuation.",
  );
  expect(response.outcomes[0]!.inTransaction).toBe(false);
  expect(scan(response)["status"]).toBe("running");
  expect(response.snapshot["finding_occurrences"]).toEqual([]);
  expect(
    readFileSync(join(input.directory, "scan-manifest.json"), "utf8"),
  ).toContain('"sealedAt"');
});

test("an indexing error rolls back artifact and scan rows while retaining the finished files", () => {
  const input = setup();
  input.request.setupSql = [
    "CREATE TRIGGER rejected BEFORE INSERT ON finding_occurrences BEGIN SELECT RAISE(ABORT,'index rejected'); END",
  ];
  const response = run(input.request);
  expect(response.outcomes[0]!.error).toBe("index rejected");
  expect(scan(response)["status"]).toBe("running");
  expect(response.snapshot["scan_artifacts"]).toEqual([]);
  expect(response.snapshot["findings"]).toEqual([]);
  expect(
    readFileSync(join(input.directory, "report.md"), "utf8").length,
  ).toBeGreaterThan(0);
});

test("Deep completion requires successful discovery before reading or rewriting results", () => {
  const input = setup(),
    path = join(input.directory, "scan-manifest.json"),
    original = readFileSync(path);
  input.request.scan!["mode"] = "deep";
  const response = run(input.request);
  expect(response.outcomes[0]!.error).toBe(
    "Deep Scan discovery orchestration must finish and persist its manifest before the parent scan can be completed.",
  );
  expect(readFileSync(path)).toEqual(original);
});

test("an incomplete draft and missing recipe outputs remain retryable", () => {
  const incomplete = setup(),
    path = join(incomplete.directory, "scan-manifest.json"),
    manifest = parseJson(readFileSync(path, "utf8")) as Table;
  (manifest["scan"] as Table)["complete"] = false;
  writeFileSync(path, stringifyJson(manifest));
  expect(run(incomplete.request).outcomes[0]!.error).toBe(
    "The latest saved scan draft is incomplete; continue the scan before completing it.",
  );
  const missing = setup();
  missing.request.scan!["recipe_json"] = '{"target":{"kind":"repository"}}';
  rmSync(join(missing.directory, "findings.json"));
  const response = run(missing.request);
  expect(response.outcomes[0]!.error).toContain(
    "Scan agent did not create required draft artifacts: findings.json.",
  );
  expect(scan(response)["status"]).toBe("running");
});

test("completion preserves iteration of legacy stored warning values", () => {
  for (const value of ["{}", '"kept"', "null"]) {
    const input = setup();
    input.request.scan!["completion_warnings_json"] = value;
    const response = run(input.request);
    if (value === "null") {
      expect(response.outcomes[0]!.error).toBe(
        "'NoneType' object is not iterable",
      );
      expect(scan(response)["status"]).toBe("running");
    } else {
      outcome(response);
      expect(scan(response)["status"]).toBe("complete");
      expect(
        parseJson(scan(response)["completion_warnings_json"] as string),
      ).toEqual(parseJson(value));
    }
  }
});

function deepSetup(actions?: Action[]) {
  const input = setup(actions);
  input.request.scan!["mode"] = "deep";
  input.request.records = {
    deep_scan_runs: [
      {
        scan_id: scanId,
        schema_version: 1,
        workflow_version: "deep-security-scan/v1",
        phase: "terminal",
        workers: 4,
        subagents: 1,
        stop_after_no_new: 3,
        max_discovery_runs: 40,
        status: "succeeded",
        terminal_reason: "saturated",
        manifest_path: join(input.directory, "scan-manifest.json"),
        created_at: "created",
        updated_at: "updated",
      },
    ],
  };
  const path = join(input.directory, "coverage.json"),
    coverage = parseJson(readFileSync(path, "utf8")) as Table;
  coverage["mode"] = "deep_repository";
  coverage["surfaces"] = [];
  writeFileSync(path, stringifyJson(coverage));
  return input;
}

test("Deep completion retries report I/O failures and leaves exhausted drafts retryable", () => {
  for (const [deep, failures] of [
    [true, 2],
    [true, 5],
    [false, 2],
  ] as const) {
    const input = (deep ? deepSetup : setup)([
      {
        operation: "complete",
        reportFault: { remaining: failures, kind: "io" },
      },
    ]);
    writeFileSync(join(input.directory, "report.md"), "previous report\n");
    const names = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ],
      original = names.map((name) => readFileSync(join(input.directory, name))),
      response = run(input.request);
    expect(Number(response.outcomes[0]!.reportCalls)).toBe(
      deep ? Math.min(failures + 1, 5) : 1,
    );
    if (deep && failures < 5) {
      outcome(response);
      expect(scan(response)["status"]).toBe("complete");
      expect(response.snapshot["finding_occurrences"]!.length).toBeGreaterThan(
        0,
      );
      expect(
        readFileSync(join(input.directory, "report.md"), "utf8"),
      ).toContain("Unsafe archive extraction");
    } else {
      expect(response.outcomes[0]!.error).toBe(
        "report projection failed: [Errno 5] Input/output error",
      );
      expect(scan(response)["status"]).toBe("running");
      expect(response.snapshot["scan_artifacts"]).toEqual([]);
      expect(response.snapshot["finding_occurrences"]).toEqual([]);
      expect(
        names.map((name) => readFileSync(join(input.directory, name))),
      ).toEqual(original);
    }
  }
});

test("Deep completion preserves the authored aggregate despite stale and unusable worker drafts", () => {
  const input = deepSetup(),
    findingsPath = join(input.directory, "findings.json"),
    findings = parseJson(readFileSync(findingsPath, "utf8")) as Table,
    authored = (findings["findings"] as Table[])[0]!;
  authored["summary"] = "Authored aggregate retained after discovery.";
  writeFileSync(findingsPath, stringifyJson(findings));
  const coverage = parseJson(
    readFileSync(join(input.directory, "coverage.json"), "utf8"),
  );
  input.request.records!["deep_scan_workers"] = [
    "stale",
    "malformed",
    "missing",
  ].map((kind, index) => {
    const directory = join(input.directory, "workers", kind),
      result = join(directory, "result.json");
    mkdirSync(directory, { recursive: true });
    if (kind === "malformed") writeFileSync(result, "{unfinished draft");
    if (kind === "stale")
      writeFileSync(
        result,
        stringifyJson({
          scanId,
          complete: true,
          findings: [{ ...authored, summary: "Stale worker wording." }],
          coverage: {
            mode: "deep_repository",
            completeness: "partial",
            deferred: [{ id: "old", reason: "obsolete" }],
          },
        }),
      );
    return {
      id: `33333333-3333-4333-8333-${String(index + 1).padStart(12, "0")}`,
      scan_id: scanId,
      kind: "discovery",
      status: "succeeded",
      prompt_path: join(directory, "prompt.txt"),
      artifact_dir: directory,
      result_manifest_path: result,
      merge_state: "merged",
      created_at: "created",
      updated_at: "updated",
    };
  });
  const response = run(input.request);
  outcome(response);
  expect(scan(response)["status"]).toBe("complete");
  const published = parseJson(readFileSync(findingsPath, "utf8")) as Table;
  expect(
    (published["findings"] as Table[]).map((row) => row["summary"]),
  ).toEqual([authored["summary"]]);
  expect(
    parseJson(readFileSync(join(input.directory, "coverage.json"), "utf8")),
  ).toEqual(coverage);
  expect(readFileSync(join(input.directory, "report.md"), "utf8")).toContain(
    authored["summary"] as string,
  );
  expect(
    readFileSync(
      join(input.directory, "workers/malformed/result.json"),
      "utf8",
    ),
  ).toBe("{unfinished draft");
});
