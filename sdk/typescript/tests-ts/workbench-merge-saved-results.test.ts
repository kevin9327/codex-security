import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  SavedMergeBinding,
  SavedMergeOptions,
} from "../../../plugins/codex-security/mcp-app/src/workbench-merge-saved-results";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-results-fixture";

type Table = Record<string, unknown>;
const scanId = "11111111-1111-4111-8111-111111111111";
const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-merge-saved-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-results-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(...actions: Action[]): Table[] {
  const request: Request = { actions };
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const response = (parseJson(child.stdout) as unknown as Response[])[0]!;
  expect(response.node).toBe(nodeVersion);
  for (const outcome of response.outcomes) {
    expect(outcome.error).toBeUndefined();
    expect(outcome.events).toEqual([]);
    expect(outcome.inTransaction).toBe(false);
  }
  return response.outcomes.map((outcome) => outcome.result as Table);
}
function root(name: string): string {
  const path = join(directory, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}
function write(scan: string, path: string, value: unknown): void {
  mkdirSync(join(scan, path, ".."), { recursive: true });
  writeFileSync(join(scan, path), stringifyJson(value));
}
function encoded(value: unknown): string {
  return stringifyJson(value, {
    compact: true,
    sortKeys: true,
    separators: [",", ":"],
  });
}
const digest = (value: unknown) =>
  createHash("sha256").update(encoded(value)).digest("hex");
const binding: SavedMergeBinding = {
  status: "failed",
  allowedTargetKinds: ["directory_snapshot"],
  target: {
    targetId: "repo:synthetic",
    snapshotDigest: `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`,
  },
  scope: { includePaths: ["src"], excludePaths: [] },
  coverageMode: "scoped_path",
};
const finding = (path = "src/a.ts", severity = "medium"): Table => ({
  ruleId: "unsafe-write",
  identity: { anchor: "destination" },
  title: "Unchecked destination",
  summary: "The destination is unchecked.",
  severity: { level: severity },
  confidence: { level: "high", rationale: "Source trace" },
  taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
  locations: [{ path, startLine: 1n, endLine: 1n }],
  remediation: "Check the destination.",
  provenance: { source: "local_plugin" },
  extensions: { candidateId: "candidate" },
});
const draft = (
  findings: unknown[] = [],
  coverage: Table = {},
  complete = false,
): Table => ({
  scanId,
  findings,
  complete,
  coverage: {
    completeness: "complete",
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
    ...coverage,
  },
});
function checkpoint(
  scan: string,
  value: Table,
  directory = "checkpoints",
): string {
  const path = `${directory}/${digest(value)}.json`;
  write(scan, path, value);
  return path;
}
const worker = (scan: string, id = "worker", kind = "discovery") => ({
  id,
  kind,
  attempt: 1n,
  status: "succeeded",
  completed_at: "2026-01-01",
  artifact_dir: join(scan, "workers", id, "output"),
  result_manifest_path: join(scan, "workers", id, "output/result.json"),
});
const action = (
  scan: string,
  workers: Action["workers"] = [],
  options: Partial<SavedMergeOptions> = {},
): Action => ({
  operation: "savedMerge",
  directory: scan,
  workers,
  binding,
  mergeOptions: { stopped: true, reason: "Stopped by request.", ...options },
  warnings: [],
});
function merged(result: Table): [Table, Table, Table] {
  expect(result["error"]).toBeUndefined();
  return result["merged"] as [Table, Table, Table];
}
function parent(
  scan: string,
  findings: unknown[],
  coverage: Table = {},
  extra: Table = {},
): void {
  write(scan, "scan-manifest.json", {
    scan: {
      id: scanId,
      target: binding.target,
      scope: binding.scope,
      sealedAt: "sealed",
      ...extra,
    },
  });
  write(scan, "findings.json", { scanId, findings });
  write(scan, "coverage.json", draft([], coverage)["coverage"]);
}

test("saved finding identities retain source locations, historical order and cycles", () => {
  const base = finding();
  const [first, second, nullIdentity, history, cycle] = run(
    { operation: "savedFindingHelpers", value: base },
    { operation: "savedFindingHelpers", value: finding("src/b.ts") },
    {
      operation: "savedFindingHelpers",
      value: { title: "Fallback", identity: null },
    },
    {
      operation: "savedFindingHelpers",
      value: {
        title: "root",
        provenance: {
          previousFindings: [{ title: "previous" }],
          sourceFindings: [{ finding: { title: "source" } }],
        },
      },
    },
    {
      operation: "savedFindingHelpers",
      value: { title: "cycle" },
      cycle: true,
    },
  );
  expect(first!["key"]).not.toBe(second!["key"]);
  expect(first!["candidate"]).toEqual(second!["candidate"]);
  expect(nullIdentity!["identity"]).toBeNull();
  expect(nullIdentity!["candidate"]).toEqual([
    "worker",
    "candidate",
    null,
    null,
    null,
  ]);
  expect(history!["retained"]).toEqual(["root", "source", "previous"]);
  expect(cycle!["retained"]).toEqual(["cycle"]);
});

test("retained history traversal preserves ordering for large flat histories", () => {
  const previous = Array.from({ length: 200_000 }, (_, index) => ({
    title: String(index),
  }));
  const [result] = run({
    operation: "savedFindingHelpers",
    value: { title: "root", provenance: { previousFindings: previous } },
  });
  const retained = result!["retained"] as string[];
  expect(retained).toHaveLength(previous.length + 1);
  expect(retained.slice(0, 3)).toEqual(["root", "0", "1"]);
  expect(retained.at(-1)).toBe("199999");
});

test("stopped merges retain the stronger finding and superseded source evidence", () => {
  const scan = root("history"),
    older = finding("src/a.ts", "low"),
    latest = finding("src/a.ts", "critical");
  const earlier = draft([older]),
    current = draft([latest], {
      deferred: [{ candidateId: "candidate", reason: "Pending" }],
    });
  const oldPath = checkpoint(
    scan,
    earlier,
    "workers/worker/output/checkpoints",
  );
  write(scan, "workers/worker/output/result.json", current);
  const request = action(scan, [worker(scan)]),
    before = encoded(request);
  const result = run(request)[0]!,
    [manifest, document, coverage] = merged(result);
  const findings = document["findings"] as Table[];
  expect(findings).toHaveLength(1);
  expect(findings[0]!["severity"]).toEqual({ level: "critical" });
  expect((findings[0]!["provenance"] as Table)["previousFindings"]).toEqual([
    older,
  ]);
  expect((manifest["scan"] as Table)["preservedSources"]).toEqual({
    "workers/worker/output/result.json": digest(current),
    [oldPath]: digest(earlier),
  });
  expect(coverage["deferred"]).toEqual([
    { id: "scan-stopped", reason: "Stopped by request." },
  ]);
  expect(coverage["completeness"]).toBe("partial");
  expect(result["warnings"]).toEqual([]);
  expect(result["binding"]).toEqual(binding);
  expect(result["workers"]).toEqual(request.workers!);
  expect(result["options"]).toEqual(request.mergeOptions!);
  expect(encoded(request)).toBe(before);
});

test("independent locations retain distinct identities and scope warnings", () => {
  const scan = root("locations");
  write(scan, "workers/a/output/result.json", draft([finding()]));
  write(
    scan,
    "workers/b/output/result.json",
    draft([finding("src/b.ts"), finding("outside/c.ts")]),
  );
  const result = run(
      action(scan, [
        worker(scan, "a"),
        worker(scan, "b"),
        {
          ...worker(scan, "invalid"),
          result_manifest_path: join(scan, "invalid\0.json"),
        },
        {
          ...worker(scan, "unencodable"),
          result_manifest_path: join(scan, "\ud800.json"),
        },
      ]),
    )[0]!,
    [, document, coverage] = merged(result);
  const findings = document["findings"] as Table[];
  expect(findings).toHaveLength(2);
  expect(findings[0]!["identity"]).toEqual({ anchor: "destination" });
  expect((findings[1]!["identity"] as Table)["instance"]).toMatch(
    /^saved-[a-f0-9]{16}$/u,
  );
  expect((findings[1]!["provenance"] as Table)["preservedIdentity"]).toEqual({
    anchor: "destination",
  });
  expect(result["warnings"]).toEqual([
    "Skipped out-of-scope finding from workers/b/output/result.json.",
  ]);
  expect(coverage["completeness"]).toBe("partial");
});

test("a worker rejection preserves the matching sealed finding in coverage history", () => {
  const scan = root("rejection"),
    original = finding();
  original["provenance"] = { source: "local_plugin", workerId: "worker" };
  const canonical = {
    id: "canonical",
    label: "Existing coverage",
    disposition: "reported",
  };
  parent(scan, [original], { surfaces: [canonical] });
  write(
    scan,
    "workers/worker/output/result.json",
    draft([], {
      surfaces: [{ candidateId: "candidate", disposition: "rejected" }],
    }),
  );
  const result = run(action(scan, [worker(scan)]))[0]!,
    [manifest, document, coverage] = merged(result);
  expect(document["findings"]).toEqual([]);
  expect((manifest["scan"] as Table)["sealedAt"]).toBeUndefined();
  expect(coverage["surfaces"]).toEqual([
    canonical,
    {
      candidateId: "candidate",
      disposition: "rejected",
      previousFindings: [original],
      id: "candidate",
      receiptRefs: [],
    },
  ]);
});

test("committed archived reducers select the latest parent before discovery results", () => {
  const scan = root("reducer"),
    early = draft([finding()]),
    latest = draft([
      { ...finding(), identity: { anchor: "latest" }, title: "Latest" },
    ]);
  write(scan, "workers/reduce/output/result.json", early);
  checkpoint(scan, early, "workers/reduce/output/checkpoints");
  write(scan, "workers/reduce/attempts/attempt-٢/result.json", latest);
  checkpoint(scan, latest, "workers/reduce/attempts/attempt-٢/checkpoints");
  write(
    scan,
    "workers/worker/output/result.json",
    draft([
      { ...finding(), identity: { anchor: "worker" }, title: "Discovery" },
    ]),
  );
  const result = run(
      action(scan, [worker(scan, "reduce", "dedup"), worker(scan)]),
    )[0]!,
    [, document] = merged(result);
  expect(
    (document["findings"] as Table[]).map((value) => value["title"]),
  ).toEqual(["Latest", "Unchecked destination", "Discovery"]);
});

test("frozen failures preserve parent checkpoint writes and caller source maps", () => {
  const scan = root("frozen"),
    value = finding();
  parent(scan, [value], {}, { sealedAt: null });
  const request = action(scan, [], {
    frozenSourceDigests: { missing: "digest" },
    allowFrozenLegacyParent: true,
  });
  const result = run(request)[0]!;
  expect(result["error"]).toBe(
    "Frozen stopped-scan checkpoint set is incomplete.",
  );
  expect(result["options"]).toEqual(request.mergeOptions!);
  const [name] = readdirSync(join(scan, "checkpoints"));
  expect(name).toMatch(/^[a-f0-9]{64}\.json$/u);
  const bytes = readFileSync(join(scan, "checkpoints", name!));
  expect(createHash("sha256").update(bytes).digest("hex") + ".json").toBe(
    name!,
  );
  expect(bytes.toString("utf8")).toBe(encoded(parseJson(bytes)));
  const saved = parseJson(bytes) as Table;
  const checkpointPath = `checkpoints/${name}`;
  const changed = run(
    action(scan, [], { frozenSourceDigests: { [checkpointPath]: "changed" } }),
  )[0]!;
  expect(changed["error"]).toBe(
    "Frozen stopped-scan checkpoint set is incomplete.",
  );
  expect(changed["warnings"]).toEqual([
    `Preserved unreadable checkpoint ${checkpointPath}: checkpoint changed after the scan stopped`,
  ]);
  expect(saved["findings"]).toEqual([value]);
});

test("reducer drafts retain original hashes while recovery supplies missing coverage", () => {
  for (const archived of [false, true]) {
    for (const frozen of [false, true]) {
      const scan = root(`coverage-${archived}-${frozen}`);
      const reducer = {
        scanId,
        findings: [finding()],
        context: "Reducer context",
      };
      const output = archived
        ? "workers/reduce/attempts/attempt-2"
        : "workers/reduce/output";
      const resultPath = `${output}/result.json`;
      write(scan, resultPath, reducer);
      const sources = { [resultPath]: digest(reducer) };
      if (archived) {
        const saved = checkpoint(scan, reducer, `${output}/checkpoints`);
        sources[saved] = digest(reducer);
      }
      const request = action(
        scan,
        [
          {
            ...worker(scan, "reduce", "dedup"),
            ...(archived
              ? { status: "failed", result_manifest_path: null }
              : {}),
          },
        ],
        frozen ? { frozenSourceDigests: sources } : {},
      );
      const result = run(request)[0]!;
      const [manifest, document, coverage] = merged(result);
      expect(result["warnings"]).toEqual([]);
      expect((manifest["scan"] as Table)["preservedSources"]).toEqual(sources);
      expect(
        (document["findings"] as Table[]).map((value) => value["title"]),
      ).toEqual(["Unchecked destination"]);
      expect(coverage).toMatchObject({
        completeness: "partial",
        mode: "scoped_path",
        inventoryStrategy: "scoped_path",
        includePaths: ["src"],
        deferred: [{ id: "scan-stopped", reason: "Stopped by request." }],
      });
      expect(readFileSync(join(scan, resultPath), "utf8")).toBe(
        stringifyJson(reducer),
      );
      expect(reducer).not.toHaveProperty("coverage");
    }
  }
});
