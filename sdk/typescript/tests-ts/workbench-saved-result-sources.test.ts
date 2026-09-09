import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-results-fixture";
const scanId = "11111111-1111-4111-8111-111111111111";
const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-saved-sources-")),
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
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as unknown as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
const value = (response: Response, index = 0) =>
  response.outcomes[index]!.result;
function root(name: string) {
  const path = join(directory, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}
function write(root: string, relative: string, value: unknown) {
  const path = join(root, relative);
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, stringifyJson(value));
}
const checkpoint = `checkpoints/${"a".repeat(64)}.json`;
const draft = { scanId, findings: [], coverage: {}, note: "é🧭" };
const digest = createHash("sha256")
  .update(
    stringifyJson(draft, {
      compact: true,
      sortKeys: true,
      separators: [",", ":"],
    }),
  )
  .digest("hex");
const recovery: Action[] = [
  { operation: "savedChanged" },
  { operation: "savedRecovery" },
  { operation: "savedNeeded" },
];
const queries = (response: Response, index = 0) =>
  response.outcomes[index]!.events.filter(
    (event) => (event as unknown[])[0] === "query",
  );

test("saved source hashes retain compact ASCII JSON and numeric representation", () => {
  const [response] = run({
    actions: [
      {
        operation: "savedEncoded",
        valueJson: '{"é":"🧭","n":1.0,"i":9007199254740993,"10":1,"2":2}',
      },
      {
        operation: "savedDigests",
        value: { "source.json": "digest" },
        label: "Frozen",
      },
      {
        operation: "savedDigests",
        value: { "source.json": 1n },
        label: "Frozen",
      },
    ],
  });
  const text =
    '{"10":1,"2":2,"i":9007199254740993,"n":1.0,"\\u00e9":"\\ud83e\\udded"}';
  expect(value(response!)).toEqual({
    text,
    digest: createHash("sha256").update(text).digest("hex"),
  });
  expect(value(response!, 1)).toEqual({ "source.json": "digest" });
  expect(response!.outcomes[2]!.error).toBe(
    "Frozen source digests are malformed.",
  );
});

test("saved paths retain checkpoint order, Unicode attempts, duplicate paths and reducer precedence", () => {
  const scan = root("paths");
  write(scan, checkpoint, draft);
  if (process.platform !== "win32")
    write(scan, `checkpoints/${"b".repeat(64)}.json\n`, draft);
  const discovery = "workers/discovery/output",
    first = "workers/first/output",
    latest = "workers/latest/output";
  write(scan, `${discovery}/${checkpoint}`, draft);
  for (const name of ["attempt-2", "attempt-10", "attempt-٢"])
    mkdirSync(join(scan, "workers/discovery/attempts", name), {
      recursive: true,
    });
  const worker = (id: string, kind: string, output: string) => ({
    id,
    kind,
    status: "succeeded",
    completed_at: "same",
    artifact_dir: join(scan, output),
    result_manifest_path: join(scan, output, "result.json"),
  });
  const workers = [
    worker("first", "dedup", first),
    worker("discovery", "discovery", discovery),
    worker("latest", "dedup", latest),
  ];
  const [response] = run({
    actions: [
      { operation: "savedPaths", directory: scan, workers },
      { operation: "savedReducer", workers },
    ],
  });
  expect(value(response!)).toEqual([
    [checkpoint, null],
    [`${discovery}/result.json`, "discovery"],
    [`${discovery}/${checkpoint}`, "discovery"],
    ["workers/discovery/attempts/attempt-10/result.json", "discovery"],
    ["workers/discovery/attempts/attempt-2/result.json", "discovery"],
    ["workers/discovery/attempts/attempt-٢/result.json", "discovery"],
    [`${discovery}/result.json`, "discovery"],
    [`${latest}/result.json`, "dedup"],
  ]);
  expect(value(response!, 1)).toMatchObject({ id: "latest" });
  if (process.platform !== "win32") {
    symlinkSync(join(scan, "checkpoints"), join(scan, "alias"));
    expect(
      value(
        run({
          actions: [
            { operation: "savedChildren", directory: scan, relative: "alias" },
          ],
        })[0]!,
      ),
    ).toEqual([]);
  }
});

test("checkpoint and parent readers retain semantic validation and unsealed identity rules", () => {
  const scan = root("readers");
  write(scan, checkpoint, draft);
  write(scan, "scan-manifest.json", {
    scan: {
      id: "other",
      sealedAt: "",
      artifacts: {},
      scope: null,
      complete: false,
    },
  });
  write(scan, "findings.json", { scanId: "other", findings: [] });
  write(scan, "coverage.json", { scanId: "other" });
  const [response] = run({
    actions: [
      { operation: "savedRead", directory: scan, relative: checkpoint },
      { operation: "savedParent", directory: scan },
    ],
  });
  expect(value(response!)).toEqual([draft, digest]);
  expect((value(response!, 1) as unknown[])[1]).toEqual({
    scanId,
    findings: [],
    coverage: { scanId: "other" },
    scope: null,
    complete: false,
  });
  write(scan, "scan-manifest.json", {
    scan: { id: "other", sealedAt: "sealed" },
  });
  expect(
    run({ actions: [{ operation: "savedParent", directory: scan }] })[0]!
      .outcomes[0]!.error,
  ).toBe("Saved parent documents belong to a different scan");
  expect(
    run({
      actions: [
        { operation: "savedRead", directory: scan, relative: "../outside" },
      ],
    })[0]!.outcomes[0]!.error,
  ).toContain("Saved scan checkpoint");
});

test("frozen sources control availability and are validated with discovered worker kinds", () => {
  const scan = root("frozen");
  write(scan, checkpoint, draft);
  const request: Request = {
    scan: { scan_dir: scan, status: "failed" },
    actions: recovery,
  };
  const [discovered, empty, missing, changed, unchanged] = run(
    request,
    {
      ...request,
      scan: { ...request.scan, retained_source_digests_json: "{}" },
    },
    {
      ...request,
      scan: {
        ...request.scan,
        retained_source_digests_json: '{"missing.json":"digest"}',
      },
    },
    {
      ...request,
      scan: {
        ...request.scan,
        retained_source_digests_json: JSON.stringify({
          [checkpoint]: "different",
        }),
      },
    },
    { ...request, actions: [] },
  );
  expect(value(discovered!)).toBe(true);
  expect(value(discovered!, 1)).toEqual([{ [checkpoint]: digest }, true]);
  expect(value(empty!)).toBe(false);
  expect(value(empty!, 1)).toEqual([{ [checkpoint]: digest }, false]);
  expect(value(missing!)).toBe(true);
  expect(missing!.outcomes[1]!.error).toBe(
    "Frozen stopped-scan checkpoint set is incomplete.",
  );
  expect(changed!.outcomes[1]!.error).toBe(
    "checkpoint changed after the scan stopped",
  );
  expect(queries(missing!, 1)).toHaveLength(2);
  expect(queries(changed!, 1)).toHaveLength(2);
  expect(discovered!.snapshot).toEqual(unchanged!.snapshot);
});

test("published source maps preserve stopped-scan consistency and parent inclusion", () => {
  const scan = root("published");
  write(scan, checkpoint, draft);
  write(scan, "scan-manifest.json", {
    scan: { sealedAt: "sealed", preservedSources: { [checkpoint]: digest } },
  });
  const request: Request = {
    scan: { scan_dir: scan, status: "failed", seal_manifest_digest: "sealed" },
    actions: recovery,
  };
  const [published, conflict] = run(request, {
    ...request,
    scan: {
      ...request.scan,
      retained_source_digests_json: JSON.stringify({
        [checkpoint]: "different",
      }),
    },
  });
  expect(value(published!)).toBe(false);
  expect(value(published!, 1)).toEqual([{ [checkpoint]: digest }, false]);
  expect(value(conflict!)).toBe(false);
  expect(conflict!.outcomes[1]!.error).toBe(
    "Stopped scan sources changed after terminal publication.",
  );
  expect(queries(conflict!, 1)).toHaveLength(1);
  write(scan, "scan-manifest.json", {
    scan: { sealedAt: "sealed", preservedSources: {} },
  });
  const empty = run({
    ...request,
    scan: {
      ...request.scan,
      retained_source_digests_json: JSON.stringify({ [checkpoint]: digest }),
    },
  })[0]!;
  expect(value(empty)).toBe(true);
  expect(value(empty, 1)).toEqual([{ [checkpoint]: digest }, true]);
});

test("recovery short-circuits warnings and publication errors and preserves caller transactions", () => {
  const scan = root("eligibility");
  write(scan, checkpoint, draft);
  const [warning, canceled, publication, transaction, invalid] = run(
    {
      scan: {
        scan_dir: join(scan, "absent"),
        status: "failed",
        completion_warnings_json:
          '["Saved scan evidence remains on disk; result publication needs follow-up: retry"]',
      },
      actions: [{ operation: "savedNeeded" }],
    },
    {
      scan: {
        status: "failed",
        canceled_at: "canceled",
        completion_warnings_json: "invalid",
      },
      actions: [{ operation: "savedNeeded" }],
    },
    {
      scan: { status: "failed", scan_dir: join(scan, "absent") },
      records: {
        deep_scan_runs: [
          {
            scan_id: scanId,
            schema_version: 1n,
            workflow_version: "deep/v1",
            status: "failed",
            phase: "terminal",
            workers: 1n,
            subagents: 0n,
            stop_after_no_new: 1n,
            max_discovery_runs: 1n,
            created_at: "created",
            updated_at: "updated",
            publication_error_message: "publication failed",
          },
        ],
      },
      actions: [{ operation: "savedNeeded" }],
    },
    {
      scan: { status: "failed", scan_dir: scan },
      actions: [
        { operation: "sql", sql: "UPDATE scans SET status='running'" },
        { operation: "savedNeeded" },
        { operation: "rollback" },
        { operation: "savedNeeded" },
      ],
    },
    {
      scan: { status: "failed", completion_warnings_json: "null" },
      actions: [{ operation: "savedNeeded" }],
    },
  );
  expect(value(warning!)).toBe(true);
  expect(queries(warning!)).toHaveLength(1);
  expect(value(canceled!)).toBe(false);
  expect(queries(canceled!)).toHaveLength(1);
  expect(value(publication!)).toBe(true);
  expect(queries(publication!)).toHaveLength(2);
  expect(value(transaction!, 1)).toBe(false);
  expect(transaction!.outcomes[1]!.inTransaction).toBe(true);
  expect(value(transaction!, 3)).toBe(true);
  expect(transaction!.outcomes[3]!.inTransaction).toBe(false);
  expect(invalid!.outcomes[0]!.error).toBe("'NoneType' object is not iterable");
  expect(queries(invalid!)).toHaveLength(1);
});

test("recovery accepts reducer findings without coverage and hashes the unchanged document", () => {
  const scan = root("reducer-without-coverage");
  const relative = "workers/reducer/output/result.json";
  const result = { scanId, findings: [], context: "Reducer context" };
  write(scan, relative, result);
  const expected = createHash("sha256")
    .update(
      stringifyJson(result, {
        compact: true,
        sortKeys: true,
        separators: [",", ":"],
      }),
    )
    .digest("hex");
  const worker = (kind: string) => ({
    id: "reducer",
    scan_id: scanId,
    kind,
    status: "succeeded",
    artifact_dir: join(scan, "workers/reducer/output"),
    result_manifest_path: join(scan, relative),
    prompt_path: "/prompt",
    completed_at: "completed",
    created_at: "created",
    updated_at: "updated",
  });
  const request: Request = {
    scan: { scan_dir: scan, status: "failed" },
    records: { deep_scan_workers: [worker("dedup")] },
    actions: [
      { operation: "savedRead", directory: scan, relative, kind: "dedup" },
      ...recovery,
    ],
  };
  const [reducer, discovery, frozen] = run(
    request,
    {
      ...request,
      records: { deep_scan_workers: [worker("discovery")] },
      actions: recovery,
    },
    {
      ...request,
      scan: {
        ...request.scan,
        retained_source_digests_json: JSON.stringify({ [relative]: expected }),
      },
    },
  );
  expect(value(reducer!)).toEqual([result, expected]);
  expect(value(reducer!, 1)).toBe(true);
  expect(value(reducer!, 2)).toEqual([{ [relative]: expected }, true]);
  expect(value(reducer!, 3)).toBe(true);
  expect(value(discovery!)).toBe(false);
  expect(value(discovery!, 1)).toEqual([{}, true]);
  expect(value(frozen!, 2)).toEqual([{ [relative]: expected }, false]);
  write(scan, relative, { ...result, coverage: null });
  expect(run(request)[0]!.outcomes[0]!.error).toBe(
    "checkpoint has no semantic findings or coverage",
  );
});
