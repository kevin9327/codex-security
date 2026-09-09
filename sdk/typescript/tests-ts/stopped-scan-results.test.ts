import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, afterEach, expect, test } from "bun:test";
import { buildSync } from "esbuild";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

const bundleRoot = mkdtempSync(join(tmpdir(), "stopped-result-bundle-"));
const fixture = join(bundleRoot, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/stopped-result-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(bundleRoot, { recursive: true, force: true }));
function runProbe(root: string, source: string, terminalStatus?: string) {
  return spawnSync(
    node,
    [
      fixture,
      PLUGIN_ROOT,
      root,
      source,
      ...(terminalStatus ? [terminalStatus] : []),
    ],
    {
      encoding: "utf8",
      env: { ...process.env, PYTHON: "/unavailable/python" },
    },
  );
}

test.each(["accepted", "checkpoint"] as const)(
  "preserves %s Deep findings when the scan stops",
  (source) => {
    const root = mkdtempSync(join(tmpdir(), "codex-security-stopped-scan-"));
    temporaryDirectories.push(root);
    const result = runProbe(root, source);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      findingCount: 1,
      progressStatus: "failed",
      artifactFindingCount: 1,
    });
  },
  30_000,
);

test("keeps refined checkpoints as one finding with retained history", () => {
  const root = mkdtempSync(
    join(tmpdir(), "codex-security-refined-checkpoint-"),
  );
  temporaryDirectories.push(root);
  const result = runProbe(root, "refined-checkpoint");
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    findingCount: 1,
    progressStatus: "failed",
    artifactFindingCount: 1,
    historyCount: 1,
    representedStartLines: [21, 24],
  });
}, 30_000);

test.each(["failed", "interrupted"] as const)(
  "keeps the first %s seal immutable when a worker writes late",
  (terminalStatus) => {
    const root = mkdtempSync(join(tmpdir(), "codex-security-late-checkpoint-"));
    temporaryDirectories.push(root);
    const result = runProbe(root, "late-checkpoint", terminalStatus);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      findingCount: 1,
      artifactFindingCount: 1,
      manifestUnchanged: true,
      findingsUnchanged: true,
    });
  },
  30_000,
);

test("retries a legacy stopped seal after transient publication failure", () => {
  const root = mkdtempSync(join(tmpdir(), "codex-security-legacy-seal-retry-"));
  temporaryDirectories.push(root);
  const result = runProbe(root, "legacy-seal-io-retry");
  expect(result.status, result.stderr).toBe(0);
  const recovered = JSON.parse(result.stdout);
  expect(recovered).toMatchObject({
    firstFailed: true,
    frozenAfterFailure: "{}",
    retryPublished: true,
    status: "failed",
    findingCount: 1,
  });
  const frozenSources = Object.entries(recovered.frozenAfterSuccess);
  expect(frozenSources).toHaveLength(1);
  const [checkpointPath, checkpointDigest] = frozenSources[0]!;
  expect(checkpointDigest).toMatch(/^[0-9a-f]{64}$/);
  expect(checkpointPath).toBe(`checkpoints/${checkpointDigest}.json`);
}, 30_000);

test("preserves distinct instances from one worker candidate", () => {
  const root = mkdtempSync(
    join(tmpdir(), "codex-security-distinct-instances-"),
  );
  temporaryDirectories.push(root);
  const result = runProbe(root, "distinct-instances");
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    findingCount: 2,
    artifactFindingCount: 2,
    instances: ["first", "second"],
  });
}, 30_000);

test("retries canceled result publication after a transient failure", () => {
  const root = mkdtempSync(join(tmpdir(), "codex-security-cancel-retry-"));
  temporaryDirectories.push(root);
  const result = runProbe(root, "cancel-io-retry");
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    findingCount: 1,
    progressStatus: "canceled",
    artifactFindingCount: 1,
    frozen: expect.any(Object),
  });
}, 30_000);
