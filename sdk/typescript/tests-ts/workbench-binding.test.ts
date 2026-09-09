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
import { PLUGIN_ROOT } from "./plugin-root";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Request, Response } from "./support/workbench-binding-fixture";

const scanId = "11111111-1111-4111-8111-111111111111",
  directory = realpathSync(mkdtempSync(join(tmpdir(), "workbench-binding-"))),
  fixture = join(directory, "fixture.cjs"),
  pluginRoot = join(directory, "plugin"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() => {
  mkdirSync(join(pluginRoot, ".codex-plugin"), { recursive: true });
  writeFileSync(
    join(pluginRoot, ".codex-plugin/plugin.json"),
    '{"version":"1.2.3"}',
  );
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-binding-fixture.ts", import.meta.url),
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
});
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
const digest = (bytes: string | Buffer) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
function scanDirectory(name: string) {
  const path = join(directory, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}
function manifest(kind = "git_worktree") {
  return {
    scan: {
      id: scanId,
      target: {
        targetId: "target-id",
        displayName: "target",
        kind,
        revision: "revision",
      },
      scope: { includePaths: ["src"], excludePaths: [] },
    },
  };
}
test("completion binds the persisted target, scoped recipe, producer version and timestamps", () => {
  const [response] = run({
    scan: {
      target_id: "target-id",
      recipe_json: '{"target":{"kind":"paths","paths":["src","lib"]}}',
    },
    actions: [{ operation: "binding", completedAt: "finished", pluginRoot }],
  });
  expect(response!.outcomes[0]!.value).toEqual({
    scanId,
    startedAt: "started",
    completedAt: "finished",
    producer: { name: "codex-security-plugin", version: "1.2.3" },
    target: {
      targetId: "target-id",
      displayName: "target",
      revision: "revision",
    },
    allowedTargetKinds: ["git_worktree", "git_revision"],
    scope: { includePaths: ["src", "lib"], excludePaths: [] },
    coverageMode: "scoped_path",
  });
});
test("completion keeps unversioned snapshots and validated diff revision contracts", () => {
  const responses = run(
    {
      scan: {
        target_revision: "unversioned",
        target_snapshot_digest: "snapshot",
      },
      actions: [{ operation: "binding", pluginRoot }],
    },
    ...["commit", "range", "working_tree"].map(
      (kind): Request => ({
        scan: {
          mode: "diff",
          diff_target_kind: kind,
          diff_base_revision: "base",
          diff_head_revision: "head",
          diff_content_digest: "digest",
        },
        actions: [{ operation: "binding", pluginRoot }],
      }),
    ),
    { scan: { mode: "diff" }, actions: [{ operation: "binding", pluginRoot }] },
  );
  expect(responses[0]!.outcomes[0]!.value).toMatchObject({
    target: { snapshotDigest: "snapshot" },
    allowedTargetKinds: ["directory_snapshot"],
  });
  expect(
    (responses[0]!.outcomes[0]!.value as Record<string, unknown>)["target"],
  ).not.toHaveProperty("revision");
  for (const [index, coverageMode] of [
    "commit",
    "branch_diff",
    "working_tree",
  ].entries()) {
    const binding = responses[index + 1]!.outcomes[0]!.value as Record<
      string,
      unknown
    >;
    expect(binding).toMatchObject({
      coverageMode,
      allowedTargetKinds: ["git_diff"],
      target: { baseRevision: "base", headRevision: "head" },
    });
    if (index === 2)
      expect(binding["target"]).toHaveProperty("snapshotDigest", "digest");
    else expect(binding["target"]).not.toHaveProperty("snapshotDigest");
  }
  expect(responses[4]!.outcomes[0]!.error).toBe(
    "This migrated diff scan does not have a validated change set.",
  );
});
test("completion rejects absent or non-string plugin versions while retaining nonempty version text", () => {
  const requests = ["", null, 1, "  "].map((version, index): Request => {
    const root = join(directory, `version-${index}`);
    mkdirSync(join(root, ".codex-plugin"), { recursive: true });
    writeFileSync(
      join(root, ".codex-plugin/plugin.json"),
      JSON.stringify({ version }),
    );
    return { actions: [{ operation: "binding", pluginRoot: root }] };
  });
  const responses = run(...requests);
  for (const response of responses.slice(0, 3))
    expect(response.outcomes[0]!.error).toBe(
      "plugin.json: expected a nonempty Codex Security plugin version.",
    );
  expect(responses[3]!.outcomes[0]!.value).toHaveProperty(
    "producer.version",
    "  ",
  );
});
test("manifest checks identity before target metadata and scope", () => {
  const requests: Request[] = [
    { actions: [{ operation: "verify", manifest: {} }] },
    { actions: [{ operation: "verify", manifest: { scan: { id: "other" } } }] },
    { actions: [{ operation: "verify", manifest: { scan: { id: scanId } } }] },
  ];
  const responses = run(...requests);
  expect(responses.map((response) => response.outcomes[0]!.error)).toEqual([
    "scan-manifest.json scan must be an object.",
    "scan-manifest.json scan.id must match the workbench scan ID.",
    "scan-manifest.json scan.target must be an object.",
  ]);
});
test("manifest binds target identity, name, kind and revision", () => {
  const updates = [
    {},
    { targetId: "other" },
    { displayName: "other" },
    { kind: "directory_snapshot" },
    { revision: "other" },
  ];
  const responses = run(
    ...updates.map((update): Request => {
      const value = manifest();
      Object.assign(value.scan.target, update);
      return {
        scan: { target_id: "target-id", scope: "src" },
        actions: [{ operation: "verify", manifest: value }],
      };
    }),
  );
  expect(responses[0]!.outcomes[0]!.value).toBeNull();
  expect(
    responses.slice(1).map((response) => response.outcomes[0]!.error),
  ).toEqual([
    "scan-manifest.json targetId must match the workbench target.",
    "scan-manifest.json target displayName must match the workbench target.",
    "scan-manifest.json target kind must match the workbench target.",
    "scan-manifest.json target revision must match the workbench target.",
  ]);
});
test("standard manifests require exact scope and diff manifests may only narrow it", () => {
  const requests: Request[] = [];
  for (const mode of ["standard", "diff"]) {
    for (const paths of [["src"], ["src/child"], ["../outside"], []]) {
      const value = manifest(mode === "diff" ? "git_diff" : "git_worktree");
      Object.assign(value.scan.target, {
        baseRevision: "base",
        headRevision: "head",
      });
      value.scan.scope.includePaths = paths;
      requests.push({
        scan: {
          target_id: "target-id",
          scope: "src",
          mode,
          diff_target_kind: "range",
          diff_base_revision: "base",
          diff_head_revision: "head",
        },
        actions: [{ operation: "verify", manifest: value }],
      });
    }
  }
  const responses = run(...requests);
  expect(
    responses.map((response) => response.outcomes[0]!.error ?? null),
  ).toEqual([
    null,
    "scan-manifest.json scope must match the workbench scan scope.",
    "scan-manifest.json scope must match the workbench scan scope.",
    "scan-manifest.json scope must match the workbench scan scope.",
    null,
    null,
    "scan-manifest.json scope must stay inside the workbench scan scope.",
    null,
  ]);
});
test("working-tree manifests bind both revisions and the selected content digest", () => {
  const responses = run(
    ...[
      {},
      { baseRevision: "wrong" },
      { headRevision: "wrong" },
      { snapshotDigest: "wrong" },
    ].map((update): Request => {
      const value = manifest("git_diff");
      Object.assign(
        value.scan.target,
        {
          baseRevision: "base",
          headRevision: "head",
          snapshotDigest: "digest",
        },
        update,
      );
      return {
        scan: {
          target_id: "target-id",
          mode: "diff",
          scope: "src",
          diff_target_kind: "working_tree",
          diff_base_revision: "base",
          diff_head_revision: "head",
          diff_content_digest: "digest",
        },
        actions: [{ operation: "verify", manifest: value }],
      };
    }),
  );
  expect(responses[0]!.outcomes[0]!.value).toBeNull();
  expect(
    responses.slice(1).map((response) => response.outcomes[0]!.error),
  ).toEqual([
    "scan-manifest.json target baseRevision must match the workbench diff target.",
    "scan-manifest.json target headRevision must match the workbench diff target.",
    "scan-manifest.json target snapshotDigest must match the selected working-tree contents.",
  ]);
});
test("file hashing streams past the read boundary and closes descriptors on success and rejection", () => {
  const scanDir = scanDirectory("stream"),
    bytes = Buffer.alloc(1024 * 1024 + 17, 42);
  writeFileSync(join(scanDir, "artifact"), bytes);
  const [response] = run({
    actions: [
      { operation: "digest", scanDir, relative: "artifact" },
      { operation: "digest", scanDir, relative: "missing" },
      { operation: "digest", scanDir, relative: "../outside" },
    ],
  });
  expect(response!.outcomes[0]!.value).toBe(digest(bytes));
  for (const outcome of response!.outcomes.slice(1))
    expect(outcome).toMatchObject({
      error: "Patch path must identify a scan-local regular file.",
      systemExit: true,
    });
  if (process.platform === "linux")
    for (const outcome of response!.outcomes)
      expect(outcome.descriptors).toBe(0n);
});
test.skipIf(process.platform === "win32")(
  "file hashing retains scan-local symlink rejection",
  () => {
    const scanDir = scanDirectory("symlink");
    writeFileSync(join(scanDir, "artifact"), "fixture");
    symlinkSync("artifact", join(scanDir, "link"));
    const [response] = run({
      actions: [{ operation: "digest", scanDir, relative: "link" }],
    });
    expect(response!.outcomes[0]!.error).toBe(
      "Patch path must identify a scan-local regular file.",
    );
  },
);
test("published manifests require canonical sorted ASCII JSON with the final newline", () => {
  const scanDir = scanDirectory("published");
  const canonical =
    '{\n  "a": "\\u00e9\\ud83e\\udded",\n  "z": [\n    1.0,\n    -0.0,\n    9007199254740993\n  ]\n}\n';
  const value = parseJson(
    '{"z":[1.0,-0.0,9007199254740993],"a":"é🧭"}',
  ) as Record<string, unknown>;
  writeFileSync(join(scanDir, "scan-manifest.json"), canonical);
  const [response] = run({
    scan: { seal_manifest_digest: digest(canonical) },
    actions: [
      { operation: "published", scanDir, manifest: value },
      { operation: "recorded", scanDir },
    ],
  });
  expect(response!.outcomes[0]!.value).toBe(digest(canonical));
  expect(response!.outcomes[1]!.value).toBeNull();
  writeFileSync(join(scanDir, "scan-manifest.json"), canonical.trimEnd());
  const [changed] = run({
    scan: { seal_manifest_digest: digest(canonical) },
    actions: [
      { operation: "published", scanDir, manifest: value },
      { operation: "recorded", scanDir },
    ],
  });
  expect(changed!.outcomes.map((outcome) => outcome.error)).toEqual([
    "The sealed scan manifest changed while it was being published.",
    "The sealed scan manifest changed after completion.",
  ]);
});
test("legacy scans skip a digest read until a digest has been recorded", () => {
  const scanDir = join(directory, "absent");
  const responses = run(
    { actions: [{ operation: "recorded", scanDir }] },
    {
      scan: { seal_manifest_digest: "" },
      actions: [{ operation: "recorded", scanDir }],
    },
  );
  expect(responses[0]!.outcomes[0]!.value).toBeNull();
  expect(responses[1]!.outcomes[0]!.error).toBeDefined();
});
test("legacy digest pinning commits once, allows repeat reads and rejects a changed digest", () => {
  const [response] = run({
    actions: [
      { operation: "pin", digest: "digest" },
      { operation: "pin", digest: "digest" },
      { operation: "pin", digest: "other" },
    ],
  });
  expect(response!.scans[0]!["seal_manifest_digest"]).toBe("digest");
  for (const outcome of response!.outcomes)
    expect(outcome.inTransaction).toBe(false);
  expect(response!.outcomes[0]!.events).toEqual([
    ["query", "BEGIN IMMEDIATE", false],
    ["transaction", "BEGIN IMMEDIATE", false],
    ["query", "SELECT * FROM scans WHERE id = ?", true],
    ["query", "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?", true],
    ["transaction", "COMMIT", true],
  ]);
  expect(response!.outcomes[1]!.events).toHaveLength(4);
  expect(response!.outcomes[2]!).toMatchObject({
    error: "The sealed scan manifest changed after completion.",
    systemExit: true,
  });
  expect(response!.outcomes[2]!.events.at(-1)).toEqual([
    "transaction",
    "ROLLBACK",
    true,
  ]);
});
test("pinning leaves an existing caller transaction intact when BEGIN fails", () => {
  const [response] = run({
    actions: [
      { operation: "sql", sql: "UPDATE scans SET scope='pending'" },
      { operation: "pin", digest: "digest" },
    ],
  });
  expect(response!.outcomes[1]!).toMatchObject({
    error: "cannot start a transaction within a transaction",
    inTransaction: true,
  });
  expect(response!.scans[0]!).toMatchObject({
    scope: "pending",
    seal_manifest_digest: null,
  });
});
test("pinning rolls back both update failures and deferred commit failures", () => {
  const responses = run(
    {
      setupSql: [
        "CREATE TRIGGER reject_digest BEFORE UPDATE OF seal_manifest_digest ON scans BEGIN SELECT RAISE(ABORT, 'digest rejected'); END;",
      ],
      actions: [{ operation: "pin", digest: "digest" }],
    },
    {
      setupSql: [
        "CREATE TABLE audit(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER bad_audit AFTER UPDATE OF seal_manifest_digest ON scans BEGIN INSERT INTO audit VALUES ('absent'); END;",
      ],
      actions: [{ operation: "pin", digest: "digest" }],
    },
    {
      actions: [
        {
          operation: "pin",
          id: "33333333-3333-4333-8333-333333333333",
          digest: "digest",
        },
      ],
    },
  );
  expect(responses.map((response) => response.outcomes[0]!.error)).toEqual([
    "digest rejected",
    "FOREIGN KEY constraint failed",
    "Codex Security scan not found.",
  ]);
  for (const response of responses) {
    expect(response.outcomes[0]!.inTransaction).toBe(false);
    expect(response.outcomes[0]!.events.at(-1)).toEqual([
      "transaction",
      "ROLLBACK",
      true,
    ]);
    expect(response.scans[0]!["seal_manifest_digest"]).toBeNull();
  }
});
