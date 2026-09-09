import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
import type {
  Operation,
  Request,
  Response,
} from "./support/contract-validation-fixture";

type Table = Record<string, unknown>;
const directory = realpathSync(
    mkdtempSync(join(tmpdir(), "contract-validation-")),
  ),
  fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const scanRoot = join(directory, "scan");
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/contract-validation-fixture.ts", import.meta.url),
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
  for (const folder of ["artifacts", "reports", "hardening"])
    mkdirSync(join(scanRoot, folder), { recursive: true });
  for (const file of [
    "artifacts/a.json",
    "artifacts/b.json",
    "reports/finding.md",
    "hardening/hardening.md",
  ])
    writeFileSync(join(scanRoot, file), "synthetic");
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
const example = (name: string): Table =>
  JSON.parse(
    readFileSync(
      new URL(
        `../../../plugins/codex-security/examples/completed-scan/${name}`,
        import.meta.url,
      ),
      "utf8",
    ),
  ) as Table;
const manifest = example("scan-manifest.json"),
  findings = example("findings.json"),
  coverage = example("coverage.json"),
  finding = (findings["findings"] as Table[])[0]!;
function request(
  operation: Operation,
  payload: unknown,
  options: Omit<Request, "operation" | "source"> = {},
): Request {
  return {
    operation,
    source: JSON.stringify(payload),
    root: scanRoot,
    ...options,
  };
}
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = JSON.parse(child.stdout) as Response[];
  if (process.platform === "linux")
    for (const response of responses) expect(response.leaked).toBe(0);
  return responses;
}
function success(response: Response): unknown {
  expect(response.error).toBeUndefined();
  return JSON.parse(response.value!);
}
const after = (response: Response): unknown => JSON.parse(response.after);
function modify(
  value: Table,
  path: (string | number)[],
  replacement: unknown,
): Table {
  const result = structuredClone(value);
  let parent: Table | unknown[] = result;
  for (const key of path.slice(0, -1)) parent = (parent as Table)[key] as Table;
  (parent as Table)[path.at(-1)!] = replacement;
  return result;
}

test("target validation preserves URL acceptance, credential checks and coordinate requirements", () => {
  const target = (manifest["scan"] as Table)["target"] as Table;
  const urls = [
    "ftp://example.test:bad/repo",
    "https://:@example.test/repo?",
    "https://[::1%scope]:999999/repo",
    "https://user@example.test/repo",
    "https://example.test/repo?query",
    "https://example.test/repo#fragment",
    "git@example.test:repo",
    "https://[127.0.0.1]/repo",
  ];
  const results = run(urls.map((url) => request("remote", url)));
  for (const result of results.slice(0, 3)) expect(success(result)).toBeNull();
  for (const result of results.slice(3, 6))
    expect(result.error).toBe(
      "context: remote URL must not contain credentials, query, or fragment",
    );
  expect(results[6]!.error).toBe(
    "context: expected a sanitized canonical absolute URL",
  );
  expect(results[7]!.error).toBe("An IPv4 address cannot be in brackets");
  const targets = run([
    request("target", { ...target, kind: "git_revision", revision: "" }),
    request("target", { ...target, kind: "git_diff", snapshotDigest: "" }),
    request("target", { ...target, targetId: "", remote: "invalid" }),
    request("target", { ...target, remote: null }),
  ]);
  expect(targets.map((result) => result.error ?? null)).toEqual([
    "scan.target.revision: expected a non-empty string",
    "scan.target.snapshotDigest: expected a non-empty string",
    "scan.target.targetId: expected a non-empty string",
    null,
  ]);
});

test("required values preserve Python whitespace and retain their original contents", () => {
  const results = run([
    request("string", { value: " \u0085 " }, { key: "value" }),
    request("string", { value: "\ufeff" }, { key: "value" }),
    request("string", { value: " text " }, { key: "value" }),
    request("dict", { value: [] }, { key: "value" }),
    request("list", {}, { key: "value" }),
  ]);
  expect(results[0]!.error).toBe("context.value: expected a non-empty string");
  expect(success(results[1]!)).toBe("\ufeff");
  expect(success(results[2]!)).toBe(" text ");
  expect(results[3]!.error).toBe("context.value: expected an object");
  expect(results[4]!.error).toBe("context.value: expected an array");
});

test("logical fingerprints survive path changes while scan IDs and sibling instances separate occurrences", () => {
  const moved = modify(
    finding,
    ["locations"],
    [{ path: "renamed.ts", startLine: 100 }],
  );
  const sibling = modify(finding, ["identity", "instance"], "sibling");
  const target = ((manifest["scan"] as Table)["target"] as Table)["targetId"];
  const fingerprints = run(
    [finding, moved, sibling].map((row) =>
      request("fingerprint", [target, row]),
    ),
  ).map(success);
  expect(fingerprints[0]).toBe(
    "codex-security/v1:sha256:990a4a6a2ec18440dd47eac4d7256c0ee2c02db1b43104720cab3cbe9db706ca",
  );
  expect(fingerprints[1]).toBe(fingerprints[0]);
  expect(fingerprints[2]).not.toBe(fingerprints[0]);
  const populated = run([
    request("populate", [manifest, findings]),
    request("populate", [
      modify(manifest, ["scan", "id"], "other-scan"),
      { ...findings, scanId: "other-scan" },
    ]),
  ]);
  for (const result of populated) success(result);
  const first = (after(populated[0]!) as [Table, Table])[1],
    second = (after(populated[1]!) as [Table, Table])[1];
  const row = (first["findings"] as Table[])[0]!,
    other = (second["findings"] as Table[])[0]!;
  expect(row["findingId"]).toBe(other["findingId"]);
  expect(row["occurrenceId"]).not.toBe(other["occurrenceId"]);
  const repeated = run([
    request("populate", [manifest, first]),
    request("identities", [manifest, first]),
  ]);
  for (const result of repeated) success(result);
  expect(after(repeated[0]!)).toEqual([manifest, first]);
});

test("duplicate derived identities fail before draft fields are mutated or sealed IDs are checked", () => {
  const duplicate = {
    ...findings,
    findings: [
      finding,
      { ...finding, findingId: "draft", occurrenceId: "draft" },
    ],
  };
  const results = run([
    request("populate", [manifest, duplicate]),
    request("identities", [manifest, duplicate]),
    request("fingerprint", [
      "target",
      modify(finding, ["identity", "anchor"], "anchor\n"),
    ]),
  ]);
  for (const result of results.slice(0, 2)) {
    expect(result.error).toBe(
      "findings.findings[1]: duplicate occurrence identity; use identity.instance to split siblings",
    );
    expect(after(result)).toEqual([manifest, duplicate]);
  }
  expect(results[2]!.error).toBe(
    "finding.identity.anchor: expected a stable lowercase semantic slug",
  );
  const populated = run([request("populate", [manifest, findings])])[0]!;
  success(populated);
  const normalized = (after(populated) as [Table, Table])[1];
  const invalid = run([
    request("identities", [
      manifest,
      modify(normalized, ["findings", 0, "findingId"], "wrong"),
    ]),
    request("identities", [
      manifest,
      modify(normalized, ["findings", 0, "occurrenceId"], "wrong"),
    ]),
    request("identities", [
      manifest,
      modify(normalized, ["findings", 0, "fingerprints"], {}),
    ]),
  ]);
  expect(invalid.map((result) => result.error)).toEqual([
    "findings.findings[0].findingId: does not match derived fingerprint identity",
    "findings.findings[0].occurrenceId: does not match scan occurrence identity",
    "findings.findings[0].fingerprints: does not match derived fingerprint",
  ]);
});

test("semantic location checks distinguish integer and decimal JSON while retaining bool behavior", () => {
  const results = run([
    {
      ...request("location", null),
      source: '{"path":"./src//a.ts","startLine":1,"endLine":2}',
    },
    {
      ...request("location", null),
      source: '{"path":"src/a.ts","startLine":1.0}',
    },
    request("location", { path: "src/a.ts", startLine: true, endLine: true }),
    request("location", { path: "src/a.ts", startLine: 2, endLine: 1 }),
    request("location", { path: "../outside", startLine: 0 }),
    request("location", { path: "src/a.ts", startLine: 1, role: " " }),
  ]);
  success(results[0]!);
  expect(after(results[0]!)).toEqual({
    path: "./src//a.ts",
    startLine: 1,
    endLine: 2,
  });
  expect(results[1]!.error).toBe(
    "context.startLine: expected a positive integer",
  );
  success(results[2]!);
  expect(results[3]!.error).toBe(
    "context.endLine: expected an integer >= startLine",
  );
  expect(results[4]!.error).toBe(
    "context.path: expected a safe repository-relative POSIX path",
  );
  success(results[5]!);
});

test("finding validation keeps alias-wide evidence IDs and ordered nested-reference errors", () => {
  const valid = {
    ...finding,
    codeEvidence: [{ id: "one", code: "code" }],
    code_evidence: [{ id: "two", code: "legacy" }],
    attackPath: { data_flow: { evidence_refs: ["one", "two"] } },
  };
  const results = run([
    request("finding", valid),
    request("finding", {
      ...valid,
      code_evidence: [{ id: "one", code: "legacy" }],
    }),
    request("finding", {
      ...valid,
      attackPath: { dataFlow: { evidenceRefs: ["😀", "\ue000", "😀"] } },
    }),
    request("finding", {
      ...valid,
      rootCause: { evidenceRefs: ["missing"] },
      attackPath: { dataFlow: { evidenceRefs: ["later"] } },
    }),
    request("finding", {
      ...valid,
      extensions: { custom: { nested: [1, true, null] } },
    }),
  ]);
  success(results[0]!);
  success(results[4]!);
  expect(results[1]!.error).toBe(
    "context.code_evidence[0].id: duplicate code-evidence id",
  );
  expect(results[2]!.error).toBe(
    "context.attackPath.dataFlow.evidenceRefs: unknown code-evidence ids: \ue000, 😀",
  );
  expect(results[3]!.error).toBe(
    "context.rootCause.evidenceRefs: unknown code-evidence ids: missing",
  );
});

test("manifest validation normalizes collision keys without rewriting artifact paths", () => {
  const normalized = modify(
    manifest,
    ["scan", "artifacts", 0, "path"],
    "./findings.json",
  );
  const duplicate = modify(
    manifest,
    ["scan", "artifacts"],
    [
      { path: "findings.json", sha256: "x", mediaType: "json" },
      { path: "coverage.json", sha256: "x", mediaType: "json" },
      { path: "AΣ", sha256: "x", mediaType: "json" },
      { path: "aς", sha256: "x", mediaType: "json" },
    ],
  );
  const results = run([
    request("manifest", normalized),
    request("manifest", duplicate),
    request(
      "manifest",
      modify(
        manifest,
        ["scan", "artifacts"],
        [{ path: "coverage.json", sha256: "x", mediaType: "json" }],
      ),
    ),
    request(
      "manifest",
      modify(manifest, ["scan", "coverageRef"], "other.json"),
    ),
  ]);
  success(results[0]!);
  expect(after(results[0]!)).toEqual(normalized);
  expect(results[1]!.error).toBe(
    "manifest.scan.artifacts[3].path: duplicate artifact path",
  );
  expect(results[2]!.error).toBe(
    "manifest.scan.artifacts: missing required artifact: findings.json",
  );
  expect(results[3]!.error).toBe(
    "manifest.scan.coverageRef: expected 'coverage.json'",
  );
});

test("coverage receipt normalization survives late failure and closes opened files", () => {
  const value = modify(
    coverage,
    ["surfaces", 0, "receiptRefs"],
    ["./artifacts//a.json", "./artifacts//missing", "./artifacts//b.json"],
  );
  const result = run([
    request("coverage", [manifest, value], { trace: true }),
  ])[0]!;
  expect(result.error).toBe(
    "coverage.surfaces[0].receiptRefs[1]: expected a file inside the scan directory",
  );
  expect(
    ((after(result) as [Table, Table])[1]["surfaces"] as Table[])[0]![
      "receiptRefs"
    ],
  ).toEqual(["artifacts/a.json", "artifacts/missing", "./artifacts//b.json"]);
  if (process.platform !== "win32")
    expect(result.events).toEqual([{ open: "a.json" }, { close: "a.json" }]);
  const closed = run([
    request("file", "artifacts/a.json", { trace: true, failClose: true }),
  ])[0]!;
  if (process.platform !== "win32") {
    expect(closed.error).toBe("synthetic close failure");
    expect(closed.events).toEqual([{ open: "a.json" }, { close: "a.json" }]);
  }
});

test("coverage preserves Python scope equality and checks receipts before final JSON safety", () => {
  const scoped = modify(
    manifest,
    ["scan", "scope", "includePaths"],
    [{ value: true }],
  );
  const matching = modify(coverage, ["includePaths"], [{ value: 1 }]);
  const results = run([
    request("coverage", [scoped, matching]),
    request("coverage", [
      scoped,
      modify(matching, ["includePaths"], [{ value: 2 }]),
    ]),
    request("coverage", [
      manifest,
      modify(coverage, ["surfaces", 0, "disposition"], "needs_follow_up"),
    ]),
    request("coverage", [manifest, modify(coverage, ["deferred"], ["later"])]),
    {
      ...request("coverage", null, { trace: true }),
      source: JSON.stringify([
        manifest,
        {
          ...modify(
            coverage,
            ["surfaces", 0, "receiptRefs"],
            ["./artifacts//a.json"],
          ),
          custom: "unsafe",
        },
      ]).replace('"custom":"unsafe"', '"custom":9007199254740993'),
    },
  ]);
  success(results[0]!);
  expect(results[1]!.error).toBe(
    "coverage.includePaths: must match manifest scope",
  );
  for (const result of results.slice(2, 4))
    expect(result.error).toBe(
      "coverage.completeness: complete coverage cannot have deferred work",
    );
  expect(results[4]!.error).toBe(
    "coverage.json.<property>: unsafe integer-valued JSON numbers are not supported",
  );
  if (process.platform !== "win32")
    expect(results[4]!.events).toEqual([
      { open: "a.json" },
      { close: "a.json" },
    ]);
});

test("writeup and hardening file requirements skip absent metadata and reject symlinks", () => {
  const results = run([
    request(
      "writeups",
      {
        findings: [
          null,
          { writeup: null },
          { writeup: { reportPath: "reports/finding.md" } },
        ],
      },
      { trace: true },
    ),
    request(
      "hardening",
      { hardening: { portfolioPath: "hardening/hardening.md" } },
      { trace: true },
    ),
    request("writeups", {
      findings: [{ writeup: { reportPath: "missing.md" } }],
    }),
    request("hardening", { hardening: null }),
  ]);
  for (const result of [results[0]!, results[1]!, results[3]!]) success(result);
  expect(results[2]!.error).toBe(
    "findings[0].writeup.reportPath: expected a file inside the scan directory",
  );
  if (process.platform !== "win32") {
    symlinkSync(
      join(scanRoot, "artifacts/a.json"),
      join(scanRoot, "artifacts/alias"),
    );
    const result = run([
      request("file", "artifacts/alias", { trace: true }),
    ])[0]!;
    expect(result.error).toBe("context: expected a regular non-symlink file");
    expect(result.events).toEqual([]);
  }
});

test("finding documents preserve validation order and canonical JSON constraints", () => {
  const duplicate = { ...findings, findings: [finding, finding] };
  const results = run([
    request("findings", [manifest, duplicate]),
    {
      ...request("findings", null),
      source: JSON.stringify([
        manifest,
        modify(findings, ["findings", 0, "extensions"], { nested: "unsafe" }),
      ]).replace('"nested":"unsafe"', '"nested":9007199254740993'),
    },
    request("finding", modify(finding, ["severity", "score"], true)),
    request("finding", modify(finding, ["severity", "score"], 0)),
    request("finding", modify(finding, ["extensions"], null)),
  ]);
  expect(results[0]!.error).toBe(
    "findings.findings[1]: duplicate finding or occurrence id",
  );
  expect(results[1]!.error).toContain(
    "unsafe integer-valued JSON numbers are not supported",
  );
  expect(results[2]!.error).toBe(
    "context.severity.score: expected a number from 0 through 10",
  );
  success(results[3]!);
  success(results[4]!);
});

test("the shared date-time helper stays separate from semantic manifest string checks", () => {
  const dates = [
    "2000-02-29t00:00:00z",
    "1900-02-29T00:00:00Z",
    "2026-01-01T00:00:00+00:99",
    "2026-01-01T00:00:00+23:60",
    "2026-01-01T00:00:00Z\n",
  ];
  const results = run(dates.map((date) => request("date", date)));
  expect(results.map((result) => result.error ?? null)).toEqual([
    null,
    "context: expected an RFC 3339 timestamp",
    null,
    "context: expected an RFC 3339 timestamp",
    "context: expected an RFC 3339 timestamp",
  ]);
  const semantic = run([
    request(
      "manifest",
      modify(manifest, ["scan", "startedAt"], "nonempty draft timestamp"),
    ),
  ])[0]!;
  success(semantic);
});
