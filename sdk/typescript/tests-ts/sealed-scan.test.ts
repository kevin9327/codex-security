import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
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
import type { Request, Response } from "./support/sealed-scan-fixture";

type Table = Record<string, unknown>;
const directory = realpathSync(mkdtempSync(join(tmpdir(), "sealed-scan-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const documents = ["scan-manifest.json", "findings.json", "coverage.json"];
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/sealed-scan-fixture.ts", import.meta.url),
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
function run(requests: Request[], cwd?: string): Response[] {
  const child = spawnSync(node, [fixture], {
    cwd,
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/missing/python" },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
function seed(): string {
  const root = mkdtempSync(join(directory, "scan-"));
  for (const name of documents)
    copyFileSync(
      join(PLUGIN_ROOT, "examples/completed-scan", name),
      join(root, name),
    );
  return root;
}
const digest = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
const load = (root: string, name: string): Table =>
  JSON.parse(readFileSync(join(root, name), "utf8")) as Table;
const encoded = (value: unknown) =>
  Buffer.from(JSON.stringify(value, null, 2) + "\n");
function rewrite(
  root: string,
  name: string,
  value: Table,
  bytes = encoded(value),
): void {
  writeFileSync(join(root, name), bytes);
  if (name === "scan-manifest.json") return;
  const manifest = load(root, "scan-manifest.json"),
    scan = manifest["scan"] as Table;
  for (const artifact of scan["artifacts"] as Table[])
    if (artifact["path"] === name) artifact["sha256"] = digest(bytes);
  rewrite(root, "scan-manifest.json", manifest);
}
function payload(response: Response): Table {
  expect(response.error).toBeUndefined();
  return JSON.parse(response.value!) as Table;
}

test("reads legacy-compatible findings without changing their JSON export bytes or stored artifacts", () => {
  const root = seed(),
    findings = load(root, "findings.json");
  const finding = (findings["findings"] as Table[])[0]!;
  finding["attackPath"] = { summary: "legacy detail", steps: "first" };
  const raw = Buffer.from(
    " \r\n" +
      JSON.stringify(findings, null, 1).replaceAll("\n", "\r\n") +
      "\r\n",
  );
  rewrite(root, "findings.json", findings, raw);
  const before = documents.map((name) => readFileSync(join(root, name)));
  const results = run([
    { operation: "read", root },
    { operation: "export", root, format: "json" },
    { operation: "export", root, format: "csv" },
  ]);
  expect(results.map((row) => row.error)).toEqual([
    undefined,
    undefined,
    undefined,
  ]);
  expect(Buffer.from(results[0]!.bytes!, "base64")).toEqual(raw);
  expect(Buffer.from(results[1]!.bytes!, "base64")).toEqual(raw);
  expect(JSON.parse(results[0]!.value!)[1]).toEqual(findings);
  expect(Buffer.from(results[2]!.bytes!, "base64").toString()).toStartWith(
    "occurrence_id,finding_id,title,summary,severity,confidence,status",
  );
  expect(documents.map((name) => readFileSync(join(root, name)))).toEqual(
    before,
  );
});

test("checks canonical refs and seals before schemas or finding identities", () => {
  const root = seed(),
    manifest = load(root, "scan-manifest.json"),
    scan = manifest["scan"] as Table;
  scan["coverageRef"] = "other.json";
  scan["sealedAt"] = null;
  rewrite(root, "scan-manifest.json", manifest);
  expect(
    run([{ operation: "read", root, schemas: join(root, "missing") }])[0]!
      .error,
  ).toBe("manifest.scan.coverageRef: expected 'coverage.json'");
  scan["coverageRef"] = "coverage.json";
  rewrite(root, "scan-manifest.json", manifest);
  expect(run([{ operation: "read", root }])[0]!.error).toBe(
    "manifest.scan: test export requires a sealed scan",
  );
  scan["sealedAt"] = scan["completedAt"];
  rewrite(root, "scan-manifest.json", manifest);
  const findings = load(root, "findings.json");
  (findings["findings"] as Table[])[0]!["findingId"] = "csf_changed";
  writeFileSync(join(root, "findings.json"), encoded(findings));
  expect(run([{ operation: "read", root }])[0]!.error).toBe(
    "manifest.scan.artifacts[0]: sealed artifact changed or is missing",
  );
  rewrite(root, "findings.json", findings);
  expect(run([{ operation: "read", root }])[0]!.error).toContain("findingId");
});

test("seal verification hashes supplied bytes instead of reopening parsed documents", () => {
  const root = seed(),
    scan = load(root, "scan-manifest.json")["scan"] as Table;
  const findings = readFileSync(join(root, "findings.json")),
    coverage = readFileSync(join(root, "coverage.json"));
  writeFileSync(join(root, "findings.json"), "changed after parsing");
  const cached: [string, string][] = [
    ["findings.json", findings.toString("base64")],
    ["coverage.json", coverage.toString("base64")],
  ];
  const results = run([
    {
      operation: "seal",
      root,
      source: JSON.stringify(scan),
      artifactContents: cached,
    },
    { operation: "seal", root, source: JSON.stringify(scan) },
    {
      operation: "seal",
      root,
      source: JSON.stringify(scan),
      artifactContents: [
        ["findings.json", Buffer.from("unsealed bytes").toString("base64")],
      ],
    },
  ]);
  expect(results[0]!.error).toBeUndefined();
  expect(results.slice(1).map((row) => row.error)).toEqual(
    Array(2).fill(
      "manifest.scan.artifacts[0]: sealed artifact changed or is missing",
    ),
  );
});

test("seals reject colliding normalized Unicode artifact paths before reading duplicates", () => {
  const root = seed(),
    scan = {
      sealedAt: "now",
      completedAt: "now",
      artifacts: [
        {
          path: "AΣ",
          sha256: digest(Buffer.from("a")),
          mediaType: "text/plain",
        },
        { path: "aς", sha256: "not read", mediaType: "text/plain" },
      ],
    };
  writeFileSync(join(root, "AΣ"), "a");
  expect(
    run([{ operation: "seal", root, source: JSON.stringify(scan) }])[0]!.error,
  ).toBe("manifest.scan.artifacts[1].path: duplicate artifact path");
  const normalized = {
    ...scan,
    artifacts: [scan.artifacts[0], { ...scan.artifacts[1], path: "./AΣ" }],
  };
  expect(
    run([{ operation: "seal", root, source: JSON.stringify(normalized) }])[0]!
      .error,
  ).toBe("manifest.scan.artifacts[1].path: duplicate artifact path");
});

test("artifact records normalize portable paths and hash either streamed files or supplied bytes", () => {
  const root = seed();
  mkdirSync(join(root, "artifacts"));
  writeFileSync(join(root, "artifacts/a.bin"), "stored");
  const results = run([
    { operation: "record", root, relative: "./artifacts//a.bin" },
    { operation: "record", root, relative: "artifacts/new.bin", contents: "" },
    { operation: "record", root, relative: "../outside", contents: "" },
    { operation: "record", root, relative: "artifacts/NUL", contents: "" },
  ]);
  expect(payload(results[0]!)).toEqual({
    path: "artifacts/a.bin",
    mediaType: "application/octet-stream",
    sha256: digest(Buffer.from("stored")),
  });
  expect(payload(results[1]!)["sha256"]).toBe(digest(Buffer.alloc(0)));
  expect(results[2]!.error).toContain("safe repository-relative POSIX path");
  expect(results[3]!.error).toContain("safe scan-relative POSIX path");
});

test("coverage receipts are distinct, sorted by code point and required in the seal", () => {
  const root = seed();
  const coverage = {
    surfaces: [
      { receiptRefs: ["artifacts/😀", "artifacts/\ue000", "artifacts/a"] },
      { receiptRefs: ["artifacts/a"] },
    ],
  };
  const records = {
    artifacts: [{ path: "artifacts/😀" }, { path: "./artifacts/a" }],
  };
  const results = run([
    { operation: "receipts", root, source: JSON.stringify(coverage) },
    {
      operation: "sealedReceipts",
      root,
      source: JSON.stringify({ scan: records, coverage }),
    },
  ]);
  expect(JSON.parse(results[0]!.value!)).toEqual([
    "artifacts/a",
    "artifacts/\ue000",
    "artifacts/😀",
  ]);
  expect(results[1]!.error).toBe(
    "coverage receipt is missing from sealed artifacts: artifacts/\ue000",
  );
});

test("partial and unsuccessful SARIF exports retain invocation warnings", () => {
  const root = seed(),
    coverage = load(root, "coverage.json"),
    manifest = load(root, "scan-manifest.json");
  coverage["completeness"] = "partial";
  coverage["deferred"] = [{ id: "later", reason: "Synthetic review remains" }];
  rewrite(root, "coverage.json", coverage);
  const scan = load(root, "scan-manifest.json")["scan"] as Table;
  scan["status"] = "interrupted";
  manifest["scan"] = scan;
  rewrite(root, "scan-manifest.json", manifest);
  const results = run([
    { operation: "sarif", root },
    { operation: "export", root, format: "sarif" },
    { operation: "writeSarif", root },
  ]);
  const sarif = payload(results[0]!),
    runResult = (sarif["runs"] as Table[])[0]!;
  expect(runResult["invocations"]).toEqual([
    {
      executionSuccessful: false,
      toolExecutionNotifications: [
        { level: "warning", message: { text: "Synthetic review remains" } },
      ],
    },
  ]);
  expect(
    (runResult["properties"] as Table)["codexSecurityCoverageCompleteness"],
  ).toBe("partial");
  expect(
    JSON.parse(Buffer.from(results[1]!.bytes!, "base64").toString()),
  ).toEqual(sarif);
  expect(results[2]!.error).toBeUndefined();
  expect(load(root, "exports/results.sarif")).toEqual(sarif);
});

test("empty and dot schema directories both select current-directory schemas", () => {
  const root = seed();
  const results = run(
    [
      { operation: "read", root, schemas: "" },
      { operation: "read", root, schemas: "." },
    ],
    join(PLUGIN_ROOT, "schemas"),
  );
  expect(results.map((result) => result.error)).toEqual([undefined, undefined]);
  expect(results[0]).toEqual(results[1]);
});

test("export arguments and source-root failures retain their validation order", () => {
  const root = join(directory, "missing");
  const results = run([
    { operation: "export", root, format: "other", sourceRoot: root },
    { operation: "export", root, format: "csv", sourceRoot: root },
    { operation: "export", root, format: "sarif", sourceRoot: root },
  ]);
  expect(results.map((row) => row.error)).toEqual([
    "unsupported export format: other",
    "source-root is only supported for SARIF exports",
    "source root: expected an existing directory",
  ]);
});

test.skipIf(process.platform === "win32")(
  "sealed reads reject scan aliases and symlinked artifact files",
  () => {
    const root = seed(),
      alias = join(directory, "scan-alias");
    symlinkSync(root, alias);
    expect(run([{ operation: "read", root: alias }])[0]!.error).toBe(
      "scan directory: expected an existing non-symlink directory",
    );
    const findings = readFileSync(join(root, "findings.json"));
    writeFileSync(join(directory, "findings.json"), findings);
    rmSync(join(root, "findings.json"));
    symlinkSync(join(directory, "findings.json"), join(root, "findings.json"));
    expect(run([{ operation: "read", root }])[0]!.error).toBe(
      "findings.json: expected a file inside the scan directory",
    );
  },
);
