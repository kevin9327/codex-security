import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
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
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import { buildReportFixture } from "./support/build-report-fixture";
import type { Request, Response } from "./support/scan-finalization-fixture";

type Table = Record<string, unknown>;
const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "scan-finalization-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const documents = ["scan-manifest.json", "findings.json", "coverage.json"];
beforeAll(async () => {
  await buildReportFixture(node, {
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-finalization-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: "",
      PYTHON: "/missing/python",
      CODEX_SECURITY_STARTED_AT: undefined,
    },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
const load = (root: string, name: string): Table =>
  JSON.parse(readFileSync(join(root, name), "utf8")) as Table;
const write = (root: string, name: string, value: unknown) =>
  writeFileSync(join(root, name), JSON.stringify(value, null, 2) + "\n");
const digest = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
function seed(sealed = false): string {
  const root = mkdtempSync(join(directory, "scan-"));
  for (const name of documents)
    copyFileSync(
      join(PLUGIN_ROOT, "examples/completed-scan", name),
      join(root, name),
    );
  if (!sealed) {
    const manifest = load(root, "scan-manifest.json"),
      scan = manifest["scan"] as Table;
    delete scan["sealedAt"];
    delete scan["artifacts"];
    write(root, "scan-manifest.json", manifest);
  }
  writeFileSync(join(root, "report.md"), "old report\n");
  writeFileSync(join(root, "report.html"), "old html\n");
  return root;
}
function snapshot(root: string): Record<string, string> {
  return Object.fromEntries(
    readdirSync(root, { recursive: true, withFileTypes: true })
      .filter((item) => item.isFile())
      .map((item) => {
        const path = join(item.parentPath, item.name);
        return [
          path.slice(root.length + 1),
          readFileSync(path).toString("base64"),
        ];
      }),
  );
}
function prepared(response: Response): Table {
  expect(response.error).toBeUndefined();
  return JSON.parse(response.prepared!) as Table;
}
function addReceipt(root: string): Buffer {
  mkdirSync(join(root, "artifacts"));
  const bytes = Buffer.from("synthetic receipt\n");
  writeFileSync(join(root, "artifacts/receipt.json"), bytes);
  const coverage = load(root, "coverage.json");
  (coverage["surfaces"] as Table[])[0]!["receiptRefs"] = [
    "artifacts/receipt.json",
  ];
  write(root, "coverage.json", coverage);
  return bytes;
}

test("preparation populates a complete result without modifying files or supplied drafts", () => {
  const root = seed(),
    drafts = documents.map((name) => load(root, name));
  const source = JSON.stringify({ options: { draftDocuments: drafts } });
  const before = snapshot(root),
    response = run([{ operation: "prepare", root, source }])[0]!;
  const output = prepared(response),
    manifest = output["manifest"] as Table,
    scan = manifest["scan"] as Table;
  expect(scan["sealedAt"]).toBe(scan["completedAt"]);
  expect(output["wasSealed"]).toBe(false);
  expect(scan["artifacts"]).toHaveLength(2);
  expect(
    Buffer.from(output["reportMarkdown"] as string, "base64").toString(),
  ).toContain("Unsafe archive extraction");
  expect(JSON.parse(response.after)).toEqual(JSON.parse(source));
  expect(snapshot(root)).toEqual(before);
});

test("finalization writes canonical documents, replaces reports and publishes the seal before SARIF", () => {
  const root = seed(),
    receipt = addReceipt(root);
  const response = run([{ operation: "finalize", root, trace: true }])[0]!;
  expect(response.error).toBeUndefined();
  expect(response.stderr).toBe("");
  const manifest = load(root, "scan-manifest.json"),
    scan = manifest["scan"] as Table;
  expect((scan["artifacts"] as Table[]).map((row) => row["path"])).toEqual([
    "findings.json",
    "coverage.json",
    "artifacts/receipt.json",
  ]);
  for (const artifact of scan["artifacts"] as Table[])
    expect(artifact["sha256"]).toBe(
      digest(readFileSync(join(root, artifact["path"] as string))),
    );
  expect(
    readFileSync(join(root, "artifacts/receipt.json")).equals(receipt),
  ).toBe(true);
  expect(snapshot(root)).not.toHaveProperty("report.html");
  expect(load(root, "exports/results.sarif")["version"]).toBe("2.1.0");
  if (process.platform !== "win32")
    expect(response.events).toEqual([
      { replace: "findings.json" },
      { replace: "coverage.json" },
      { replace: "report.md" },
      { remove: "report.html" },
      { replace: "scan-manifest.json" },
      { replace: "results.sarif" },
    ]);
});

test("sealed reruns preserve original document bytes and additional artifact records", () => {
  const root = seed(true),
    manifest = load(root, "scan-manifest.json"),
    scan = manifest["scan"] as Table;
  mkdirSync(join(root, "artifacts"));
  writeFileSync(join(root, "artifacts/extra.bin"), "sealed extra");
  (scan["artifacts"] as Table[]).push({
    path: "artifacts/extra.bin",
    sha256: digest(Buffer.from("sealed extra")),
    mediaType: "application/octet-stream",
  });
  write(root, "scan-manifest.json", manifest);
  const before = documents.map((name) => readFileSync(join(root, name)));
  const response = run([{ operation: "finalize", root, trace: true }])[0]!;
  expect(response.error).toBeUndefined();
  expect(documents.map((name) => readFileSync(join(root, name)))).toEqual(
    before,
  );
  expect(snapshot(root)).not.toHaveProperty("report.html");
  if (process.platform !== "win32")
    expect(response.events).toEqual([
      { replace: "report.md" },
      { remove: "report.html" },
      { replace: "results.sarif" },
    ]);
});

test("canonical validation failure leaves every output unchanged", () => {
  const root = seed(),
    coverage = load(root, "coverage.json");
  coverage["completeness"] = "invalid";
  write(root, "coverage.json", coverage);
  const before = snapshot(root),
    response = run([{ operation: "finalize", root, trace: true }])[0]!;
  expect(response.kind).toBe("ContractError");
  expect(response.error).toContain("coverage.schema.completeness");
  expect(response.events).toEqual([]);
  expect(snapshot(root)).toEqual(before);
});

test("receipt changes after preparation are detected after the written manifest is sealed", () => {
  const root = seed();
  addReceipt(root);
  const response = run([
    {
      operation: "prepareWrite",
      root,
      trace: true,
      afterPrepare: [
        {
          relative: "artifacts/receipt.json",
          bytes: Buffer.from("changed receipt").toString("base64"),
        },
      ],
    },
  ])[0]!;
  expect(response.error).toBe(
    "manifest.scan.artifacts[2]: sealed artifact changed or is missing",
  );
  expect(
    (load(root, "scan-manifest.json")["scan"] as Table)["sealedAt"],
  ).toBeDefined();
  expect(snapshot(root)).not.toHaveProperty("exports/results.sarif");
});

test("optional SARIF failure warns after successfully publishing the scan", () => {
  const root = seed(),
    response = run([
      { operation: "finalize", root, sourceRoot: join(root, "missing-source") },
    ])[0]!;
  expect(response.error).toBeUndefined();
  expect(
    (load(root, "scan-manifest.json")["scan"] as Table)["sealedAt"],
  ).toBeDefined();
  expect(response.stderr.replaceAll("\r\n", "\n")).toBe(
    "codex-security: warning: automatic SARIF export failed: source root: expected an existing directory. Run `codex-security export <scan-dir> --export-format sarif` to retry.\n",
  );
});

test("report retries preserve deep-workbench timing and recoverable failures", () => {
  const root = seed(),
    manifest = load(root, "scan-manifest.json"),
    findings = load(root, "findings.json"),
    coverage = load(root, "coverage.json");
  coverage["mode"] = "deep_repository";
  const source = JSON.stringify({
    manifest,
    findings,
    coverage,
    options: { reportAttempts: 5 },
  });
  const responses = run([
    {
      operation: "report",
      root,
      source,
      reportFault: { remaining: 2, kind: "io" },
    },
    {
      operation: "report",
      root,
      source,
      reportFault: { remaining: 5, kind: "io" },
    },
    {
      operation: "report",
      root,
      source,
      reportFault: { remaining: 5, kind: "value" },
    },
    {
      operation: "report",
      root,
      source,
      reportFault: { remaining: 5, kind: "type" },
    },
    {
      operation: "report",
      root,
      source: JSON.stringify({
        manifest,
        findings,
        coverage: { ...coverage, mode: "repository" },
        options: { reportAttempts: 5 },
      }),
      reportFault: { remaining: 2, kind: "io" },
    },
  ]);
  expect(responses[0]!.error).toBeUndefined();
  expect(responses[0]!.reportCalls).toBe(3);
  expect(responses[0]!.sleeps).toEqual([50, 100]);
  expect(responses[1]!.kind).toBe("RecoverableContractError");
  expect(responses[1]!.reportCalls).toBe(5);
  expect(responses[1]!.sleeps).toEqual([50, 100, 200, 400]);
  expect(responses[2]!.error).toBe(
    "report projection failed: synthetic invalid report",
  );
  expect(responses[2]!.kind).toBe("ContractError");
  expect(responses[2]!.reportCalls).toBe(1);
  expect(responses[3]!.error).toBe("synthetic programming error");
  expect(responses[3]!.kind).toBe("TypeError");
  expect(responses[4]!.kind).toBe("RecoverableContractError");
  expect(responses[4]!.reportCalls).toBe(1);
  expect(responses[4]!.sleeps).toEqual([]);
});

test.skipIf(process.platform === "win32")(
  "failed manifest replacement leaves its earlier writes visible and removes the temporary file",
  () => {
    const root = seed(),
      beforeManifest = readFileSync(join(root, "scan-manifest.json"));
    const response = run([
      { operation: "finalize", root, trace: true, failWriteAt: 4 },
    ])[0]!;
    expect(response.error).toContain("Input/output error");
    expect(readFileSync(join(root, "scan-manifest.json"))).toEqual(
      beforeManifest,
    );
    expect(readFileSync(join(root, "report.md"), "utf8")).not.toBe(
      "old report\n",
    );
    expect(snapshot(root)).not.toHaveProperty("report.html");
    expect(
      Object.keys(snapshot(root)).some((name) => name.endsWith(".tmp")),
    ).toBe(false);
    expect(snapshot(root)).not.toHaveProperty("exports/results.sarif");
  },
);
