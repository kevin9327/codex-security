import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "finalizer-command-")),
);
const node = Bun.which("node")!;
let sequence = 0;
afterAll(() => rmSync(directory, { recursive: true, force: true }));

function scan() {
  const path = join(directory, `scan-${++sequence}`);
  cpSync(join(PLUGIN_ROOT, "examples/completed-scan"), path, {
    recursive: true,
  });
  return path;
}
function run(...args: string[]) {
  return spawnSync(
    node,
    [join(PLUGIN_ROOT, "mcp/helpers.mjs"), "finalize-scan-contract", ...args],
    {
      encoding: "utf8",
      env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
    },
  );
}

test("the packaged finalizer preserves its help and argument error order without Python", () => {
  const help = run("--help");
  expect(help.status, help.stderr).toBe(0);
  expect(help.stderr).toBe("");
  expect(help.stdout).toContain(
    "usage: finalize_scan_contract.py [-h] --scan-dir SCAN_DIR",
  );
  expect(help.stdout).toContain(
    "Validate and seal additive Codex Security scan-contract artifacts.",
  );
  for (const [args, error] of [
    [[], "the following arguments are required: --scan-dir"],
    [["--scan-dir"], "argument --scan-dir: expected one argument"],
    [
      ["--scan-dir", "missing", "--export-format", "xml"],
      "argument --export-format: invalid choice: 'xml' (choose from csv, json, sarif)",
    ],
    [
      [
        "--scan-dir",
        "missing",
        "--sarif-only",
        "--export-format",
        "json",
        "--sarif-output",
        "out",
      ],
      "--sarif-only cannot be combined with --export-format",
    ],
    [
      [
        "--scan-dir",
        "missing",
        "--export-output",
        "out",
        "--sarif-output",
        "out",
      ],
      "--export-output requires --export-format",
    ],
    [
      ["--scan-dir", "missing", "--sarif-output", "out"],
      "--sarif-output requires --sarif-only",
    ],
  ] as const) {
    const result = run(...args);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr.trimEnd().split(/\r?\n/u).at(-1)).toBe(
      `finalize_scan_contract.py: error: ${error}`,
    );
  }
});

test("the packaged finalizer seals unsealed artifacts and generates the report and SARIF without Python", () => {
  const path = scan();
  const manifestPath = join(path, "scan-manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  writeFileSync(manifestPath, JSON.stringify(manifest));
  rmSync(join(path, "report.md"));
  const result = run("--scan-dir", path);
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toBe("");
  expect(result.stderr).toBe("");
  const completed = JSON.parse(readFileSync(manifestPath, "utf8"));
  expect(completed.scan.sealedAt).toBe(completed.scan.completedAt);
  expect(completed.scan.artifacts.length).toBeGreaterThan(0);
  expect(readFileSync(join(path, "report.md"), "utf8")).toContain(
    "Unsafe archive extraction",
  );
  expect(
    JSON.parse(readFileSync(join(path, "exports/results.sarif"), "utf8"))
      .version,
  ).toBe("2.1.0");
});

test("the packaged finalizer preserves raw exports and both SARIF command forms without changing sealed artifacts", () => {
  const path = scan();
  const canonical = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const before = canonical.map((name) => readFileSync(join(path, name)));
  for (const format of ["csv", "json", "sarif"]) {
    const args = ["--scan-dir", path, "--export-format", format];
    const stdout = run(...args);
    expect(stdout.status, stdout.stderr).toBe(0);
    expect(stdout.stderr).toBe("");
    const output = join(directory, `output.${format}`);
    const file = run(...args, "--export-output", output);
    expect(file.status, file.stderr).toBe(0);
    expect(file.stdout).toBe("");
    expect(readFileSync(output, "utf8")).toBe(stdout.stdout);
    if (format === "json") expect(stdout.stdout).toBe(before[1]!.toString());
    if (format === "sarif") {
      const sarif = run("--scan-dir", path, "--sarif-only");
      expect(sarif.status, sarif.stderr).toBe(0);
      expect(sarif.stdout).toBe(stdout.stdout);
      const reserved = join(path, "exports/results.sarif");
      const written = run(
        "--scan-dir",
        path,
        "--sarif-only",
        "--sarif-output",
        reserved,
      );
      expect(written.status, written.stderr).toBe(0);
      expect(written.stdout).toBe("");
      expect(readFileSync(reserved, "utf8")).toBe(sarif.stdout);
    }
  }
  expect(canonical.map((name) => readFileSync(join(path, name)))).toEqual(
    before,
  );
});

test("the packaged finalizer preserves strict failures and leaves invalid canonical files untouched", () => {
  const path = scan();
  const manifestPath = join(path, "scan-manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  writeFileSync(manifestPath, JSON.stringify(manifest));
  const findingsPath = join(path, "findings.json");
  const findings = JSON.parse(readFileSync(findingsPath, "utf8"));
  findings.findings[0].identity.anchor = "Invalid Anchor";
  const contents = JSON.stringify(findings);
  writeFileSync(findingsPath, contents);
  const result = run("--scan-dir", path);
  expect(result.status).toBe(2);
  expect(result.stdout).toBe("");
  expect(result.stderr).toContain("stable lowercase semantic slug");
  expect(readFileSync(findingsPath, "utf8")).toBe(contents);
});

test("the packaged finalizer retains non-contract exception diagnostics and exit status", () => {
  const path = scan();
  const manifestPath = join(path, "scan-manifest.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.scan.status = [];
  writeFileSync(manifestPath, JSON.stringify(manifest));
  const result = run("--scan-dir", path, "--export-format", "json");
  expect(result.status).toBe(1);
  expect(result.stdout).toBe("");
  expect(result.stderr.trimEnd()).toBe("TypeError: unhashable type: 'list'");
});
