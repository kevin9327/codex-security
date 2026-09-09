import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import Papa from "papaparse";
import { main } from "../src/cli.js";
import { importScanCsv } from "../src/scan-import.js";
import { loadContract } from "../src/contract.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

function csv(count = 2) {
  return Papa.unparse(
    Array.from({ length: count }, (_, index) => ({
      occurrence_id: `occ_${index.toString(16).padStart(24, "0")}`,
      finding_id: `csf_${index.toString(16).padStart(24, "0")}`,
      candidate_id: `source-${index}`,
      title: "Same reported issue",
      summary:
        'A quoted "report", with a newline.\n' +
        "Details. ".repeat(index === 0 ? 18000 : 1),
      severity: "high",
      confidence: "medium",
      status: index === 0 ? "closed" : "open",
      close_reason: index === 0 ? "wont_fix" : "",
      note: index === 0 ? "Source closed this report." : "",
      remediation: "Check access before returning the record.",
      path: "src/example.ts",
      start_line: "10",
      end_line: "11",
    })),
  );
}

async function fixture(source = csv()) {
  const root = await mkdtemp(
    join(await realpath(tmpdir()), "scan-import-test-"),
  );
  roots.push(root);
  const repository = join(root, "caller");
  await mkdir(repository);
  const csvPath = join(repository, "findings.csv");
  await writeFile(csvPath, source);
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_HOME: join(root, "home"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const workbench: Parameters<typeof importScanCsv>[1]["runWorkbench"] = (
    args,
    input,
    signal,
  ) =>
    runWorkbench(
      { python: python!, pluginRoot: PLUGIN_ROOT, environment, signal },
      args,
      input,
    );
  return { root, repository, csvPath, environment, workbench, source };
}

test("scan import saves 5000 distinct rows in SQLite and seals ordinary scan artifacts", async () => {
  const { repository, csvPath, environment, workbench, source } = await fixture(
    csv(5000),
  );
  const output = capture();
  const errors = capture();
  expect(
    await main(
      ["scan", "import", "--csv", "findings.csv", "--json"],
      output.stream,
      errors.stream,
      dependencies({
        currentDirectory: repository,
        environment,
        onWorkbench: workbench,
        onRun: () => {
          throw new Error("Import started analysis");
        },
      }),
    ),
    errors.text(),
  ).toBe(0);
  expect(errors.text()).toBe("");
  const result = JSON.parse(output.text());
  expect(result.findingCount).toBe(5000);
  const contract = await loadContract(result.scanDir, {
    pluginRoot: PLUGIN_ROOT,
  });
  expect(contract.manifest.scan.status).toBe("completed");
  expect(contract.manifest.scan.target.kind).toBe("directory_snapshot");
  expect(contract.coverage.completeness).toBe("unknown");
  const findings = contract.findings.findings;
  expect(findings).toHaveLength(5000);
  expect(new Set(findings.map((finding) => finding.findingId)).size).toBe(5000);
  expect(new Set(findings.map((finding) => finding.occurrenceId)).size).toBe(
    5000,
  );
  const closed = findings.find(
    (finding) => finding.extensions?.["candidateId"] === "source-0",
  )!;
  expect(closed.summary).toBe(
    Papa.parse<Record<string, string>>(source, { header: true }).data[0]![
      "summary"
    ]!,
  );
  expect(closed.provenance).toEqual({ source: "csv_import" });
  expect(closed.validation?.status).toBe("closed");
  expect(closed.validation?.summary).toContain("Source close reason: wont_fix");
  const sourceDir = join(dirname(result.scanDir), "source");
  expect(await readFile(join(sourceDir, "findings.csv"), "utf8")).toBe(source);
  expect(await readFile(csvPath, "utf8")).toBe(source);
  expect(await readdir(repository)).toEqual(["findings.csv"]);
  const history = await workbench(["list-scans", "--repository", sourceDir]);
  expect(history["scans"]).toHaveLength(1);
  expect(
    (await workbench(["list-scans", "--repository", repository]))["scans"],
  ).toHaveLength(0);
  const indexed = await workbench(["get-scan", "--scan-id", result.scanId]);
  expect(indexed["scan"]).toMatchObject({
    findingCount: 5000,
    progress: { status: "complete" },
  });
  const rerunErrors = capture();
  expect(
    await main(
      ["scans", "rerun", result.scanId],
      capture().stream,
      rerunErrors.stream,
      dependencies({ onWorkbench: workbench }),
    ),
  ).toBe(2);
  expect(rerunErrors.text()).toContain("scan import --csv");
}, 120_000);

test("invalid CSV is rejected before registering a scan or creating state", async () => {
  const { root, csvPath, environment } = await fixture("title\nIncomplete\n");
  await expect(
    importScanCsv(csvPath, {
      environment,
      runWorkbench: async () => {
        throw new Error("Unexpected workbench call");
      },
    }),
  ).rejects.toThrow("export columns");
  expect(await readdir(root)).toEqual(["caller"]);
});

test("a failed import leaves a terminal failed scan", async () => {
  const { csvPath, environment, workbench } = await fixture();
  let scanId: string | undefined;
  await expect(
    importScanCsv(csvPath, {
      environment,
      runWorkbench: async (args, input, signal) => {
        if (args[0] === "prepare-scan-completion")
          throw new Error("Completion failed");
        const result = await workbench(args, input, signal);
        if (args[0] === "register-cli-scan")
          scanId = result["scanId"] as string;
        return result;
      },
    }),
  ).rejects.toThrow("Completion failed");
  const scan = await workbench(["get-scan", "--scan-id", scanId!]);
  expect(scan["scan"]).toMatchObject({ progress: { status: "failed" } });
});

test("scan import exposes its CSV option in help and schema and requires it", async () => {
  for (const flag of ["--help", "--schema"]) {
    const output = capture();
    expect(
      await main(
        ["scan", "import", flag],
        output.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(output.text()).toContain("csv");
  }
  expect(
    await main(
      ["scan", "import"],
      capture().stream,
      capture().stream,
      dependencies(),
    ),
  ).not.toBe(0);
});

test("canceling CSV completion marks the scan failed and removes signal listeners", async () => {
  const { csvPath, environment, workbench } = await fixture();
  const signals = new FakeSignals();
  let scanId: string | undefined;
  const exitCode = await main(
    ["scan", "import", "--csv", csvPath],
    capture().stream,
    capture().stream,
    dependencies({
      environment,
      signals,
      onWorkbench: async (args, input, signal) => {
        if (args[0] === "prepare-scan-completion") {
          signals.emit("SIGINT");
          signal!.throwIfAborted();
        }
        const result = await workbench(args, input, signal);
        if (args[0] === "register-cli-scan")
          scanId = result["scanId"] as string;
        return result;
      },
    }),
  );
  expect(exitCode).toBe(130);
  const scan = await workbench(["get-scan", "--scan-id", scanId!]);
  expect(scan["scan"]).toMatchObject({ progress: { status: "failed" } });
  expect(
    [...signals.listeners.values()].every((listeners) => listeners.size === 0),
  ).toBe(true);
});
