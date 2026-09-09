import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import type { JsonObject } from "./config.js";
import { CodexSecurityError, safeErrorMessage } from "./errors.js";
import { csvRowFinding, parseFindingsCsv } from "./findings-csv.js";
import {
  codexSecurityStateDirectory,
  preparePersistentOutputRoot,
} from "./runtime.js";

interface ImportDependencies {
  environment: NodeJS.ProcessEnv;
  runWorkbench(
    args: readonly string[],
    input?: string,
    signal?: AbortSignal,
  ): Promise<JsonObject>;
}

export async function importScanCsv(
  csvPath: string,
  dependencies: ImportDependencies,
  signal?: AbortSignal,
): Promise<{ scanId: string; scanDir: string; findingCount: number }> {
  const source = await readFile(csvPath, { encoding: "utf8", signal });
  const rows = parseFindingsCsv(source);
  signal?.throwIfAborted();
  const root = await preparePersistentOutputRoot(
    codexSecurityStateDirectory(dependencies.environment),
    "scans",
    basename(csvPath),
  );
  const directory = await mkdtemp(join(root, "import-"));
  // The imported dataset is its own target, independent of the caller's repository.
  const repository = join(directory, "source");
  const scanDir = join(directory, "scan");
  await mkdir(repository, { mode: 0o700 });
  await mkdir(scanDir, { mode: 0o700 });
  await writeFile(join(repository, "findings.csv"), source, {
    flag: "wx",
    signal,
  });
  const workbench = dependencies.runWorkbench;
  let scanId: string | undefined;
  try {
    const registration = await workbench(
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--registration-json-stdin",
      ],
      JSON.stringify({
        recipe: {
          repository,
          target: { kind: "repository", paths: [] },
          mode: "standard",
          config: {},
          importCsv: true,
        },
      }),
      signal,
    );
    if (typeof registration["scanId"] !== "string") {
      throw new CodexSecurityError(
        "CSV import registration did not return a scan ID.",
      );
    }
    scanId = registration["scanId"];
    const description =
      "Findings imported from CSV. No security analysis was performed; source status is retained as metadata.";
    const documents = {
      "scan-manifest.json": {
        scan: {
          target: { kind: "directory_snapshot" },
          scope: {
            summary: description,
            runtimeStatus: "imported",
            limitations: [description],
          },
          extensions: { importCsv: true },
        },
      },
      "findings.json": {
        findings: rows.map((row) => {
          const { findingId, occurrenceId, fingerprints, ...draft } =
            csvRowFinding(row, scanId!);
          return draft;
        }),
      },
      "coverage.json": {
        completeness: "unknown",
        inventoryStrategy: "custom",
        surfaces: rows.map((row) => ({
          id: row.finding_id,
          label: row.title,
          disposition: "reported",
          receiptRefs: [],
        })),
        explicitExclusions: [],
        deferred: [],
      },
    };
    for (const [name, document] of Object.entries(documents)) {
      await writeFile(join(scanDir, name), `${JSON.stringify(document)}\n`, {
        flag: "wx",
        signal,
      });
    }
    await workbench(
      ["prepare-scan-completion", "--scan-id", scanId],
      undefined,
      signal,
    );
    await workbench(["complete-scan", "--scan-id", scanId], undefined, signal);
    return { scanId, scanDir, findingCount: rows.length };
  } catch (error) {
    if (scanId !== undefined) {
      await workbench([
        "fail-scan",
        "--scan-id",
        scanId,
        "--message",
        safeErrorMessage(error),
      ]).catch(() => undefined);
    }
    throw error;
  }
}
