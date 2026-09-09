import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import * as os from "node:os";
import { tmpdir } from "node:os";
import { dirname, join, toNamespacedPath } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  inspectPublicationStore,
  preparePublicationStore,
  recordPublishedIssues,
} from "../src/publication-store.js";
import {
  prepareScanPublication,
  type PreparedScanPublication,
} from "../src/publication.js";
import type { FindingsDocument, ScanManifest } from "../src/models.js";
import type { PublishedScanIssue } from "../src/publish.js";
import { runWorkbench } from "../src/runtime.js";
import * as runtime from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { Parameter } from "../../../plugins/codex-security/native/sqlite.mjs";
import { MIGRATIONS } from "../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import { applyMigrations } from "../../../plugins/codex-security/mcp-app/src/workbench-schema";
import {
  withWorkbenchDatabase,
  workbenchRows,
  workbenchSnapshot,
} from "./support/workbench-database.js";

const SCAN_ID = "22222222-2222-4222-8222-222222222222";
const OTHER_SCAN_ID = "33333333-3333-4333-8333-333333333333";
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

interface PublicationFixture {
  environment: NodeJS.ProcessEnv;
  publication: PreparedScanPublication;
  stateDirectory: string;
}

async function publicationFixture(
  options: {
    count?: number;
    createDatabase?: boolean;
    seedScan?: boolean;
    stateDirectoryName?: string;
  } = {},
): Promise<PublicationFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-publication-store-")),
  );
  temporaryDirectories.push(root);
  const scanDirectory = join(root, "completed-scan");
  await mkdir(scanDirectory, { mode: 0o700 });
  const stateDirectory = join(root, options.stateDirectoryName ?? "state");
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: stateDirectory,
    PYTHON: "/unavailable/python",
  };
  const publication: PreparedScanPublication = {
    scanId: SCAN_ID,
    uploadId: SCAN_ID,
    scanDirectory,
    destination: {
      type: "linear",
      teamId: "team-example",
      projectId: "project-example",
    },
    issues: Array.from({ length: options.count ?? 2 }, (_, index) => ({
      findingId: `finding-${index + 1}`,
      occurrenceId: `occurrence-${index + 1}`,
      title: `[Codex Security][HIGH] Example finding ${index + 1}`,
      description: `Example finding ${index + 1}`,
      priority: 2,
    })),
  };
  const fixture = { environment, publication, stateDirectory };
  if (options.createDatabase !== false) {
    await mkdir(stateDirectory, { mode: 0o700 });
    await runWorkbench({ pluginRoot: PLUGIN_ROOT, environment }, [
      "database-info",
    ]);
    if (options.seedScan !== false) seedPublicationScan(fixture, publication);
  }
  return fixture;
}

function seedPublicationScan(
  fixture: PublicationFixture,
  publication: PreparedScanPublication,
): void {
  withWorkbenchDatabase(
    join(fixture.stateDirectory, "workbench.sqlite3"),
    (connection) => {
      connection.exec("PRAGMA foreign_keys = ON");
      connection.transaction(() => {
        const workspaceId = randomUUID(),
          timestamp = "2026-08-01T00:00:00Z";
        connection
          .prepare(
            "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
          )
          .run([workspaceId, timestamp, timestamp]);
        connection
          .prepare(
            "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          )
          .run([
            publication.scanId,
            workspaceId,
            publication.scanDirectory,
            "example-revision",
            ".",
            "standard",
            publication.scanDirectory,
            "complete",
            "reporting",
            timestamp,
            timestamp,
            timestamp,
            timestamp,
          ]);
        for (const issue of publication.issues) {
          connection
            .prepare(
              "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
            )
            .run([
              issue.findingId,
              "fingerprint-" + issue.findingId,
              "example-rule",
              issue.findingId,
              timestamp,
              timestamp,
            ]);
          connection
            .prepare(
              "INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, confidence, remediation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .run([
              issue.occurrenceId,
              issue.findingId,
              publication.scanId,
              issue.title,
              "example summary",
              "high",
              "high",
              "example remediation",
              timestamp,
            ]);
        }
      });
    },
  );
}

function databaseRows(
  fixture: PublicationFixture,
  query: string,
  values: readonly Parameter[] = [],
): Record<string, unknown>[] {
  return workbenchRows(
    join(fixture.stateDirectory, "workbench.sqlite3"),
    query,
    values,
  );
}

function publishedIssue(
  publication: PreparedScanPublication,
  index: number,
  identifier = `EXAMPLE-${index + 1}`,
): PublishedScanIssue {
  const issue = publication.issues[index]!;
  return {
    findingId: issue.findingId,
    occurrenceId: issue.occurrenceId,
    issueIdentifier: identifier,
    url: `https://linear.app/example/issue/${identifier}`,
  };
}

describe("read-only publication history", () => {
  test("preserves native paths in the read-only SQLite URI", async () => {
    const fixture = await publicationFixture({
      stateDirectoryName: "state #% data",
    });
    const stateDirectories = [fixture.stateDirectory];
    if (process.platform === "win32") {
      stateDirectories.push(toNamespacedPath(fixture.stateDirectory));
    }
    for (const stateDirectory of stateDirectories) {
      await expect(
        inspectPublicationStore(fixture.publication, {
          ...fixture.environment,
          CODEX_SECURITY_STATE_DIR: stateDirectory,
        }),
      ).resolves.toEqual([]);
    }
  });

  test("matches the manifest recorded when the scan completed", async () => {
    const fixture = await publicationFixture({ seedScan: false });
    const scanDirectory = fixture.publication.scanDirectory;
    await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDirectory, {
      recursive: true,
    });
    const options = {
      destination: "linear" as const,
      teamId: "team-example",
      projectId: "project-example",
      environment: fixture.environment,
    };
    const original = await prepareScanPublication(scanDirectory, options);
    seedPublicationScan(fixture, original);
    const manifestPath = join(scanDirectory, "scan-manifest.json");
    const originalManifest = await readFile(manifestPath);
    const digest = `sha256:${createHash("sha256").update(originalManifest).digest("hex")}`;
    databaseRows(
      fixture,
      "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
      [digest, original.scanId],
    );
    await expect(
      inspectPublicationStore(original, fixture.environment),
    ).resolves.toEqual([]);

    const findingsPath = join(scanDirectory, "findings.json");
    const findings = JSON.parse(
      await readFile(findingsPath, "utf8"),
    ) as FindingsDocument;
    findings.findings[0]!.summary = "Updated synthetic finding summary.";
    await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);
    const manifest = JSON.parse(originalManifest.toString()) as ScanManifest;
    for (const artifact of manifest.scan.artifacts) {
      artifact.sha256 = createHash("sha256")
        .update(await readFile(join(scanDirectory, artifact.path)))
        .digest("hex");
    }
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const changed = await prepareScanPublication(scanDirectory, options);
    expect(changed.issues[0]!.description).toContain(
      "Updated synthetic finding summary.",
    );
    for (const operation of [
      inspectPublicationStore,
      preparePublicationStore,
    ]) {
      await expect(operation(changed, fixture.environment)).rejects.toThrow(
        /sealed scan manifest changed after completion/u,
      );
    }
    expect(
      databaseRows(
        fixture,
        "SELECT seal_manifest_digest FROM scans WHERE id = ?",
        [original.scanId],
      ),
    ).toEqual([{ seal_manifest_digest: digest }]);
  });

  test("keeps inspection temporaries outside the completed scan", async () => {
    const fixture = await publicationFixture();
    const scan = fixture.publication.scanDirectory;
    const nested = join(scan, "temporary");
    const alias = join(dirname(fixture.stateDirectory), "temporary-link");
    await mkdir(nested);
    await symlink(
      nested,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const temporary = spyOn(os, "tmpdir");
    try {
      for (const root of [scan, nested, alias]) {
        temporary.mockReturnValue(root);
        await expect(
          inspectPublicationStore(fixture.publication, fixture.environment),
        ).rejects.toThrow(/temporary directory must be outside/u);
        expect(await readdir(scan)).toEqual(["temporary"]);
        expect(await readdir(nested)).toEqual([]);
      }
    } finally {
      temporary.mockRestore();
    }
  });

  test("forwards cancellation to the workbench and cleans up its input", async () => {
    const fixture = await publicationFixture();
    const controller = new AbortController();
    const reason = new Error("Synthetic inspection cancellation.");
    let inputFile = "";
    let started!: () => void;
    const inspecting = new Promise<void>((resolve) => {
      started = resolve;
    });
    const workbench = spyOn(runtime, "runWorkbench").mockImplementation(
      async (options, args) => {
        started();
        expect(options.signal).toBe(controller.signal);
        expect(args[0]).toBe("inspect-linear-publication");
        inputFile = args[args.indexOf("--input-file") + 1]!;
        return new Promise<never>((_resolve, reject) => {
          options.signal!.addEventListener(
            "abort",
            () => reject(options.signal!.reason),
            { once: true },
          );
        });
      },
    );
    try {
      const pending = inspectPublicationStore(
        fixture.publication,
        fixture.environment,
        controller.signal,
      );
      await inspecting;
      controller.abort(reason);
      await expect(pending).rejects.toBe(reason);
      expect(inputFile).not.toBe("");
      expect(existsSync(dirname(inputFile))).toBe(false);
    } finally {
      controller.abort(reason);
      workbench.mockRestore();
    }
  });

  test("rejects a pre-aborted inspection before looking for local history", async () => {
    const fixture = await publicationFixture({ createDatabase: false });
    const controller = new AbortController();
    const reason = new Error("Inspection already canceled.");
    controller.abort(reason);
    await expect(
      inspectPublicationStore(
        fixture.publication,
        fixture.environment,
        controller.signal,
      ),
    ).rejects.toBe(reason);
    expect(existsSync(fixture.stateDirectory)).toBe(false);
  });

  test("does not create a missing database or migrate old history", async () => {
    const missing = await publicationFixture({ createDatabase: false });
    await expect(
      inspectPublicationStore(missing.publication, missing.environment),
    ).rejects.toThrow(/scan-history database does not exist/u);
    expect(existsSync(missing.stateDirectory)).toBe(false);

    const fixture = await publicationFixture();
    databaseRows(fixture, "DROP TABLE finding_publications");
    databaseRows(fixture, "DELETE FROM schema_migrations WHERE version >= ?", [
      29,
    ]);
    const database = join(fixture.stateDirectory, "workbench.sqlite3");
    const before = await readFile(database);
    const mode = (await stat(database)).mode;
    await expect(
      inspectPublicationStore(fixture.publication, fixture.environment),
    ).resolves.toEqual([]);
    expect(await readFile(database)).toEqual(before);
    expect((await stat(database)).mode).toBe(mode);
    expect(
      (await readdir(fixture.stateDirectory)).some((name) =>
        name.startsWith("publication-"),
      ),
    ).toBe(false);
    expect(
      databaseRows(
        fixture,
        "SELECT version FROM schema_migrations WHERE version >= ?",
        [29],
      ),
    ).toEqual([]);
    expect(
      databaseRows(
        fixture,
        "SELECT name FROM sqlite_master WHERE name = 'finding_publications'",
      ),
    ).toEqual([]);
  });

  test("reads history from before recorded manifest digests without migrating it", async () => {
    const fixture = await publicationFixture({ createDatabase: false });
    await mkdir(fixture.stateDirectory, { mode: 0o700 });
    const database = join(fixture.stateDirectory, "workbench.sqlite3");
    withWorkbenchDatabase(database, (connection, native) => {
      applyMigrations(
        native,
        connection,
        MIGRATIONS.filter(([version]) => version < 8),
        () => "2026-08-01T00:00:00Z",
        () => {},
      );
    });
    seedPublicationScan(fixture, fixture.publication);
    const before = await readFile(database);
    await expect(
      inspectPublicationStore(fixture.publication, fixture.environment),
    ).resolves.toEqual([]);
    expect(await readFile(database)).toEqual(before);
    expect(
      databaseRows(
        fixture,
        "SELECT MAX(version) AS version FROM schema_migrations",
      ),
    ).toEqual([{ version: 7 }]);
  });

  test("returns one recorded issue per exact scan occurrence and destination", async () => {
    const fixture = await publicationFixture();
    const first = publishedIssue(fixture.publication, 0, "EXAMPLE-101");
    const second = publishedIssue(fixture.publication, 1, "EXAMPLE-102");
    await recordPublishedIssues(
      fixture.publication,
      [second, first],
      fixture.environment,
    );
    await recordPublishedIssues(
      fixture.publication,
      [publishedIssue(fixture.publication, 0, "EXAMPLE-201")],
      fixture.environment,
    );
    const teamOnly: PreparedScanPublication = {
      ...fixture.publication,
      destination: { type: "linear", teamId: "team-example" },
    };
    const withoutProject = publishedIssue(teamOnly, 1, "EXAMPLE-301");
    await recordPublishedIssues(
      teamOnly,
      [withoutProject],
      fixture.environment,
    );

    await expect(
      inspectPublicationStore(fixture.publication, fixture.environment),
    ).resolves.toEqual([first, second]);
    await expect(
      inspectPublicationStore(teamOnly, fixture.environment),
    ).resolves.toEqual([withoutProject]);
    for (const destination of [
      { ...fixture.publication.destination, teamId: "another-team" },
      { ...fixture.publication.destination, projectId: "another-project" },
    ]) {
      await expect(
        inspectPublicationStore(
          { ...fixture.publication, destination },
          fixture.environment,
        ),
      ).resolves.toEqual([]);
    }

    const scanDirectory = join(fixture.stateDirectory, "another-scan");
    await mkdir(scanDirectory, { mode: 0o700 });
    const otherScan: PreparedScanPublication = {
      ...fixture.publication,
      scanId: OTHER_SCAN_ID,
      uploadId: OTHER_SCAN_ID,
      scanDirectory,
      issues: fixture.publication.issues.map((issue) => ({
        ...issue,
        occurrenceId: `other-${issue.occurrenceId}`,
      })),
    };
    seedPublicationScan(fixture, otherScan);
    await expect(
      inspectPublicationStore(otherScan, fixture.environment),
    ).resolves.toEqual([]);
    await expect(
      inspectPublicationStore(
        { ...fixture.publication, issues: [fixture.publication.issues[0]!] },
        fixture.environment,
      ),
    ).rejects.toThrow(/exactly match/u);
  });

  test("includes committed associations that are still in the WAL", async () => {
    const fixture = await publicationFixture({ count: 1 });
    const original = publishedIssue(fixture.publication, 0, "EXAMPLE-401");
    const changed = publishedIssue(fixture.publication, 0, "EXAMPLE-402");
    await recordPublishedIssues(
      fixture.publication,
      [original],
      fixture.environment,
    );
    const database = join(fixture.stateDirectory, "workbench.sqlite3");
    const update = spawnSync(
      process.execPath,
      [
        "--eval",
        `import {withWorkbenchDatabase} from ${JSON.stringify(new URL("./support/workbench-database.ts", import.meta.url).href)};
withWorkbenchDatabase(process.argv[1], (connection) => {
  connection.exec('PRAGMA wal_autocheckpoint = 0');
  connection.transaction(() => connection.prepare('UPDATE finding_publications SET external_id = ?, external_url = ?').run([process.argv[2], process.argv[3]]));
  // Bypass native finalizers so the committed WAL survives the fixture process.
  process.kill(process.pid, 'SIGKILL');
});`,
        database,
        changed.issueIdentifier,
        changed.url!,
      ],
      { encoding: "utf8", env: fixture.environment },
    );
    expect(update.error).toBeUndefined();
    expect(update.stderr).toBe("");
    expect(update.status).not.toBe(0);
    expect(existsSync(`${database}-wal`)).toBe(true);
    await expect(
      inspectPublicationStore(fixture.publication, fixture.environment),
    ).resolves.toEqual([changed]);
  });
});

describe("persisted finding publication associations", () => {
  test("rolls back failed migrations without losing populated scan history", async () => {
    const fixture = await publicationFixture({ count: 1 });
    await recordPublishedIssues(
      fixture.publication,
      [publishedIssue(fixture.publication, 0)],
      fixture.environment,
    );
    databaseRows(
      fixture,
      "INSERT INTO finding_triage (occurrence_id, status, close_reason, note, updated_at) VALUES (?, 'closed', 'false_positive', 'synthetic triage note', '2026-08-01T00:00:00Z')",
      [fixture.publication.issues[0]!.occurrenceId],
    );

    withWorkbenchDatabase(
      join(fixture.stateDirectory, "workbench.sqlite3"),
      (connection, native) => {
        connection.exec("PRAGMA foreign_keys = ON");
        const now = () => "2026-08-01T00:00:00Z";
        const migrate = () =>
          applyMigrations(native, connection, MIGRATIONS, now, () => {});
        migrate();
        const before = workbenchSnapshot(connection);
        expect(() =>
          applyMigrations(
            native,
            connection,
            [
              ...MIGRATIONS,
              [
                MIGRATIONS.at(-1)![0] + 1,
                "synthetic failing migration",
                `
CREATE TABLE synthetic_migration_probe (value TEXT);
INSERT INTO synthetic_migration_probe VALUES ('synthetic');
DELETE FROM finding_triage;
INSERT INTO synthetic_missing_table VALUES (1);
`,
              ],
            ],
            now,
            () => {},
          ),
        ).toThrow("synthetic_missing_table");
        expect(connection.inTransaction).toBe(false);
        expect(workbenchSnapshot(connection)).toEqual(before);
        migrate();
        migrate();
        expect(workbenchSnapshot(connection)).toEqual(before);
        expect(connection.prepare("PRAGMA foreign_key_check").all()).toEqual(
          [],
        );
        expect(connection.prepare("PRAGMA integrity_check").get()!.get(0)).toBe(
          "ok",
        );
        expect(
          Object.fromEntries(
            [
              "scans",
              "finding_occurrences",
              "finding_triage",
              "finding_publications",
            ].map((table) => [
              table,
              Number(
                connection
                  .prepare(`SELECT COUNT(*) FROM ${table}`)
                  .get()!
                  .get(0),
              ),
            ]),
          ),
        ).toEqual({
          scans: 1,
          finding_occurrences: 1,
          finding_triage: 1,
          finding_publications: 1,
        });
      },
    );
  });

  test("upgrades existing scan history and verifies every completed finding before publication", async () => {
    const fixture = await publicationFixture();
    databaseRows(fixture, "DROP TABLE finding_publications");
    databaseRows(
      fixture,
      "DELETE FROM schema_migrations WHERE version IN (?, ?)",
      [29, 30],
    );

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).resolves.toBeUndefined();

    expect(
      databaseRows(
        fixture,
        "SELECT version, name FROM schema_migrations WHERE version BETWEEN ? AND ? ORDER BY version",
        [29, 30],
      ),
    ).toEqual([
      { version: 29, name: "persist finding publication associations" },
      {
        version: 30,
        name: "preserve team-only finding publication associations",
      },
    ]);
    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 0 }]);
  });

  test("upgrades scan history from before stopped-result preservation", async () => {
    const fixture = await publicationFixture();
    databaseRows(
      fixture,
      "ALTER TABLE scans DROP COLUMN retained_source_digests_json",
    );
    databaseRows(
      fixture,
      "ALTER TABLE deep_scan_runs DROP COLUMN publication_error_message",
    );
    databaseRows(
      fixture,
      "DELETE FROM schema_migrations WHERE version BETWEEN ? AND ?",
      [31, 32],
    );

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).resolves.toBeUndefined();

    expect(
      databaseRows(
        fixture,
        "SELECT version, name FROM schema_migrations WHERE version BETWEEN ? AND ? ORDER BY version",
        [31, 32],
      ),
    ).toEqual([
      { version: 31, name: "freeze stopped scan source digests" },
      { version: 32, name: "separate deep scan publication failures" },
    ]);
    expect(
      databaseRows(
        fixture,
        "SELECT name FROM pragma_table_info('scans') WHERE name = 'retained_source_digests_json'",
      ),
    ).toEqual([{ name: "retained_source_digests_json" }]);
    expect(
      databaseRows(
        fixture,
        "SELECT name FROM pragma_table_info('deep_scan_runs') WHERE name = 'publication_error_message'",
      ),
    ).toEqual([{ name: "publication_error_message" }]);
  });

  test("upgrades existing project-scoped associations without changing recorded issues", async () => {
    const fixture = await publicationFixture({ count: 1 });
    const original = publishedIssue(fixture.publication, 0, "EXAMPLE-401");
    await recordPublishedIssues(
      fixture.publication,
      [original],
      fixture.environment,
    );

    databaseRows(
      fixture,
      "DROP INDEX finding_publications_team_only_occurrence",
    );
    databaseRows(
      fixture,
      "DROP INDEX finding_publications_team_only_external_issue",
    );
    databaseRows(fixture, "DELETE FROM schema_migrations WHERE version = ?", [
      30,
    ]);

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).resolves.toBeUndefined();

    expect(
      databaseRows(
        fixture,
        "SELECT version, name FROM schema_migrations WHERE version = ?",
        [30],
      ),
    ).toEqual([
      {
        version: 30,
        name: "preserve team-only finding publication associations",
      },
    ]);
    expect(
      databaseRows(
        fixture,
        "SELECT project_id, external_id FROM finding_publications",
      ),
    ).toEqual([
      {
        project_id: "project-example",
        external_id: original.issueIdentifier,
      },
    ]);
  });

  test("rejects a missing local scan-history database without creating one", async () => {
    const fixture = await publicationFixture({ createDatabase: false });

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).rejects.toThrow(/scan-history database does not exist/u);

    expect(existsSync(fixture.stateDirectory)).toBe(false);
  });

  test("rejects a scan absent from existing local scan history", async () => {
    const fixture = await publicationFixture({ seedScan: false });

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).rejects.toThrow(/scan is not present in the local/u);
    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 0 }]);
  });

  test("rejects an incomplete scan before publication", async () => {
    const fixture = await publicationFixture();
    databaseRows(fixture, "UPDATE scans SET status = ? WHERE id = ?", [
      "running",
      SCAN_ID,
    ]);

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).rejects.toThrow(/Only completed scans/u);
  });

  test("rejects a selected directory that differs from its recorded scan", async () => {
    const fixture = await publicationFixture();
    const anotherDirectory = join(fixture.stateDirectory, "another-scan");
    await mkdir(anotherDirectory, { mode: 0o700 });

    await expect(
      preparePublicationStore(
        { ...fixture.publication, scanDirectory: anotherDirectory },
        fixture.environment,
      ),
    ).rejects.toThrow(/directory does not match/u);
  });

  test("rejects missing, mismatched, or omitted scan findings before publication", async () => {
    const fixture = await publicationFixture();

    for (const issues of [
      [
        {
          ...fixture.publication.issues[0]!,
          occurrenceId: "occurrence-not-in-scan",
        },
        fixture.publication.issues[1]!,
      ],
      [
        { ...fixture.publication.issues[0]!, findingId: "finding-not-in-scan" },
        fixture.publication.issues[1]!,
      ],
      [fixture.publication.issues[0]!],
    ]) {
      await expect(
        preparePublicationStore(
          { ...fixture.publication, issues },
          fixture.environment,
        ),
      ).rejects.toThrow(/finding|occurrence/u);
    }
  });

  test("rejects a real finding occurrence that belongs to another scan", async () => {
    const fixture = await publicationFixture({ count: 1 });
    const anotherDirectory = join(fixture.stateDirectory, "another-scan");
    await mkdir(anotherDirectory, { mode: 0o700 });
    const otherScan: PreparedScanPublication = {
      ...fixture.publication,
      scanId: OTHER_SCAN_ID,
      uploadId: OTHER_SCAN_ID,
      scanDirectory: anotherDirectory,
      issues: [
        {
          ...fixture.publication.issues[0]!,
          findingId: "finding-other-scan",
          occurrenceId: "occurrence-other-scan",
        },
      ],
    };
    seedPublicationScan(fixture, otherScan);

    await expect(
      preparePublicationStore(
        { ...fixture.publication, issues: otherScan.issues },
        fixture.environment,
      ),
    ).rejects.toThrow(/does not belong to the completed scan/u);
  });

  test("returns only database-backed current results in original finding order", async () => {
    const fixture = await publicationFixture();
    const first = publishedIssue(fixture.publication, 0, "EXAMPLE-101");
    const second = publishedIssue(fixture.publication, 1, "EXAMPLE-102");

    const created = await recordPublishedIssues(
      fixture.publication,
      [second, first],
      fixture.environment,
    );

    expect(created).toEqual([first, second]);
    expect(
      databaseRows(
        fixture,
        "SELECT scan_id, finding_id, occurrence_id, destination_type, team_id, project_id, external_id, external_url FROM finding_publications ORDER BY finding_id",
      ),
    ).toEqual([
      {
        scan_id: SCAN_ID,
        finding_id: first.findingId,
        occurrence_id: first.occurrenceId,
        destination_type: "linear",
        team_id: "team-example",
        project_id: "project-example",
        external_id: first.issueIdentifier,
        external_url: first.url,
      },
      {
        scan_id: SCAN_ID,
        finding_id: second.findingId,
        occurrence_id: second.occurrenceId,
        destination_type: "linear",
        team_id: "team-example",
        project_id: "project-example",
        external_id: second.issueIdentifier,
        external_url: second.url,
      },
    ]);
  });

  test("records optional issue URLs without inventing one", async () => {
    const fixture = await publicationFixture({ count: 1 });
    const issue = publishedIssue(fixture.publication, 0);
    delete issue.url;

    await expect(
      recordPublishedIssues(fixture.publication, [issue], fixture.environment),
    ).resolves.toEqual([issue]);
    expect(
      databaseRows(fixture, "SELECT external_url FROM finding_publications"),
    ).toEqual([{ external_url: null }]);
  });

  test("persists team-only issues with a null project and rejects conflicting associations", async () => {
    const fixture = await publicationFixture();
    const publication: PreparedScanPublication = {
      ...fixture.publication,
      destination: {
        type: "linear",
        teamId: fixture.publication.destination.teamId,
      },
    };
    const first = publishedIssue(publication, 0, "EXAMPLE-411");
    const second = publishedIssue(publication, 1, "EXAMPLE-412");

    await expect(
      preparePublicationStore(publication, fixture.environment),
    ).resolves.toBeUndefined();
    await expect(
      recordPublishedIssues(publication, [first], fixture.environment),
    ).resolves.toEqual([first]);
    await expect(
      recordPublishedIssues(publication, [first], fixture.environment),
    ).resolves.toEqual([first]);

    expect(
      databaseRows(
        fixture,
        "SELECT project_id, external_id FROM finding_publications",
      ),
    ).toEqual([{ project_id: null, external_id: first.issueIdentifier }]);

    await expect(
      recordPublishedIssues(
        publication,
        [{ ...second, issueIdentifier: first.issueIdentifier }],
        fixture.environment,
      ),
    ).rejects.toThrow(/already associated with a different finding/u);
    await expect(
      recordPublishedIssues(
        publication,
        [{ ...first, url: "https://linear.app/example/issue/EXAMPLE-OTHER" }],
        fixture.environment,
      ),
    ).rejects.toThrow(/already associated with a different URL/u);

    await expect(
      recordPublishedIssues(publication, [first, second], fixture.environment),
    ).resolves.toEqual([first, second]);
    expect(
      databaseRows(
        fixture,
        "SELECT project_id, external_id FROM finding_publications ORDER BY id",
      ),
    ).toEqual([
      { project_id: null, external_id: first.issueIdentifier },
      { project_id: null, external_id: second.issueIdentifier },
    ]);
  });

  test("replays exact associations without suppressing distinct issues on republish", async () => {
    const fixture = await publicationFixture();
    const original = publishedIssue(fixture.publication, 0, "EXAMPLE-201");
    const replacement = publishedIssue(fixture.publication, 0, "EXAMPLE-202");
    const additional = publishedIssue(fixture.publication, 1, "EXAMPLE-203");

    await expect(
      recordPublishedIssues(
        fixture.publication,
        [original],
        fixture.environment,
      ),
    ).resolves.toEqual([original]);
    await expect(
      recordPublishedIssues(
        fixture.publication,
        [additional, replacement],
        fixture.environment,
      ),
    ).resolves.toEqual([replacement, additional]);
    await expect(
      recordPublishedIssues(
        fixture.publication,
        [additional, replacement],
        fixture.environment,
      ),
    ).resolves.toEqual([replacement, additional]);

    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 3 }]);
    expect(
      databaseRows(
        fixture,
        "SELECT external_id FROM finding_publications WHERE finding_id = ? ORDER BY id",
        [original.findingId],
      ),
    ).toEqual([
      { external_id: original.issueIdentifier },
      { external_id: replacement.issueIdentifier },
    ]);
  });

  test("rejects swapped occurrences, duplicate mappings, and malformed issue IDs", async () => {
    const fixture = await publicationFixture();
    const first = publishedIssue(fixture.publication, 0);
    const second = publishedIssue(fixture.publication, 1);

    for (const records of [
      [{ ...first, occurrenceId: second.occurrenceId }],
      [first, { ...first, issueIdentifier: "EXAMPLE-999" }],
      [first, { ...second, issueIdentifier: first.issueIdentifier }],
      [{ ...first, issueIdentifier: "  " }],
    ]) {
      await expect(
        recordPublishedIssues(
          fixture.publication,
          records,
          fixture.environment,
        ),
      ).rejects.toThrow(/finding|occurrence|issue|association/u);
    }
    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 0 }]);
  });

  test("rolls back the entire import when an issue belongs to another finding", async () => {
    const fixture = await publicationFixture();
    const existing = publishedIssue(fixture.publication, 0, "EXAMPLE-301");
    await recordPublishedIssues(
      fixture.publication,
      [existing],
      fixture.environment,
    );

    await expect(
      recordPublishedIssues(
        fixture.publication,
        [
          publishedIssue(fixture.publication, 0, "EXAMPLE-302"),
          publishedIssue(fixture.publication, 1, existing.issueIdentifier),
        ],
        fixture.environment,
      ),
    ).rejects.toThrow(/already associated with a different finding/u);

    expect(
      databaseRows(
        fixture,
        "SELECT finding_id, external_id FROM finding_publications ORDER BY id",
      ),
    ).toEqual([
      {
        finding_id: existing.findingId,
        external_id: existing.issueIdentifier,
      },
    ]);
  });
});
