import { statSync } from "node:fs";
import { basename, dirname } from "node:path";
import type { Connection, Row } from "../../native/sqlite.mjs";
import { widePath, windowsFileSystem } from "../../native/windows-files.mjs";
import { unixBinding, windowsBinding } from "./native";
import { contractValuesEqual } from "./helpers/contract-validation";
import { fileInfo, readFile } from "./helpers/helper-files";
import { decodePosixBytes, encodePosixPath } from "./helpers/posix-path";
import {
  parsePythonDateTime,
  type PythonDateTime,
} from "./helpers/python-date-time";
import {
  JsonFloat,
  JsonSyntaxError,
  object,
  parseJson,
  pythonRepr,
} from "./helpers/python-json";
import { fullPatternMatch } from "./helpers/python-regex";
import { appendPath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { decodePythonUtf8, UnicodeDecodeError } from "./helpers/utf8";
import { withScanCompletionLock } from "./workbench-completion-lock";
import {
  canonicalDiscoveryArtifacts,
  deepScanDeadlineReached,
  pathExists,
} from "./workbench-deep-files";
import { requireCurrentCoordinator } from "./workbench-deep-lease";
import {
  publicationMatchesSnapshot,
  replacePublicationFile,
  unlinkPublicationFile,
} from "./workbench-deep-publication";
import {
  deepScanResult,
  requireOwnedScan,
  requireRunningDeepScan,
} from "./workbench-deep-state";
import { cancelActiveWorkers } from "./workbench-deep-terminal";
import { requireCurrentContinuation } from "./workbench-handoff";
import { requireScan } from "./workbench-records";
import { requireUuid } from "./workbench-validation";

const windows = process.platform === "win32";
const osError = (error: unknown) =>
  (error as { errno?: number }).errno !== undefined ||
  (error as { winerror?: number }).winerror !== undefined;
const text = (value: unknown): string =>
  typeof value === "string"
    ? value
    : pythonRepr(
        typeof value === "number" ? new JsonFloat(String(value)) : value,
      );
function timestamp(value: unknown): PythonDateTime {
  return parsePythonDateTime(
    typeof value === "string" && /[Zz]$/u.test(value)
      ? value.slice(0, -1) + "+00:00"
      : (value as string),
  );
}
function later(left: PythonDateTime, right: PythonDateTime): boolean {
  if (left.aware !== right.aware)
    throw new TypeError(
      "can't compare offset-naive and offset-aware datetimes",
    );
  return left.microseconds > right.microseconds;
}

export function coordinatorLeaseIsLive(
  connection: Connection,
  run: Row,
  scan: Row,
  current: string,
): boolean {
  if (run.get("coordinator_generation") === 1n) {
    const activeWorker = connection
      .prepare(
        `
            SELECT 1 FROM deep_scan_workers
            WHERE scan_id = ? AND status IN ('queued', 'running')
            LIMIT 1
            `,
      )
      .get([run.get("scan_id")]);
    if (activeWorker === undefined) return false;
    const heartbeat = timestamp(text(run.get("updated_at"))),
      now = timestamp(current);
    return later(heartbeat, {
      ...now,
      microseconds: now.microseconds - 120_000_000n,
    });
  }
  let heartbeat = timestamp(text(run.get("updated_at")));
  const path = appendPath(
    parsedPath(scan.get("scan_dir") as string),
    `artifacts/deep_discovery/coordinator-heartbeat-${text(run.get("coordinator_generation"))}.json`,
  );
  try {
    let raw: Buffer;
    if (windows) {
      const result = windowsBinding().windowsReadFileCrt(widePath(path));
      if (result.errno)
        throw Object.assign(new Error(), { errno: result.errno });
      raw = result.value;
    } else raw = readFile(path);
    const payload = parseJson(decodePythonUtf8(raw).replace(/\r\n?/gu, "\n"));
    if (
      object(payload) &&
      contractValuesEqual(
        payload["coordinatorGeneration"],
        run.get("coordinator_generation"),
      )
    ) {
      const updated = timestamp(payload["updatedAt"]);
      if (later(updated, heartbeat)) heartbeat = updated;
    }
  } catch (error) {
    if (
      !(
        osError(error) ||
        error instanceof TypeError ||
        error instanceof JsonSyntaxError ||
        error instanceof UnicodeDecodeError ||
        (error as Error).name === "ValueError"
      )
    )
      throw error;
  }
  const now = timestamp(current);
  return later(heartbeat, {
    ...now,
    microseconds: now.microseconds - 30_000_000n,
  });
}

function ledgerBackups(ledger: string): string[] {
  const parent = dirname(ledger);
  if (!fileInfo(parent)?.isDirectory()) return [];
  let names: string[];
  try {
    if (windows)
      names = windowsFileSystem(windowsBinding())
        .entriesWithTypes(widePath(parent))
        .map((entry) => entry.name.toString("utf16le"));
    else {
      const result = unixBinding().directoryEntries(
        encodePosixPath(parent),
        false,
      );
      if (result.errno)
        throw Object.assign(new Error(), { errno: result.errno });
      names = result.value.map((entry) => decodePosixBytes(entry.name));
    }
  } catch (error) {
    if (!osError(error)) throw error;
    return [];
  }
  const pattern = `(?${windows ? "is" : "s"}:\\.candidate_ledger\\.jsonl\\..*\\.backup)`;
  return names
    .filter((name) => fullPatternMatch(pattern, name))
    .map((name) => {
      const path = appendPath(parent, name);
      let modified: bigint;
      if (windows) {
        const result = windowsBinding().readCopyStat(widePath(path), true);
        if (result.error)
          throw Object.assign(new Error(), { winerror: result.error, path });
        modified = result.metadata!.mtimeNs;
      } else
        modified = statSync(encodePosixPath(path), { bigint: true }).mtimeNs;
      return { path, modified };
    })
    .sort((left, right) =>
      left.modified > right.modified
        ? -1
        : left.modified < right.modified
          ? 1
          : 0,
    )
    .map(({ path }) => path);
}

export function recoverCandidateLedgerPublication(
  connection: Connection,
  scanId: string,
): void {
  const scan = requireScan(connection, scanId);
  const ledger = appendPath(
    parsedPath(scan.get("scan_dir") as string),
    "artifacts/02_discovery/candidate_ledger.jsonl",
  );
  const backups = ledgerBackups(ledger);
  if (!pathExists(ledger) && !backups.length) return;
  const reducers = connection
    .prepare(
      `
        SELECT status, artifact_dir
        FROM deep_scan_workers
        WHERE scan_id = ? AND kind = 'dedup'
          AND status IN ('queued', 'running', 'succeeded')
        ORDER BY updated_at DESC
        `,
    )
    .iterate([scanId]);
  for (const reducer of reducers) {
    const snapshot = appendPath(
      parsedPath(reducer.get("artifact_dir") as string),
      `canonical/${basename(ledger)}`,
    );
    if (!pathExists(snapshot)) continue;
    const published = publicationMatchesSnapshot(ledger, snapshot),
      interrupted = reducer.get("status") !== "succeeded";
    if (!published && !(interrupted && backups.length && !pathExists(ledger)))
      continue;
    if (interrupted) {
      if (backups.length) replacePublicationFile(backups.shift()!, ledger);
      else unlinkPublicationFile(ledger);
    }
    for (const backup of backups) unlinkPublicationFile(backup);
    return;
  }
}

export function recoverExpiredCoordinator(
  connection: Connection,
  run: Row,
  updated: string,
): void {
  const scanId = run.get("scan_id");
  recoverCandidateLedgerPublication(connection, scanId as string);
  const legacy = run.get("coordinator_generation") === 1n ? 1n : 0n;
  const interrupted = connection
    .prepare(
      `
            SELECT COUNT(*)
            FROM deep_scan_workers
            WHERE scan_id = ? AND kind = 'discovery'
              AND (
                status IN ('queued', 'running')
                OR (
                    status = 'canceled'
                    AND (
                        error_message LIKE 'coordinator_shutdown:%'
                        OR (? = 1 AND error_message IS NULL)
                    )
                )
              )
            `,
    )
    .get([scanId, legacy])!.values[0]!;
  connection
    .prepare(
      `
        UPDATE deep_scan_workers
        SET merge_state = 'buffered', updated_at = ?
        WHERE scan_id = ? AND merge_state = 'merging'
            AND id IN (
                SELECT inputs.discovery_worker_id
                FROM deep_scan_dedup_inputs AS inputs
                JOIN deep_scan_workers AS reducers ON reducers.id = inputs.dedup_worker_id
                WHERE reducers.scan_id = ?
                    AND reducers.kind = 'dedup'
                    AND (
                        reducers.status IN ('queued', 'running', 'failed')
                        OR (
                            reducers.status = 'canceled'
                            AND (
                                reducers.error_message LIKE 'coordinator_shutdown:%'
                                OR (? = 1 AND reducers.error_message IS NULL)
                            )
                        )
                    )
            )
        `,
    )
    .run([updated, scanId, scanId, legacy]);
  cancelActiveWorkers(connection, scanId as string, updated);
  connection
    .prepare(
      `
        UPDATE deep_scan_workers
        SET error_message = 'coordinator_shutdown_recovered: replacement attempt required',
            updated_at = ?
        WHERE scan_id = ? AND status = 'canceled'
            AND (
                error_message LIKE 'coordinator_shutdown:%'
                OR (? = 1 AND error_message IS NULL)
            )
        `,
    )
    .run([updated, scanId, legacy]);
  connection
    .prepare(
      `
        UPDATE deep_scan_runs
        SET discovery_runs_dispatched = discovery_runs_dispatched - ?,
            phase = CASE WHEN phase = 'setup' THEN 'setup' ELSE 'discovery' END,
            updated_at = ?
        WHERE scan_id = ?
        `,
    )
    .run([interrupted, updated, scanId]);
}

export interface ClaimCoordinatorArguments {
  scanId: string;
  threadId: string;
  claimToken: string | null;
  coordinatorGeneration: bigint | null;
}
export interface DeepCoordinatorContext {
  now(): string;
}

export function claimDeepScanCoordinator(
  context: DeepCoordinatorContext,
  connection: Connection,
  args: ClaimCoordinatorArguments,
) {
  const scanId = requireUuid(args.scanId, "scan-id");
  return withScanCompletionLock(scanId, () =>
    claimDeepScanCoordinatorLocked(context, connection, args, scanId),
  );
}

export function claimDeepScanCoordinatorLocked(
  context: DeepCoordinatorContext,
  connection: Connection,
  args: ClaimCoordinatorArguments,
  scanId: string,
) {
  const result = (disposition: string) => ({
    ...deepScanResult(connection, scanId, {
      canonicalDiscoveryArtifacts,
      deepScanDeadlineReached: (run) =>
        deepScanDeadlineReached(run, context.now),
    }),
    coordinatorDisposition: disposition,
  });
  connection.exec("BEGIN IMMEDIATE");
  let disposition: string;
  try {
    const [scan] = requireOwnedScan(connection, scanId, args.threadId);
    requireCurrentContinuation(scan, args.claimToken, {
      errorMessage: "Deep Scan orchestration is owned by another continuation.",
    });
    const [run] = requireRunningDeepScan(connection, scanId);
    const updated = context.now();
    if (args.coordinatorGeneration !== null) {
      requireCurrentCoordinator(run, args);
      disposition = "claimed";
    } else if (coordinatorLeaseIsLive(connection, run, scan, updated)) {
      connection.commit();
      return result("observing");
    } else {
      const adopted =
        (run.get("coordinator_generation") as bigint) > 1n ||
        run.get("phase") !== "setup";
      if (adopted) recoverExpiredCoordinator(connection, run, updated);
      disposition = adopted ? "adopted" : "claimed";
    }
    connection
      .prepare(
        `
            UPDATE deep_scan_runs
            SET coordinator_generation = coordinator_generation + ?, updated_at = ?
            WHERE scan_id = ? AND status = 'running'
            `,
      )
      .run([
        args.coordinatorGeneration !== run.get("coordinator_generation")
          ? 1n
          : 0n,
        updated,
        scanId,
      ]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return result(disposition);
}
