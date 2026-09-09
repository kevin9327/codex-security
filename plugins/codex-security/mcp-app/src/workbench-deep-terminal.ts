import type { Connection } from "../../native/sqlite.mjs";

export function clearDeepScanPublicationFailure(
  connection: Connection,
  scanId: string,
  now: () => string,
): void {
  connection.transaction(() => {
    connection
      .prepare(
        "UPDATE deep_scan_runs SET publication_error_message = NULL, updated_at = ? " +
          "WHERE scan_id = ? AND publication_error_message IS NOT NULL",
      )
      .run([now(), scanId]);
  });
}

export function failFromParentScan(
  connection: Connection,
  scanId: string,
  message: string | null,
  timestamp: string,
): void {
  connection
    .prepare(
      `UPDATE deep_scan_runs
       SET status = 'failed', phase = 'terminal', cancel_requested = 1,
           error_message = ?, completed_at = ?, updated_at = ?
       WHERE scan_id = ? AND status = 'running'`,
    )
    .run([message, timestamp, timestamp, scanId]);
  cancelActiveWorkers(connection, scanId, timestamp);
}

export function cancelFromParentScan(
  connection: Connection,
  scanId: string,
  timestamp: string,
): void {
  connection
    .prepare(
      `UPDATE deep_scan_runs
       SET status = 'canceled', phase = 'terminal', cancel_requested = 1,
           completed_at = ?, updated_at = ?
       WHERE scan_id = ? AND status IN ('running', 'succeeded')`,
    )
    .run([timestamp, timestamp, scanId]);
  cancelActiveWorkers(connection, scanId, timestamp);
}

export function cancelActiveWorkers(
  connection: Connection,
  scanId: string,
  timestamp: string,
): void {
  connection
    .prepare(
      `UPDATE deep_scan_workers
       SET status = 'canceled', completed_at = ?, updated_at = ?
       WHERE scan_id = ? AND status IN ('queued', 'running')`,
    )
    .run([timestamp, timestamp, scanId]);
}
