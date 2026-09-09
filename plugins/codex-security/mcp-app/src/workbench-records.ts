import type { Connection, Row } from "../../native/sqlite.mjs";
import { lowercase } from "./helpers/unicode-case";
import {
  normalizedUuid,
  requireUuid,
  WorkbenchValidationError,
} from "./workbench-validation";

export function requireWorkspace(connection: Connection, value: string): Row {
  const id = requireUuid(value, "workspace-id");
  const row = connection
    .prepare("SELECT * FROM workspaces WHERE id = ?")
    .get([id]);
  if (row === undefined)
    throw new WorkbenchValidationError(
      "Codex Security workspace not found. Reopen it to continue.",
    );
  return row;
}

export function resolveScanId(connection: Connection, value: string): string {
  const canonical = normalizedUuid(value);
  if (canonical !== null) return canonical;
  const length = Array.from(value).length;
  if (length < 8)
    throw new WorkbenchValidationError(
      "Scan ID prefixes must be at least eight characters.",
    );
  const rows = connection
    .prepare("SELECT id FROM scans WHERE substr(id, 1, ?) = ? LIMIT 2")
    .all([BigInt(length), lowercase(value)]);
  if (!rows.length)
    throw new WorkbenchValidationError("Codex Security scan not found.");
  if (rows.length > 1)
    throw new WorkbenchValidationError(
      `Scan ID prefix "${value}" matches multiple scans; use a longer prefix.`,
    );
  return rows[0]!.get("id") as string;
}

export function requireScan(connection: Connection, value: string): Row {
  const id = resolveScanId(connection, value);
  const row = connection.prepare("SELECT * FROM scans WHERE id = ?").get([id]);
  if (row === undefined)
    throw new WorkbenchValidationError("Codex Security scan not found.");
  return row;
}
