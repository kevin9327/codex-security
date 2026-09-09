import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  Connection,
  Row,
} from "../../../../plugins/codex-security/native/sqlite.mjs";
import { sqliteBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import { coordinatorLeaseIsLive } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-coordinator";
import { deepScanDeadlineReached } from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-files";

export interface TimestampProbe {
  operation: "deadline" | "coordinator";
  now: string;
  createdAt?: string;
  updatedAt?: string;
  maxTimeHours?: number;
  generation?: number;
  activeWorker?: boolean;
  heartbeat?: { coordinatorGeneration: number; updatedAt: unknown };
}
function execute(probe: TimestampProbe): boolean {
  const generation = probe.generation ?? 1;
  const run = new Row(
    [
      "scan_id",
      "created_at",
      "updated_at",
      "max_time_hours",
      "coordinator_generation",
    ],
    [
      "scan",
      probe.createdAt ?? null,
      probe.updatedAt ?? null,
      probe.maxTimeHours ?? null,
      BigInt(generation),
    ],
  );
  if (probe.operation === "deadline")
    return deepScanDeadlineReached(run, () => probe.now);
  const connection = new Connection(sqliteBinding(), ":memory:");
  const directory = mkdtempSync(join(tmpdir(), "coordinator-timestamp-"));
  try {
    connection.exec(
      "CREATE TABLE deep_scan_workers (scan_id TEXT, status TEXT)",
    );
    if (probe.activeWorker)
      connection
        .prepare("INSERT INTO deep_scan_workers VALUES ('scan', 'running')")
        .run();
    if (probe.heartbeat !== undefined) {
      const path = join(
        directory,
        "artifacts",
        "deep_discovery",
        `coordinator-heartbeat-${generation}.json`,
      );
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, JSON.stringify(probe.heartbeat));
    }
    return coordinatorLeaseIsLive(
      connection,
      run,
      new Row(["scan_dir"], [directory]),
      probe.now,
    );
  } finally {
    connection.close();
    rmSync(directory, { recursive: true, force: true });
  }
}
process.stdout.write(
  JSON.stringify(
    execute(JSON.parse(readFileSync(0, "utf8")) as TimestampProbe),
  ),
);
