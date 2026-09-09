import { readFileSync } from "node:fs";
import { processBinding, sqliteBinding } from "../native";
import { connect, databasePath } from "../workbench-db";
import { dashboard, type DashboardQuery } from "../workbench-dashboard";
import {
  object,
  objectEntries,
  objectFromEntries,
  parseJson,
  stringifyJson,
} from "./python-json";
import { compare } from "./rank-worklists";

function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (object(value))
    return objectFromEntries(
      objectEntries(value)
        .sort(([left], [right]) => compare(left, right))
        .map(([key, child]) => [key, sorted(child)]),
    );
  return value;
}

export function timestamp(microseconds: bigint): string {
  const fraction = ((microseconds % 1_000_000n) + 1_000_000n) % 1_000_000n;
  const seconds = new Date(Number((microseconds - fraction) / 1000n))
    .toISOString()
    .slice(0, -5);
  return `${seconds}${fraction === 0n ? "" : `.${fraction.toString().padStart(6, "0")}`}+00:00`;
}

export async function workbenchReadCommand(
  command: "dashboard" | "database-info",
): Promise<number> {
  const connection = await connect(sqliteBinding(), () =>
    timestamp(processBinding().wallClockMicroseconds()),
  );
  try {
    const result =
      command === "dashboard"
        ? dashboard(
            connection,
            parseJson(readFileSync(0, "utf8")) as DashboardQuery,
          )
        : { databasePath: databasePath() };
    process.stdout.write(
      `${stringifyJson(sorted(result), { compact: true, allowNan: false })}\n`,
    );
    return 0;
  } finally {
    connection.close();
  }
}
