import { readFileSync } from "node:fs";
import { processBinding, sqliteBinding } from "../native";
import { connect, databasePath } from "../workbench-db";
import { dashboard, type DashboardQuery } from "../workbench-dashboard";
import {
  findPotentialDuplicates,
  listDedupeGroups,
  listStoredFindings,
  storeDedupeGroups,
  storeFindings,
  type ImportedEntry,
} from "../workbench-findings";
import { parseJson, stringifyJson } from "./python-json";
import { decodePosixBytes } from "./posix-path";
import { ArgumentError, argumentsFor, print } from "./rank-worklists";

type Command =
  | "dashboard"
  | "database-info"
  | "store-findings"
  | "list-stored-findings"
  | "find-potential-duplicates"
  | "store-dedupe-groups"
  | "list-dedupe-groups";

export function timestamp(microseconds: bigint): string {
  const fraction = ((microseconds % 1_000_000n) + 1_000_000n) % 1_000_000n;
  const seconds = new Date(Number((microseconds - fraction) / 1000n))
    .toISOString()
    .slice(0, -5);
  return `${seconds}${fraction === 0n ? "" : `.${fraction.toString().padStart(6, "0")}`}+00:00`;
}

export async function workbenchCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const paging = command === "list-stored-findings";
  const duplicates = command === "find-potential-duplicates";
  const finding = duplicates || command === "list-dedupe-groups";
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h]${paging ? " --limit LIMIT --offset OFFSET" : finding ? " --finding-id FINDING_ID" : ""}${duplicates ? " (--repository-id REPOSITORY_ID | --all-repositories)" : ""}`;
  let options: ReturnType<typeof argumentsFor> = {};
  if (command !== "dashboard" && command !== "database-info") {
    let scope: string | undefined;
    try {
      options = argumentsFor(
        args,
        paging ? ["limit", "offset"] : finding ? ["finding-id"] : [],
        paging ? ["limit", "offset"] : [],
        duplicates ? { "repository-id": undefined } : {},
        (name, value) => {
          if (name === "limit" && (value as bigint) < 1n)
            throw new ArgumentError(
              "argument --limit: expected a positive integer",
            );
          if (name === "offset" && (value as bigint) < 0n)
            throw new ArgumentError(
              "argument --offset: expected a non-negative integer",
            );
          if (name === "repository-id" || name === "all-repositories") {
            if (scope !== undefined && scope !== name)
              throw new ArgumentError(
                `argument --${name}: not allowed with argument --${scope}`,
              );
            scope = name;
          }
        },
        duplicates ? ["all-repositories"] : [],
        4300,
      );
      if (options["help"]) {
        print(
          `${usage}\n\noptions:\n  -h, --help  show this help message and exit${paging ? "\n  --limit LIMIT\n  --offset OFFSET" : finding ? "\n  --finding-id FINDING_ID" : ""}${duplicates ? "\n  --repository-id REPOSITORY_ID\n  --all-repositories" : ""}`,
        );
        return 0;
      }
      if (duplicates && scope === undefined)
        throw new ArgumentError(
          "one of the arguments --repository-id --all-repositories is required",
        );
    } catch (error) {
      print(usage, true);
      print(
        `${command}: error: ${(error as Error).message.replace("--limit: invalid int value:", "--limit: invalid positive_int value:").replace("--offset: invalid int value:", "--offset: invalid non_negative_int value:")}`,
        true,
      );
      return 2;
    }
  }
  const now = () => timestamp(processBinding().wallClockMicroseconds());
  const connection = await connect(sqliteBinding(), now);
  try {
    const input = () =>
      parseJson(
        decodePosixBytes(readFileSync(0)).replace(/\r\n?/g, "\n"),
        false,
        (source) => {
          const digits = source.replace(/^-/, "").length;
          if (digits > 4300)
            throw new Error(
              `Exceeds the limit (4300 digits) for integer string conversion: value has ${digits} digits; use sys.set_int_max_str_digits() to increase the limit`,
            );
          return BigInt(source);
        },
      );
    let result: unknown;
    switch (command) {
      case "database-info":
        result = { databasePath: databasePath() };
        break;
      case "dashboard":
        result = dashboard(
          connection,
          parseJson(readFileSync(0, "utf8")) as DashboardQuery,
        );
        break;
      case "store-findings": {
        const payload = input() as {
          entries: ImportedEntry[];
          repositoryId?: string | null;
        };
        result = storeFindings(
          connection,
          payload.entries,
          now(),
          payload.repositoryId ?? null,
        );
        break;
      }
      case "store-dedupe-groups":
        result = storeDedupeGroups(
          connection,
          (input() as { groups: string[][] }).groups,
          now(),
        );
        break;
      case "list-stored-findings":
        result = listStoredFindings(
          connection,
          options["limit"] as bigint,
          options["offset"] as bigint,
        );
        break;
      case "find-potential-duplicates":
        result = findPotentialDuplicates(
          connection,
          options["finding-id"] as string,
          (options["repository-id"] as string | undefined) ?? null,
        );
        break;
      case "list-dedupe-groups":
        result = listDedupeGroups(connection, options["finding-id"] as string);
        break;
    }
    print(
      stringifyJson(result, { compact: true, allowNan: false, sortKeys: true }),
    );
    return 0;
  } finally {
    connection.close();
  }
}
