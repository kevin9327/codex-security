import { timestamp } from "./utc-timestamp";
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
import {
  listGlobalFindings,
  listRepositories,
  type NavigationQuery,
} from "../workbench-navigation";
import { listScans } from "../workbench-scan-history";

type Command =
  | "dashboard"
  | "database-info"
  | "store-findings"
  | "list-stored-findings"
  | "find-potential-duplicates"
  | "store-dedupe-groups"
  | "list-dedupe-groups"
  | "list-global-findings"
  | "list-repositories"
  | "list-scans";

export { timestamp } from "./utc-timestamp";

export async function workbenchCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const paging = command === "list-stored-findings";
  const duplicates = command === "find-potential-duplicates";
  const finding = duplicates || command === "list-dedupe-groups";
  const navigation =
    command === "list-global-findings" ||
    command === "list-repositories" ||
    command === "list-scans";
  const navigationOptions =
    command === "list-global-findings"
      ? {
          query: undefined,
          severity: ["critical", "high", "medium", "low", "informational"],
          status: ["open", "closed"],
          "target-id": undefined,
          offset: undefined,
          limit: undefined,
        }
      : command === "list-scans"
        ? {
            query: undefined,
            "target-id": undefined,
            status: ["running", "complete", "failed", "canceled"],
            mode: ["diff", "standard", "deep"],
            repository: undefined,
            "scan-root": undefined,
            offset: undefined,
            limit: undefined,
          }
        : {
            query: undefined,
            "target-id": undefined,
            status: ["scanned", "not_scanned", "open_findings"],
            offset: undefined,
            limit: undefined,
          };
  const navigationUsage = Object.entries(navigationOptions)
    .map(
      ([name, choices]) =>
        ` [--${name} ${choices ? `{${choices.join(",")}}` : name.toUpperCase().replaceAll("-", "_")}]`,
    )
    .join("");
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h]${navigation ? navigationUsage : paging ? " --limit LIMIT --offset OFFSET" : finding ? " --finding-id FINDING_ID" : ""}${duplicates ? " (--repository-id REPOSITORY_ID | --all-repositories)" : ""}`;
  let options: ReturnType<typeof argumentsFor> = {};
  if (command !== "dashboard" && command !== "database-info") {
    let scope: string | undefined;
    try {
      options = argumentsFor(
        args,
        paging ? ["limit", "offset"] : finding ? ["finding-id"] : [],
        paging || navigation ? ["limit", "offset"] : [],
        navigation
          ? navigationOptions
          : duplicates
            ? { "repository-id": undefined }
            : {},
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
          `${usage}\n\noptions:\n  -h, --help  show this help message and exit${navigation ? navigationUsage.replaceAll(" [", "\n  ").replaceAll("]", "") : paging ? "\n  --limit LIMIT\n  --offset OFFSET" : finding ? "\n  --finding-id FINDING_ID" : ""}${duplicates ? "\n  --repository-id REPOSITORY_ID\n  --all-repositories" : ""}`,
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
      case "list-scans":
        result = listScans(connection, {
          query: options["query"] as string | undefined,
          targetId: options["target-id"] as string | undefined,
          status: options["status"] as string | undefined,
          mode: options["mode"] as string | undefined,
          repository: options["repository"] as string | undefined,
          scanRoot: options["scan-root"] as string | undefined,
          offset: (options["offset"] as bigint | undefined) ?? 0n,
          limit: options["limit"] as bigint | undefined,
        });
        break;
      case "list-global-findings":
      case "list-repositories": {
        const query: NavigationQuery = {
          query: options["query"] as string | undefined,
          targetId: options["target-id"] as string | undefined,
          severity: options["severity"] as string | undefined,
          status: options["status"] as string | undefined,
          offset: (options["offset"] as bigint | undefined) ?? 0n,
          limit: options["limit"] as bigint | undefined,
        };
        result =
          command === "list-global-findings"
            ? listGlobalFindings(connection, query)
            : listRepositories(connection, query);
        break;
      }
    }
    print(
      stringifyJson(result, { compact: true, allowNan: false, sortKeys: true }),
    );
    return 0;
  } finally {
    connection.close();
  }
}
