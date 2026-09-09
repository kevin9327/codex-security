import { processBinding, sqliteBinding } from "../native";
import { connect } from "../workbench-db";
import { TargetInspectionError } from "../workbench-git-snapshot";
import {
  listFindings,
  resultCallbacks,
  scanContext,
  workspaceState,
} from "../workbench-results";
import { inspectSetup, inspectTarget } from "../workbench-setup";
import { WorkbenchValidationError } from "../workbench-validation";
import { stringifyJson } from "./python-json";
import { ArgumentError, argumentsFor, print } from "./rank-worklists";
import { timestamp } from "./utc-timestamp";

type Command =
  | "inspect-target"
  | "inspect-setup"
  | "get-workspace"
  | "get-scan"
  | "list-findings";
interface Arguments {
  required: string[];
  options: Record<string, readonly string[] | undefined>;
}
const specifications: Record<Command, Arguments> = {
  "inspect-target": { required: ["target-path"], options: {} },
  "inspect-setup": {
    required: ["target-path", "scope", "mode"],
    options: {
      mode: ["diff", "standard", "deep"],
      "diff-target-kind": ["working_tree", "commit", "range"],
      "diff-base-revision": undefined,
      "diff-head-revision": undefined,
      "diff-content-digest": undefined,
    },
  },
  "get-workspace": {
    required: ["workspace-id"],
    options: { "thread-id": undefined },
  },
  "get-scan": {
    required: ["scan-id"],
    options: { "occurrence-id": undefined },
  },
  "list-findings": {
    required: ["scan-id"],
    options: {
      query: undefined,
      severity: ["critical", "high", "medium", "low", "informational"],
      status: ["open", "closed"],
      offset: undefined,
      limit: undefined,
    },
  },
};

export async function workbenchResultsCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const spec = specifications[command];
  const argument = (name: string) =>
    `--${name} ${spec.options[name] ? `{${spec.options[name]!.join(",")}}` : name.toUpperCase().replaceAll("-", "_")}`;
  const parameters = [
    ...spec.required.map(argument),
    ...Object.keys(spec.options)
      .filter((name) => !spec.required.includes(name))
      .map((name) => `[${argument(name)}]`),
  ];
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] ${parameters.join(" ")}`;
  let options: ReturnType<typeof argumentsFor>;
  try {
    options = argumentsFor(
      args,
      spec.required,
      command === "list-findings" ? ["offset", "limit"] : [],
      spec.options,
      (name, value) => {
        if (name === "limit" && (value as bigint) < 1n)
          throw new ArgumentError(
            "argument --limit: expected a positive integer",
          );
        if (name === "offset" && (value as bigint) < 0n)
          throw new ArgumentError(
            "argument --offset: expected a non-negative integer",
          );
      },
      [],
      4300,
    );
    if (options["help"]) {
      print(
        `${usage}\n\noptions:\n  -h, --help  show this help message and exit\n  ${[...spec.required, ...Object.keys(spec.options).filter((name) => !spec.required.includes(name))].map(argument).join("\n  ")}`,
      );
      return 0;
    }
  } catch (error) {
    print(usage, true);
    print(
      `${command}: error: ${(error as Error).message.replace("--limit: invalid int value:", "--limit: invalid positive_int value:").replace("--offset: invalid int value:", "--offset: invalid non_negative_int value:")}`,
      true,
    );
    return 2;
  }
  const text = (name: string) => (options[name] as string | undefined) ?? null;
  const output = (value: unknown) =>
    print(
      stringifyJson(value, { compact: true, allowNan: false, sortKeys: true }),
    );
  try {
    if (command === "inspect-target") {
      output(inspectTarget(text("target-path")!));
      return 0;
    }
    if (command === "inspect-setup") {
      output(
        inspectSetup({
          targetPath: text("target-path")!,
          scope: text("scope")!,
          mode: text("mode")!,
          diffTargetKind: text("diff-target-kind"),
          diffBaseRevision: text("diff-base-revision"),
          diffHeadRevision: text("diff-head-revision"),
          diffContentDigest: text("diff-content-digest"),
        }),
      );
      return 0;
    }
    const connection = await connect(sqliteBinding(), () =>
      timestamp(processBinding().wallClockMicroseconds()).replace(
        "+00:00",
        "Z",
      ),
    );
    try {
      if (command === "get-workspace") {
        output(
          workspaceState(connection, text("workspace-id")!, resultCallbacks, {
            threadId: text("thread-id"),
          }),
        );
      } else if (command === "get-scan") {
        output(
          scanContext(
            connection,
            text("scan-id")!,
            resultCallbacks,
            text("occurrence-id"),
          ),
        );
      } else {
        output(
          listFindings(
            connection,
            {
              scanId: text("scan-id")!,
              query: text("query"),
              severity: text("severity"),
              status: text("status"),
              offset: (options["offset"] as bigint | undefined) ?? 0n,
              limit: (options["limit"] as bigint | undefined) ?? 20n,
            },
            resultCallbacks,
          ),
        );
      }
    } finally {
      connection.close();
    }
    return 0;
  } catch (error) {
    if (
      !(error instanceof WorkbenchValidationError) &&
      !(error instanceof TargetInspectionError)
    )
      throw error;
    print(error.message, true);
    return 1;
  }
}
