import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { processBinding, sqliteBinding } from "../native";
import { connect } from "../workbench-db";
import { registerCliScan } from "../workbench-cli-registration";
import { TargetInspectionError } from "../workbench-git-snapshot";
import { requireWorkspace } from "../workbench-records";
import { resultCallbacks, workspaceState } from "../workbench-results";
import {
  startHeadlessStandardScan,
  startPromptOnlyScan,
  startScan,
} from "../workbench-scan-kickoff";
import { getScanRecipe, setScanThread } from "../workbench-scan-recipes";
import { createWorkspace, saveWorkspace } from "../workbench-setup";
import { WorkbenchValidationError } from "../workbench-validation";
import { decodePosixBytes } from "./posix-path";
import { stringifyJson } from "./python-json";
import { ArgumentError, argumentsFor, print } from "./rank-worklists";
import { decodePythonUtf8 } from "./utf8";
import { timestamp } from "./utc-timestamp";

type Command =
  | "create-workspace"
  | "save-workspace"
  | "start-scan"
  | "start-prompt-only-scan"
  | "start-headless-standard-scan"
  | "register-cli-scan"
  | "set-scan-thread"
  | "get-scan-recipe";
interface Specification {
  required: string[];
  options: Record<string, readonly string[] | undefined>;
  flags?: string[];
  exclusive?: { names: string[]; required?: boolean }[];
}
const diffOptions = {
  "diff-target-kind": ["working_tree", "commit", "range"],
  "diff-base-revision": undefined,
  "diff-head-revision": undefined,
  "diff-content-digest": undefined,
};
const userContext = { names: ["user-context", "user-context-stdin"] };
const launchOptions = {
  "scan-root": undefined,
  model: undefined,
  "reasoning-effort": undefined,
};
const specifications: Record<Command, Specification> = {
  "create-workspace": {
    required: ["workspace-id"],
    options: {
      "thread-id": undefined,
      "target-path": undefined,
      "target-title": undefined,
      "target-summary": undefined,
      "user-context": undefined,
      scope: undefined,
      mode: ["diff", "standard", "deep"],
      ...diffOptions,
    },
    flags: ["user-context-stdin"],
    exclusive: [userContext],
  },
  "save-workspace": {
    required: ["workspace-id", "target-path", "scope", "mode"],
    options: {
      mode: ["diff", "standard", "deep"],
      "target-summary": undefined,
      "user-context": undefined,
      ...diffOptions,
    },
    flags: ["user-context-stdin"],
    exclusive: [userContext],
  },
  "start-scan": { required: ["workspace-id"], options: launchOptions },
  "start-prompt-only-scan": {
    required: ["thread-id", "target-path", "scope", "mode"],
    options: {
      mode: ["diff", "standard"],
      "target-summary": undefined,
      "user-context": undefined,
      ...diffOptions,
      ...launchOptions,
    },
    flags: ["user-context-stdin"],
    exclusive: [userContext],
  },
  "start-headless-standard-scan": {
    required: ["thread-id", "target-path", "scope"],
    options: {
      "target-summary": undefined,
      "user-context": undefined,
      ...launchOptions,
    },
    flags: ["user-context-stdin"],
    exclusive: [userContext],
  },
  "register-cli-scan": {
    required: ["scan-dir", "repository"],
    options: {
      "recipe-json": undefined,
      "parent-scan-id": undefined,
      "archived-scan-dir": undefined,
    },
    flags: ["recipe-json-stdin", "registration-json-stdin", "archive-existing"],
    exclusive: [
      {
        names: ["recipe-json", "recipe-json-stdin", "registration-json-stdin"],
        required: true,
      },
    ],
  },
  "set-scan-thread": { required: ["scan-id", "thread-id"], options: {} },
  "get-scan-recipe": { required: ["scan-id"], options: {} },
};

export async function workbenchLifecycleCommand(
  command: Command,
  args: string[],
): Promise<number> {
  const spec = specifications[command];
  const argument = (name: string) =>
    `--${name}${spec.flags?.includes(name) ? "" : ` ${spec.options[name] ? `{${spec.options[name]!.join(",")}}` : name.toUpperCase().replaceAll("-", "_")}`}`;
  const optional = [
    ...Object.keys(spec.options).filter(
      (name) => !spec.required.includes(name),
    ),
    ...(spec.flags ?? []),
  ];
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] ${[...spec.required.map(argument), ...optional.map((name) => `[${argument(name)}]`)].join(" ")}`;
  let options: ReturnType<typeof argumentsFor>;
  try {
    // The existing CLI consumes this transport before parsing any command options.
    if (args.includes("--user-context-stdin")) {
      if (
        args.filter((value) => value === "--user-context-stdin").length !== 1 ||
        args.includes("--user-context")
      )
        throw new ArgumentError("pass exactly one user-context transport");
      args = args.map((value) =>
        value === "--user-context-stdin"
          ? `--user-context=${decodePythonUtf8(readFileSync(0))}`
          : value,
      );
    }
    const selected = new Map<number, string>();
    options = argumentsFor(
      args,
      spec.required,
      [],
      spec.options,
      (name) => {
        for (const [index, group] of (spec.exclusive ?? []).entries()) {
          if (!group.names.includes(name)) continue;
          const prior = selected.get(index);
          if (prior !== undefined && prior !== name)
            throw new ArgumentError(
              `argument --${name}: not allowed with argument --${prior}`,
            );
          selected.set(index, name);
        }
      },
      spec.flags ?? [],
      4300,
      [],
      (spec.exclusive ?? [])
        .filter((group) => group.required)
        .map((group) => group.names),
    );
    if (options["help"]) {
      print(
        `${usage}\n\noptions:\n  -h, --help  show this help message and exit\n  ${[...spec.required, ...optional].map(argument).join("\n  ")}`,
      );
      return 0;
    }
  } catch (error) {
    if (!(error instanceof ArgumentError)) throw error;
    print(usage, true);
    print(`${command}: error: ${error.message}`, true);
    return 2;
  }
  const text = (name: string) => (options[name] as string | undefined) ?? null;
  const context = {
    now: () =>
      timestamp(processBinding().wallClockMicroseconds()).replace(
        "+00:00",
        "Z",
      ),
    uuid: randomUUID,
    stdin: () => decodePosixBytes(readFileSync(0)).replace(/\r\n?/g, "\n"),
  };
  try {
    const connection = await connect(sqliteBinding(), context.now);
    try {
      const setup = {
        targetPath: text("target-path")!,
        scope: text("scope")!,
        mode: text("mode") ?? "standard",
        diffTargetKind: text("diff-target-kind"),
        diffBaseRevision: text("diff-base-revision"),
        diffHeadRevision: text("diff-head-revision"),
        diffContentDigest: text("diff-content-digest"),
      };
      const user = {
        targetSummary: text("target-summary"),
        userContext: text("user-context"),
        userContextStdin: options["user-context-stdin"] === true,
      };
      const launch = {
        scanRoot: text("scan-root"),
        model: text("model"),
        reasoningEffort: text("reasoning-effort"),
      };
      let result: unknown;
      switch (command) {
        case "create-workspace":
        case "save-workspace": {
          const callbacks = {
            now: context.now,
            readStdin: context.stdin,
            requireWorkspace,
            workspaceState: (current: typeof connection, id: string) =>
              workspaceState(current, id, resultCallbacks),
          };
          const values = {
            ...setup,
            ...user,
            workspaceId: text("workspace-id")!,
          };
          result =
            command === "create-workspace"
              ? createWorkspace(
                  connection,
                  {
                    ...values,
                    threadId: text("thread-id"),
                    targetTitle: text("target-title"),
                  },
                  callbacks,
                )
              : saveWorkspace(connection, values, callbacks);
          break;
        }
        case "start-scan":
          result = startScan(context, connection, {
            workspaceId: text("workspace-id")!,
            ...launch,
          });
          break;
        case "start-prompt-only-scan":
        case "start-headless-standard-scan": {
          const values = {
            ...setup,
            ...user,
            ...launch,
            threadId: text("thread-id")!,
          };
          result =
            command === "start-prompt-only-scan"
              ? startPromptOnlyScan(context, connection, values)
              : startHeadlessStandardScan(context, connection, values);
          break;
        }
        case "register-cli-scan":
          result = registerCliScan(context, connection, {
            repository: text("repository")!,
            scanDir: text("scan-dir")!,
            recipeJson: text("recipe-json"),
            recipeJsonStdin: options["recipe-json-stdin"] === true,
            registrationJsonStdin: options["registration-json-stdin"] === true,
            parentScanId: text("parent-scan-id"),
            archivedScanDir: text("archived-scan-dir"),
            archiveExisting: options["archive-existing"] === true,
          });
          break;
        case "set-scan-thread":
          result = setScanThread(
            connection,
            { scanId: text("scan-id")!, threadId: text("thread-id")! },
            context.now,
          );
          break;
        case "get-scan-recipe":
          result = getScanRecipe(connection, { scanId: text("scan-id")! });
          break;
      }
      print(
        stringifyJson(result, {
          compact: true,
          allowNan: false,
          sortKeys: true,
        }),
      );
      return 0;
    } finally {
      connection.close();
    }
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
