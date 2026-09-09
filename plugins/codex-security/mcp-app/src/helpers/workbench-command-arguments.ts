import { readFileSync } from "node:fs";
import { ArgumentError, argumentsFor, print } from "./rank-worklists";
import { decodePythonUtf8 } from "./utf8";

export interface WorkbenchCommandSpecification {
  description?: string;
  optionHelp?: Record<string, string>;
  required: string[];
  options: Record<string, readonly string[] | undefined>;
  flags?: string[];
  exclusive?: { names: string[]; required?: boolean }[];
  positiveIntegers?: string[];
  nonNegativeIntegers?: string[];
  repeated?: string[];
}
export function parseWorkbenchCommandArguments(
  command: string,
  args: string[],
  spec: WorkbenchCommandSpecification,
):
  | number
  | {
      values: ReturnType<typeof argumentsFor>;
      repeated: Record<string, string[]>;
    } {
  const argument = (name: string) =>
    `--${name}${spec.flags?.includes(name) ? "" : ` ${spec.options[name] ? `{${spec.options[name]!.join(",")}}` : name.toUpperCase().replaceAll("-", "_")}`}`;
  const optional = [
    ...Object.keys(spec.options).filter(
      (name) => !spec.required.includes(name),
    ),
    ...(spec.flags ?? []),
  ];
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] ${[...spec.required.map(argument), ...optional.map((name) => `[${argument(name)}]`)].join(" ")}`;
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
    const selected = new Map<number, string>(),
      repeated: Record<string, string[]> = {};
    const values = argumentsFor(
      args,
      spec.required,
      [...(spec.positiveIntegers ?? []), ...(spec.nonNegativeIntegers ?? [])],
      spec.options,
      (name, value) => {
        for (const [index, group] of (spec.exclusive ?? []).entries()) {
          if (!group.names.includes(name)) continue;
          const prior = selected.get(index);
          if (prior !== undefined && prior !== name)
            throw new ArgumentError(
              `argument --${name}: not allowed with argument --${prior}`,
            );
          selected.set(index, name);
        }
        if (spec.positiveIntegers?.includes(name) && (value as bigint) < 1n)
          throw new ArgumentError(
            `argument --${name}: expected a positive integer`,
          );
        if (spec.nonNegativeIntegers?.includes(name) && (value as bigint) < 0n)
          throw new ArgumentError(
            `argument --${name}: expected a non-negative integer`,
          );
        if (spec.repeated?.includes(name))
          (repeated[name] ??= []).push(value as string);
      },
      spec.flags ?? [],
      4300,
      [],
      (spec.exclusive ?? [])
        .filter((group) => group.required)
        .map((group) => group.names),
    );
    if (values["help"]) {
      print(
        `${usage}${spec.description ? `\n\n${spec.description}` : ""}\n\noptions:\n  -h, --help  show this help message and exit\n  ${[...spec.required, ...optional].map((name) => argument(name) + (spec.optionHelp?.[name] ? `  ${spec.optionHelp[name]}` : "")).join("\n  ")}`,
      );
      return 0;
    }
    return { values, repeated };
  } catch (error) {
    if (!(error instanceof ArgumentError)) throw error;
    const message = error.message.replace(
      /^argument --([^:]+): invalid int value:/,
      (text, name: string) =>
        spec.positiveIntegers?.includes(name)
          ? text.replace("invalid int", "invalid positive_int")
          : spec.nonNegativeIntegers?.includes(name)
            ? text.replace("invalid int", "invalid non_negative_int")
            : text,
    );
    print(usage, true);
    print(`${command}: error: ${message}`, true);
    return 2;
  }
}
