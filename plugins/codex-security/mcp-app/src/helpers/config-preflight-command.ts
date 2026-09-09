import { dirname } from "node:path";
import { ArgumentError, argumentsFor, print } from "./rank-worklists";
import { stringifyJson } from "./python-json";
import { HomeExpansionError, parsedPath } from "./resolve-security-md";
import { SymlinkLoopError } from "./posix-path";
import { environment } from "./environment";
import { resolvedPath } from "./resolve-path";
import {
  evaluatePreflight,
  preflightError,
  preflightPaths,
} from "./preflight-config";

const usage =
  "usage: launch_codex_security_mcp[.cmd] --helper config-preflight [-h] (--profile PROFILE | --skill SKILL) [--registry REGISTRY] [--config CONFIG] [--cwd CWD] [--codex-config-profile CODEX_CONFIG_PROFILE] [--multi-agent-runtime-owner {codex-bridge,native}] [--multi-agent-runtime-version {v1,v2}] [--multi-agent-session-cap MULTI_AGENT_SESSION_CAP] [--multi-agent-runtime-provenance {app-server,thread-context,tool-surface,verified-bridge}] [--runtime-check NAME=BOOL] [--available-plugin-skill SKILL_NAME] [--effective-config PATH=JSON]";
const options = {
  profile: undefined,
  skill: undefined,
  registry: undefined,
  config: undefined,
  cwd: undefined,
  "codex-config-profile": undefined,
  "multi-agent-runtime-owner": ["codex-bridge", "native"],
  "multi-agent-runtime-version": ["v1", "v2"],
  "multi-agent-runtime-provenance": [
    "app-server",
    "thread-context",
    "tool-surface",
    "verified-bridge",
  ],
  "runtime-check": undefined,
  "available-plugin-skill": undefined,
  "effective-config": undefined,
};

export function configPreflightCommand(args: string[]): number {
  const home = environment("HOME");
  const pluginRoot = dirname(dirname(resolvedPath(process.argv[1]!, false)));
  const paths = preflightPaths(pluginRoot, home);
  const repeated = {
    config: [],
    "runtime-check": [],
    "available-plugin-skill": [],
    "effective-config": [],
  } as Record<string, string[]>;
  let values: ReturnType<typeof argumentsFor>;
  let selector: string | undefined;
  try {
    values = argumentsFor(
      args,
      [],
      ["multi-agent-session-cap"],
      options,
      (name, value, raw) => {
        if (name === "profile" || name === "skill") {
          if (selector !== undefined && selector !== name)
            throw new ArgumentError(
              `argument --${name}: not allowed with argument --${selector}`,
            );
          selector = name;
        }
        if (name === "multi-agent-session-cap" && (value as bigint) < 1n)
          throw new ArgumentError(
            "argument --multi-agent-session-cap: expected a positive integer",
          );
        if (Object.hasOwn(repeated, name)) repeated[name]!.push(raw);
      },
    );
    if (values.help) {
      print(
        `${usage}\n\nEvaluate Codex Security capability profiles against the current Codex setup.\n\noptions:\n  -h, --help  show this help message and exit\n  --profile PROFILE  Capability profile id to evaluate.\n  --skill SKILL  Top-level skill id to resolve through registry routes.\n  --registry REGISTRY  Capability registry path (default: bundled registry).\n  --config CONFIG  Config layer, from lower to higher precedence; repeat to override cwd discovery.\n  --cwd CWD  Working directory used to discover trusted project layers (default: current directory).\n  --codex-config-profile CODEX_CONFIG_PROFILE  Selected Codex config profile.\n  --multi-agent-runtime-owner {codex-bridge,native}  Verified active runtime owner.\n  --multi-agent-runtime-version {v1,v2}  Version exposed by the active tool surface.\n  --multi-agent-session-cap MULTI_AGENT_SESSION_CAP  Positive V2 session cap, including the root thread.\n  --multi-agent-runtime-provenance {app-server,thread-context,tool-surface,verified-bridge}  Evidence source for runtime facts.\n  --runtime-check NAME=BOOL  Known runtime capability; repeat for multiple checks.\n  --available-plugin-skill SKILL_NAME  Exposed plugin-local skill; repeat for multiple skills.\n  --effective-config PATH=JSON  Known effective config value; repeat for multiple values.`,
      );
      return 0;
    }
    if (values.profile === undefined && values.skill === undefined)
      throw new ArgumentError(
        "one of the arguments --profile --skill is required",
      );
  } catch (error) {
    print(usage, true);
    print(
      `config-preflight: error: ${(error as Error).message.replace("invalid int value:", "invalid positive_int value:")}`,
      true,
    );
    return 2;
  }
  let payload: ReturnType<typeof evaluatePreflight>;
  try {
    payload = evaluatePreflight(
      {
        profile: (values.profile as string | undefined) ?? null,
        skill: (values.skill as string | undefined) ?? null,
        configs: repeated.config!,
        cwd: (values.cwd as string | undefined) ?? resolvedPath(".", false),
        configProfile:
          (values["codex-config-profile"] as string | undefined) ?? null,
        checks: repeated["runtime-check"]!,
        availableSkills:
          values["available-plugin-skill"] === undefined
            ? null
            : repeated["available-plugin-skill"]!,
        effective: repeated["effective-config"]!,
        runtime: {
          owner:
            (values["multi-agent-runtime-owner"] as string | undefined) ?? null,
          version:
            (values["multi-agent-runtime-version"] as string | undefined) ??
            null,
          sessionCap:
            (values["multi-agent-session-cap"] as bigint | undefined) ?? null,
          provenance:
            (values["multi-agent-runtime-provenance"] as string | undefined) ??
            null,
        },
      },
      {
        ...paths,
        registry:
          values.registry === undefined
            ? paths.registry
            : parsedPath(values.registry as string),
      },
      home,
    );
  } catch (error) {
    if (
      error instanceof HomeExpansionError ||
      error instanceof SymlinkLoopError
    )
      throw error;
    print(
      stringifyJson(
        { status: "error", error: preflightError(error) },
        { sortKeys: true },
      ),
    );
    return 2;
  }
  print(stringifyJson(payload, { sortKeys: true }));
  return payload.status === "blocked"
    ? 1
    : payload.status === "incomplete"
      ? 2
      : 0;
}
