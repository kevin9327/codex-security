import { statSync } from "node:fs";
import { dirname } from "node:path";
import { windowsBinding } from "../native";
import {
  widePath,
  windowsFileSystem,
  windowsJoin,
} from "../../../native/windows-files.mjs";
import { environment } from "./environment";
import { encodePosixPath } from "./posix-path";
import {
  JsonSyntaxError,
  object,
  objectEntries,
  objectFromEntries,
  parseJson,
  pythonRepr,
} from "./python-json";
import { resolvedPath } from "./resolve-path";
import { expandHome, parsedPath } from "./resolve-security-md";
import { readToml } from "./toml-file";
import {
  evaluatePreflightProfile,
  lookupLayeredValue,
  resolveActiveConfigProfile,
  resolvePreflightProfileId,
  validatePreflightRegistry,
  type PreflightLayer,
  type PreflightRegistry,
  type PreflightRuntime,
} from "./config-preflight";

const windows = process.platform === "win32";
const append = (left: string, right: string) =>
  parsedPath(
    windows
      ? windowsJoin(left, right)
      : right.startsWith("/")
        ? right
        : `${left}/${right}`,
  );

export interface PreflightPaths {
  registry: string;
  codexHome: string;
  systemConfig: string;
}
export interface PreflightOptions {
  profile: string | null;
  skill: string | null;
  configs: string[];
  cwd: string;
  configProfile: string | null;
  checks: string[];
  availableSkills: string[] | null;
  effective: string[];
  runtime: PreflightRuntime;
}

export function preflightPaths(
  pluginRoot: string,
  home: string | undefined,
): PreflightPaths {
  return {
    registry: append(pluginRoot, "preflight/capability-profiles.toml"),
    codexHome: parsedPath(
      expandHome(parsedPath(environment("CODEX_HOME") ?? "~/.codex"), home),
    ),
    systemConfig: windows
      ? append(
          environment("ProgramData") ?? "C:\\ProgramData",
          "OpenAI/Codex/config.toml",
        )
      : "/etc/codex/config.toml",
  };
}

function metadata(path: string) {
  if (path.includes("\0")) return undefined;
  try {
    return windows
      ? windowsFileSystem(windowsBinding()).stat(widePath(path))
      : statSync(encodePosixPath(path));
  } catch (error) {
    const { code, winerror } = error as NodeJS.ErrnoException & {
      winerror?: number;
    };
    if (
      ["ENOENT", "ENOTDIR", "EBADF", "ELOOP"].includes(code ?? "") ||
      (windows && [21, 123].includes(winerror ?? 0))
    )
      return undefined;
    throw error;
  }
}

export function projectTrustLevel(
  layers: PreflightLayer[],
  root: string,
): string | null {
  for (let i = layers.length - 1; i >= 0; i--) {
    const projects = layers[i]![1]["projects"];
    if (!object(projects)) continue;
    let project = projects[root];
    if (!object(project) && windows) {
      const key = resolvedPath(root, false).toLowerCase();
      project = objectEntries(projects).find(
        ([path]) => resolvedPath(path, false).toLowerCase() === key,
      )?.[1];
    }
    if (object(project) && typeof project["trust_level"] === "string")
      return project["trust_level"];
  }
  return null;
}

export function discoverPreflightConfig(
  cwd: string,
  basePaths: string[],
  integer: (source: string) => bigint,
  home: string | undefined,
) {
  const resolved = resolvedPath(expandHome(parsedPath(cwd), home), false);
  if (!metadata(resolved)?.isDirectory())
    throw new Error(`cwd must be a directory, got ${pythonRepr(resolved)}`);
  const layers: PreflightLayer[] = basePaths.map((path) => [
    path,
    readToml(path, false, integer),
  ]);
  const [found, configured] = lookupLayeredValue(
    "project_root_markers",
    layers,
  );
  const markers = found ? configured : [".git"];
  if (
    !Array.isArray(markers) ||
    !markers.every((marker) => typeof marker === "string")
  )
    throw new Error("project_root_markers must be an array of strings");
  let root = resolved;
  if (markers.length) {
    for (let candidate = resolved; ; candidate = dirname(candidate)) {
      if (
        markers.some(
          (marker) => metadata(append(candidate, marker)) !== undefined,
        )
      ) {
        root = candidate;
        break;
      }
      if (dirname(candidate) === candidate) break;
    }
  }
  const trust = projectTrustLevel(layers, root);
  const projects: string[] = [];
  if (trust === "trusted") {
    const directories = [resolved];
    while (directories.at(-1) !== root)
      directories.push(dirname(directories.at(-1)!));
    projects.push(
      ...directories
        .reverse()
        .map((path) => append(path, ".codex/config.toml")),
    );
  }
  return {
    paths: [...basePaths, ...projects],
    projectPaths: new Set(projects),
    discovery: {
      cwd: resolved,
      project_root: root,
      project_trust_level: trust,
      project_layers_loaded: trust === "trusted",
    },
  };
}

function assignment(raw: string): [string, string] {
  const index = raw.indexOf("=");
  if (index < 1 || index === raw.length - 1)
    throw new Error(`expected NAME=VALUE, got ${pythonRepr(raw)}`);
  return [raw.slice(0, index), raw.slice(index + 1)];
}

export function preflightInteger(source: string): bigint {
  const setting = environment("PYTHONINTMAXSTRDIGITS");
  const limit = setting ? Number(setting) : 4300;
  if (
    (setting && !/^[\t-\r ]*[+-]?[0-9]+$/u.test(setting)) ||
    !Number.isInteger(limit) ||
    limit < 0 ||
    limit > 2147483647 ||
    (limit > 0 && limit < 640)
  )
    throw new Error(
      "PYTHONINTMAXSTRDIGITS: invalid limit; must be >= 640 or 0 for unlimited.",
    );
  const clean = source.replaceAll("_", "");
  const digits = clean.replace(/^[+-]/u, "").length;
  if (!/^0[box]/u.test(clean) && limit && digits > limit)
    throw new Error(
      `Exceeds the limit (${limit} digits) for integer string conversion: value has ${digits} digits; use sys.set_int_max_str_digits() to increase the limit`,
    );
  return BigInt(clean);
}

export function evaluatePreflight(
  options: PreflightOptions,
  paths: PreflightPaths,
  home: string | undefined,
) {
  const registry = readToml(
    paths.registry,
    true,
    preflightInteger,
  ) as unknown as PreflightRegistry;
  validatePreflightRegistry(registry);
  const profileId = resolvePreflightProfileId(
    registry,
    options.profile,
    options.skill,
  );
  if (
    typeof profileId !== "string" ||
    !Object.hasOwn(registry.profiles, profileId)
  )
    throw new Error(`unknown capability profile: ${pythonRepr(profileId)}`);
  const userConfig = append(paths.codexHome, "config.toml");
  let profilePath: string | null = null;
  let configPaths = options.configs.map(parsedPath);
  let projectPaths = new Set<string>();
  let discovery:
    | ReturnType<typeof discoverPreflightConfig>["discovery"]
    | null = null;
  if (!configPaths.length) {
    if (options.configProfile !== null) {
      if (
        !options.configProfile ||
        /[^A-Za-z0-9_-]/u.test(options.configProfile)
      )
        throw new Error(
          `invalid config profile name ${pythonRepr(options.configProfile)}; pass a plain name such as 'work'`,
        );
      const candidate = append(
        paths.codexHome,
        `${options.configProfile}.config.toml`,
      );
      if (metadata(candidate)?.isFile()) profilePath = candidate;
    }
    const discovered = discoverPreflightConfig(
      options.cwd,
      [
        paths.systemConfig,
        userConfig,
        ...(profilePath === null ? [] : [profilePath]),
      ],
      preflightInteger,
      home,
    );
    configPaths = discovered.paths;
    projectPaths = discovered.projectPaths;
    discovery = discovered.discovery;
  }
  const layers: PreflightLayer[] = configPaths.map((path) => {
    let config = readToml(path, false, preflightInteger);
    if (projectPaths.has(path))
      config = objectFromEntries(
        objectEntries(config).filter(
          ([key]) => key !== "profile" && key !== "profiles",
        ),
      );
    return [path, config];
  });
  const [profile, embedded] = resolveActiveConfigProfile(
    layers,
    options.configProfile,
    options.configProfile !== null,
  );
  const checks = objectFromEntries(
    options.checks.map((raw) => {
      const [key, value] = assignment(raw);
      const normalized = value.toLowerCase();
      if (normalized !== "true" && normalized !== "false")
        throw new Error(`expected true or false, got ${pythonRepr(value)}`);
      return [key, normalized === "true"];
    }),
  ) as Record<string, boolean>;
  const skills = options.availableSkills;
  for (const skill of skills ?? [])
    if (skill.includes(":"))
      throw new Error(
        `expected plugin-local skill name, got ${pythonRepr(skill)}; omit the plugin prefix`,
      );
  const effective = objectFromEntries(
    options.effective.map((raw) => {
      const [key, value] = assignment(raw);
      try {
        return [key, parseJson(value, false, preflightInteger)];
      } catch (error) {
        if (error instanceof JsonSyntaxError)
          throw new Error(
            `expected JSON value for ${pythonRepr(key)}, got ${pythonRepr(value)}`,
          );
        throw error;
      }
    }),
  );
  return {
    ...evaluatePreflightProfile(
      registry,
      profileId,
      { layers, effective, profile: embedded },
      options.runtime,
      checks,
      skills === null ? null : new Set(skills),
    ),
    config_resolution: options.configs.length
      ? "manual-layers"
      : "cwd-discovery",
    user_config_path: options.configs.length ? null : profilePath ?? userConfig,
    config_paths: configPaths,
    config_discovery: discovery,
    config_profile: profile,
    config_profile_path: profilePath,
  };
}

export { filesystemErrorMessage as preflightError } from "./file-errors";
