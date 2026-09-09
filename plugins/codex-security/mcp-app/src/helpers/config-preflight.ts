import {
  JsonFloat,
  object,
  objectEntries,
  objectFromEntries,
  pythonRepr,
} from "./python-json.js";

type Table = Record<string, unknown>;
export type PreflightLayer = readonly [source: string, config: Table];
export interface PreflightRequirement {
  capability: string;
  severity: string;
  reason: string;
  modes?: string[];
}
export interface PreflightProfile {
  description: string;
  requirements: PreflightRequirement[];
  remediation?: Table;
}
export interface PreflightRegistry {
  version: bigint;
  capabilities: Record<string, Table>;
  profiles: Record<string, PreflightProfile>;
  routes: { skill: string; profile: string }[];
}
export interface PreflightConfig {
  layers: PreflightLayer[];
  effective: Table;
  profile: string | null;
}
export interface PreflightRuntime {
  owner: string | null;
  version: string | null;
  sessionCap: bigint | null;
  provenance: string | null;
}
export interface MultiAgentContext {
  mode: "unknown" | "v1" | "v2" | "bridge-v2";
  owner: string;
  owner_source: string | null;
  version: string;
  version_source: string | null;
  runtime_provenance: string | null;
  config_v2_enabled: boolean;
  agent_max_threads_configured: boolean;
  agent_max_threads: unknown;
  agent_max_threads_source: string | null;
}
export interface PreflightResult extends Table {
  capability: string;
  severity: string;
  reason: string;
  status: "pass" | "fail" | "unknown";
}
type Lookup = [found: boolean, actual: unknown, source: string | null];
const has = (table: Table, key: string) => Object.hasOwn(table, key);
function required(table: Table, key: string): unknown {
  if (!has(table, key)) throw new Error(pythonRepr(key));
  return table[key];
}
function truth(value: unknown): boolean {
  if (value instanceof JsonFloat) return Number(value.source) !== 0;
  if (Array.isArray(value)) return value.length !== 0;
  if (object(value)) return objectEntries(value).length !== 0;
  return Boolean(value);
}
function numeric(value: unknown): number | bigint | undefined {
  if (value instanceof JsonFloat) return Number(value.source);
  if (typeof value === "boolean") return value ? 1n : 0n;
  if (typeof value === "bigint" || typeof value === "number") return value;
  return undefined;
}
function equal(left: unknown, right: unknown): boolean {
  const a = numeric(left),
    b = numeric(right);
  if (a !== undefined && b !== undefined) return a == b;
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right))
    return (
      left.length === right.length &&
      left.every((item, i) => equal(item, right[i]))
    );
  if (object(left) && object(right)) {
    const entries = objectEntries(left);
    return (
      entries.length === objectEntries(right).length &&
      entries.every(
        ([key, value]) => has(right, key) && equal(value, right[key]),
      )
    );
  }
  return false;
}
export function compareCapability(
  actual: unknown,
  op: string,
  expected: unknown,
): boolean {
  if (op === "==") return equal(actual, expected);
  if (op === ">=") {
    if (typeof actual !== "bigint") return false;
    const value = numeric(expected);
    if (value === undefined)
      throw new TypeError(
        "'>=' not supported between instances of 'int' and '" +
          (expected === null
            ? "NoneType"
            : typeof expected === "string"
              ? "str"
              : Array.isArray(expected)
                ? "list"
                : "dict") +
          "'",
      );
    return actual >= value;
  }
  throw new Error(`unsupported comparison operator: ${pythonRepr(op)}`);
}
export function lookupDotted(config: Table, path: string): [boolean, unknown] {
  let current: unknown = config;
  for (const part of path.split(".")) {
    if (!object(current) || !has(current, part)) return [false, null];
    current = current[part];
  }
  return [true, current];
}
export function lookupLayeredValue(
  path: string,
  layers: PreflightLayer[],
): [boolean, unknown] {
  for (let i = layers.length - 1; i >= 0; i--) {
    const result = lookupDotted(layers[i]![1], path);
    if (result[0]) return result;
  }
  return [false, null];
}
function* configViews(config: PreflightConfig): Generator<PreflightLayer> {
  for (let i = config.layers.length - 1; i >= 0; i--) {
    const [source, layer] = config.layers[i]!;
    const profiles = layer["profiles"];
    if (config.profile !== null && object(profiles)) {
      const profile = profiles[config.profile];
      if (object(profile) && has(profile, "features"))
        yield [
          `${source} [profiles.${config.profile}]`,
          { features: profile["features"] },
        ];
    }
    yield [source, layer];
  }
}
export function lookupConfigValue(
  path: string,
  config: PreflightConfig,
  defaults: { value: unknown } | null = null,
): Lookup {
  if (has(config.effective, path))
    return [true, config.effective[path], "effective-config"];
  for (const [source, layer] of configViews(config)) {
    const [found, actual] = lookupDotted(layer, path);
    if (found) return [true, actual, source];
  }
  return defaults
    ? [true, defaults.value, "documented-default"]
    : [false, null, null];
}
export function resolveActiveConfigProfile(
  layers: PreflightLayer[],
  override: string | null,
  cliSelected: boolean,
): [string | null, string | null] {
  if (cliSelected) {
    if (override === null)
      throw new Error(
        "CLI profile selection requires an explicit config profile name",
      );
    return [override, null];
  }
  let profile = override;
  if (profile === null) {
    const [found, configured] = lookupLayeredValue("profile", layers);
    if (!found) return [null, null];
    if (typeof configured !== "string")
      throw new Error("profile must be a string");
    profile = configured;
  }
  const values = layers.flatMap(([, layer]) => {
    const profiles = layer["profiles"];
    return object(profiles) && has(profiles, profile)
      ? [profiles[profile]]
      : [];
  });
  if (!values.length)
    throw new Error(`config profile ${pythonRepr(profile)} not found`);
  if (values.some((value) => !object(value)))
    throw new Error(`config profile ${pythonRepr(profile)} must be a table`);
  return [profile, profile];
}
function mergeValues(base: unknown, overlay: unknown): unknown {
  if (!object(base) || !object(overlay)) return overlay;
  const merged = objectFromEntries(objectEntries(base));
  for (const [key, value] of objectEntries(overlay))
    merged[key] = has(merged, key) ? mergeValues(merged[key], value) : value;
  return merged;
}
export function lookupMultiAgentV2Enabled(
  config: PreflightConfig,
): [boolean, boolean | null, string | null] {
  if (has(config.effective, "features.multi_agent_v2.enabled")) {
    const enabled = config.effective["features.multi_agent_v2.enabled"];
    if (typeof enabled !== "boolean")
      throw new Error("features.multi_agent_v2.enabled must be a boolean");
    return [true, enabled, "effective-config"];
  }
  const values: [string, unknown][] = [];
  for (const [source, layer] of [...configViews(config)].reverse()) {
    const [found, value] = lookupDotted(layer, "features.multi_agent_v2");
    if (found) values.push([source, value]);
  }
  if (has(config.effective, "features.multi_agent_v2"))
    values.push([
      "effective-config",
      config.effective["features.multi_agent_v2"],
    ]);
  if (!values.length) return [false, null, null];
  let merged: unknown = null,
    source: string | null = null;
  for (const [i, [currentSource, value]] of values.entries()) {
    if (i && !(object(merged) && object(value))) source = null;
    merged = i ? mergeValues(merged, value) : value;
    if (typeof value === "boolean" || (object(value) && has(value, "enabled")))
      source = currentSource;
  }
  if (typeof merged === "boolean") return [true, merged, source];
  if (!object(merged))
    throw new Error("features.multi_agent_v2 must be a boolean or table");
  if (!has(merged, "enabled")) return [true, false, "documented-default"];
  const enabled = merged["enabled"];
  if (typeof enabled !== "boolean")
    throw new Error("features.multi_agent_v2.enabled must be a boolean");
  return [true, enabled, source];
}
export function resolveMultiAgentContext(
  config: PreflightConfig,
  runtime: PreflightRuntime,
  validate: boolean,
): MultiAgentContext {
  const supplied =
    runtime.owner !== null ||
    runtime.version !== null ||
    runtime.sessionCap !== null;
  if (supplied && runtime.provenance === null)
    throw new Error(
      "explicit multi-agent runtime facts require --multi-agent-runtime-provenance",
    );
  if (runtime.provenance !== null && !supplied)
    throw new Error(
      "--multi-agent-runtime-provenance requires an explicit runtime owner, version, or cap",
    );
  if (
    runtime.owner === "codex-bridge" &&
    runtime.provenance !== "verified-bridge"
  )
    throw new Error(
      "codex-bridge ownership requires --multi-agent-runtime-provenance verified-bridge",
    );
  if (runtime.owner === "native" && runtime.provenance === "verified-bridge")
    throw new Error("native ownership cannot use verified-bridge provenance");
  const [featureFound, enabled, featureSource] =
    lookupMultiAgentV2Enabled(config);
  const [version, versionSource] =
    runtime.version !== null
      ? [runtime.version, "runtime-fact"]
      : featureFound
        ? [enabled ? "v2" : "v1", featureSource]
        : runtime.owner === "codex-bridge"
          ? ["v2", "runtime-owner"]
          : ["unknown", null];
  const [owner, ownerSource] =
    runtime.owner !== null
      ? [runtime.owner, "runtime-fact"]
      : featureFound
        ? ["native", featureSource]
        : ["unknown", null];
  if (owner === "codex-bridge" && version !== "v2")
    throw new Error(
      "codex-bridge ownership requires multi-agent runtime version v2",
    );
  if (runtime.sessionCap !== null && version !== "v2")
    throw new Error("--multi-agent-session-cap is valid only for a V2 runtime");
  const [bridgeFound, bridgeCap, bridgeSource] = lookupConfigValue(
    "multiagent_config.max_concurrency",
    config,
  );
  if (bridgeFound && owner !== "codex-bridge" && (validate || supplied))
    throw new Error(
      "multiagent_config.max_concurrency does not prove bridge ownership; pass --multi-agent-runtime-owner codex-bridge only when the active runtime is verified as bridge-managed",
    );
  if (
    bridgeFound &&
    runtime.sessionCap !== null &&
    !equal(bridgeCap, runtime.sessionCap)
  )
    throw new Error(
      `conflicting bridge concurrency facts: multiagent_config.max_concurrency from ${bridgeSource} is ${pythonRepr(bridgeCap)}, but --multi-agent-session-cap is ${pythonRepr(runtime.sessionCap)}`,
    );
  const [threadsFound, threads, threadsSource] = lookupConfigValue(
    "agents.max_threads",
    config,
  );
  if (owner !== "codex-bridge" && featureFound && enabled && threadsFound)
    throw new Error(
      "agents.max_threads cannot be set when multi_agent_v2 is enabled",
    );
  return {
    mode:
      version === "v1"
        ? "v1"
        : version === "v2" && owner === "codex-bridge"
          ? "bridge-v2"
          : version === "v2" && owner === "native"
            ? "v2"
            : "unknown",
    owner: owner!,
    owner_source: ownerSource!,
    version: version!,
    version_source: versionSource!,
    runtime_provenance: runtime.provenance,
    config_v2_enabled: featureFound && Boolean(enabled),
    agent_max_threads_configured: threadsFound,
    agent_max_threads: threadsFound ? threads : null,
    agent_max_threads_source: threadsFound ? threadsSource : null,
  };
}
export function profileRequiresMultiAgentConfig(
  profile: PreflightProfile,
  capabilities: Record<string, Table>,
): boolean {
  const runtimePath = (path: unknown) =>
    typeof path === "string" &&
    ([
      "agents",
      "features",
      "features.multi_agent_v2",
      "multiagent_config",
    ].includes(path) ||
      ["agents.", "multiagent_config.", "features.multi_agent_v2."].some(
        (prefix) => path.startsWith(prefix),
      ));
  for (const requirement of profile.requirements) {
    const capability = required(capabilities, requirement.capability) as Table;
    if (
      ["multi_agent_capacity", "multi_agent_mode"].includes(
        required(capability, "kind") as string,
      ) ||
      truth(requirement.modes) ||
      runtimePath(capability["path"])
    )
      return true;
  }
  const remediation = profile.remediation ?? {};
  return (
    truth(remediation["variants"]) ||
    ((remediation["patches"] ?? []) as Table[]).some((patch) =>
      runtimePath(patch["path"]),
    )
  );
}
export function validatePreflightRegistry(registry: PreflightRegistry): void {
  for (const [id] of objectEntries(registry.profiles)) {
    const profile = registry.profiles[id]!;
    for (const requirement of profile.requirements) {
      if (!has(registry.capabilities, requirement.capability))
        throw new Error(
          `profile ${pythonRepr(id)} references unknown capability ${pythonRepr(requirement.capability)}`,
        );
      if (!["block", "warn", "suggest"].includes(requirement.severity))
        throw new Error(
          `profile ${pythonRepr(id)} has unsupported severity ${pythonRepr(requirement.severity)}`,
        );
    }
  }
}
function evaluateCapacity(
  result: Pick<PreflightResult, "capability" | "severity" | "reason">,
  capability: Table,
  config: PreflightConfig,
  context: MultiAgentContext,
  sessionCap: bigint | null,
): PreflightResult {
  const mode = context.mode;
  if (mode === "unknown")
    return {
      ...result,
      status: "unknown",
      check: "active_multi_agent_mode",
    };
  let path: string, found: boolean, actual: unknown, source: string | null;
  if (mode === "v1") {
    path = "agents.max_threads";
    [found, actual, source] = lookupConfigValue(
      path,
      config,
      has(capability, "v1_default")
        ? { value: capability["v1_default"] }
        : null,
    );
  } else if (sessionCap !== null) {
    path = "runtime.multi_agent.session_cap";
    [found, actual, source] = [true, sessionCap, "runtime-fact"];
  } else if (context.owner === "codex-bridge") {
    path = "multiagent_config.max_concurrency";
    [found, actual, source] = lookupConfigValue(path, config);
  } else if (context.owner === "native" && context.config_v2_enabled) {
    path = "features.multi_agent_v2.max_concurrent_threads_per_session";
    [found, actual, source] = lookupConfigValue(path, config, { value: 4n });
  } else {
    path = "runtime.multi_agent.session_cap";
    [found, actual, source] = [false, null, null];
  }
  if (!found)
    return {
      ...result,
      status: "unknown",
      path,
      multi_agent_mode: mode,
    };
  const slots =
    mode !== "v1" && typeof actual === "bigint" ? actual - 1n : actual;
  const op = required(capability, "op") as string,
    expected = required(capability, "value");
  return {
    ...result,
    status: compareCapability(slots, op, expected) ? "pass" : "fail",
    path,
    actual: slots,
    configured_value: actual,
    expected: { op, value: expected },
    source,
    multi_agent_mode: mode,
  };
}
export function evaluatePreflightRequirement(
  requirement: PreflightRequirement,
  capabilities: Record<string, Table>,
  config: PreflightConfig,
  runtimeChecks: Record<string, boolean>,
  availableSkills: Set<string> | null,
  context: MultiAgentContext,
  sessionCap: bigint | null,
): PreflightResult {
  const capability = required(capabilities, requirement.capability) as Table;
  const result = {
    capability: requirement.capability,
    severity: requirement.severity,
    reason: requirement.reason,
  };
  const kind = required(capability, "kind");
  if (kind === "runtime") {
    const check = required(capability, "check") as string;
    if (!has(runtimeChecks, check))
      return { ...result, status: "unknown", check };
    const actual = runtimeChecks[check];
    return { ...result, status: actual ? "pass" : "fail", actual, check };
  }
  if (kind === "multi_agent_mode") {
    const actual = { owner: context.owner, version: context.version };
    const expected = {
      owner: required(capability, "owner"),
      version: required(capability, "version"),
    };
    return Object.values(actual).includes("unknown")
      ? {
          ...result,
          status: "unknown",
          check: "active_multi_agent_mode",
          actual,
          expected,
        }
      : {
          ...result,
          status: equal(actual, expected) ? "pass" : "fail",
          actual,
          expected,
        };
  }
  if (kind === "plugin_skills") {
    const skills = required(capability, "required") as string[],
      plugin = required(capability, "plugin");
    const requiredSkills = skills.map((skill) => `${plugin}:${skill}`);
    if (availableSkills === null)
      return {
        ...result,
        status: "unknown",
        check: "available_plugin_skills",
        required: requiredSkills,
      };
    const unavailable = skills
      .filter((skill) => !availableSkills.has(skill))
      .map((skill) => `${plugin}:${skill}`);
    return {
      ...result,
      status: unavailable.length ? "fail" : "pass",
      unavailable,
      required: requiredSkills,
    };
  }
  if (kind === "multi_agent_capacity")
    return evaluateCapacity(result, capability, config, context, sessionCap);
  const path = required(capability, "path") as string;
  const [found, actual, source] = lookupConfigValue(
    path,
    config,
    kind !== "config_absent" && has(capability, "default")
      ? { value: capability["default"] }
      : null,
  );
  if (kind === "config_absent")
    return found
      ? { ...result, status: "fail", path, actual, expected: "unset", source }
      : { ...result, status: "pass", path, expected: "unset" };
  if (!found) return { ...result, status: "unknown", path };
  const op = required(capability, "op") as string,
    expected = required(capability, "value");
  return {
    ...result,
    status: compareCapability(actual, op, expected) ? "pass" : "fail",
    path,
    actual,
    expected: { op, value: expected },
    source,
  };
}
export function resolvePreflightRemediation(
  profile: PreflightProfile,
  context: MultiAgentContext,
): Table {
  const configured = profile.remediation ?? {};
  const remediation = objectFromEntries(
    objectEntries(configured).filter(([key]) => key !== "variants"),
  );
  const variants = (configured["variants"] ?? []) as Table[];
  remediation["multi_agent_mode"] = context.mode;
  for (const variant of variants) {
    if (required(variant, "mode") !== context.mode) continue;
    if (context.mode === "v2" && context.owner !== "native") break;
    let patches = (variant["patches"] ?? []) as Table[];
    if (context.mode === "v2" && !context.agent_max_threads_configured)
      patches = patches.filter(
        (patch) =>
          !(
            patch["kind"] === "remove" && patch["path"] === "agents.max_threads"
          ),
      );
    remediation["patches"] = [
      ...((remediation["patches"] ?? []) as Table[]),
      ...patches,
    ];
    return remediation;
  }
  if (variants.length)
    remediation["note"] =
      "Do not apply a concurrency patch until the active runtime version and config ownership are known.";
  return remediation;
}
export function evaluatePreflightProfile(
  registry: PreflightRegistry,
  profileId: string,
  config: PreflightConfig,
  runtime: PreflightRuntime,
  checks: Record<string, boolean>,
  availableSkills: Set<string> | null,
) {
  validatePreflightRegistry(registry);
  if (!has(registry.profiles, profileId))
    throw new Error(`unknown capability profile: ${pythonRepr(profileId)}`);
  const profile = registry.profiles[profileId]!;
  const context = resolveMultiAgentContext(
    config,
    runtime,
    profileRequiresMultiAgentConfig(profile, registry.capabilities),
  );
  const results = profile.requirements
    .filter(
      (requirement) =>
        !truth(requirement.modes) || requirement.modes!.includes(context.mode),
    )
    .map((requirement) =>
      evaluatePreflightRequirement(
        requirement,
        registry.capabilities,
        config,
        checks,
        availableSkills,
        context,
        runtime.sessionCap,
      ),
    );
  const failed = results.filter((result) => result.status === "fail"),
    unknown = results.filter((result) => result.status === "unknown");
  const status = failed.some((result) => result.severity === "block")
    ? "blocked"
    : unknown.some((result) => result.severity === "block")
      ? "incomplete"
      : "ready";
  return {
    version: registry.version,
    profile: profileId,
    description: profile.description,
    multi_agent_mode: context.mode,
    multi_agent_context: context,
    status,
    results,
    failed,
    unknown,
    remediation: resolvePreflightRemediation(profile, context),
  };
}
