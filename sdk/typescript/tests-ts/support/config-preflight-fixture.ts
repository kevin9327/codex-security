import { readFileSync } from "node:fs";
import {
  compareCapability,
  evaluatePreflightProfile,
  lookupConfigValue,
  lookupMultiAgentV2Enabled,
  resolveActiveConfigProfile,
  resolveMultiAgentContext,
  type PreflightConfig,
  type PreflightRegistry,
  type PreflightRuntime,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/config-preflight";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface PreflightRequest {
  action: "profile" | "context" | "lookup" | "v2" | "selected" | "compare";
  config?: Partial<PreflightConfig>;
  runtime?: Partial<PreflightRuntime>;
  registry?: PreflightRegistry;
  profileId?: string;
  checks?: Record<string, boolean>;
  skills?: string[] | null;
  validate?: boolean;
  path?: string;
  defaults?: { value: unknown } | null;
  override?: string | null;
  cliSelected?: boolean;
  actual?: unknown;
  op?: string;
  expected?: unknown;
}
export interface PreflightResponse {
  value?: unknown;
  error?: string;
}
function run(request: PreflightRequest): PreflightResponse {
  const config: PreflightConfig = {
    layers: [],
    effective: {},
    profile: null,
    ...request.config,
  };
  const runtime: PreflightRuntime = {
    owner: null,
    version: null,
    sessionCap: null,
    provenance: null,
    ...request.runtime,
  };
  try {
    const value =
      request.action === "profile"
        ? evaluatePreflightProfile(
            request.registry!,
            request.profileId ?? "scan",
            config,
            runtime,
            request.checks ?? {},
            request.skills === undefined || request.skills === null
              ? null
              : new Set(request.skills),
          )
        : request.action === "context"
          ? resolveMultiAgentContext(config, runtime, request.validate ?? true)
          : request.action === "lookup"
            ? lookupConfigValue(request.path!, config, request.defaults)
            : request.action === "v2"
              ? lookupMultiAgentV2Enabled(config)
              : request.action === "selected"
                ? resolveActiveConfigProfile(
                    config.layers,
                    request.override ?? null,
                    request.cliSelected ?? false,
                  )
                : compareCapability(
                    request.actual,
                    request.op!,
                    request.expected,
                  );
    return { value };
  } catch (error) {
    return { error: (error as Error).message };
  }
}
const requests = parseJson(readFileSync(0, "utf8")) as PreflightRequest[];
process.stdout.write(stringifyJson(requests.map(run), { compact: true }));
