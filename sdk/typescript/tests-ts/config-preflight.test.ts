import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { parse } from "smol-toml";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import {
  JsonFloat,
  objectFromEntries,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type {
  PreflightRegistry,
  PreflightLayer,
} from "../../../plugins/codex-security/mcp-app/src/helpers/config-preflight";
import type {
  PreflightRequest,
  PreflightResponse,
} from "./support/config-preflight-fixture";

const node = Bun.which("node")!;
const directory = mkdtempSync(join(tmpdir(), "config-preflight-"));
const fixture = join(directory, "fixture.cjs");
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/config-preflight-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(requests: PreflightRequest[]): PreflightResponse[] {
  const result = spawnSync(node, [fixture], {
    encoding: "utf8",
    input: stringifyJson(requests),
    env: { ...process.env, PATH: "" },
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as PreflightResponse[];
}
const registry: PreflightRegistry = {
  version: 1n,
  routes: [],
  capabilities: {
    workers: {
      kind: "multi_agent_capacity",
      op: ">=",
      value: 6n,
      v1_default: 6n,
    },
    delegation: { kind: "runtime", check: "delegation_available" },
  },
  profiles: {
    scan: {
      description: "Scan",
      requirements: [
        { capability: "workers", severity: "block", reason: "Workers" },
        { capability: "delegation", severity: "warn", reason: "Delegation" },
      ],
    },
  },
};
const profile = (
  request: Partial<PreflightRequest> = {},
): PreflightRequest => ({ action: "profile", registry, ...request });
function layer(value: Record<string, unknown>): PreflightLayer[] {
  return [["base.toml", value]];
}
test("keeps shipped profiles and advisory delegation behavior", () => {
  const shipped = parse(
    readFileSync(
      join(PLUGIN_ROOT, "preflight/capability-profiles.toml"),
      "utf8",
    ),
    { integersAsBigInt: true },
  ) as unknown as PreflightRegistry;
  const results = run(
    Object.keys(shipped.profiles).map((profileId) =>
      profile({
        registry: shipped,
        profileId,
        checks: { delegation_available: false },
      }),
    ),
  );
  for (const result of results)
    expect(result.value).toMatchObject({ status: "ready" });
  expect(results[2]!.value).toMatchObject({
    profile: "deep_security_scan",
    results: [],
    failed: [],
    unknown: [],
  });
});
test("resolves configured and observed V1, native V2, bridge V2, and unknown capacity", () => {
  const results = run([
    profile(),
    profile({
      runtime: { owner: "native", version: "v1", provenance: "tool-surface" },
    }),
    profile({
      config: { layers: layer({ features: { multi_agent_v2: true } }) },
    }),
    profile({
      config: {
        layers: layer({
          features: {
            multi_agent_v2: {
              enabled: true,
              max_concurrent_threads_per_session: 7n,
            },
          },
        }),
      },
    }),
    profile({
      runtime: { owner: "native", version: "v2", provenance: "thread-context" },
    }),
    profile({
      runtime: {
        owner: "native",
        version: "v2",
        sessionCap: 7n,
        provenance: "app-server",
      },
    }),
    profile({
      runtime: { owner: "codex-bridge", provenance: "verified-bridge" },
      config: { effective: { "multiagent_config.max_concurrency": 7n } },
    }),
  ]);
  expect(
    results.map((result) => (result.value as { status: string }).status),
  ).toEqual([
    "incomplete",
    "ready",
    "blocked",
    "ready",
    "incomplete",
    "ready",
    "ready",
  ]);
  for (const index of [3, 5, 6])
    expect(results[index]!.value).toMatchObject({
      results: [
        { status: "pass", actual: 6, configured_value: 7 },
        { status: "unknown" },
      ],
    });
  expect(results[2]!.value).toMatchObject({
    results: [
      { actual: 3, configured_value: 4, source: "documented-default" },
      { status: "unknown" },
    ],
  });
});
test("preserves effective overrides, layer precedence, and legacy features-only profiles", () => {
  const layers: PreflightLayer[] = [
    [
      "low.toml",
      {
        features: { goals: true },
        agents: { max_depth: 2n },
        profiles: {
          work: { features: { goals: false }, agents: { max_depth: 99n } },
        },
      },
    ],
    ["high.toml", { features: { goals: true } }],
  ];
  expect(
    run([
      {
        action: "lookup",
        path: "features.goals",
        config: { layers, profile: "work" },
      },
      {
        action: "lookup",
        path: "features.goals",
        config: { layers: layers.slice(0, 1), profile: "work" },
      },
      {
        action: "lookup",
        path: "agents.max_depth",
        config: { layers, profile: "work" },
      },
      {
        action: "lookup",
        path: "features.goals",
        config: { layers, effective: { "features.goals": null } },
      },
      { action: "lookup", path: "missing", defaults: { value: false } },
      { action: "lookup", path: "constructor" },
    ]).map((result) => result.value),
  ).toEqual([
    [true, true, "high.toml"],
    [true, false, "low.toml [profiles.work]"],
    [true, 2, "low.toml"],
    [true, null, "effective-config"],
    [true, false, "documented-default"],
    [false, null, null],
  ]);
});
test("merges partial V2 tables and resets inherited enablement when their types change", () => {
  const base: PreflightLayer = [
    "low.toml",
    {
      features: {
        multi_agent_v2: {
          enabled: true,
          max_concurrent_threads_per_session: 7n,
        },
      },
    },
  ];
  const higher = (value: unknown): PreflightLayer => [
    "high.toml",
    { features: { multi_agent_v2: value } },
  ];
  expect(
    run([
      {
        action: "v2",
        config: {
          layers: [base, higher({ max_concurrent_threads_per_session: 8n })],
        },
      },
      { action: "v2", config: { layers: [base, higher(false)] } },
      {
        action: "v2",
        config: {
          layers: [
            higher(true),
            higher({ max_concurrent_threads_per_session: 8n }),
          ],
        },
      },
      {
        action: "v2",
        config: {
          layers: [base],
          effective: { "features.multi_agent_v2": false },
        },
      },
      {
        action: "v2",
        config: {
          layers: [higher("invalid")],
          effective: { "features.multi_agent_v2.enabled": true },
        },
      },
    ]).map((result) => result.value),
  ).toEqual([
    [true, true, "low.toml"],
    [true, false, "high.toml"],
    [true, false, "documented-default"],
    [true, false, "effective-config"],
    [true, true, "effective-config"],
  ]);
});
test("preserves explicit profile selection and legacy profile errors", () => {
  const layers = layer({
    profile: "work",
    profiles: { work: { features: { goals: true } } },
  });
  const results = run([
    { action: "selected", config: { layers } },
    {
      action: "selected",
      config: { layers },
      override: "other",
      cliSelected: true,
    },
    { action: "selected", override: "missing" },
    { action: "selected", config: { layers: layer({ profile: 1n }) } },
    {
      action: "selected",
      override: "work",
      config: { layers: layer({ profiles: { work: false } }) },
    },
  ]);
  expect(results.map((result) => result.value ?? result.error)).toEqual([
    ["work", "work"],
    ["other", null],
    "config profile 'missing' not found",
    "profile must be a string",
    "config profile 'work' must be a table",
  ]);
});
test("retains provenance and conflicting configuration checks", () => {
  const results = run([
    { action: "context", runtime: { owner: "native" } },
    { action: "context", runtime: { provenance: "app-server" } },
    {
      action: "context",
      runtime: { owner: "codex-bridge", provenance: "tool-surface" },
    },
    {
      action: "context",
      runtime: { owner: "native", provenance: "verified-bridge" },
    },
    {
      action: "context",
      config: { effective: { "multiagent_config.max_concurrency": 4n } },
    },
    {
      action: "context",
      config: { effective: { "multiagent_config.max_concurrency": 4n } },
      runtime: {
        owner: "codex-bridge",
        sessionCap: 5n,
        provenance: "verified-bridge",
      },
    },
    {
      action: "context",
      config: {
        layers: layer({
          features: { multi_agent_v2: true },
          agents: { max_threads: 8n },
        }),
      },
    },
    {
      action: "context",
      runtime: { version: "v1", sessionCap: 7n, provenance: "tool-surface" },
    },
  ]);
  for (const result of results) expect(result.error).toBeString();
  expect(results[0]!.error).toContain(
    "require --multi-agent-runtime-provenance",
  );
  expect(results[4]!.error).toContain("does not prove bridge ownership");
  expect(results[5]!.error).toContain(
    "is 4, but --multi-agent-session-cap is 5",
  );
  expect(results[6]!.error).toContain("agents.max_threads cannot be set");
});
test("keeps advisory failures ready and filters requirements and remediation by actual mode", () => {
  const configured: PreflightRegistry = structuredClone(registry);
  configured.profiles["scan"]!.requirements[0]!.severity = "warn";
  configured.profiles["scan"]!.requirements[1]!.modes = ["v1"];
  configured.profiles["scan"]!.remediation = {
    summary: "Configure capacity",
    patches: [{ path: "features.goals", value: true }],
    variants: [
      {
        mode: "v2",
        patches: [
          { kind: "remove", path: "agents.max_threads" },
          {
            path: "features.multi_agent_v2.max_concurrent_threads_per_session",
            value: 7n,
          },
        ],
      },
    ],
  };
  const results = run([
    profile({ registry: configured }),
    profile({
      registry: configured,
      config: { layers: layer({ features: { multi_agent_v2: true } }) },
    }),
  ]);
  expect(results[0]!.value).toMatchObject({
    status: "ready",
    results: [{ status: "unknown" }],
    remediation: {
      note: expect.stringContaining("Do not apply a concurrency patch"),
    },
  });
  expect(results[1]!.value).toMatchObject({
    status: "ready",
    results: [{ status: "fail" }],
    remediation: {
      patches: [
        { path: "features.goals", value: true },
        {
          path: "features.multi_agent_v2.max_concurrent_threads_per_session",
          value: 7,
        },
      ],
    },
  });
});
test("compares Python integer, float, boolean and nested values without rounding integers", () => {
  const requests: PreflightRequest[] = [
    { action: "compare", actual: true, op: ">=", expected: 1n },
    { action: "compare", actual: new JsonFloat("7.0"), op: ">=", expected: 1n },
    { action: "compare", actual: new JsonFloat("7.0"), op: "==", expected: 7n },
    {
      action: "compare",
      actual: 9007199254740993n,
      op: ">=",
      expected: 9007199254740994n,
    },
    {
      action: "compare",
      actual: 9007199254740993n,
      op: "==",
      expected: 9007199254740992n,
    },
    { action: "compare", actual: true, op: "==", expected: 1n },
    {
      action: "compare",
      actual: [1n, { key: false }],
      op: "==",
      expected: [true, { key: 0n }],
    },
  ];
  expect(run(requests).map((result) => result.value)).toEqual([
    false,
    false,
    true,
    false,
    false,
    true,
    true,
  ]);
});

test("reports the first invalid profile in document order for integer-looking IDs", () => {
  const invalid = {
    description: "Synthetic profile",
    requirements: [
      { capability: "missing", severity: "block", reason: "Check" },
    ],
  };
  const profiles = objectFromEntries([
    ["10", invalid],
    ["2", invalid],
  ]) as PreflightRegistry["profiles"];
  const result = run([
    profile({
      registry: { version: 1n, capabilities: {}, profiles, routes: [] },
      profileId: "10",
    }),
  ])[0]!;
  expect(result.error).toBe(
    "profile '10' references unknown capability 'missing'",
  );
});
