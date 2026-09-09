import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("registers security access through the Codex Security MCP, not a hosted app", async () => {
  const [appConfiguration, mcpConfiguration] = await Promise.all([
    readFile(join(PLUGIN_ROOT, ".app.json"), "utf8"),
    readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
  ]);
  const apps = (JSON.parse(appConfiguration) as Record<string, unknown>)[
    "apps"
  ] as Record<string, unknown>;
  const mcpServers = (JSON.parse(mcpConfiguration) as Record<string, unknown>)[
    "mcpServers"
  ] as Record<string, unknown>;

  expect(apps).not.toHaveProperty("codex-security-access");
  expect(
    Object.values(apps).some(
      (app) =>
        (app as Record<string, unknown>)["id"] ===
        "connector_openai_codex_security_access",
    ),
  ).toBe(false);
  expect(mcpServers).toHaveProperty("codex-security");
  expect(mcpServers).not.toHaveProperty("codex-security-access");
});

test("tracking providers are available on demand and the deep-scan override reaches MCP", async () => {
  const read = async (name: string): Promise<Record<string, unknown>> =>
    JSON.parse(await readFile(join(PLUGIN_ROOT, name), "utf8")) as Record<
      string,
      unknown
    >;
  const apps = (await read(".app.json"))["apps"] as Record<
    string,
    { id: string; capabilities: string[] }
  >;
  const ids = ["linear", "github", "atlassian"].map((name) => apps[name]!.id);
  for (const id of ids) {
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);
  }
  expect(new Set(ids).size).toBe(ids.length);
  expect(apps["atlassian"]!.capabilities).toEqual(["read", "write"]);
  expect((await read(".codex-plugin/plugin.json"))["apps"]).toBe("./.app.json");
  const servers = (await read(".mcp.json"))["mcpServers"] as Record<
    string,
    { env_vars: string[] }
  >;
  expect(servers["codex-security"]!.env_vars).toContain(
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  );
});
