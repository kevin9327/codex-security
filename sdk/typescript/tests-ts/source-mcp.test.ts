import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { Codex } from "@openai/codex-sdk";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse } from "smol-toml";
import {
  resolveSourceMcp,
  sourceMcpConfig,
  sourceMcpInstructions,
  SOURCE_MCP_CONFIG_PATH,
} from "../src/source-mcp.js";
import {
  DiffTarget,
  normalizeTarget,
  validateCommittedDiffCheckout,
  validateSourceMcpTarget,
} from "../src/targets.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { resolveCodexCommand } from "../src/runtime.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);
const git = (repo: string, ...args: string[]): string =>
  execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" }).trim();

test("native Codex stops before model generation when the required source MCP cannot start", async () => {
  const home = await temporaryDirectory();
  let modelRequests = 0;
  let authenticatedSourceRequests = 0;
  const server = createServer((request, response) => {
    if (request.url?.startsWith("/mcp")) {
      if (request.headers.authorization === "token synthetic-source-auth")
        authenticatedSourceRequests++;
      response.writeHead(503).end("Synthetic source server unavailable");
    } else {
      if (request.url?.includes("responses")) modelRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as { port: number };
  const url = `http://127.0.0.1:${address.port}`;
  try {
    const source = await resolveSourceMcp(
      "source",
      {
        mcp_servers: {
          source: {
            url: `${url}/mcp`,
            startup_timeout_sec: 2,
            env_http_headers: { Authorization: "SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home, SOURCE_AUTH: "token synthetic-source-auth" },
    );
    const codex = new Codex({
      codexPathOverride: resolveCodexCommand({}).command,
      env: {
        PATH: process.env["PATH"] ?? "",
        CODEX_HOME: home,
        ...source.environment,
      },
      config: {
        ...sourceMcpConfig(source, {}),
        features: { plugins: false },
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      },
    });
    await expect(
      codex
        .startThread({ workingDirectory: home, skipGitRepoCheck: true })
        .run("Read source using the required MCP server.", {
          signal: AbortSignal.timeout(15_000),
        }),
    ).rejects.toThrow(/required.*source|source.*required/i);
    expect(authenticatedSourceRequests).toBeGreaterThan(0);
    expect(modelRequests).toBe(0);
  } finally {
    const closed = new Promise<void>((resolve) =>
      server.close(() => resolve()),
    );
    server.closeAllConnections();
    await closed;
  }
});

test("native read-only source tools cannot bypass deny-all approval", async () => {
  const home = await temporaryDirectory();
  let sourceCalls = 0;
  const modelInputs: string[] = [];
  let advertisedSourceTool = false;
  const server = createServer(async (request, response) => {
    if (request.method !== "POST") {
      response.writeHead(405).end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString() || "{}");
    if (request.url === "/mcp") {
      if (body.id === undefined) {
        response.writeHead(202).end();
        return;
      }
      const result =
        body.method === "initialize"
          ? {
              protocolVersion: "2024-11-05",
              capabilities: { tools: {} },
              serverInfo: { name: "source", version: "1" },
            }
          : body.method === "tools/list"
            ? {
                tools: [
                  {
                    name: "read_source",
                    description: "Read source in a repository",
                    inputSchema: {
                      type: "object",
                      properties: { repository: { type: "string" } },
                      required: ["repository"],
                    },
                    annotations: { readOnlyHint: true },
                  },
                ],
              }
            : { content: [{ type: "text", text: "Synthetic source" }] };
      if (body.method === "tools/call") sourceCalls++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      return;
    }
    if (!request.url?.includes("responses")) {
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
      return;
    }
    modelInputs.push(
      JSON.stringify(
        body.input.filter((item: { type: string }) =>
          item.type.endsWith("call_output"),
        ),
      ),
    );
    const toolDefinitions =
      body.tools ??
      body.input.flatMap((item: { tools?: unknown[] }) => item.tools ?? []);
    const catalog = toolDefinitions.flatMap(
      (tool: { type: string; name: string; tools?: { name: string }[] }) =>
        tool.type === "namespace"
          ? tool.tools!.map((entry) => ({ ...entry, namespace: tool.name }))
          : [tool],
    );
    const sourceTool = catalog.find((tool: { name: string }) =>
      tool.name.endsWith("read_source"),
    );
    const execTool = catalog.find(
      (tool: { name: string }) => tool.name === "exec",
    );
    advertisedSourceTool ||= sourceTool !== undefined || execTool !== undefined;
    const item =
      modelInputs.length === 1 && execTool
        ? {
            type: "custom_tool_call",
            id: "ctc_source",
            call_id: "call_source",
            name: execTool.name,
            namespace: execTool.namespace,
            input:
              'text(await tools.mcp__source__read_source({repository:"other/repository"}));',
          }
        : modelInputs.length === 1 && sourceTool
          ? {
              type: "function_call",
              id: "fc_source",
              call_id: "call_source",
              name: sourceTool.name,
              ...(sourceTool.namespace
                ? { namespace: sourceTool.namespace }
                : {}),
              arguments: '{"repository":"other/repository"}',
            }
          : {
              type: "message",
              id: "msg_done",
              role: "assistant",
              content: [{ type: "output_text", text: "Source access denied." }],
            };
    response.writeHead(200, { "Content-Type": "text/event-stream" }).end(
      [
        { type: "response.output_item.done", item },
        {
          type: "response.completed",
          response: {
            id: `resp_${modelInputs.length}`,
            usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
          },
        },
      ]
        .map((event) => `data: ${JSON.stringify(event)}\n\n`)
        .join(""),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const source = await resolveSourceMcp(
      "source",
      { mcp_servers: { source: { url: `${url}/mcp` } } },
      { CODEX_HOME: home },
    );
    const codex = new Codex({
      codexPathOverride: resolveCodexCommand({}).command,
      env: { PATH: process.env["PATH"] ?? "", CODEX_HOME: home },
      config: {
        ...sourceMcpConfig(source, {}),
        features: {
          plugins: false,
          code_mode: { enabled: false },
          tool_search: false,
        },
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      },
    });
    await codex
      .startThread({
        workingDirectory: home,
        skipGitRepoCheck: true,
        sandboxMode: "read-only",
        approvalPolicy: "never",
      })
      .run("Read only approved/repository using the source MCP.", {
        signal: AbortSignal.timeout(15_000),
      });
    expect(advertisedSourceTool).toBe(true);
    expect(modelInputs.length).toBe(2);
    expect(modelInputs[1]).toContain("approval");
    expect(sourceCalls).toBe(0);
  } finally {
    const closed = new Promise<void>((resolve) =>
      server.close(() => resolve()),
    );
    server.closeAllConnections();
    await closed;
  }
});

async function sparseRepository() {
  const root = await temporaryDirectory();
  const repo = join(root, "repo");
  await mkdir(join(repo, "src"), { recursive: true });
  await writeFile(join(repo, "src", "app.ts"), "export const value = 1;\n");
  await writeFile(
    join(repo, "SECURITY.md"),
    "Review the authorization boundary.\n",
  );
  git(repo, "init", "-b", "main");
  git(repo, "config", "user.email", "test@example.com");
  git(repo, "config", "user.name", "Test");
  git(repo, "add", ".");
  git(repo, "commit", "-m", "initial");
  git(repo, "remote", "add", "origin", "https://git.example.com/team/repo.git");
  git(repo, "sparse-checkout", "set", "--cone", "docs");
  return { root, repo };
}

test("source MCP resolves only the selected server and keeps credentials out of config", async () => {
  const home = await temporaryDirectory();
  await writeFile(
    join(home, "config.toml"),
    `[mcp_servers.sourcegraph]\nurl = "https://source.example.com/.api/mcp"\nhttp_headers = { Authorization = "token synthetic-source-credential" }\n[mcp_servers.unrelated]\ncommand = "unrelated-command"\n`,
  );
  const source = await resolveSourceMcp(
    "sourcegraph",
    {
      mcp_servers: {
        sourcegraph: {
          default_tools_approval_mode: "approve",
          tools: { read_source: { approval_mode: "approve" } },
        },
      },
    },
    { CODEX_HOME: home },
  );
  const config = sourceMcpConfig(source, {
    shell_environment_policy: {
      set: { CODEX_SECURITY_SOURCE_HEADER_0: "shell-value" },
    },
  });
  expect(config["mcp_servers"]).toEqual({
    sourcegraph: {
      url: "https://source.example.com/.api/mcp",
      env_http_headers: { Authorization: "CODEX_SECURITY_SOURCE_HEADER_0" },
      enabled: true,
      required: true,
      default_tools_approval_mode: "prompt",
      tools: { read_source: { approval_mode: "prompt" } },
    },
  });
  expect(JSON.stringify(config)).not.toContain("synthetic-source-credential");
  expect(source.environment).toEqual({
    CODEX_SECURITY_SOURCE_HEADER_0: "token synthetic-source-credential",
  });
  expect(config["shell_environment_policy"]).toEqual({
    exclude: ["CODEX_SECURITY_SOURCE_HEADER_0"],
    set: {},
  });
  await expect(
    resolveSourceMcp("missing", {}, { CODEX_HOME: home }),
  ).rejects.toThrow("not configured");
  await expect(
    resolveSourceMcp(
      "sourcegraph",
      { mcp_servers: { sourcegraph: { enabled: false } } },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("disabled");
  await expect(
    resolveSourceMcp(
      "sourcegraph",
      {
        mcp_servers: {
          sourcegraph: {
            env_http_headers: { Authorization: "MISSING_SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("MISSING_SOURCE_AUTH");
});

test("MCP scope uses committed sparse files and rejects local changes and escaped targets", async () => {
  const { repo } = await sparseRepository();
  expect(existsSync(join(repo, "src", "app.ts"))).toBe(false);
  await expect(normalizeTarget(repo, ["src"])).rejects.toThrow(
    "does not exist",
  );
  const target = await normalizeTarget(repo, ["src"], undefined, true);
  expect(await validateSourceMcpTarget(repo, target)).toEqual(["src/app.ts"]);
  await expect(
    normalizeTarget(repo, ["../missing"], undefined, true),
  ).rejects.toThrow("outside");
  await expect(
    validateSourceMcpTarget(repo, { kind: "paths", paths: ["missing"] }),
  ).rejects.toThrow("committed source");
  await expect(
    validateSourceMcpTarget(
      repo,
      await normalizeTarget(repo, DiffTarget.workingTree({})),
    ),
  ).rejects.toThrow("uncommitted");
  await writeFile(join(repo, "local.txt"), "local-only content");
  await expect(validateSourceMcpTarget(repo, target)).rejects.toThrow(
    "clean checkout",
  );
});

test("committed diff inventory includes deleted baseline files without materializing sparse files", async () => {
  const { repo } = await sparseRepository();
  const base = git(repo, "rev-parse", "HEAD");
  git(repo, "sparse-checkout", "disable");
  git(repo, "rm", "src/app.ts");
  await writeFile(join(repo, "SECURITY.md"), "Updated policy.\n");
  git(repo, "commit", "-am", "delete source");
  git(repo, "sparse-checkout", "set", "--cone", "docs");
  const target = await normalizeTarget(repo, DiffTarget.refs({ base }));
  await validateCommittedDiffCheckout(repo, target, undefined, true);
  expect(await validateSourceMcpTarget(repo, target)).toEqual([
    "SECURITY.md",
    "src/app.ts",
  ]);
  const instructions = await sourceMcpInstructions(
    { name: "sourcegraph", server: {}, environment: {} },
    repo,
    target,
  );
  expect(instructions).toContain(base);
  expect(instructions).toContain(target.head!);
  expect(instructions).toContain("git.example.com/team/repo");
});

test.each([false, true])(
  "scan binds MCP source and credentials before model startup (HEAD changes: %s)",
  async (changeHead) => {
    const { root, repo } = await sparseRepository();
    const home = join(root, "codex-home");
    await mkdir(home);
    const environment = {
      CODEX_HOME: home,
      SOURCE_AUTH: "token synthetic-source-auth",
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    let privatePath: string | undefined;
    let recipe: Record<string, unknown> | undefined;
    let sawPrompt = false;
    await using client = new TestClient(
      {
        codexOverrides: {
          mcp_servers: {
            "source.graph": {
              url: "https://source.example.com/.api/mcp",
              env_http_headers: { Authorization: "SOURCE_AUTH" },
            },
          },
        },
      },
      {
        environment,
        prepareRuntime: async () => {
          if (changeHead)
            git(
              repo,
              "commit",
              "--allow-empty",
              "-m",
              "concurrent checkout update",
            );
          return { ...preparedRuntime(home), environment };
        },
        resolvePluginPython: async () => "python",
        runWorkbench: async (_options, args, input) => {
          const result = mockWorkbench(args, input);
          if (args[0] === "register-cli-scan") {
            const registration = JSON.parse(input!);
            recipe = registration.recipe;
            expect(registration.sourceFiles).toEqual(["src/app.ts"]);
            await writeFile(
              join(root, "scan", "scoped-source-input.jsonl"),
              registration.sourceFiles
                .map((path: string) => JSON.stringify({ path }) + "\n")
                .join(""),
            );
            result["scopeFileCount"] = registration.sourceFiles.length;
            result["targetRevision"] = git(repo, "rev-parse", "HEAD");
          }
          return result;
        },
        createCodex(options) {
          privatePath = options.env![SOURCE_MCP_CONFIG_PATH]!;
          expect(options.env!["SOURCE_AUTH"]).toBe(environment.SOURCE_AUTH);
          const overrides = parse(options.configOverrides!.join("\n"));
          expect(overrides["mcp_servers"]).toEqual({
            "source.graph": {
              url: "https://source.example.com/.api/mcp",
              env_http_headers: { Authorization: "SOURCE_AUTH" },
              required: true,
              enabled: true,
              default_tools_approval_mode: "prompt",
            },
          });
          expect(JSON.stringify(overrides)).toContain(
            JSON.stringify(dirname(privatePath)),
          );
          expect(JSON.stringify(overrides)).toContain("deny");
          expect(JSON.stringify(options.config)).not.toContain(
            environment.SOURCE_AUTH,
          );
          return {
            startThread() {
              return {
                id: null,
                async runStreamed(prompt) {
                  sawPrompt = true;
                  expect(prompt).toContain("source.graph");
                  expect(prompt).toContain(git(repo, "rev-parse", "HEAD"));
                  expect(prompt).not.toContain(environment.SOURCE_AUTH);
                  expect(prompt).not.toContain("make-repo-scope-input");
                  expect(prompt).toContain("bind-repo-scopes");
                  expect(prompt).toContain("scoped-source-input.jsonl");
                  const runtime = JSON.parse(
                    await readFile(privatePath!, "utf8"),
                  );
                  expect(runtime).not.toHaveProperty("files");
                  expect(runtime.config.approval_policy).toBe("on-request");
                  expect(runtime.config.approvals_reviewer).toBe("auto_review");
                  expect(runtime.environment.SOURCE_AUTH).toBe(
                    environment.SOURCE_AUTH,
                  );
                  expect(
                    await readFile(
                      join(root, "scan", "scoped-source-input.jsonl"),
                      "utf8",
                    ),
                  ).toBe('{"path":"src/app.ts"}\n');
                  throw new Error("synthetic scan stop");
                },
              };
            },
          };
        },
      },
    );
    expect(
      await client.preflight(repo, {
        sourceMcp: "source.graph",
        target: ["src"],
      }),
    ).toMatchObject({ sourceMcp: "source.graph", target: { paths: ["src"] } });
    await expect(
      client.run(repo, {
        sourceMcp: "source.graph",
        target: ["src"],
        outputDir: join(root, "scan"),
      }),
    ).rejects.toThrow(changeHead ? "HEAD changed" : "synthetic scan stop");
    expect(sawPrompt).toBe(!changeHead);
    expect(recipe?.["sourceMcp"]).toBe("source.graph");
    expect(JSON.stringify(recipe)).not.toContain(environment.SOURCE_AUTH);
    if (privatePath !== undefined) expect(existsSync(privatePath)).toBe(false);
  },
);

test.skipIf(process.platform !== "win32")(
  "source credentials exclude inherited Windows environment aliases",
  async () => {
    const home = await temporaryDirectory();
    const source = await resolveSourceMcp(
      "source",
      {
        mcp_servers: {
          source: {
            url: "https://source.example.com/mcp",
            env_http_headers: { Authorization: "SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home, source_auth: "token synthetic-source-auth" },
    );
    expect(sourceMcpConfig(source, {})["shell_environment_policy"]).toEqual({
      exclude: ["SOURCE_AUTH", "source_auth"],
    });
  },
);
