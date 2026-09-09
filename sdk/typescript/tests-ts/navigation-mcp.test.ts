import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directory = mkdtempSync(join(tmpdir(), "navigation-mcp-"));
afterAll(() => rmSync(directory, { recursive: true, force: true }));
const node = Bun.which("node")!;
interface Response {
  error?: { message: string };
  result?: {
    isError?: boolean;
    content?: { text?: string }[];
    structuredContent?: Record<string, unknown>;
  };
}
async function start(environment: Record<string, string | undefined>) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...environment,
    PATH: "",
    PYTHON: "missing-navigation-python",
  };
  for (const key of Object.keys(env))
    if (env[key] === undefined) delete env[key];
  const child = spawn(node, [join(PLUGIN_ROOT, "mcp/server.mjs"), "--stdio"], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const pending = new Map<
    number,
    { resolve: (response: Response) => void; reject: (error: Error) => void }
  >();
  let sequence = 0,
    stdout = "",
    stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
    let newline: number;
    while ((newline = stdout.indexOf("\n")) !== -1) {
      const line = stdout.slice(0, newline);
      stdout = stdout.slice(newline + 1);
      if (!line.trim()) continue;
      const response = JSON.parse(line) as Response & { id?: number };
      if (response.id !== undefined) {
        pending.get(response.id)?.resolve(response);
        pending.delete(response.id);
      }
    }
  });
  child.once("exit", () => {
    for (const value of pending.values())
      value.reject(new Error(`MCP exited: ${stderr}`));
    pending.clear();
  });
  const request = (
    method: string,
    params: Record<string, unknown>,
  ): Promise<Response> => {
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`MCP request timed out: ${stderr}`));
      }, 15_000);
      pending.set(id, {
        resolve: (result) => {
          clearTimeout(timer);
          resolve(result);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      child.stdin.write(
        JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n",
      );
    });
  };
  const initialized = await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "navigation-test", version: "1" },
  });
  expect(initialized.error, stderr).toBeUndefined();
  return {
    call: (name: string, arguments_: Record<string, unknown> = {}) =>
      request("tools/call", { name, arguments: arguments_ }),
    events: () =>
      stderr.split(/\r?\n/).flatMap((line) => {
        try {
          const value = JSON.parse(line) as {
            event?: string;
            [key: string]: unknown;
          };
          return value.event === "state_fallback_pinned" ? [value] : [];
        } catch {
          return [];
        }
      }),
    async stop() {
      if (child.exitCode !== null) return;
      const exited = once(child, "exit");
      const timer = setTimeout(() => child.kill("SIGKILL"), 2000);
      child.stdin.end();
      try {
        await exited;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
const findings = "list_codex_security_global_findings";
const repositories = "list_codex_security_repositories";
const scans = "list_codex_security_scans";
function successful(response: Response) {
  expect(response.error).toBeUndefined();
  expect(response.result?.isError, JSON.stringify(response)).toBeUndefined();
  return response.result?.structuredContent;
}
function failed(response: Response, message: RegExp) {
  expect(response.error).toBeUndefined();
  expect(response.result?.isError).toBe(true);
  expect(response.result?.content?.map((item) => item.text).join("\n")).toMatch(
    message,
  );
}

test("native MCP tools share their first persistent selection and keep proven failures visible", async () => {
  const home = join(directory, "persistent"),
    scanRoot = join(directory, "persistent-scans");
  const database = join(home, "state/plugins/codex-security/workbench.sqlite3");
  const server = await start({
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: undefined,
    CODEX_SECURITY_SCAN_ROOT: scanRoot,
  });
  try {
    const responses = await Promise.all([
      server.call(findings),
      server.call(repositories),
      server.call(scans),
    ]);
    expect(successful(responses[0]!)).toEqual({
      findings: [],
      limit: 20,
      nextOffset: null,
      offset: 0,
    });
    expect(successful(responses[1]!)).toEqual({ repositories: [] });
    expect(successful(responses[2]!)).toEqual({ scans: [] });
    expect(
      successful(
        await server.call(scans, {
          limit: 50,
          offset: 1,
          mode: "deep",
          status: "complete",
        }),
      ),
    ).toEqual({ scans: [], limit: 20, offset: 1, nextOffset: null });
    expect(statSync(database).isFile()).toBe(true);
    expect(server.events()).toEqual([]);
    rmSync(database);
    mkdirSync(database);
    failed(await server.call(repositories), /unable to open database file/);
    expect(server.events()).toEqual([]);
    expect(existsSync(join(scanRoot, "workbench-state"))).toBe(false);
  } finally {
    await server.stop();
  }
});

test.each(["0", "1"])(
  "native MCP open failure pins one fallback without Python with FORCE_COLOR=%s",
  async (color) => {
    const home = join(directory, `fallback-${color}`),
      scanRoot = join(directory, `fallback-scans-${color}`);
    mkdirSync(join(home, "state/plugins/codex-security/workbench.sqlite3"), {
      recursive: true,
    });
    const server = await start({
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: undefined,
      CODEX_SECURITY_SCAN_ROOT: scanRoot,
      FORCE_COLOR: color,
    });
    try {
      const responses = await Promise.all([
        server.call(repositories),
        server.call(findings),
        server.call(scans),
      ]);
      expect(successful(responses[0]!)).toEqual({ repositories: [] });
      expect(successful(responses[1]!)).toEqual({
        findings: [],
        limit: 20,
        nextOffset: null,
        offset: 0,
      });
      successful(await server.call(repositories));
      expect(successful(responses[2]!)).toEqual({ scans: [] });
      expect(
        statSync(join(scanRoot, "workbench-state/workbench.sqlite3")).isFile(),
      ).toBe(true);
      expect(server.events()).toEqual([
        {
          component: "codex_security_workbench",
          event: "state_fallback_pinned",
          reason: "persistent_sqlite_unwritable",
        },
      ]);
    } finally {
      await server.stop();
    }
  },
);

test("configured state and malformed databases retain the existing no-fallback boundary", async () => {
  for (const configured of [true, false]) {
    const home = join(directory, `failure-${configured}`),
      scanRoot = join(directory, `failure-scans-${configured}`);
    const state = configured
      ? join(home, "explicit-state")
      : join(home, "state/plugins/codex-security");
    mkdirSync(state, { recursive: true });
    if (configured) mkdirSync(join(state, "workbench.sqlite3"));
    else writeFileSync(join(state, "workbench.sqlite3"), "not a database");
    const server = await start({
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: configured ? state : undefined,
      CODEX_SECURITY_SCAN_ROOT: scanRoot,
    });
    try {
      failed(
        await server.call(scans),
        configured ? /unable to open database file/ : /file is not a database/,
      );
      expect(server.events()).toEqual([]);
      expect(existsSync(join(scanRoot, "workbench-state"))).toBe(false);
    } finally {
      await server.stop();
    }
  }
});

test("MCP setup, handoff, context and progress work without Python", async () => {
  const root = realpathSync(mkdtempSync(join(directory, "lifecycle-"))),
    target = join(root, "target"),
    state = join(root, "state");
  mkdirSync(target);
  writeFileSync(join(target, "source.ts"), "synthetic source\n");
  const server = await start({
    CODEX_SECURITY_STATE_DIR: state,
    CODEX_HOME: join(root, "codex"),
    CODEX_SQLITE_HOME: join(root, "sqlite"),
    CODEX_SECURITY_SCAN_ROOT: join(root, "scans"),
  });
  try {
    const opened = successful(
      await server.call("open_codex_security_workspace", {
        targetPath: target,
        scope: ".",
        mode: "standard",
      }),
    )!["workspace"] as Record<string, unknown>;
    expect(opened["targetPath"]).toBe(target);
    const context = "Review Σ.\nKeep the context.";
    const saved = successful(
      await server.call("submit_codex_security_setup", {
        sessionId: opened["id"],
        targetPath: target,
        scope: ".",
        mode: "standard",
        userContext: context,
      }),
    )!["workspace"] as Record<string, unknown>;
    expect(saved["userContext"]).toBe(context);
    const started = successful(
      await server.call("start_codex_security_scan", {
        sessionId: opened["id"],
      }),
    )!["workspace"] as Record<string, unknown>;
    expect(started["results"]).toMatchObject({
      progress: { status: "running" },
      userContext: context,
    });
    const scanId = (started["results"] as Record<string, unknown>)["scanId"],
      claimToken = "22222222-2222-4222-8222-222222222222";
    for (const name of [
      "claim_codex_security_scan_handoff_delivery",
      "release_codex_security_scan_handoff_delivery",
      "claim_codex_security_scan_handoff_delivery",
      "attach_codex_security_scan_continuation_thread",
      "mark_codex_security_scan_handoff_delivered",
    ]) {
      const state = successful(
        await server.call(name, {
          scanId,
          claimToken,
          ...(name === "attach_codex_security_scan_continuation_thread"
            ? { threadId: "continuation" }
            : {}),
        }),
      )!["workspace"] as Record<string, unknown>;
      expect(state["results"]).toMatchObject({
        handoffClaimToken:
          name === "release_codex_security_scan_handoff_delivery"
            ? null
            : claimToken,
      });
    }
    successful(
      await server.call("update_codex_security_scan_context_from_app", {
        scanId,
        userContext: "Updated context",
      }),
    );
    successful(
      await server.call("update_codex_security_scan_progress", {
        scanId,
        handoffClaimToken: claimToken,
        phase: "preflight",
        preflightChecks: [
          {
            capability: "test",
            severity: "warn",
            status: "unknown",
            reason: "Not available",
          },
        ],
      }),
    );
    const final = successful(
      await server.call("get_codex_security_scan", { scanId }),
    )!["scan"] as Record<string, unknown>;
    expect(final).toMatchObject({
      continuationThreadId: "continuation",
      handoffStatus: "delivered",
      userContext: "Updated context",
      progress: {
        phase: "preflight",
        phaseProgress: { total: 1, completed: 0, unit: "checks" },
      },
    });
    const canceled = successful(
      await server.call("cancel_codex_security_scan_from_app", { scanId }),
    )!["workspace"] as Record<string, unknown>;
    expect(canceled["results"]).toMatchObject({
      progress: { status: "canceled" },
    });
    failed(
      await server.call("recover_codex_security_scan_results", { scanId }),
      /Canceled scans cannot recover/,
    );
    expect(statSync(join(state, "workbench.sqlite3")).isFile()).toBe(true);
    expect(server.events()).toEqual([]);
  } finally {
    await server.stop();
  }
});
