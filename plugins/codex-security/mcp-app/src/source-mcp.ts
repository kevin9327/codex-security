import { readFile } from "node:fs/promises";
import type { CodexOptions } from "@openai/codex-sdk";

/** Private host configuration supplied by the CLI, never a scan artifact. */
interface SourceMcpRuntime {
  config: NonNullable<CodexOptions["config"]>;
  environment: Record<string, string>;
  instructions: string;
  repository: string;
  scanId: string;
  inventoryDigest: string;
}

export async function readSourceMcpRuntime(repository: string | undefined, scanId: string | undefined): Promise<SourceMcpRuntime | undefined> {
  const path = process.env.CODEX_SECURITY_SOURCE_MCP_CONFIG_PATH;
  if (!path) return undefined;
  const runtime = JSON.parse(await readFile(path, "utf8")) as SourceMcpRuntime;
  if (runtime.repository !== repository || runtime.scanId !== scanId) {
    throw new Error("Source MCP configuration belongs to a different scan or repository.");
  }
  return runtime;
}
