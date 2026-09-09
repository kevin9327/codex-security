import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import ts from "typescript";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("gives prompt-only scan startup the five-minute scan timeout", async () => {
  const server = await readFile(
    new URL(
      "../../../plugins/codex-security/mcp-app/server.ts",
      import.meta.url,
    ),
    "utf8",
  );
  const parsed = ts.createSourceFile(
    "server.ts",
    server,
    ts.ScriptTarget.Latest,
  );
  const helper = parsed.statements.find(
    (statement): statement is ts.FunctionDeclaration =>
      ts.isFunctionDeclaration(statement) &&
      statement.name?.text === "executeWorkbench",
  );
  expect(helper).toBeDefined();
  const { outputText } = ts.transpileModule(helper!.getText(parsed), {
    compilerOptions: { target: ts.ScriptTarget.ESNext },
  });
  const executeWorkbench = new Function(
    "execFileAsync",
    "join",
    "PLUGIN_ROOT",
    "isJsonObject",
    `${outputText}\nreturn executeWorkbench;`,
  )(
    async (command: string, args: string[], options: { timeout: number }) => {
      expect(command).toBe(process.execPath);
      expect(args[0]).toBe(join(PLUGIN_ROOT, "mcp", "helpers.mjs"));
      return { stdout: JSON.stringify({ timeout: options.timeout }) };
    },
    join,
    PLUGIN_ROOT,
    () => true,
  ) as (args: string[]) => Promise<{ timeout: number }>;

  expect(await executeWorkbench(["start-prompt-only-scan"])).toEqual({
    timeout: 300_000,
  });
  expect(await executeWorkbench(["start-scan"])).toEqual({
    timeout: 300_000,
  });
  expect(await executeWorkbench(["other-operation"])).toEqual({
    timeout: 30_000,
  });
});
