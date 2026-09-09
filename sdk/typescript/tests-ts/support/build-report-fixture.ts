import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync, type BuildOptions } from "esbuild";

const require = createRequire(import.meta.url);

// Bun's shared esbuild service can deadlock waiting for plugin callbacks after
// earlier suites. Run the plugin build in its own Node process.
export function buildReportFixture(
  node: string,
  options: BuildOptions & { outfile: string },
): void {
  const plugin = join(dirname(options.outfile), "report-fault.cjs");
  buildSync({
    entryPoints: [fileURLToPath(new URL("./report-fault.ts", import.meta.url))],
    outfile: plugin,
    bundle: true,
    platform: "node",
    format: "cjs",
  });
  const startedAt = process.hrtime.bigint();
  const child = spawnSync(
    node,
    [
      "-e",
      `const { build } = require(${JSON.stringify(require.resolve("esbuild"))});
       const { reportFaultPlugin } = require(${JSON.stringify(plugin)});
       const options = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
       build({ ...options, plugins: [reportFaultPlugin] }).catch(error => {
         console.error(error);
         process.exitCode = 1;
       });`,
    ],
    { input: JSON.stringify(options), encoding: "utf8", timeout: 30_000 },
  );
  if (child.error) {
    console.error(
      "Report fixture process diagnostic",
      JSON.stringify({
        elapsedMs: Number(process.hrtime.bigint() - startedAt) / 1e6,
        error: child.error.message,
        signal: child.signal,
        stderr: child.stderr,
      }),
    );
    throw child.error;
  }
  if (child.status !== 0)
    throw new Error(`Report fixture build failed: ${child.stderr}`);
}
