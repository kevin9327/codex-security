import { execFile } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { buildSync, type BuildOptions } from "esbuild";

const require = createRequire(import.meta.url);

// Bun's shared esbuild service can deadlock waiting for plugin callbacks after
// earlier suites. Run the plugin build in its own Node process.
export async function buildReportFixture(
  node: string,
  options: BuildOptions & { outfile: string },
): Promise<void> {
  const plugin = join(dirname(options.outfile), "report-fault.cjs");
  buildSync({
    entryPoints: [fileURLToPath(new URL("./report-fault.ts", import.meta.url))],
    outfile: plugin,
    bundle: true,
    platform: "node",
    format: "cjs",
  });
  // Bun's synchronous Windows child timer can fire immediately after idle time.
  // https://github.com/oven-sh/bun/pull/33935
  const child = promisify(execFile)(
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
    { encoding: "utf8", timeout: 30_000 },
  );
  child.child.stdin!.end(JSON.stringify(options));
  await child;
}
