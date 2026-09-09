import { readFileSync } from "node:fs";
import type { Plugin } from "esbuild";

export const reportFaultPlugin: Plugin = {
  name: "report-fault",
  setup(build) {
    build.onLoad({ filter: /[/\\]report-projection\.ts$/ }, ({ path }) => ({
      loader: "ts",
      contents:
        readFileSync(path, "utf8").replace(
          "export function generateReportMarkdown(",
          "function originalGenerateReportMarkdown(",
        ) +
        `
        export function generateReportMarkdown(...args: Parameters<typeof originalGenerateReportMarkdown>): Buffer {
          const fault = (globalThis as unknown as { finalizationReportFault?: { remaining: number; calls: number; kind: string } }).finalizationReportFault;
          if (fault) {
            fault.calls++;
            if (fault.remaining > 0) {
              fault.remaining--;
              if (fault.kind === "io") throw Object.assign(new Error("synthetic I/O"), { errno: 5 });
              if (fault.kind === "value") throw new ReportProjectionError("synthetic invalid report");
              throw new TypeError("synthetic programming error");
            }
          }
          return originalGenerateReportMarkdown(...args);
        }
      `,
    }));
  },
};
