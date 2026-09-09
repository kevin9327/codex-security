import { spawnSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { TimestampProbe } from "./support/timestamp-fixture.js";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "deep-timestamps-")));
const fixture = join(directory, "fixture.cjs");
const node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(new URL("./support/timestamp-fixture.ts", import.meta.url)),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function runTimestampProbe(probe: TimestampProbe): boolean {
  const result = spawnSync(node, [fixture], {
    input: JSON.stringify(probe),
    encoding: "utf8",
    env: { ...process.env, PYTHON: "/unavailable/python" },
  });
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as boolean;
}

describe("Deep Scan timestamp compatibility", () => {
  test.each([
    [
      "before the deadline",
      "2026-08-15T00:00:00Z",
      "2026-08-15T00:59:59Z",
      false,
    ],
    ["at the deadline", "2026-08-15T00:00:00Z", "2026-08-15T01:00:00Z", true],
    [
      "with lowercase UTC suffixes",
      "2026-08-15T00:00:00z",
      "2026-08-15T01:00:00z",
      true,
    ],
    [
      "with explicit UTC offsets",
      "2026-08-15T02:00:00+02:00",
      "2026-08-15T01:00:00Z",
      true,
    ],
  ] as const)("evaluates timestamps %s", (_label, createdAt, now, reached) => {
    expect(
      runTimestampProbe({
        operation: "deadline",
        createdAt,
        maxTimeHours: 1,
        now,
      }),
    ).toBe(reached);
  });

  test.each([
    ["fresh legacy", 1, "2026-08-15T00:09:59Z", true],
    ["expired legacy", 1, "2026-08-15T00:08:00Z", false],
    ["fresh current", 2, "2026-08-15T00:09:59Z", true],
    ["expired current", 2, "2026-08-15T00:09:30Z", false],
  ] as const)(
    "evaluates %s coordinator leases",
    (_label, generation, updatedAt, live) => {
      expect(
        runTimestampProbe({
          operation: "coordinator",
          generation,
          activeWorker: generation === 1,
          updatedAt,
          now: "2026-08-15T00:10:00Z",
        }),
      ).toBe(live);
    },
  );

  test.each([
    ["current", 2, "2026-08-15T00:09:45Z", true],
    ["older generation", 1, "2026-08-15T00:09:45Z", false],
    ["invalid", 2, null, false],
  ] as const)(
    "uses the %s coordinator heartbeat",
    (_label, coordinatorGeneration, updatedAt, live) => {
      expect(
        runTimestampProbe({
          operation: "coordinator",
          generation: 2,
          updatedAt: "2026-08-15T00:09:00Z",
          now: "2026-08-15T00:10:00Z",
          heartbeat: { coordinatorGeneration, updatedAt },
        }),
      ).toBe(live);
    },
  );
});
