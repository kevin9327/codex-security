import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

async function run(args: string[], deps = dependencies()) {
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["feedback", ...args],
    stdout.stream,
    stderr.stream,
    deps,
  );
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

for (const requested of [undefined, "scan-pre"]) {
  test(`feedback selects ${requested ?? "the latest scan, including failed scans"}`, async () => {
    const calls: string[][] = [];
    const scan = { scanId: "scan-prefix-full", progress: { status: "failed" } };
    const deps = dependencies({
      onWorkbench: (args): JsonObject => {
        calls.push([...args]);
        return args[0] === "list-scans" ? { scans: [scan] } : { scan };
      },
    });
    const report = {
      feedbackId: "feedback-1",
      scanId: scan.scanId,
      includedLogs: true,
    };
    deps.sendFeedback = async (options) => {
      expect(options).toMatchObject({
        reason: "Scan stopped",
        includeLogs: true,
        scan,
      });
      return report;
    };
    const result = await run(
      [
        ...(requested === undefined ? [] : [requested]),
        "--reason",
        "Scan stopped",
        "--include-logs",
        "--json",
      ],
      deps,
    );
    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toEqual(report);
    expect(calls).toEqual([
      ...(requested === undefined
        ? [
            [
              "list-scans",
              "--repository",
              "/current/repository",
              "--limit",
              "1",
            ],
          ]
        : []),
      ["get-scan", "--scan-id", requested ?? scan.scanId],
    ]);
  });
}

test("feedback without saved scans sends a general report with logs off", async () => {
  const deps = dependencies();
  deps.sendFeedback = async (options) => {
    expect(options.scan).toBeUndefined();
    expect(options.includeLogs).toBe(false);
    return { feedbackId: "feedback-2", scanId: null, includedLogs: false };
  };
  const result = await run(["--reason", "Install failed", "--json"], deps);
  expect(result.code).toBe(0);
  expect(JSON.parse(result.stdout).feedbackId).toBe("feedback-2");
});

test("Ctrl-C cancels feedback and removes signal listeners", async () => {
  const signals = new FakeSignals();
  const deps = dependencies({ signals });
  deps.sendFeedback = async ({ signal }) => {
    signals.emit("SIGINT");
    signal!.throwIfAborted();
    throw new Error("Must be canceled");
  };
  const result = await run(["--reason", "Problem"], deps);
  expect(result.code).toBe(130);
  expect(result.stderr).toContain("Feedback upload canceled");
  expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
});

for (const args of [
  [],
  ["--reason", " "],
  ["extra", "scan", "--reason", "Problem"],
]) {
  test(`feedback rejects invalid arguments ${JSON.stringify(args)}`, async () => {
    const deps = dependencies({
      onWorkbench: () => {
        throw new Error("Must not read scans");
      },
    });
    deps.sendFeedback = async () => {
      throw new Error("Must not upload");
    };
    const result = await run(args, deps);
    expect(result.code).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).not.toContain("Must not");
  });
}

for (const missingScan of [false, true]) {
  test(`feedback reports ${missingScan ? "scan lookup" : "upload"} failures without a success ID`, async () => {
    const deps = dependencies({
      onWorkbench: () => {
        if (missingScan) throw new Error("Scan not found");
        return { scans: [] };
      },
    });
    const upload = mock(async () => {
      throw new Error("Upload failed");
    });
    deps.sendFeedback = upload;
    const result = await run(
      [
        ...(missingScan ? ["unknown-scan"] : []),
        "--reason",
        "Problem",
        "--json",
      ],
      deps,
    );
    expect(result.code).toBe(2);
    expect(result.stdout).toBe("");
    expect(upload).toHaveBeenCalledTimes(missingScan ? 0 : 1);
    expect(result.stderr).toContain(
      missingScan ? "Scan not found" : "Upload failed",
    );
  });
}
