import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  JsonFloat,
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { cleanWorktreeContentDigest } from "../../../plugins/codex-security/mcp-app/src/workbench-git-snapshot";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/workbench-results-fixture";

const scanId = "11111111-1111-4111-8111-111111111111";
const workspaceId = "22222222-2222-4222-8222-222222222222";
const occurrenceId = "occurrence";
const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-finding-results-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-results-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    format: "cjs",
    platform: "node",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as unknown as Response[];
  for (const response of responses) {
    expect(response.node).toBe(nodeVersion);
    for (const outcome of response.outcomes)
      expect(outcome.error).toBeUndefined();
  }
  return responses;
}
const value = (response: Response, index = 0) =>
  response.outcomes[index]!.result as Record<string, unknown>;
const occurrence = {
  id: occurrenceId,
  finding_id: "finding",
  scan_id: scanId,
  title: "Title",
  summary: "Summary",
  severity: "high",
  confidence: "medium",
  remediation: "Fix",
  details_json: "{}",
  created_at: "created",
};
const finding = { operation: "finding", occurrenceId } as const;
function root(name: string) {
  const path = join(directory, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}
const encoded = (text: string) => Buffer.from(text).toString("base64");

test("finding details preserve object JSON, byte encodings, and numeric precision", () => {
  const invalid = [
    null,
    true,
    1n,
    {},
    "[]",
    "null",
    "{",
    '{"value":NaN}',
    '{"value":Infinity}',
    `{"value":${"9".repeat(4301)}}`,
  ];
  const [response] = run({
    actions: [
      {
        operation: "details",
        value:
          '{"duplicate":1,"duplicate":2,"integer":9007199254740993,"fraction":1.0}',
      },
      {
        operation: "details",
        valueBytes: Buffer.from('\ufeff{"title":"😀"}', "utf16le").toString(
          "base64",
        ),
      },
      {
        operation: "details",
        valueBytes: Buffer.from([0xff]).toString("base64"),
      },
      ...invalid.map((item) => ({
        operation: "details" as const,
        value: item,
      })),
    ],
  });
  expect(value(response!)).toEqual({
    duplicate: 2n,
    integer: 9007199254740993n,
    fraction: new JsonFloat("1.0"),
  });
  expect(value(response!, 1)).toEqual({ title: "😀" });
  for (const outcome of response!.outcomes.slice(2))
    expect(outcome.result).toEqual({});
  expect(
    response!.outcomes.every(
      (outcome) => outcome.events.length === 0 && !outcome.inTransaction,
    ),
  ).toBe(true);
});

test("finding projections preserve rich detail while bounding stored fields and ordering locations", () => {
  const target = root("bounded-target");
  const records = {
    finding_occurrences: [
      {
        ...occurrence,
        title: "😀".repeat(130),
        summary: "x".repeat(2100),
        details_json: JSON.stringify({
          confidence: { level: "low", rationale: "evidence" },
          severity: { level: "low", rationale: "impact" },
          root_cause: { summary: "legacy cause" },
          validation: { summary: "validated" },
          artifactPaths: ["../outside"],
        }),
      },
    ],
    finding_locations: Array.from({ length: 10 }, (_, index) => ({
      occurrence_id: occurrenceId,
      sort_order: BigInt(index),
      relative_path: `src/${index}.ts`,
      start_line: 1n,
      end_line: 2n,
      role: index === 9 ? "root_control" : "secondary",
    })),
  };
  const request: Request = {
    targetIdentityPath: target,
    scan: { target_revision: "unversioned" },
    records,
    actions: [finding],
  };
  const [response, unchanged] = run(request, { ...request, actions: [] });
  const result = value(response!);
  expect(result).toMatchObject({
    confidence: { level: "medium", rationale: "evidence" },
    severity: { level: "high", rationale: "impact" },
    root_cause: { summary: "legacy cause" },
    validation: { summary: "validated" },
    title: "😀".repeat(128),
    summary: "x".repeat(2000),
    remediationState: { state: "idle" },
    triage: { status: "open" },
    artifactPaths: [],
  });
  const locations = result["locations"] as Record<string, unknown>[];
  expect(locations).toHaveLength(8);
  expect(locations.map((location) => location["path"])).toEqual([
    "src/9.ts",
    ...Array.from({ length: 7 }, (_, index) => `src/${index}.ts`),
  ]);
  expect(locations[0]).toMatchObject({
    absolutePath: join(target, "src", "9.ts"),
    role: "root_control",
  });
  expect(response!.snapshot).toEqual(unchanged!.snapshot);
  expect(response!.outcomes[0]!.inTransaction).toBe(false);
});

test("remediation availability and source paths retain the captured target identity requirement", () => {
  const target = root("identity-target");
  const request: Request = {
    targetIdentityPath: target,
    scan: { status: "complete", target_revision: "revision" },
    records: {
      finding_occurrences: [occurrence],
      finding_locations: [
        {
          occurrence_id: occurrenceId,
          sort_order: 0n,
          relative_path: "source.ts",
          start_line: 1n,
          end_line: 1n,
        },
      ],
    },
    actions: [
      { operation: "availability", git: [{ stdout: encoded("revision\n") }] },
    ],
  };
  const [valid, changed, absent, mismatch, incomplete] = run(
    request,
    { ...request, scan: { ...request.scan, target_revision: "changed" } },
    {
      ...request,
      scan: { ...request.scan, target_inode: null },
      actions: [{ operation: "availability" }, finding],
    },
    {
      ...request,
      scan: { ...request.scan, target_inode: 1n },
      actions: [{ operation: "availability" }, finding],
    },
    { actions: [{ operation: "availability", row: { status: "running" } }] },
  );
  expect(valid!.outcomes[0]!.result).toEqual([true, null]);
  expect(changed!.outcomes[0]!.result).toEqual([
    false,
    "Remediation is unavailable because the selected checkout is not at the revision that was scanned. Check out the scanned revision or start a new scan.",
  ]);
  for (const response of [absent!, mismatch!]) {
    expect((response.outcomes[0]!.result as unknown[])[0]).toBe(false);
    expect(
      (value(response, 1)["locations"] as unknown[])[0],
    ).not.toHaveProperty("absolutePath");
  }
  expect(incomplete!.outcomes[0]!.result).toEqual([
    false,
    "Remediation is available only for successfully completed scans.",
  ]);
  expect(incomplete!.outcomes[0]!.events).toEqual([]);
});

test("source excerpts use the sealed revision and artifacts come from the selected scan", () => {
  const target = root("source-target"),
    scan = root("source-scan");
  writeFileSync(join(target, "source.ts"), "current checkout contents\n");
  const report = "findings/example/example.md";
  mkdirSync(join(scan, "findings/example/poc"), { recursive: true });
  writeFileSync(join(scan, report), "# Example\n");
  writeFileSync(join(scan, "findings/example/poc/reproduce.py"), "print(1)\n");
  if (process.platform !== "win32")
    symlinkSync(
      join(target, "source.ts"),
      join(scan, "findings/example/poc/outside"),
    );
  const request: Request = {
    targetIdentityPath: target,
    scan: {
      scan_dir: scan,
      target_revision: "sealed",
      target_snapshot_digest: cleanWorktreeContentDigest(),
    },
    records: {
      finding_occurrences: [
        {
          ...occurrence,
          details_json: JSON.stringify({
            writeup: { reportPath: report },
            artifactPaths: ["../outside"],
          }),
        },
      ],
      finding_locations: [
        {
          occurrence_id: occurrenceId,
          sort_order: 0n,
          relative_path: "source.ts",
          start_line: 2n,
          end_line: 2n,
          role: "root_control",
        },
        {
          occurrence_id: occurrenceId,
          sort_order: 1n,
          relative_path: "../outside",
          start_line: 1n,
          end_line: 1n,
        },
      ],
    },
    actions: [
      {
        ...finding,
        git: [{ stdout: encoded("sealed one\nsealed two\nsealed three\n") }],
      },
    ],
  };
  const [response, dirty] = run(request, {
    ...request,
    scan: { ...request.scan, target_snapshot_digest: "dirty" },
    actions: [finding],
  });
  expect(value(response!)["sourceExcerpt"]).toBe(
    "1  sealed one\n2  sealed two\n3  sealed three",
  );
  expect(value(response!)["artifactPaths"]).toEqual([
    report,
    "findings/example/poc/reproduce.py",
  ]);
  expect((value(response!)["locations"] as unknown[])[1]).not.toHaveProperty(
    "absolutePath",
  );
  expect(response!.outcomes[0]!.events).toContainEqual([
    "git",
    [
      "-c",
      "core.fsmonitor=false",
      "-c",
      "i18n.logOutputEncoding=UTF-8",
      "-C",
      target,
      "cat-file",
      "blob",
      "sealed:source.ts",
    ],
  ]);
  expect(value(dirty!)).not.toHaveProperty("sourceExcerpt");
  expect(
    dirty!.outcomes[0]!.events.some(
      (event) => (event as unknown[])[0] === "git",
    ),
  ).toBe(false);
});

test("the latest remediation attempt keeps its action state when patch validation fails", () => {
  const scan = root("patch-scan"),
    patch =
      "diff --git a/source.ts b/source.ts\n--- a/source.ts\n+++ b/source.ts\n@@ -1 +1 @@\n-old\n+new\n";
  writeFileSync(join(scan, "fix.patch"), patch);
  const digest = `sha256:${createHash("sha256").update(patch).digest("hex")}`;
  const attempt = {
    occurrence_id: occurrenceId,
    state: "generated",
    version: 9007199254740993n,
    base_revision: "revision",
    pending_action: "verify",
    pending_action_claim_token: "claim",
    pending_action_claimed_at: "claimed",
    pending_action_delivered_at: "delivered",
    patch_path: "fix.patch",
    patch_digest: digest,
    summary: "Summary",
    verification_summary: "Verified",
    created_at: "latest",
    updated_at: "updated",
  };
  const request: Request = {
    scan: { scan_dir: scan },
    records: {
      finding_occurrences: [occurrence],
      finding_remediation_attempts: [
        { ...attempt, request_id: "first" },
        { ...attempt, request_id: "second" },
        { ...attempt, request_id: "older", created_at: "earlier" },
      ],
    },
    actions: [
      { operation: "remediation", occurrenceId },
      {
        operation: "sql",
        sql: "UPDATE finding_remediation_attempts SET patch_digest = 'mismatch' WHERE request_id = 'second'",
      },
      { operation: "remediation", occurrenceId },
      { operation: "rollback" },
      { operation: "remediation", occurrenceId },
      { operation: "remediation", occurrenceId: "missing" },
    ],
  };
  const [response] = run(request);
  const expected = {
    requestId: "second",
    version: 9007199254740993n,
    state: "generated",
    pendingAction: "verify",
    actionClaimToken: "claim",
    actionClaimedAt: "claimed",
    actionDeliveredAt: "delivered",
    summary: "Summary",
    verificationSummary: "Verified",
  };
  expect(value(response!)).toMatchObject({
    ...expected,
    patch,
    patchStats: {
      additions: 1n,
      deletions: 1n,
      fileCount: 1n,
      previewTruncated: false,
    },
  });
  expect(value(response!, 2)).toMatchObject({
    ...expected,
    patch: null,
    patchStats: null,
    patchDigest: "mismatch",
  });
  expect(response!.outcomes[2]!.inTransaction).toBe(true);
  expect(value(response!, 4)).toEqual(value(response!));
  expect(value(response!, 5)).toEqual({ state: "idle" });
});

test("finding rendering composes triage and match history without committing caller changes", () => {
  const previous = "44444444-4444-4444-8444-444444444444";
  const [response] = run({
    scan: { started_at: "2026-02-01" },
    records: {
      scans: [
        {
          id: previous,
          workspace_id: workspaceId,
          target_path: "/target",
          target_revision: "revision",
          scope: ".",
          mode: "standard",
          scan_dir: "/previous",
          status: "complete",
          phase: "reporting",
          started_at: "2026-01-01",
          created_at: "created",
          updated_at: "updated",
        },
      ],
      finding_occurrences: [
        occurrence,
        {
          ...occurrence,
          id: "previous-occurrence",
          scan_id: previous,
          title: "Previous",
        },
      ],
      finding_triage: [
        {
          occurrence_id: occurrenceId,
          status: "closed",
          close_reason: "wont_fix",
          note: "Reason",
          updated_at: "updated",
        },
      ],
      scan_comparison_matches: [
        {
          before_scan_id: previous,
          after_scan_id: scanId,
          before_occurrence_id: "previous-occurrence",
          after_occurrence_id: occurrenceId,
          reason: "same finding",
        },
      ],
    },
    actions: [
      {
        operation: "sql",
        sql: "UPDATE finding_occurrences SET title = 'Pending' WHERE id = 'occurrence'",
      },
      finding,
      { operation: "rollback" },
      finding,
    ],
  });
  expect(value(response!, 1)).toMatchObject({
    title: "Pending",
    triage: {
      status: "closed",
      closeReason: "wont_fix",
      note: "Reason",
      updatedAt: "updated",
    },
    knownSince: "2026-01-01",
    knownScanIds: [previous, scanId],
    matches: [
      {
        findingId: "finding",
        occurrenceId: "previous-occurrence",
        scanId: previous,
        title: "Previous",
        reason: "same finding",
      },
    ],
  });
  expect(response!.outcomes[1]!.inTransaction).toBe(true);
  expect(
    response!.outcomes[1]!.events.every(
      (event) => (event as unknown[])[0] === "query",
    ),
  ).toBe(true);
  expect(value(response!, 3)["title"]).toBe("Title");
  expect(response!.outcomes[3]!.inTransaction).toBe(false);
});

test("finding rendering uses supplied relations after bounded detail projection", () => {
  const related = [
    {
      findingId: "other",
      occurrenceId: "other-occurrence",
      scanId: "previous",
      title: "Related",
      reason: "similar",
    },
  ];
  const stored = [{ title: "Stored relation" }];
  const requests: Request[] = ["{}", JSON.stringify({ related: stored })].map(
    (details) => ({
      records: {
        finding_occurrences: [{ ...occurrence, details_json: details }],
      },
      actions: [
        { ...finding, related },
        { ...finding, related: [] },
      ],
    }),
  );
  const [empty, existing] = run(...requests);
  expect(value(empty!)["related"]).toEqual(related);
  expect(value(empty!, 1)).not.toHaveProperty("related");
  expect(value(existing!)["related"]).toEqual(related);
  expect(value(existing!, 1)).not.toHaveProperty("related");
  expect(empty!.outcomes[0]!.events).toEqual(empty!.outcomes[1]!.events);
  expect(existing!.outcomes[0]!.events).toEqual(existing!.outcomes[1]!.events);
});
