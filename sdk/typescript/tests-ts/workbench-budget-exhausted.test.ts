import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
import type { BudgetCandidate } from "../../../plugins/codex-security/mcp-app/src/workbench-budget-exhausted";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { Action, Outcome } from "./support/budget-exhausted-fixture";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(mkdtempSync(join(tmpdir(), "budget-exhausted-")));
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/budget-exhausted-fixture.ts", import.meta.url),
      ),
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
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
function run(...actions: Action[]): Outcome[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(actions),
    encoding: "utf8",
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return parseJson(child.stdout) as Outcome[];
}
function directory(): string {
  const path = mkdtempSync(join(root, "scan-"));
  chmodSync(path, 0o700);
  return path;
}
function candidate(
  id = "c1",
  changes: Partial<BudgetCandidate> = {},
): BudgetCandidate {
  return {
    candidate_id: id,
    summary: "Synthetic candidate",
    evidence: "Synthetic evidence",
    locations: [{ path: "src/file.ts" }],
    ...changes,
  };
}
function discovery(
  scanDir: string,
  ledger: string | Buffer,
  inventory: string | Buffer = "src/file.ts\n",
): string {
  const path = join(scanDir, "artifacts", "02_discovery");
  mkdirSync(path, { recursive: true });
  writeFileSync(join(path, "in_scope_files.txt"), inventory);
  writeFileSync(join(path, "candidate_ledger.jsonl"), ledger);
  return path;
}
const read = (path: string, name: string) =>
  parseJson(readFileSync(join(path, name), "utf8")) as Record<string, unknown>;
function draft(
  path: string,
  changes: { manifest?: unknown; findings?: unknown; coverage?: unknown } = {},
) {
  const manifest = changes.manifest ?? {
    scan: { scope: { limitations: ["kept"] } },
  };
  const findings = changes.findings ?? { findings: [] };
  const coverage = changes.coverage ?? {
    surfaces: [],
    deferred: [],
    explicitExclusions: [],
  };
  for (const [name, value] of [
    ["scan-manifest.json", manifest],
    ["findings.json", findings],
    ["coverage.json", coverage],
  ] as const)
    writeFileSync(join(path, name), stringifyJson(value));
}

test("canonical discovery checks inventory before the ledger and rejects directory aliases", () => {
  const missing = directory(),
    valid = directory(),
    alias = directory();
  const path = discovery(valid, "");
  mkdirSync(join(alias, "artifacts"));
  symlinkSync(
    path,
    join(alias, "artifacts", "02_discovery"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const outcomes = run(
    ...[missing, valid, alias].map(
      (scanDir): Action => ({ kind: "canonical", scanDir }),
    ),
  );
  expect(outcomes[0]!.error).toBe(
    "Canonical in-scope inventory path must be an existing path inside the scan directory.",
  );
  expect(outcomes[1]!.value).toEqual({
    inScopeFilesPath: join(path, "in_scope_files.txt"),
    candidateLedgerPath: join(path, "candidate_ledger.jsonl"),
  });
  expect(outcomes[2]!.error).toContain("Canonical in-scope inventory path");
});

test("candidate ledger preserves partial records, Unicode, and inventory normalization", () => {
  const scanDir = directory();
  const values = [
    candidate("first", {
      summary: "Résumé",
      extra: { integer: 9007199254740993n },
      locations: [{ path: "elsewhere" }, { path: "src/file.ts" }],
    }),
    candidate("second"),
  ];
  discovery(
    scanDir,
    "\u001c\r\n" +
      values
        .map((value) => stringifyJson(value, { compact: true }))
        .join("\r") +
      "\r\n",
    "././src/file.ts\r\n",
  );
  expect(run({ kind: "candidates", scanDir })[0]!.value).toEqual(values);
});

test("candidate ledger validates identities, relative locations, and inventory membership", () => {
  const inputs: [unknown[], string][] = [
    [[candidate(), candidate()], "contains an invalid candidate"],
    [[candidate("..")], "contains an invalid candidate"],
    [[candidate("c", { summary: "\u001c" })], "contains an invalid candidate"],
    [[null], "rows must be objects"],
    [[{ ...candidate(), locations: [null] }], "location must be an object"],
    [
      [candidate("c", { locations: [{ path: "src/../file.ts" }] })],
      "must be repository-relative",
    ],
    [
      [candidate("c", { locations: [{ path: "C:relative" }] })],
      "must be repository-relative",
    ],
    [
      [candidate("c", { locations: [{ path: "outside.ts" }] })],
      "must include a location in its in-scope inventory",
    ],
  ];
  for (const [values, message] of inputs) {
    const scanDir = directory();
    discovery(
      scanDir,
      values.map((value) => stringifyJson(value, { compact: true })).join("\n"),
    );
    const result = run({ kind: "candidates", scanDir })[0]!;
    expect(result.error).toContain(message);
    expect(result.systemExit).toBe(true);
  }
});

test("ledger decoding preserves TextIO error order and UTF-8 split across read chunks", () => {
  const cases = [
    {
      bytes: Buffer.concat([
        Buffer.from("{bad}\n"),
        Buffer.alloc(100, 32),
        Buffer.from([255]),
      ]),
      error: "position 106: invalid start byte",
    },
    {
      bytes: Buffer.concat([
        Buffer.from("{bad}\n"),
        Buffer.alloc(8192, 32),
        Buffer.from([255]),
      ]),
      error: "Expecting property name enclosed in double quotes",
    },
    {
      bytes: Buffer.concat([Buffer.alloc(8192, 32), Buffer.from([255])]),
      error: "position 0: invalid start byte",
    },
  ];
  for (const { bytes, error } of cases) {
    const scanDir = directory();
    discovery(scanDir, bytes);
    expect(run({ kind: "candidates", scanDir })[0]!.error).toContain(error);
  }
  const scanDir = directory();
  const value = candidate("split", { summary: "😀" });
  const line = JSON.stringify(value),
    offset = Buffer.byteLength(line.slice(0, line.indexOf("😀")));
  discovery(scanDir, " ".repeat(8191 - offset) + line);
  expect(run({ kind: "candidates", scanDir })[0]!.value).toEqual([value]);
});

test("new budget drafts preserve disposition precedence and create partial scoped coverage", () => {
  const scanDir = directory();
  const values = [
    candidate("follow", {
      locations: [
        { path: "src/file.ts" },
        { path: "src/file.ts" },
        { path: "other.ts" },
      ],
    }),
    candidate("deferred", {
      validation: { disposition: "not_applicable" },
      attack_path: { decision: "deferred" },
    }),
    candidate("na", {
      validation: { disposition: "not_applicable" },
      attack_path: { decision: "ignore" },
    }),
    candidate("suppressed", { validation: { disposition: "suppressed" } }),
    candidate("ignore", { attack_path: { decision: "ignore" } }),
  ];
  expect(
    run({
      kind: "draft",
      scanDir,
      candidates: values,
      scan: { scope: "src" },
      warning: "budget warning",
    })[0]!.error,
  ).toBeUndefined();
  const coverage = read(scanDir, "coverage.json");
  expect(coverage["completeness"]).toBe("partial");
  expect(coverage["inventoryStrategy"]).toBe("scoped_path");
  expect(
    (coverage["surfaces"] as Record<string, unknown>[]).map(
      (value) => value["disposition"],
    ),
  ).toEqual([
    "needs_follow_up",
    "needs_follow_up",
    "not_applicable",
    "rejected",
    "rejected",
  ]);
  expect(
    (coverage["deferred"] as Record<string, unknown>[]).map(
      (value) => value["id"],
    ),
  ).toEqual(["follow", "deferred"]);
  expect(
    (coverage["deferred"] as Record<string, unknown>[])[0]!["paths"],
  ).toEqual(["src/file.ts", "other.ts"]);
  expect(read(scanDir, "scan-manifest.json")["scan"]).toEqual({
    target: {
      kind: "directory_snapshot",
      targetId: "synthetic-target",
      displayName: "repository",
      snapshotDigest: "snapshot",
    },
    scope: { limitations: ["budget warning"], validationMode: "incomplete" },
  });
  expect(readFileSync(join(scanDir, "coverage.json"), "utf8")).toBe(
    stringifyJson(coverage, { sortKeys: true, allowNan: false }) + "\n",
  );
});

test("existing drafts retain findings and deferred rows and remain stable on replay", () => {
  const scanDir = directory();
  const findings = {
    findings: [
      { provenance: { candidateId: "found" } },
      { extensions: { reportId: "legacy" } },
      null,
    ],
  };
  const coverage = {
    surfaces: [{ id: "candidate-follow", notes: "retained" }],
    deferred: [{ id: "already", reason: "retained" }],
    explicitExclusions: ["retained"],
  };
  draft(scanDir, { findings, coverage });
  const action: Action = {
    kind: "draft",
    scanDir,
    candidates: ["found", "legacy", "already", "follow"].map((id) =>
      candidate(id),
    ),
  };
  expect(run(action)[0]!.error).toBeUndefined();
  const first = readFileSync(join(scanDir, "coverage.json"));
  expect(run(action)[0]!.error).toBeUndefined();
  expect(readFileSync(join(scanDir, "coverage.json"))).toEqual(first);
  expect(read(scanDir, "findings.json")).toEqual(findings);
  expect(read(scanDir, "coverage.json")["surfaces"]).toEqual(coverage.surfaces);
  expect((read(scanDir, "coverage.json")["deferred"] as unknown[]).length).toBe(
    2,
  );
  expect(read(scanDir, "scan-manifest.json")).toEqual({
    scan: { scope: { limitations: ["kept"] } },
  });
});

test("drafts add the general budget deferral when every candidate is rejected", () => {
  const scanDir = directory();
  expect(
    run({
      kind: "draft",
      scanDir,
      candidates: [candidate("c", { attack_path: { decision: "ignore" } })],
    })[0]!.error,
  ).toBeUndefined();
  expect(read(scanDir, "coverage.json")["deferred"]).toEqual([
    {
      id: "scan-cost-limit",
      reason:
        "Validation was deferred because the scan reached its cost limit.",
    },
  ]);
});

test("incomplete, sealed, and malformed drafts retain their original files", () => {
  for (const mode of ["incomplete", "sealed", "coverage"] as const) {
    const scanDir = directory();
    draft(
      scanDir,
      mode === "sealed"
        ? { manifest: { scan: { sealedAt: "sealed" } } }
        : mode === "coverage"
          ? { coverage: { surfaces: [], deferred: {}, explicitExclusions: [] } }
          : {},
    );
    if (mode === "incomplete") rmSync(join(scanDir, "coverage.json"));
    const before = readFileSync(join(scanDir, "findings.json"));
    expect(run({ kind: "draft", scanDir })[0]!.systemExit).toBe(true);
    expect(readFileSync(join(scanDir, "findings.json"))).toEqual(before);
  }
});

test("draft serialization failure retains earlier writes", () => {
  const scanDir = directory();
  draft(scanDir, {
    findings: { findings: [], extra: "résumé" },
  });
  writeFileSync(
    join(scanDir, "scan-manifest.json"),
    '{"scan":{},"overflow":1e9999}',
  );
  const originalManifest = readFileSync(join(scanDir, "scan-manifest.json"));
  const result = run({ kind: "draft", scanDir })[0]!;
  expect(result.error).toBe(
    "Budget-exhausted scan draft could not be saved: Out of range float values are not JSON compliant: inf",
  );
  expect(result.systemExit).toBe(true);
  expect(readFileSync(join(scanDir, "scan-manifest.json"))).toEqual(
    originalManifest,
  );
  expect(read(scanDir, "coverage.json")["completeness"]).toBe("partial");
  expect(readFileSync(join(scanDir, "findings.json"), "utf8")).toContain(
    "r\\u00e9sum\\u00e9",
  );
});
