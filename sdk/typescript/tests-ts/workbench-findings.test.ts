import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
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
import type { ImportedEntry } from "../../../plugins/codex-security/mcp-app/src/workbench-findings";
import type { Operation, Request } from "./support/imported-findings-fixture";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directory = mkdtempSync(join(tmpdir(), "imported-findings-"));
const fixture = join(directory, "fixture.cjs");
const node = Bun.which("node")!;
let counter = 0;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/imported-findings-fixture.ts", import.meta.url),
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
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
interface Result {
  value?: unknown;
  error?: string;
  kind?: string;
  code?: number;
  inTransaction: boolean;
}
function run(request: Request): { results: Result[] } {
  const child = spawnSync(
    node,
    [fixture, join(directory, `${counter++}.sqlite3`)],
    {
      input: stringifyJson(request),
      encoding: "utf8",
      env: { ...process.env, PATH: "" },
      maxBuffer: Infinity,
    },
  );
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as { results: Result[] };
}
function entry(
  id: string,
  vector: unknown[] = [1, 0],
  model = "synthetic",
): ImportedEntry {
  return {
    finding: {
      findingId: id,
      fingerprints: { primary: `fingerprint:${id}` },
      ruleId: "rule",
      identity: { anchor: "anchor" },
      title: `Finding ${id}`,
    },
    embedding: { model, vector },
  };
}
const snapshot: Operation = { type: "snapshot" };
const sql = (statement: string, parameters: string[] = []): Operation => ({
  type: "sql",
  sql: statement,
  parameters,
});

test("imports preserve stored bytes, identity, timestamps and repository membership across retries and rollback", () => {
  const original = entry("a");
  original.finding["extra"] = parseJson(
    '{"10":1.0,"2":9007199254740993,"\ud83d\ude00":{"z":0.0,"a":"✓"},"\ue000":-0.0}',
  );
  const changed = {
    ...original,
    finding: { ...original.finding, title: "Updated" },
  };
  const bad = entry("b", [new JsonFloat("NaN")]);
  const results = run({
    initialize: true,
    operations: [
      {
        type: "store",
        entries: [original],
        repository: "repo-a",
        timestamp: "first",
      },
      snapshot,
      {
        type: "store",
        entries: [changed, bad],
        repository: "repo-b",
        timestamp: "failed",
      },
      snapshot,
      {
        type: "store",
        entries: [
          changed,
          {
            ...entry("b"),
            finding: {
              ...entry("b").finding,
              fingerprints: original.finding.fingerprints,
            },
          },
        ],
      },
      snapshot,
      {
        type: "store",
        entries: [changed, changed],
        repository: "repo-b",
        timestamp: "second",
      },
      snapshot,
      { type: "upsert", finding: changed.finding, timestamp: "third" },
      snapshot,
      { type: "upsert", finding: { ...changed.finding, title: "Scan update" } },
      snapshot,
    ],
  }).results;
  expect(results[0]!.value).toEqual({ findingIds: ["a"] });
  expect(results[2]!.error).toContain("Out of range float");
  expect(results[3]!.value).toEqual(results[1]!.value);
  expect(results[4]!.value).toEqual({ error: "finding_conflict" });
  expect(results[5]!.value).toEqual(results[1]!.value);
  expect(results[6]!.value).toEqual({ findingIds: ["a", "a"] });
  const state = results[7]!.value as Record<string, Record<string, unknown>[]>;
  expect(state["findings"]![0]).toMatchObject({
    created_at: "first",
    updated_at: "second",
  });
  expect(state["findings"]![0]!["details_json"]).toContain(
    '"extra": {"10": 1.0, "2": 9007199254740993, "\\ue000": -0.0, "\\ud83d\\ude00": {"a": "\\u2713", "z": 0.0}}',
  );
  expect(state["finding_repositories"]).toEqual([
    { repository_id: "repo-a", finding_id: "a" },
    { repository_id: "repo-b", finding_id: "a" },
  ]);
  expect(
    (results[9]!.value as typeof state)["finding_embeddings"],
  ).toHaveLength(1);
  expect((results[11]!.value as typeof state)["finding_embeddings"]).toEqual(
    [],
  );
  expect(results.every((result) => !result.inTransaction)).toBe(true);
});

test("dedupe groups keep Python membership order, stable IDs and first timestamps without merging overlaps", () => {
  const ids = ["😀", "\ue000", "a"];
  const results = run({
    initialize: true,
    operations: [
      { type: "store", entries: ids.map((id) => entry(id)) },
      {
        type: "groups",
        groups: [[ids[0]!, "a", ids[1]!, "a"], ["a", ids[1]!], []],
        timestamp: "first",
      },
      snapshot,
      {
        type: "groups",
        groups: [[ids[1]!, "a", ids[0]!], ["a", ids[1]!], []],
        timestamp: "later",
      },
      { type: "groups", groups: [["a"], ["missing", "a"]] },
      snapshot,
      { type: "list-groups", id: "a" },
    ],
  }).results;
  const groups = (
    results[1]!.value as {
      groups: { groupId: string; findingIds: string[]; createdAt: string }[];
    }
  ).groups;
  expect(groups.map((group) => group.findingIds)).toEqual([
    ["a", "\ue000", "😀"],
    ["a", "\ue000"],
    [],
  ]);
  expect(groups[2]!.groupId).toBe(
    "fdg_4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
  );
  expect(results[3]!.value).toEqual(results[1]!.value);
  expect(results[4]!.value).toEqual({ error: "finding_conflict" });
  expect(results[5]!.value).toEqual(results[2]!.value);
  expect((results[6]!.value as { groups: unknown[] }).groups).toHaveLength(2);
});

test("duplicate selection retains the exact Python cutoff, model and dimension filtering, and stable top 50", () => {
  const boundary = entry("boundary", [0.5499999999999998, 0.8351646544245029]);
  const below = entry("below", [0.5499999999999997, 0.835164654424503]);
  const entries = [
    entry("anchor"),
    boundary,
    below,
    entry("dimension", [0]),
    entry("model", [1, 0], "other"),
  ];
  const results = run({
    initialize: true,
    operations: [
      { type: "store", entries, repository: "repo" },
      { type: "duplicates", id: "anchor", repository: "repo" },
      { type: "duplicates", id: "anchor", repository: "missing" },
      {
        type: "store",
        entries: Array.from({ length: 60 }, (_, index) =>
          entry(`tie-${String(index).padStart(2, "0")}`),
        ),
        timestamp: "same",
      },
      { type: "duplicates", id: "anchor" },
    ],
  }).results;
  expect(results[1]!.value).toEqual({
    finding: entries[0]!.finding,
    potentialDuplicates: [boundary.finding],
  });
  expect(results[2]!.value).toEqual({ error: "finding_not_indexed" });
  const found = (
    results[4]!.value as { potentialDuplicates: { findingId: string }[] }
  ).potentialDuplicates;
  expect(found.map((finding) => finding.findingId)).toEqual(
    Array.from(
      { length: 50 },
      (_, index) => `tie-${String(index).padStart(2, "0")}`,
    ),
  );
});

test("malformed vectors preserve dimension skips and the ValueError boundary without leaving a transaction", () => {
  const cases = [
    "[0,0]",
    "[NaN,1]",
    "[Infinity,0]",
    "invalid",
    "[0]",
    "{}",
    '{"a":1,"b":2}',
    "[null,1]",
    `[${"9".repeat(400)},1]`,
  ];
  const operations: Operation[] = [
    { type: "store", entries: [entry("a"), entry("b")] },
  ];
  for (const value of cases)
    operations.push(
      sql("UPDATE finding_embeddings SET vector_json=? WHERE finding_id='b'", [
        value,
      ]),
      { type: "duplicates", id: "a" },
    );
  const results = run({ initialize: true, operations }).results;
  expect([2, 4, 6, 8].map((index) => results[index]!.value)).toEqual(
    Array(4).fill({ error: "embedding_failed" }),
  );
  expect([10, 12].map((index) => results[index]!.value)).toEqual(
    Array(2).fill({ finding: entry("a").finding, potentialDuplicates: [] }),
  );
  expect(results[14]!.kind).toBe("TypeError");
  expect(results[16]!.kind).toBe("TypeError");
  expect(results[18]!.kind).toBe("RangeError");
  expect(results.every((result) => !result.inTransaction)).toBe(true);
});

test("listing and retrieval each hold a read snapshot while another connection changes documents and vectors", () => {
  const entries = [entry("a"), entry("b")];
  for (const interleave of ["list", "duplicates"] as const) {
    const read: Operation =
      interleave === "list"
        ? { type: "list", limit: 50n, offset: 0n }
        : { type: "duplicates", id: "a" };
    const results = run({
      initialize: true,
      interleave,
      operations: [{ type: "store", entries }, read, read],
    }).results;
    if (interleave === "list") {
      expect((results[1]!.value as { findings: unknown[] }).findings).toEqual(
        entries.map((entry) => entry.finding),
      );
      expect((results[2]!.value as { findings: unknown[] }).findings).toEqual([
        entries[0]!.finding,
        {},
      ]);
    } else {
      expect(results[1]!.value).toEqual({
        finding: entries[0]!.finding,
        potentialDuplicates: [entries[1]!.finding],
      });
      expect(results[2]!.value).toEqual({
        finding: entries[0]!.finding,
        potentialDuplicates: [],
      });
    }
  }
});

test("the norm and compensated dot product retain Python binary results for cutoff, cancellation and extreme scales", () => {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify({
      numeric: [
        [0.5499999999999998, 0.8351646544245029],
        [5e-324, 5e-324],
        [1e308, 1e308],
        [2.2250738585072014e-308, 5e-324],
        Array.from({ length: 1536 }, (_, index) => (index - 750) / 1000),
      ],
    }),
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
  });
  expect(child.status, child.stderr).toBe(0);
  const values = JSON.parse(child.stdout) as {
    norm: string;
    normalized: string[];
    similarity: string;
  }[];
  expect(values.map((value) => value.norm)).toEqual([
    "3feffffffffffffc",
    "0000000000000001",
    "7fe92c80954c51f5",
    "0010000000000000",
    "40316431988e777d",
  ]);
  expect(values[0]!.normalized[0]).toBe("3fe199999999999a");
  expect(values[4]!.normalized[0]).toBe("bfa61474701686ea");
  expect(values[4]!.normalized.at(-1)).toBe("3fa71c3c6e7dfa70");
  expect(values[4]!.similarity).toBe("3ff0000000000000");
  const dot = spawnSync(node, [fixture], {
    input: JSON.stringify({
      dot: [{ left: [1e16, 1, -1e16], right: [1, 1, 1] }],
    }),
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
  });
  expect(dot.status, dot.stderr).toBe(0);
  expect(JSON.parse(dot.stdout)).toEqual([1]);
});

test("existing finding command arguments preserve store_true, mutual exclusion and per-occurrence integer validation", () => {
  const state = join(directory, "arguments");
  for (const [args, status, error] of [
    [
      [
        "find-potential-duplicates",
        "--finding-id=a",
        "--all-repositories",
        "--all-repositories",
        "--help",
      ],
      0,
      "",
    ],
    [
      ["find-potential-duplicates", "--finding-id=a", "--all-repositories=yes"],
      2,
      "ignored explicit argument",
    ],
    [
      [
        "find-potential-duplicates",
        "--finding-id=a",
        "--repository-id=x",
        "--all-repositories",
        "--help",
      ],
      2,
      "not allowed with argument --repository-id",
    ],
    [
      ["find-potential-duplicates", "--finding-id=a"],
      2,
      "one of the arguments",
    ],
    [
      ["list-stored-findings", "--limit", "0", "--limit", "5", "--offset", "0"],
      2,
      "expected a positive integer",
    ],
    [
      ["list-stored-findings", "--limit", "1", "--offset", "-1", "--help"],
      2,
      "expected a non-negative integer",
    ],
    [
      ["list-stored-findings", "--limit=\u{10d44}", "--offset=0"],
      2,
      "invalid positive_int value",
    ],
    [
      ["list-stored-findings", `--limit=${"1".repeat(4301)}`, "--offset=0"],
      2,
      "invalid positive_int value",
    ],
  ] as const) {
    const child = spawnSync(
      node,
      [join(PLUGIN_ROOT, "mcp/helpers.mjs"), ...args],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: "",
          PYTHONINTMAXSTRDIGITS: "0",
          CODEX_SECURITY_STATE_DIR: state,
        },
      },
    );
    expect(child.status, child.stderr).toBe(status);
    expect(child.stderr).toContain(error);
  }
  expect(existsSync(state)).toBe(false);
});

test("the import command retains UTF-8-mode stdin surrogateescape inside stored JSON", () => {
  const imported = entry("raw-input");
  imported.finding["title"] = "raw-byte-marker";
  const input = Buffer.from(
    JSON.stringify({ entries: [imported] }).replace("raw-byte-marker", "\xff"),
    "latin1",
  );
  const environment = {
    ...process.env,
    PATH: "",
    PYTHON: join(directory, "missing-python"),
    CODEX_SECURITY_STATE_DIR: join(directory, "raw-input"),
  };
  const written = spawnSync(
    node,
    [join(PLUGIN_ROOT, "mcp/helpers.mjs"), "store-findings"],
    { input, encoding: "utf8", env: environment },
  );
  expect(written.status, written.stderr).toBe(0);
  const read = spawnSync(
    node,
    [
      join(PLUGIN_ROOT, "mcp/helpers.mjs"),
      "list-stored-findings",
      "--limit=1",
      "--offset=0",
    ],
    { encoding: "utf8", env: environment },
  );
  expect(read.status, read.stderr).toBe(0);
  expect(JSON.parse(read.stdout).findings[0].title).toBe("\udcff");
});

test("JSON imports retain the isolated Python integer limit regardless of Python environment settings", () => {
  const imported = entry("integer-input");
  imported.finding["extra"] = "integer-marker";
  const payload = JSON.stringify({ entries: [imported] });
  const environment = {
    ...process.env,
    PATH: "",
    CODEX_SECURITY_STATE_DIR: join(directory, "integer-input"),
  };
  const accepted = spawnSync(
    node,
    [join(PLUGIN_ROOT, "mcp/helpers.mjs"), "store-findings"],
    {
      input: payload.replace('"integer-marker"', "1".repeat(700)),
      encoding: "utf8",
      env: { ...environment, PYTHONINTMAXSTRDIGITS: "640" },
    },
  );
  expect(accepted.status, accepted.stderr).toBe(0);
  const rejected = spawnSync(
    node,
    [join(PLUGIN_ROOT, "mcp/helpers.mjs"), "store-findings"],
    {
      input: payload.replace('"integer-marker"', "1".repeat(4301)),
      encoding: "utf8",
      env: { ...environment, PYTHONINTMAXSTRDIGITS: "0" },
    },
  );
  expect(rejected.status).toBe(1);
  expect(rejected.stderr).toContain("Exceeds the limit (4300 digits)");
  const read = spawnSync(
    node,
    [
      join(PLUGIN_ROOT, "mcp/helpers.mjs"),
      "list-stored-findings",
      "--limit=1",
      "--offset=0",
    ],
    { encoding: "utf8", env: environment },
  );
  expect(read.status, read.stderr).toBe(0);
  expect(read.stdout).toContain(`"extra": ${"1".repeat(700)}`);
});
