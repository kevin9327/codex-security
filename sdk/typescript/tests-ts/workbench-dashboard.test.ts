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
import type { DashboardQuery } from "../../../plugins/codex-security/mcp-app/src/workbench-dashboard";
import type { DashboardSnapshot } from "../src/server/dashboard-types.js";
import type { FindingDedupeGroup } from "../src/finding-dedupe-groups.js";
import type { Request } from "./support/dashboard-fixture";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directory = mkdtempSync(join(tmpdir(), "workbench-dashboard-"));
const fixture = join(directory, "fixture.cjs");
const storeFixture = join(directory, "store.cjs");
const node = Bun.which("node")!;
let populated: string;
let counter = 0;
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(new URL("./support/dashboard-fixture.ts", import.meta.url)),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp", "helpers.mjs")).href,
      ),
    },
  });
  populated = (run({ action: "describe" }) as { populated: string }).populated;
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/dashboard-store-fixture.ts", import.meta.url),
      ),
    ],
    outfile: storeFixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        new URL("../src/runtime.ts", import.meta.url).href,
      ),
    },
  });
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(
  request: Request,
  decode: (value: string) => unknown = JSON.parse,
): unknown {
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
  return decode(child.stdout);
}
const query = (options: Partial<DashboardQuery> = {}): DashboardQuery => ({
  view: "findings",
  sort: "activity",
  limit: 50n,
  offset: 0n,
  ...options,
});
interface Report {
  before: unknown;
  after: unknown;
  results: {
    value?: DashboardSnapshot;
    error?: string;
    code?: number;
    inTransaction: boolean;
  }[];
  groups: { groups: FindingDedupeGroup[] }[];
}
function queries(
  values: DashboardQuery[],
  setup = populated,
  findingIds: string[] = [],
): Report {
  const report = run({
    action: "queries",
    setup,
    queries: values,
    findingIds,
    readOnly: true,
  }) as Report;
  expect(report.after).toEqual(report.before);
  for (const result of report.results) expect(result.inTransaction).toBe(false);
  return report;
}

test("reads empty stores using only the four findings and dedupe tables", () => {
  const report = queries([query(), query({ view: "groups" })], "");
  expect(Object.keys(report.before as object)).toEqual([
    "findings",
    "finding_repositories",
    "finding_dedupe_groups",
    "finding_dedupe_group_members",
  ]);
  for (const result of report.results)
    expect(result.value).toEqual({
      overview: { findings: 0, groups: 0 },
      repositories: [],
      items: [],
      total: 0,
      limit: 50,
      offset: 0,
      nextOffset: null,
      detail: null,
    });
});

test("keeps SQL ordering, stable pages, independent selected details and exact repository filters", () => {
  const report = queries([
    query({ sort: "newest", limit: 2n }),
    query({ sort: "newest", limit: 2n, offset: 2n }),
    query(),
    query({ repository: "repo-z", id: "b" }),
    query({ repository: "REPO-Z" }),
    query({ offset: 99n }),
    query({ id: "unlisted" }),
    query({ id: "missing" }),
  ]);
  const values = report.results.map((result) => result.value!);
  expect(values[0]!.items.map((item) => item.id)).toEqual(["b", "c"]);
  expect(values[0]!.nextOffset).toBe(2);
  expect(values[1]!.items.map((item) => item.id)).toEqual(["a"]);
  expect(values[1]!.nextOffset).toBeNull();
  expect(values[2]!.items.map((item) => item.id)).toEqual(["a", "b", "c"]);
  expect(values[2]!.overview).toEqual({ findings: 3, groups: 3 });
  expect(values[2]!.repositories).toEqual(
    ["repo-a", "repo-b", "repo-z"].map((id) => ({ id, label: id })),
  );
  expect(values[3]!.items.map((item) => item.id)).toEqual(["a"]);
  expect(values[3]!.detail!.item.id).toBe("b");
  expect(values[3]!.detail!.groups!.map((group) => group.groupId)).toEqual([
    "10",
    "2",
  ]);
  expect(values[4]!.total).toBe(0);
  expect(values[5]!.items).toEqual([]);
  expect(values[5]!.nextOffset).toBeNull();
  expect(values[6]!.detail).toBeNull();
  expect(values[7]!.detail).toBeNull();
});

test("retains accepted float and boolean pagination values and Python arithmetic types", () => {
  const report = run(
    {
      action: "queries",
      setup: populated,
      readOnly: true,
      queries: [
        query({ limit: new JsonFloat("1.0"), offset: new JsonFloat("0.0") }),
        query({ limit: true, offset: false }),
        query({ limit: false, offset: true }),
        query({ limit: false, offset: new JsonFloat("-0.0") }),
        query({ limit: new JsonFloat("1.0"), offset: true }),
        query({ limit: new JsonFloat("1.5") }),
        query({ offset: new JsonFloat("0.5") }),
        query({ offset: "0" as unknown as DashboardQuery["offset"] }),
      ],
    },
    parseJson,
  ) as {
    results: { value?: unknown; error?: string; inTransaction: boolean }[];
  };
  expect(
    report.results.slice(0, 5).map((result) => result.value),
  ).toMatchObject([
    {
      limit: new JsonFloat("1.0"),
      offset: new JsonFloat("0.0"),
      nextOffset: new JsonFloat("1.0"),
    },
    { limit: true, offset: false, nextOffset: 1n },
    { limit: false, offset: true, nextOffset: 1n },
    {
      limit: false,
      offset: new JsonFloat("-0.0"),
      nextOffset: new JsonFloat("0.0"),
    },
    { limit: new JsonFloat("1.0"), offset: true, nextOffset: 2n },
  ]);
  expect(report.results.slice(5).map((result) => result.error)).toEqual([
    "datatype mismatch",
    "datatype mismatch",
    'can only concatenate str (not "int") to str',
  ]);
  expect(report.results.every((result) => !result.inTransaction)).toBe(true);
});

test("uses full Unicode15 folding for titles, identifiers and repository text", () => {
  expect(
    run({
      action: "casefold",
      values: ["Straße ẞ", "Σςσ", "İIı", "ﬃ", "Ꭰꭰ", "K", "\u1c89"],
    }),
  ).toEqual(["strasse ss", "σσσ", "i\u0307iı", "ffi", "ᎠᎠ", "k", "\u1c89"]);
  const report = queries(
    ["STRASSE", "σσ", "i\u0307", "FFI", "Ꭰ", "REPO-Z"].map((text) =>
      query({ query: text }),
    ),
  );
  for (const result of report.results)
    expect(result.value!.items.map((item) => item.id)).toEqual(["a"]);
  const filtered = queries([
    query({ query: "STRASSE", repository: "repo-b" }),
    query({ query: "%' OR 1=1 --" }),
  ]);
  expect(filtered.results.map((result) => result.value!.total)).toEqual([0, 0]);
});

test("projects overlapping, empty and repository-filtered groups with all member IDs", () => {
  const report = queries(
    [
      query({ view: "groups", sort: "newest", limit: 2n, id: "2" }),
      query({ view: "groups", repository: "repo-b" }),
      query({ view: "groups", id: "empty", query: "not-found" }),
      query({ id: "a" }),
    ],
    populated,
    ["b", "unlisted", "missing"],
  );
  const values = report.results.map((result) => result.value!);
  expect(values[0]!.items.map((item) => [item.id, item.memberCount])).toEqual([
    ["10", 2],
    ["2", 3],
  ]);
  expect(values[0]!.detail!.group).toEqual({
    groupId: "2",
    createdAt: "2026-01-02",
    findingIds: ["b", "c", "unlisted"],
  });
  expect(values[1]!.items.map((item) => item.id)).toEqual(["10", "2"]);
  expect(values[2]!.items).toEqual([]);
  expect(values[2]!.detail!.group!.findingIds).toEqual([]);
  expect(values[2]!.detail!.item.repositoryIds).toEqual([]);
  expect(values[3]!.detail!.finding).toMatchObject({
    title: "Straße Σς İ ﬃ Ꭰꭰ",
    evidence: { text: "complete ✓", values: [1, null, true] },
  });
  expect(
    report.groups.map((result) => result.groups.map((group) => group.groupId)),
  ).toEqual([["10", "2"], ["2"], []]);
});

test("rolls back failed reads without changing stored rows or retaining a transaction", () => {
  const malformed = queries(
    [query()],
    populated + "UPDATE findings SET details_json='not-json' WHERE id='a';",
  );
  expect(malformed.results[0]!.error).toBe("malformed JSON");
  expect(malformed.results[0]!.code).toBe(1);
  const nontext = queries(
    [query({ query: "not-found" }), query()],
    populated +
      "UPDATE findings SET details_json='{\"title\":7}' WHERE id='a';",
  );
  expect(nontext.results[0]!.error).toBe(
    "user-defined function raised exception",
  );
  expect(nontext.results[1]!.value!.total).toBe(3);
});

test("keeps overview, repositories, pages and detail in one snapshot across a committed writer", () => {
  const values = run({
    action: "interleave",
    setup: populated,
    queries: [query({ id: "a" }), query({ id: "a" })],
  }) as DashboardSnapshot[];
  expect(values[0]!.overview).toEqual({ findings: 3, groups: 3 });
  expect(values[0]!.repositories).toHaveLength(3);
  expect(values[0]!.items).toHaveLength(3);
  expect(values[0]!.detail!.finding!.title).toBe("Straße Σς İ ﬃ Ꭰꭰ");
  expect(values[1]!.overview).toEqual({ findings: 4, groups: 4 });
  expect(values[1]!.repositories).toHaveLength(4);
  expect(values[1]!.items).toHaveLength(4);
  expect(values[1]!.detail!.finding!.title).toBe("changed");
});

test("formats native wall-clock microseconds with Python UTC fractional precision", () => {
  const result = run({
    action: "timestamps",
    values: ["0", "1", "123456", "1000000", "-1", "-1000000"],
  }) as { values: string[]; now: string };
  expect(result.values).toEqual([
    "1970-01-01T00:00:00+00:00",
    "1970-01-01T00:00:00.000001+00:00",
    "1970-01-01T00:00:00.123456+00:00",
    "1970-01-01T00:00:01+00:00",
    "1969-12-31T23:59:59.999999+00:00",
    "1969-12-31T23:59:59+00:00",
  ]);
  expect(result.now).toMatch(
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{6})?\+00:00$/u,
  );
});

test("the SDK initializes and reads through the packaged helper on the actual Node runtime", () => {
  const state = join(directory, "sdk state");
  const child = spawnSync(node, [storeFixture], {
    input: stringifyJson(query()),
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: "",
      PYTHON: join(directory, "missing-python"),
      CODEX_SECURITY_STATE_DIR: state,
    },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const result = JSON.parse(child.stdout) as {
    result: DashboardSnapshot;
    page: { total: number };
  };
  expect(result.result.overview).toEqual({ findings: 0, groups: 0 });
  expect(result.page.total).toBe(0);
});

test("database utility help and argument errors leave state untouched", () => {
  for (const command of ["dashboard", "database-info"]) {
    for (const argument of ["--help", "-h", "--unknown", "unexpected"]) {
      const state = join(directory, `arguments-${counter++}`);
      const child = spawnSync(
        node,
        [join(PLUGIN_ROOT, "mcp", "helpers.mjs"), command, argument],
        {
          input: "",
          encoding: "utf8",
          env: { ...process.env, PATH: "", CODEX_SECURITY_STATE_DIR: state },
        },
      );
      if (argument === "--help" || argument === "-h") {
        expect(child.status, child.stderr).toBe(0);
        expect(child.stderr).toBe("");
        expect(child.stdout).toContain(`--helper ${command} [-h]`);
        expect(child.stdout).toContain("--help");
      } else {
        expect(child.status, child.stderr).toBe(2);
        expect(child.stdout).toBe("");
        expect(child.stderr).toContain(`unrecognized arguments: ${argument}`);
      }
      expect(existsSync(state)).toBe(false);
    }
  }
});
