import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { LinearPublication } from "../../../plugins/codex-security/mcp-app/src/workbench-publication";
import type {
  Action,
  Request,
  Response,
} from "./support/workbench-publication-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-publication-")),
);
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
const scanId = "11111111-1111-4111-8111-111111111111";
let sequence = 0;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-publication-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(root, { recursive: true, force: true }));
function run(
  ...requests: (Omit<Request, "root"> & { root?: string })[]
): Response[] {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(
      requests.map((request) => ({
        root: join(root, String(sequence++)),
        ...request,
      })),
    ),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = parseJson(child.stdout) as Response[];
  for (const response of responses) expect(response.node).toBe(nodeVersion);
  return responses;
}
const issue = (
  index = 0,
  values: Partial<LinearPublication> = {},
): LinearPublication => ({
  findingId: `finding-${index}`,
  occurrenceId: `occurrence-${index}`,
  issueIdentifier: `SYNTHETIC-${index + 1}`,
  ...values,
});
const record = (...publications: LinearPublication[]): Action => ({
  operation: "record",
  payload: { publications },
});
const inspect: Action = { operation: "inspect" };
const prepare: Action = { operation: "prepare" };
const error = (response: Response, index = 0) =>
  response.outcomes[index]!.error ?? null;
const value = (response: Response, index = 0) =>
  response.outcomes[index]!.value as Record<string, unknown>;
const receipts = (response: Response) =>
  response.snapshot["finding_publications"]!;
const transactionEvents = (response: Response, index = 0) =>
  response.outcomes[index]!.events.filter(
    (event) => (event as unknown[])[0] === "transaction",
  );

test("payload validation preserves exact identities and Python whitespace rules", () => {
  const destination = {
    type: "linear",
    teamId: " team \ufeff",
    projectId: " project ",
  };
  const identity = { findingId: "__proto__", occurrenceId: "constructor" };
  const responses = run(
    {
      actions: [
        { operation: "input", payload: { destination, findings: [identity] } },
      ],
    },
    { actions: [{ operation: "input", omit: ["findings"] }] },
    { actions: [{ operation: "input", payload: { publications: [] } }] },
    {
      actions: [
        {
          operation: "input",
          payload: { destination: { type: "linear", teamId: "\x1c\x85" } },
        },
      ],
    },
    {
      actions: [
        { operation: "input", payload: { findings: [identity, identity] } },
      ],
    },
    { actions: [{ operation: "input", inputText: "[]" }] },
  );
  const input = responses[0]!.outcomes[0]!.value as unknown[];
  expect(input[1]).toEqual(destination);
  expect(input[2]).toEqual([identity]);
  expect(responses.map((response) => error(response))).toEqual([
    null,
    "Linear publication input contains unexpected or missing fields.",
    "Linear publication input contains unexpected or missing fields.",
    "Linear publication input must identify the exact team and optional project.",
    "Linear publication input repeats a finding or occurrence.",
    "input.json: expected a JSON object.",
  ]);
  for (const response of responses)
    expect(response.outcomes[0]!.events).toEqual([]);
});

test("preparation requires the exact completed scan and every finding occurrence", () => {
  const responses = run(
    { actions: [prepare] },
    { actions: [{ ...prepare, payload: { scanId: "11111111" } }] },
    { actions: [{ ...prepare, payload: { scanId: "bad" } }] },
    { scan: { status: "running" }, actions: [prepare] },
    { actions: [{ ...prepare, payload: { findings: [] } }] },
    {
      actions: [
        {
          ...prepare,
          payload: {
            findings: [
              { findingId: "finding-1", occurrenceId: "occurrence-0" },
            ],
          },
        },
      ],
    },
    { occurrences: [], actions: [prepare] },
    { scan: { canceled_at: "canceled" }, actions: [prepare] },
  );
  expect(value(responses[0]!)).toEqual({
    scanId,
    destination: { type: "linear", teamId: "synthetic-team" },
    findingCount: 2n,
  });
  expect(responses.map((response) => error(response))).toEqual([
    null,
    "Linear publication must use the exact completed scan identifier.",
    "The completed scan is not present in the local Codex Security scan-history database. Use the state directory where the scan was completed.",
    "Only completed scans can publish findings to Linear.",
    "The completed scan findings do not exactly match local Codex Security scan history.",
    "A selected finding or occurrence does not belong to the completed scan in local Codex Security scan history.",
    null,
    null,
  ]);
  expect(value(responses[6]!)["findingCount"]).toBe(0n);
  expect(transactionEvents(responses[0]!)).toEqual([
    ["transaction", "BEGIN IMMEDIATE", false],
    ["transaction", "COMMIT", true],
  ]);
  expect(transactionEvents(responses[1]!)).toEqual([
    ["transaction", "BEGIN IMMEDIATE", false],
    ["transaction", "ROLLBACK", true],
  ]);
});

test("publication checks the canonical scan directory and pinned manifest before writing", () => {
  const directoryRoot = join(root, "directory-check"),
    aliasRoot = join(root, "alias-check");
  const responses = run(
    {
      root: directoryRoot,
      actions: [
        {
          ...prepare,
          payload: { scanDirectory: join(directoryRoot, "other-scan") },
        },
      ],
    },
    {
      root: aliasRoot,
      actions: [
        {
          ...prepare,
          payload: { scanDirectory: join(aliasRoot, "scan-alias") },
        },
      ],
    },
    { pinManifest: true, actions: [record(issue())] },
    {
      pinManifest: true,
      actions: [{ ...record(issue()), manifest: "changed" }],
    },
    { actions: [{ ...record(issue()), manifest: "changed" }] },
  );
  expect(error(responses[0]!)).toContain("directory does not match");
  expect(error(responses[1]!)).toBe(
    "Scan directory must be an existing canonical non-symlink directory.",
  );
  expect(error(responses[2]!)).toBeNull();
  expect(error(responses[3]!)).toBe(
    "The sealed scan manifest changed after completion.",
  );
  expect(receipts(responses[3]!)).toEqual([]);
  expect(
    responses[3]!.outcomes[0]!.events.some(
      (event) => (event as unknown[])[0] === "now",
    ),
  ).toBe(false);
  expect(error(responses[4]!)).toBeNull();
});

test("recording retries partial receipts and returns persisted values in planned order", () => {
  const first = issue(0, { url: "https://example.test/1" }),
    second = issue(1);
  const [response] = run({
    actions: [record(second), record(second, first), record(issue()), inspect],
  });
  expect(response!.outcomes.every((outcome) => !outcome.error)).toBe(true);
  expect(value(response!, 0)["created"]).toEqual([second]);
  expect(value(response!, 1)["created"]).toEqual([first, second]);
  expect(value(response!, 2)["created"]).toEqual([first]);
  expect(value(response!, 3)["recorded"]).toEqual([first, second]);
  expect(receipts(response!)).toHaveLength(2);
  expect(receipts(response!).every((row) => row["project_id"] === null)).toBe(
    true,
  );
  expect(response!.outcomes[3]!.databaseUnchanged).toBe(true);
});

test("conflicting issue ownership and URLs roll back every receipt in the batch", () => {
  const existing = { external_url: "https://example.test/original" };
  const responses = run(
    {
      receipts: [existing],
      actions: [
        record(
          issue(0, { issueIdentifier: "SYNTHETIC-NEW" }),
          issue(1, { issueIdentifier: "SYNTHETIC-1" }),
        ),
      ],
    },
    {
      receipts: [existing],
      actions: [
        record(issue(1), issue(0, { url: "https://example.test/changed" })),
      ],
    },
    {
      receipts: [{}],
      actions: [record(issue(0, { url: "https://example.test/added" }))],
    },
  );
  expect(error(responses[0]!)).toBe(
    "This Linear issue is already associated with a different finding.",
  );
  expect(error(responses[1]!)).toBe(
    "This Linear issue is already associated with a different URL.",
  );
  expect(error(responses[2]!)).toBe(
    "This Linear issue is already associated with a different URL.",
  );
  for (const response of responses) {
    expect(receipts(response)).toHaveLength(1);
    expect(receipts(response)[0]!["external_id"]).toBe("SYNTHETIC-1");
    expect(transactionEvents(response).at(-1)).toEqual([
      "transaction",
      "ROLLBACK",
      true,
    ]);
  }
});

test("destinations remain distinct and republishing can record another issue", () => {
  const team = { type: "linear", teamId: "synthetic-team" },
    project = { ...team, projectId: "synthetic-project" };
  const [response] = run({
    actions: [
      record(issue()),
      {
        ...record(issue(1, { issueIdentifier: "SYNTHETIC-1" })),
        payload: {
          publications: [issue(1, { issueIdentifier: "SYNTHETIC-1" })],
          destination: project,
        },
      },
      record(issue(0, { issueIdentifier: "SYNTHETIC-3" })),
      inspect,
      { ...inspect, payload: { destination: project } },
    ],
  });
  expect(response!.outcomes.every((outcome) => !outcome.error)).toBe(true);
  expect(receipts(response!)).toHaveLength(3);
  expect(value(response!, 3)["recorded"]).toEqual([issue()]);
  expect(value(response!, 4)["recorded"]).toEqual([
    issue(1, { issueIdentifier: "SYNTHETIC-1" }),
  ]);
});

test("inspection picks the earliest receipt per occurrence and preserves finding order", () => {
  const [response] = run({
    receipts: [
      { external_id: "SYNTHETIC-9", created_at: "later" },
      { external_id: "SYNTHETIC-3", created_at: "earlier" },
      { external_id: "SYNTHETIC-2", created_at: "earlier", external_url: "" },
      {
        finding_id: "finding-1",
        occurrence_id: "occurrence-1",
        external_id: "SYNTHETIC-4",
      },
      { external_id: "SYNTHETIC-1", team_id: "other-team", created_at: "a" },
    ],
    actions: [
      inspect,
      {
        ...inspect,
        payload: {
          findings: [
            { findingId: "finding-1", occurrenceId: "occurrence-1" },
            { findingId: "finding-0", occurrenceId: "occurrence-0" },
          ],
        },
      },
    ],
  });
  const first = issue(0, { issueIdentifier: "SYNTHETIC-2", url: "" }),
    second = issue(1, { issueIdentifier: "SYNTHETIC-4" });
  expect(value(response!, 0)["recorded"]).toEqual([first, second]);
  expect(value(response!, 1)["recorded"]).toEqual([second, first]);
  for (const outcome of response!.outcomes) {
    expect(outcome.databaseUnchanged).toBe(true);
    expect(outcome.events.at(-1)).toEqual(["close", true]);
  }
});

test("read-only inspection leaves older databases unchanged and never creates a missing one", () => {
  const missingRoot = join(root, "missing-database"),
    missing = join(missingRoot, "missing.sqlite3");
  const responses = run(
    { migrationsBefore: 8, actions: [inspect] },
    { setupSql: ["DROP TABLE finding_publications"], actions: [inspect] },
    { root: missingRoot, actions: [{ ...inspect, databasePath: missing }] },
    {
      actions: [
        { ...inspect, databaseError: "database failed", omit: ["findings"] },
      ],
    },
  );
  for (const response of responses.slice(0, 2)) {
    expect(error(response)).toBeNull();
    expect(value(response)["recorded"]).toEqual([]);
    expect(response.snapshot["finding_publications"]).toBeNull();
    expect(response.outcomes[0]!.databaseUnchanged).toBe(true);
  }
  expect(error(responses[2]!)).toBe("unable to open database file");
  expect(existsSync(missing)).toBe(false);
  expect(error(responses[3]!)).toContain("unexpected or missing fields");
  expect(responses[3]!.outcomes[0]!.events).toEqual([]);
});

test("inspection quotes native Windows paths and keeps strict UTF-8 encoding errors", () => {
  const paths = [
    [
      String.raw`C:\state\history.sqlite3`,
      "file:C%3A%5Cstate%5Chistory.sqlite3?mode=ro",
    ],
    [
      String.raw`\\server\share\state\history.sqlite3`,
      "file:%5C%5Cserver%5Cshare%5Cstate%5Chistory.sqlite3?mode=ro",
    ],
    [
      String.raw`\\?\C:\state\history.sqlite3`,
      "file:%5C%5C%3F%5CC%3A%5Cstate%5Chistory.sqlite3?mode=ro",
    ],
    [
      String.raw`\\?\UNC\server\share\history.sqlite3`,
      "file:%5C%5C%3F%5CUNC%5Cserver%5Cshare%5Chistory.sqlite3?mode=ro",
    ],
    [
      "relative?#%/é.sqlite3",
      "file:relative%3F%23%25%2F%C3%A9.sqlite3?mode=ro",
    ],
  ];
  const responses = run(
    ...paths.map(([databasePath]) => ({
      actions: [
        { ...inspect, databasePath: databasePath!, captureConnection: true },
      ],
    })),
    {
      actions: [
        {
          ...inspect,
          databasePath: "/synthetic/\ud800.sqlite3",
          captureConnection: true,
        },
      ],
    },
  );
  for (const [index, [, uri]] of paths.entries()) {
    expect(error(responses[index]!)).toBe("captured connection");
    expect(responses[index]!.outcomes[0]!.events).toEqual([
      ["databasePath", false],
      ["connect", uri, false, true],
    ]);
  }
  expect(error(responses[5]!)).toBe(
    "'utf-8' codec can't encode character '\\ud800' in position 11: surrogates not allowed",
  );
  expect(responses[5]!.outcomes[0]!.events).toEqual([["databasePath", false]]);
});

test("inspection sees committed WAL receipts and hides an existing caller transaction", () => {
  const insert = `INSERT INTO finding_publications(scan_id,finding_id,occurrence_id,destination_type,team_id,external_id,created_at) VALUES ('${scanId}','finding-0','occurrence-0','linear','synthetic-team','SYNTHETIC-1','uncommitted')`;
  const responses = run(
    {
      actions: [
        { operation: "sql", sql: "PRAGMA journal_mode=WAL" },
        record(issue()),
        inspect,
      ],
    },
    {
      actions: [
        { operation: "sql", sql: insert },
        inspect,
        { operation: "rollback" },
        inspect,
      ],
    },
  );
  expect(value(responses[0]!, 2)["recorded"]).toEqual([issue()]);
  expect(value(responses[1]!, 1)["recorded"]).toEqual([]);
  expect(responses[1]!.outcomes[1]!.inTransaction).toBe(true);
  expect(value(responses[1]!, 3)["recorded"]).toEqual([]);
  expect(responses[1]!.outcomes[3]!.inTransaction).toBe(false);
});

test("invalid results fail before BEGIN and failed BEGIN preserves caller changes", () => {
  const update: Action = {
    operation: "sql",
    sql: "UPDATE scans SET updated_at='caller'",
  };
  const responses = run(
    {
      actions: [
        update,
        { operation: "record", payload: { publications: [issue(), issue()] } },
      ],
    },
    { actions: [update, record(issue())] },
    { actions: [update, prepare] },
  );
  expect(error(responses[0]!, 1)).toContain("repeat a finding");
  expect(responses[0]!.outcomes[1]!.events).toEqual([]);
  for (const response of responses.slice(1)) {
    expect(error(response, 1)).toBe(
      "cannot start a transaction within a transaction",
    );
    expect(transactionEvents(response, 1)).toEqual([
      ["transaction", "BEGIN IMMEDIATE", true],
    ]);
  }
  for (const response of responses) {
    expect(response.outcomes[1]!.inTransaction).toBe(true);
    expect(response.snapshot["scans"]![0]!["updated_at"]).toBe("caller");
    expect(receipts(response)).toEqual([]);
  }
});

test("trigger and commit failures roll back and successful reads return stored receipts", () => {
  const responses = run(
    {
      setupSql: [
        "CREATE TRIGGER synthetic_ignore BEFORE INSERT ON finding_publications BEGIN SELECT RAISE(IGNORE); END",
      ],
      actions: [record(issue())],
    },
    {
      setupSql: [
        "CREATE TABLE deferred_audit(id TEXT REFERENCES scans(id) DEFERRABLE INITIALLY DEFERRED)",
        "CREATE TRIGGER deferred_failure AFTER INSERT ON finding_publications BEGIN INSERT INTO deferred_audit VALUES ('missing'); END",
      ],
      actions: [record(issue())],
    },
    {
      setupSql: [
        "CREATE TRIGGER stored_url AFTER INSERT ON finding_publications BEGIN UPDATE finding_publications SET external_url='stored' WHERE id=NEW.id; END",
      ],
      actions: [record(issue())],
    },
  );
  expect(error(responses[0]!)).toBe(
    "A created Linear issue could not be read from scan history.",
  );
  expect(error(responses[1]!)).toBe("FOREIGN KEY constraint failed");
  expect(transactionEvents(responses[1]!)).toEqual([
    ["transaction", "BEGIN IMMEDIATE", false],
    ["transaction", "COMMIT", true],
    ["transaction", "ROLLBACK", true],
  ]);
  for (const response of responses.slice(0, 2)) {
    expect(receipts(response)).toEqual([]);
    expect(response.outcomes[0]!.inTransaction).toBe(false);
  }
  expect(value(responses[2]!)["created"]).toEqual([
    issue(0, { url: "stored" }),
  ]);
});

test("clock failure rolls back while mutations after verification retain original ordering", () => {
  const responses = run(
    {
      actions: [
        {
          ...record(issue()),
          nowSql: "INSERT INTO synthetic_audit VALUES ('clock')",
          nowError: "clock failed",
        },
      ],
    },
    {
      pinManifest: true,
      actions: [{ ...record(issue()), nowManifest: "changed" }],
    },
    {
      actions: [
        {
          ...record(issue()),
          nowSql: "UPDATE scans SET status='failed'",
          now: "original timestamp",
        },
      ],
    },
  );
  expect(error(responses[0]!)).toBe("clock failed");
  expect(receipts(responses[0]!)).toEqual([]);
  expect(responses[0]!.snapshot["synthetic_audit"]).toEqual([]);
  expect(error(responses[1]!)).toBeNull();
  expect(responses[1]!.manifest).toBe("changed");
  expect(receipts(responses[1]!)).toHaveLength(1);
  expect(error(responses[2]!)).toBeNull();
  expect(responses[2]!.snapshot["scans"]![0]!["status"]).toBe("failed");
  expect(receipts(responses[2]!)[0]!["created_at"]).toBe("original timestamp");
});
