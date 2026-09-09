import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { Request, Response } from "./support/source-excerpt-fixture";

const root = realpathSync(mkdtempSync(join(tmpdir(), "source-excerpt-")));
const repository = join(root, "repository ☃"),
  fixture = join(root, "fixture.mjs");
const node = Bun.which("node")!;
const env = { ...process.env };
for (const key of [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
])
  delete env[key];
Object.assign(env, {
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "Fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
});
let revision: string;
const source =
  Array.from({ length: 110 }, (_, index) => `source line ${index + 1}`).join(
    "\n",
  ) + "\n";
function git(args: string[]) {
  const result = spawnSync("git", ["-C", repository, ...args], { env });
  expect(result.status, result.stderr.toString()).toBe(0);
  return result.stdout.toString().trim();
}
function write(name: string, data: string | Buffer) {
  const path = join(repository, name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, data);
  return path;
}
function run(
  requests: Request[],
  environment: NodeJS.ProcessEnv = {},
): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    encoding: "utf8",
    env: { ...env, ...environment },
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const responses = JSON.parse(child.stdout) as Response[];
  for (const response of responses) {
    expect(response.error).toBeUndefined();
    expect(response.unchanged).toBe(true);
  }
  return responses;
}
function scan(snapshot: string | null = null, selected = revision) {
  return JSON.stringify({
    target_revision: selected,
    target_snapshot_digest: snapshot,
  });
}
function excerpt(locations: unknown[], path = "source.txt"): Request {
  return {
    action: "excerpt",
    target: repository,
    scan: scan(),
    locations: JSON.stringify(
      locations.map((location) => ({ path, ...(location as object) })),
    ),
  };
}
beforeAll(() => {
  mkdirSync(repository);
  git(["init", "--quiet"]);
  git(["config", "core.autocrlf", "false"]);
  write("source.txt", source);
  write(
    "invalid.txt",
    Buffer.from([0xef, 0xbb, 0xbf, 0x61, 0xf0, 0x9f, 0x62, 0xff]),
  );
  write("binary.txt", "text\0binary\n");
  write("empty.txt", "");
  write(
    "split.txt",
    "one\r\ntwo\rthree\nfour\vfive\fsix\x1cseven\x1deight\x1enine\x85ten\u2028eleven\u2029twelve\n",
  );
  write("unicode.txt", "😀".repeat(5000));
  write(
    "large.txt",
    "x".repeat(1024 * 1024 + 1) + "\n" + "late\n".repeat(100_001),
  );
  write("literal[1].txt", "literal\n");
  write("nested/file.txt", "nested\n");
  git(["add", "."]);
  git(["commit", "--quiet", "-m", "Source fixture"]);
  revision = git(["rev-parse", "HEAD"]);
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/source-excerpt-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp", "helpers.mjs")).href,
      ),
    },
  });
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

test("reads the sealed Git blob with isolated Git settings after the worktree and HEAD change", () => {
  write("source.txt", "replacement\n");
  git(["add", "source.txt"]);
  git(["commit", "--quiet", "-m", "Replacement fixture"]);
  write("source.txt", "dirty replacement\n");
  const result = run(
    [
      {
        action: "source",
        target: repository,
        scan: scan(),
        path: "source.txt",
      },
      {
        action: "source",
        target: repository,
        scan: scan(),
        path: "literal[1].txt",
      },
    ],
    {
      GIT_DIR: root,
      GIT_WORK_TREE: root,
      GIT_INDEX_FILE: join(root, "missing-index"),
    },
  );
  expect(result.map((item) => item.result)).toEqual([source, "literal\n"]);
  expect(result[0]!.queries).toHaveLength(1);
  expect(result[0]!.queries[0]!.slice(-3)).toEqual([
    "cat-file",
    "blob",
    `${revision}:source.txt`,
  ]);
});

test("allows only original clean snapshot digests and versioned scans", () => {
  const clean = run([{ action: "clean" }])[0]!.result!;
  const values = [null, clean, "dirty", ""];
  const responses = run([
    ...values.map(
      (value): Request => ({
        action: "source",
        target: repository,
        scan: scan(value),
        path: "source.txt",
      }),
    ),
    {
      action: "source",
      target: repository,
      scan: scan(null, "unversioned"),
      path: "source.txt",
    },
    {
      action: "source",
      target: repository,
      scan: scan(null, "missing-revision"),
      path: "source.txt",
    },
  ]);
  expect(responses.map((item) => item.result)).toEqual([
    source,
    source,
    null,
    null,
    null,
    null,
  ]);
  expect(responses.map((item) => item.queries.length)).toEqual([
    1, 1, 0, 0, 0, 1,
  ]);
});

test("keeps path containment, missing paths, and the original Git object name", () => {
  const paths = [
    "nested/./file.txt",
    "nested//file.txt",
    "missing/file.txt",
    "",
    "../outside",
    "/absolute",
    "nested/../file.txt",
    "nested\\file.txt",
    "nul\0name",
  ];
  const responses = run(
    paths.map(
      (path): Request => ({ action: "safe", target: repository, path }),
    ),
  );
  expect(responses.map((item) => item.result)).toEqual([
    join(repository, "nested", "file.txt"),
    join(repository, "nested", "file.txt"),
    join(repository, "missing", "file.txt"),
    repository,
    null,
    null,
    null,
    null,
    null,
  ]);
  const original = run([
    {
      action: "source",
      target: repository,
      scan: scan(),
      path: "nested/./file.txt",
    },
  ])[0]!;
  expect(original.queries[0]!.at(-1)).toBe(`${revision}:nested/./file.txt`);
  expect(original.result).toBeNull();
});

(process.platform === "win32" ? test.skip : test)(
  "rejects escaping and looping POSIX symlinks while permitting an internal link",
  () => {
    const outside = join(root, "outside.txt");
    writeFileSync(outside, "outside");
    symlinkSync(outside, join(repository, "outside-link"));
    symlinkSync("source.txt", join(repository, "inside-link"));
    symlinkSync("loop", join(repository, "loop"));
    expect(
      run(
        ["outside-link", "inside-link", "loop"].map(
          (path): Request => ({ action: "safe", target: repository, path }),
        ),
      ).map((item) => item.result),
    ).toEqual([null, join(repository, "source.txt"), null]);
  },
);

(process.platform === "win32" ? test : test.skip)(
  "keeps Windows junction containment and drive paths",
  () => {
    const outside = join(root, "outside"),
      inside = join(repository, "nested");
    mkdirSync(outside);
    symlinkSync(outside, join(repository, "outside-junction"), "junction");
    symlinkSync(inside, join(repository, "inside-junction"), "junction");
    expect(
      run(
        [
          "outside-junction/file.txt",
          "inside-junction/file.txt",
          outside.replaceAll("\\", "/"),
        ].map(
          (path): Request => ({ action: "safe", target: repository, path }),
        ),
      ).map((item) => item.result),
    ).toEqual([null, join(inside, "file.txt"), null]);
  },
);

test("selects root-control locations, preserves line types, and bounds line context", () => {
  const response = run([
    excerpt([
      { startLine: 1 },
      { startLine: 41, endLine: 44, role: { ROOT_CONTROL: "present" } },
    ]),
    excerpt([{ startLine: 5, endLine: 1 }]),
    excerpt([{ startLine: 5, endLine: "100" }]),
    excerpt([{ startLine: 5, endLine: 100 }]),
    excerpt([{ startLine: true }]),
    ...[0, -1, 111, "5", false].map((startLine) => excerpt([{ startLine }])),
    {
      action: "excerpt",
      target: repository,
      scan: scan(),
      locations: '[{"path":"source.txt","startLine":1.0}]',
    },
    { ...excerpt([{ startLine: 1 }]), target: null },
    excerpt([]),
  ]);
  expect(response[0]!.result!.split("\n")).toEqual(
    Array.from(
      { length: 10 },
      (_, index) => `${index + 38}  source line ${index + 38}`,
    ),
  );
  expect(response[1]!.result!.split("\n")).toEqual(
    response[2]!.result!.split("\n"),
  );
  expect(response[3]!.result!.split("\n")).toHaveLength(60);
  expect(response[4]!.result).toBe(
    "1  source line 1\n2  source line 2\n3  source line 3\n4  source line 4",
  );
  expect(response.slice(5).map((item) => item.result)).toEqual(
    Array(8).fill(null),
  );
});

test("matches Python decoding and splitlines while rejecting empty or NUL source excerpts", () => {
  const responses = run([
    { action: "source", target: repository, scan: scan(), path: "invalid.txt" },
    excerpt([{ startLine: 6 }], "split.txt"),
    excerpt([{ startLine: 1 }], "binary.txt"),
    excerpt([{ startLine: 1 }], "empty.txt"),
  ]);
  expect(responses[0]!.result).toBe("\ufeffa\ufffdb\ufffd");
  expect(responses[1]!.result).toBe(
    "3  three\n4  four\n5  five\n6  six\n7  seven\n8  eight\n9  nine",
  );
  expect(responses.slice(2).map((item) => item.result)).toEqual([null, null]);
});

test("keeps large source blobs and late lines while cutting excerpt bytes between UTF-8 characters", () => {
  const responses = run([
    excerpt([{ startLine: 1 }], "unicode.txt"),
    excerpt([{ startLine: 100_002 }], "large.txt"),
    { action: "source", target: repository, scan: scan(), path: "large.txt" },
  ]);
  expect(responses[0]!.result).toBe("1  " + "😀".repeat(3999));
  expect(Buffer.byteLength(responses[0]!.result!)).toBe(15999);
  expect(responses[1]!.result).toBe(
    " 99999  late\n100000  late\n100001  late\n100002  late",
  );
  expect(responses[2]!.result!.length).toBe(1024 * 1024 + 2 + 100_001 * 5);
});

test("treats unavailable Git as an absent source", () => {
  const response = run(
    [
      {
        action: "source",
        target: repository,
        scan: scan(),
        path: "source.txt",
      },
    ],
    { PATH: "", Path: "" },
  )[0]!;
  expect(response.result).toBeNull();
  expect(response.queries).toHaveLength(1);
});
