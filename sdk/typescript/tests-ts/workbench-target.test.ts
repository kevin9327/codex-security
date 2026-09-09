import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lchmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { SnapshotScan } from "../../../plugins/codex-security/mcp-app/src/workbench-target";
import type { Request, Response } from "./support/workbench-target-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-target-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!,
  spoolDirectory = join(directory, "spooled-diffs");
const environment: NodeJS.ProcessEnv = {
  ...process.env,
  PYTHON: "/unavailable/python",
  TMPDIR: spoolDirectory,
};
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
  delete environment[key];
Object.assign(environment, {
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "Fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
});
let childPath = process.env["PATH"];
beforeAll(() => {
  mkdirSync(spoolDirectory);
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-target-fixture.ts", import.meta.url),
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
  if (process.platform !== "win32") {
    const bin = join(directory, "bin");
    mkdirSync(bin);
    symlinkSync(Bun.which("git")!, join(bin, "git"));
    childPath = bin;
  }
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function run(...requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    env: { ...environment, PATH: childPath },
    input: JSON.stringify(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Response[];
}
function result(request: Request) {
  const response = run(request)[0]!;
  expect(response.error).toBeUndefined();
  return response.result;
}
function root() {
  return realpathSync(mkdtempSync(join(directory, "target Σ ")));
}
function write(
  path: string,
  name: string,
  contents: string | Buffer = "contents\n",
) {
  const target = join(path, name);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, contents);
  return target;
}
function git(path: string, ...args: string[]) {
  const execution = spawnSync(
    "git",
    ["-c", "protocol.file.allow=always", "-C", path, ...args],
    { env: environment, encoding: "utf8" },
  );
  expect(execution.status, execution.stderr).toBe(0);
  return execution.stdout.trim();
}
function repository(commit = true) {
  const path = root();
  git(path, "init", "-q", "-b", "main");
  git(path, "config", "core.autocrlf", "false");
  write(path, "tracked.txt");
  write(path, "scope/source.txt");
  write(path, ".gitignore", "*.tmp\n");
  if (commit) {
    git(path, "add", ".");
    git(path, "commit", "-qm", "docs: café 日本語 🔧");
  }
  return path;
}
function scan(path: string, revision = "unversioned"): SnapshotScan {
  const identity = result({
    action: "scanIdentity",
    target: path,
    diffTarget: { headRevision: revision },
  }) as [string, null, unknown, unknown];
  return {
    target_path: path,
    target_inode: identity[3],
    target_revision: revision,
    scan_dir: join(path, "scan"),
    diff_target_kind: null,
    target_snapshot_digest: null,
    diff_head_revision: null,
    diff_content_digest: null,
  };
}
const directoryDigest = (target: string, extra: Partial<Request> = {}) =>
  result({ action: "directory", target, ...extra });
const worktreeDigest = (target: string) =>
  result({ action: "worktree", target });

test("Git snapshots use the next temporary directory when TMPDIR is unusable", () => {
  const path = repository();
  write(path, "tracked.txt", "changed\n");
  const expected = worktreeDigest(path);
  const blocked = write(directory, "blocked-temporary-parent");
  for (const temporary of [
    blocked,
    join(directory, "missing-temporary-parent"),
  ]) {
    const child = spawnSync(node, [fixture], {
      env: {
        ...environment,
        PATH: childPath,
        TMPDIR: temporary,
        TEMP: spoolDirectory,
      },
      input: JSON.stringify([{ action: "worktree", target: path }]),
      encoding: "utf8",
    });
    expect(child.status, child.stderr).toBe(0);
    expect(child.stderr).toBe("");
    expect(JSON.parse(child.stdout)).toEqual([{ result: expected }]);
    expect(
      readdirSync(spoolDirectory).filter((name) =>
        name.startsWith("codex-security-git-"),
      ),
    ).toEqual([]);
  }
});

test.skipIf(process.platform === "win32")(
  "keeps the original directory hash framing, path order, modes, links and exclusions",
  () => {
    const path = root();
    mkdirSync(join(path, "a"));
    mkdirSync(join(path, "empty"));
    chmodSync(join(path, "a"), 0o755);
    chmodSync(join(path, "empty"), 0o755);
    chmodSync(write(path, "a-b", "dash\n"), 0o644);
    chmodSync(write(path, "a/file", Buffer.from([0, 255, 10])), 0o600);
    symlinkSync("a/file", join(path, "a-link"));
    if (process.platform === "darwin") lchmodSync(join(path, "a-link"), 0o777);
    const digest =
      "codex-security-snapshot/v1:sha256:5a66ed809f9ecae49bb6eb085cc0b223d09e6cc7b19185c3391f597f1cc060d9";
    expect(directoryDigest(path)).toBe(digest);
    expect(directoryDigest(path, { includeIgnored: true })).toBe(digest);
    expect(
      directoryDigest(path, {
        excluded: [join(path, "a"), join(directory, "unrelated")],
      }),
    ).toBe(
      "codex-security-snapshot/v1:sha256:f7a97d5a2de2ee03bfe68cbed6069dd309d561d38dc2db527cedb2ba75b8e5b5",
    );
    expect(result({ action: "count", target: path })).toBe(2);
    chmodSync(join(path, "a-b"), 0o600);
    expect(directoryDigest(path)).not.toBe(digest);
  },
);

test("source snapshots retain ignored files and skip Git metadata; ordinary snapshots follow Git's selected file set", () => {
  const path = repository(false);
  const original = directoryDigest(path),
    source = directoryDigest(path, { includeIgnored: true });
  write(path, "ignored.tmp");
  write(path, ".git/cache", "internal");
  expect(directoryDigest(path)).toBe(original);
  expect(directoryDigest(path, { includeIgnored: true })).not.toBe(source);
  const nextSource = directoryDigest(path, { includeIgnored: true });
  write(path, ".git/cache", "changed");
  expect(directoryDigest(path, { includeIgnored: true })).toBe(nextSource);
  git(path, "add", "-f", "ignored.tmp");
  expect(directoryDigest(path)).not.toBe(original);
  write(path, "missing.txt");
  git(path, "add", "missing.txt");
  rmSync(join(path, "missing.txt"));
  expect(result({ action: "count", target: path })).toBe(4);
  const sourcePaths = result({
    action: "sourcePaths",
    target: path,
  }) as string[];
  expect(sourcePaths).toContain(join(path, "scope"));
  expect(
    sourcePaths.some(
      (value) =>
        value === join(path, ".git") ||
        value.startsWith(join(path, ".git") + sep),
    ),
  ).toBe(false);
});

test("worktree hashes keep tracked diffs, raw untracked bytes, ignored paths and scoped changes distinct", () => {
  const path = repository();
  const clean = result({ action: "clean", target: path });
  expect(worktreeDigest(path)).toBe(clean);
  write(path, "ignored.tmp");
  expect(worktreeDigest(path)).toBe(clean);
  write(path, "tracked.txt", "changed\n");
  const tracked = worktreeDigest(path);
  expect(tracked).not.toBe(clean);
  expect(worktreeDigest(join(path, "scope"))).toBe(clean);
  write(path, "scope/untracked.bin", Buffer.from([0, 255, 10]));
  const untracked = worktreeDigest(path);
  expect(untracked).not.toBe(tracked);
  const scoped = worktreeDigest(join(path, "scope"));
  expect(scoped).not.toBe(clean);
  write(path, "tracked.txt", "changed again\n");
  expect(worktreeDigest(join(path, "scope"))).toBe(scoped);
  expect(
    result({
      action: "context",
      target: path,
      pathspec: "scope",
      gitDir: join(path, ".git"),
      workTree: path,
    }),
  ).toBe(scoped);
  git(path, "config", "diff.external", "must-not-run");
  expect(worktreeDigest(path)).toBeDefined();
  expect(
    readdirSync(spoolDirectory).filter((name) =>
      name.startsWith("codex-security-git-"),
    ),
  ).toEqual([]);
});

test.skipIf(process.platform === "win32")(
  "POSIX byte filenames and symlink targets survive content snapshots",
  () => {
    const path = root();
    const filenameBytes =
      process.platform === "darwin" ? Buffer.from("λ") : Buffer.from([255]);
    const raw = Buffer.concat([Buffer.from(path + "/file-"), filenameBytes]);
    writeFileSync(raw, "bytes");
    const digest = directoryDigest(path);
    symlinkSync(
      Buffer.concat([Buffer.from("t"), filenameBytes]),
      Buffer.from(join(path, "link")),
    );
    const linked = directoryDigest(path);
    expect(linked).not.toBe(digest);
    writeFileSync(raw, "changed");
    expect(directoryDigest(path)).not.toBe(linked);
    expect(result({ action: "count", target: path })).toBe(1);
  },
);

test("streams a tracked binary patch larger than a hash read and preserves its digest", () => {
  const path = repository(),
    size = 1024 * 1024 + 17;
  const bytes = (seed: string) =>
    createHash("shake256", { outputLength: size }).update(seed).digest();
  write(path, "fixture.bin", bytes("original binary fixture"));
  git(path, "add", "fixture.bin");
  git(path, "commit", "-qm", "Add binary fixture");
  write(path, "fixture.bin", bytes("changed binary fixture"));
  const diff = spawnSync(
    "git",
    [
      "-C",
      path,
      "diff",
      "--binary",
      "--full-index",
      "--no-ext-diff",
      "--no-textconv",
      "--ignore-submodules=none",
      "HEAD",
      "--",
      ".",
    ],
    { env: environment, maxBuffer: Infinity },
  );
  expect(diff.status, diff.stderr.toString()).toBe(0);
  expect(diff.stdout.includes(Buffer.from("GIT binary patch"))).toBe(true);
  expect(diff.stdout.length).toBeGreaterThan(1024 * 1024);
  const digest = createHash("sha256");
  for (const [name, value] of [
    ["format", Buffer.from("codex-security-snapshot/v1")],
    ["tracked-diff", diff.stdout],
  ] as const) {
    const label = Buffer.from(name),
      header = Buffer.alloc(4),
      length = Buffer.alloc(8);
    header.writeUInt32BE(label.length);
    length.writeBigUInt64BE(BigInt(value.length));
    digest.update(header).update(label).update(length).update(value);
  }
  expect(
    result({ action: "worktree", target: path, requireStreamedDiff: true }),
  ).toBe(`codex-security-snapshot/v1:sha256:${digest.digest("hex")}`);
  expect(
    readdirSync(spoolDirectory).filter((name) =>
      name.startsWith("codex-security-git-"),
    ),
  ).toEqual([]);
});

test("nested untracked Git repositories hash their selected content without ignored runtime files", () => {
  const path = repository();
  const nested = join(path, "nested");
  mkdirSync(nested);
  git(nested, "init", "-q");
  write(nested, "source");
  write(nested, ".gitignore", "*.tmp\n");
  git(nested, "add", ".");
  git(nested, "commit", "-qm", "nested");
  const before = [directoryDigest(path), worktreeDigest(path)];
  write(nested, "ignored.tmp");
  write(nested, ".git/cache");
  expect([directoryDigest(path), worktreeDigest(path)]).toEqual(before);
  write(nested, "source", "changed");
  expect(directoryDigest(path)).not.toBe(before[0]);
  expect(worktreeDigest(path)).not.toBe(before[1]);
});

test("submodule integrity checks keep recorded revisions and reject dirty initialized worktrees", () => {
  const source = repository(),
    path = repository();
  git(path, "submodule", "add", "-q", source, "modules/sub");
  git(path, "commit", "-qam", "submodule");
  const submodule = join(path, "modules/sub"),
    revision = git(submodule, "rev-parse", "HEAD");
  expect(result({ action: "submodules", target: path })).toEqual([
    [submodule, revision],
  ]);
  expect(result({ action: "cleanSubmodules", target: path })).toBeNull();
  write(submodule, "ignored.tmp");
  expect(result({ action: "cleanSubmodules", target: path })).toBeNull();
  write(submodule, "untracked");
  expect(run({ action: "worktree", target: path })[0]).toMatchObject({
    error: `Dirty Git submodules are not supported for remediation integrity checks: ${join("modules", "sub")}`,
    systemExit: true,
  });
  rmSync(join(submodule, "untracked"));
  git(submodule, "commit", "--allow-empty", "-qm", "new head");
  expect(run({ action: "cleanSubmodules", target: path })[0]?.error).toContain(
    `revision recorded by the parent repository: ${join("modules", "sub")}`,
  );
  if (process.platform !== "win32") {
    chmodSync(dirname(submodule), 0);
    try {
      expect(run({ action: "cleanSubmodules", target: path })[0]).toMatchObject(
        {
          systemExit: false,
        },
      );
      expect(
        run({ action: "cleanSubmodules", target: path })[0]?.error,
      ).toContain("Permission denied");
    } finally {
      chmodSync(dirname(submodule), 0o755);
    }
  }
  rmSync(join(submodule, ".git"));
  expect(result({ action: "cleanSubmodules", target: path })).toBeNull();
  rmSync(submodule, { recursive: true });
  expect(result({ action: "cleanSubmodules", target: path })).toBeNull();
});

test("metadata preserves Unicode subjects, detached and unborn states, bare repositories, and nested scope support", () => {
  const plain = root();
  expect(result({ action: "metadata", target: plain })).toEqual({
    hasHead: false,
    isGit: false,
    isWorktree: false,
    reviewChangesSupported: false,
  });
  const unborn = repository(false);
  expect(result({ action: "metadata", target: unborn })).toMatchObject({
    hasHead: false,
    isGit: true,
    isWorktree: true,
    reviewChangesSupported: false,
    branch: "main",
    detachedHead: false,
  });
  const path = repository(),
    revision = git(path, "rev-parse", "HEAD");
  git(path, "config", "i18n.logOutputEncoding", "ISO-8859-1");
  expect(result({ action: "metadata", target: path })).toEqual({
    hasHead: true,
    isGit: true,
    isWorktree: true,
    reviewChangesSupported: true,
    branch: "main",
    detachedHead: false,
    commitSubject: "docs: café 日本語 🔧",
    revision,
    shortRevision: revision.slice(0, 7),
  });
  expect(
    result({ action: "metadata", target: join(path, "scope") }),
  ).toMatchObject({ reviewChangesSupported: false });
  git(path, "checkout", "--detach", revision);
  expect(result({ action: "metadata", target: path })).toMatchObject({
    branch: null,
    detachedHead: true,
  });
  const bare = join(root(), "bare.git");
  git(directory, "clone", "--bare", path, bare);
  expect(result({ action: "metadata", target: bare })).toMatchObject({
    isGit: true,
    isWorktree: false,
    hasHead: true,
    reviewChangesSupported: false,
  });
  expect(run({ action: "head", target: bare })[0]?.error).toBe(
    "Review changes requires a non-bare Git worktree with a resolvable HEAD.",
  );
});

test("target identities retain wide serialization and reject missing, aliased and replaced checkouts", () => {
  const path = root(),
    original = scan(path);
  expect(result({ action: "identity", target: path, scan: original })).toBe(
    path,
  );
  expect(
    run({
      action: "identity",
      target: path,
      scan: { ...original, target_inode: null },
    })[0]?.error,
  ).toContain("does not record checkout identity");
  expect(run({ action: "remediationTarget", target: "." })[0]?.error).toBe(
    "Remediation target must be an absolute local directory path.",
  );
  const alias = join(directory, "alias");
  symlinkSync(path, alias, process.platform === "win32" ? "junction" : "dir");
  expect(
    run({ action: "remediationTarget", target: alias })[0]?.error,
  ).toContain("checkout path was replaced");
  renameSync(path, path + "-original");
  mkdirSync(path);
  expect(
    run({ action: "identity", target: path, scan: original })[0]?.error,
  ).toContain("checkout path was replaced");
  rmSync(path, { recursive: true });
  expect(
    run({ action: "identity", target: path, scan: original })[0]?.error,
  ).toContain("no longer accessible");
  const wide = result({
    action: "scanIdentity",
    target: "missing",
    diffTarget: { headRevision: "selected-head" },
    metadata: { dev: String((1n << 64n) - 1n), ino: String((1n << 128n) - 1n) },
  });
  expect(wide).toEqual([
    "selected-head",
    null,
    "stat:ffffffffffffffff",
    "stat:ffffffffffffffffffffffffffffffff",
  ]);
});

test("scan identity capture snapshots only non-diff scans and accepts a supplied metadata result", () => {
  const path = root();
  write(path, "source");
  const identity = result({
    action: "scanIdentity",
    target: path,
    diffTarget: null,
  }) as unknown[];
  expect(identity.slice(0, 2)).toEqual(["unversioned", directoryDigest(path)]);
  expect(
    (
      result({
        action: "scanIdentity",
        target: path,
        diffTarget: {},
      }) as unknown[]
    ).slice(0, 2),
  ).toEqual(["unversioned", null]);
  const project = repository(),
    revision = git(project, "rev-parse", "HEAD");
  expect(
    (
      result({
        action: "scanIdentity",
        target: project,
        diffTarget: null,
      }) as unknown[]
    ).slice(0, 2),
  ).toEqual([revision, worktreeDigest(project)]);
  expect(
    run({
      action: "scanIdentity",
      target: join(path, "missing"),
      diffTarget: { headRevision: "selected-head" },
      git: [],
    })[0],
  ).toMatchObject({ systemExit: false, calls: [] });
});

test("snapshot warnings retain directory exclusions, HEAD-before-content precedence and the original early return", () => {
  const path = root();
  write(path, "source");
  write(path, "scan/output");
  const stored = scan(path);
  stored.target_snapshot_digest = directoryDigest(path, {
    excluded: [stored.scan_dir],
  }) as string;
  expect(result({ action: "snapshot", target: path, scan: stored })).toEqual([
    "unversioned",
    stored.target_snapshot_digest,
  ]);
  write(path, "scan/output", "changed scan output");
  expect(result({ action: "warning", target: path, scan: stored })).toBeNull();
  write(path, "source", "changed source");
  expect(result({ action: "warning", target: path, scan: stored })).toBe(
    "Directory contents changed while the scan was running; results were saved for the original snapshot.",
  );
  const project = repository(),
    revision = git(project, "rev-parse", "HEAD"),
    saved = scan(project, revision);
  saved.target_snapshot_digest = worktreeDigest(project) as string;
  expect(
    result({ action: "warning", target: project, scan: saved }),
  ).toBeNull();
  write(project, "tracked.txt", "changed");
  expect(result({ action: "warning", target: project, scan: saved })).toBe(
    "Working-tree contents changed while the scan was running; results were saved for the original snapshot.",
  );
  git(project, "commit", "--allow-empty", "-qm", "changed HEAD");
  expect(result({ action: "warning", target: project, scan: saved })).toBe(
    "Repository HEAD changed while the scan was running; results were saved for the original revision.",
  );
  expect(
    run({ action: "snapshot", target: project, scan: saved })[0]?.error,
  ).toBe(
    "Repository HEAD changed. Regenerate the remediation patch against the current checkout.",
  );
  renameSync(join(project, ".git"), join(project, "git-metadata"));
  expect(result({ action: "warning", target: project, scan: saved })).toContain(
    "Git repository became unavailable",
  );
  rmSync(project, { recursive: true });
  expect(result({ action: "warning", target: project, scan: saved })).toContain(
    "scan target became unavailable",
  );
  expect(
    result({
      action: "warning",
      target: project,
      scan: { ...saved, target_snapshot_digest: null },
    }),
  ).toBeNull();
});

test("filesystem identity serialization preserves signed SQLite integers and wide tagged values", () => {
  const values = [
    0n,
    1n,
    42n,
    -(1n << 63n),
    (1n << 63n) - 1n,
    1n << 63n,
    (1n << 128n) - 1n,
  ];
  const responses = run(
    ...values.map((current) => ({
      action: "serialize" as const,
      target: "",
      current: String(current),
    })),
  );
  expect(responses.map((response) => response.result)).toEqual([
    { integer: "0" },
    { integer: "1" },
    { integer: "42" },
    { integer: "-9223372036854775808" },
    { integer: "9223372036854775807" },
    "stat:8000000000000000",
    "stat:ffffffffffffffffffffffffffffffff",
  ]);
  const matches = run(
    ...[
      ["42", 42, true],
      ["42", 42.5, false],
      ["42", "42", false],
      ["1", true, true],
      ["0", false, true],
      [String(1n << 63n), "stat:8000000000000000", true],
      [String(1n << 63n), { integer: String(1n << 63n) }, false],
    ].map(([current, stored]) => ({
      action: "matches" as const,
      target: "",
      current: current as string,
      stored,
    })),
  );
  expect(matches.map((response) => response.result)).toEqual([
    true,
    false,
    false,
    true,
    true,
    true,
    false,
  ]);
});

test("Git failures retain the original probe order and malformed submodule record diagnostics", () => {
  const path = root();
  const encoded = (stdout: string, status = 0) => ({
    stdout: Buffer.from(stdout).toString("base64"),
    status,
  });
  const snapshot = run({
    action: "context",
    target: path,
    git: [encoded("", 1), encoded("")],
  })[0]!;
  expect(snapshot.error).toBe(
    "Could not snapshot the selected working-tree changes.",
  );
  expect(
    readdirSync(spoolDirectory).filter((name) =>
      name.startsWith("codex-security-git-"),
    ),
  ).toEqual([]);
  expect(snapshot.calls!.map((args) => args.slice(6))).toEqual([
    [
      "diff",
      "--binary",
      "--full-index",
      "--no-ext-diff",
      "--no-textconv",
      "--ignore-submodules=none",
      "HEAD",
      "--",
      ".",
    ],
    ["ls-files", "--others", "--exclude-standard", "-z", "--", "."],
  ]);
  const metadata = run({
    action: "metadata",
    target: path,
    git: [encoded(""), encoded(""), encoded("")],
  })[0]!;
  expect(metadata.calls!.map((args) => args.slice(6))).toEqual([
    ["rev-parse", "--git-dir"],
    ["rev-parse", "--is-inside-work-tree"],
    ["rev-parse", "--verify", "HEAD"],
  ]);
  expect(
    run({
      action: "metadata",
      target: path,
      git: [
        encoded(".git"),
        encoded("true"),
        encoded("abc1234"),
        encoded(path),
        encoded("main"),
        { stdout: Buffer.from([0xff]).toString("base64") },
      ],
    })[0]?.error,
  ).toBe(
    "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
  );
  const invalid = run({
    action: "submodules",
    target: path,
    git: [encoded(path + "\n"), encoded("malformed\0")],
  })[0]!;
  expect(invalid).toMatchObject({
    error: "Could not inspect Git submodules in the selected working tree.",
    systemExit: true,
  });
});

test("Windows mode metadata retains directory, executable, readonly and link permissions", () => {
  const cases = [
    {
      target: "C:\\source.txt",
      attributes: 0x80,
      permissions: 0o666,
      kind: 0o100000,
    },
    {
      target: "C:\\source.txt",
      attributes: 1,
      permissions: 0o444,
      kind: 0o100000,
    },
    {
      target: "C:\\source.EXE",
      attributes: 1,
      permissions: 0o555,
      kind: 0o100000,
    },
    {
      target: "C:\\directory",
      attributes: 0x10,
      permissions: 0o777,
      kind: 0o040000,
    },
    {
      target: "C:\\junction",
      attributes: 0x410,
      reparseTag: 0xa0000003,
      permissions: 0o777,
      kind: 0o040000,
    },
    {
      target: "C:\\link.cmd",
      attributes: 0x400,
      reparseTag: 0xa000000c,
      permissions: 0o777,
      kind: 0o120000,
    },
  ];
  const actual = run(
    ...cases.map((value) => ({ action: "windowsMode" as const, ...value })),
  );
  actual.forEach((response, index) =>
    expect(response.result).toMatchObject({
      mode: cases[index]!.kind | cases[index]!.permissions,
      closed: 1,
    }),
  );
});

test.skipIf(process.platform === "win32")(
  "remediation preserves the original symlink-loop diagnostic",
  () => {
    const loop = join(root(), "loop");
    symlinkSync(loop, loop);
    expect(run({ action: "remediationTarget", target: loop })[0]).toEqual({
      error: `Symlink loop from '${loop}'`,
      systemExit: false,
    });
    expect(existsSync(loop)).toBe(false);
  },
);
