import { execFileSync, spawnSync } from "node:child_process";
import {
  closeSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const node = Bun.which("node")!;
const pathVariable =
  process.platform === "win32"
    ? Object.keys(process.env).find((key) => key.toUpperCase() === "PATH") ??
      "PATH"
    : "PATH";
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function write(
  root: string,
  name: string,
  contents: string | Buffer = "value = 1\n",
) {
  const path = join(root, name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
  return path;
}
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "rank-input-")));
  roots.push(root);
  const repository = join(root, "repository");
  mkdirSync(repository);
  return {
    root,
    repository,
    output: write(root, "output.jsonl", "previous\n"),
  };
}
type Fixture = ReturnType<typeof fixture>;
function git(repository: string, ...args: string[]) {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();
}
function commit(repository: string) {
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "Fixture");
  return git(repository, "rev-parse", "HEAD");
}
function run(
  f: Fixture,
  command: string,
  args: string[] = [],
  env: NodeJS.ProcessEnv = {},
) {
  return spawnSync(
    node,
    [helper, command, "--repo", f.repository, "--out", f.output, ...args],
    {
      encoding: "utf8",
      maxBuffer: Infinity,
      env: { ...process.env, PYTHON: join(f.root, "missing-python"), ...env },
    },
  );
}
function rows(f: Fixture) {
  return readFileSync(f.output, "utf8")
    .trimEnd()
    .split("\n")
    .filter(Boolean)
    .map(
      (row) =>
        JSON.parse(row) as { path: string; area?: string; preview?: string },
    );
}
function scopes(f: Fixture, paths: string[]) {
  return ["--scopes-file", write(f.root, "scopes.json", JSON.stringify(paths))];
}
function succeeds(result: ReturnType<typeof run>) {
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
}
function preserves(
  f: Fixture,
  result: ReturnType<typeof run>,
  message: string,
) {
  expect(result.status, result.stderr).toBe(1);
  expect(result.stderr).toContain(message);
  expect(readFileSync(f.output, "utf8")).toBe("previous\n");
}

test.each([
  "make-repo-rank-input",
  "make-repo-scope-input",
  "make-diff-rank-input",
])(
  "%s provides help and validates required arguments without Python",
  (command) => {
    const help = spawnSync(node, [helper, command, "--help"], {
      encoding: "utf8",
      env: { ...process.env, [pathVariable]: "" },
    });
    succeeds(help);
    expect(help.stdout).toContain("Codex Security scan worklist helper");
    const missing = spawnSync(node, [helper, command], { encoding: "utf8" });
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain("the following arguments are required:");
  },
);

test("keeps the golden repository worklist and excludes generated or binary noise", () => {
  const f = fixture();
  write(f.repository, "src/zeta.py", "zeta = 2");
  write(f.repository, "src/alpha.py", "alpha = 1");
  for (const path of [
    "src/binary.py",
    "tests/ignored.py",
    "src/app.min.js",
    "src/source.map",
    "README.md",
  ])
    write(
      f.repository,
      path,
      path.includes("binary") ? "value\0binary" : "ignored",
    );
  const result = run(f, "make-repo-rank-input", ["--scope", "src"], {
    [pathVariable]: "",
  });
  succeeds(result);
  expect(readFileSync(f.output, "utf8").replaceAll("\r\n", "\n")).toBe(
    '{"path":"src/alpha.py","area":"src","preview":"alpha = 1"}\n{"path":"src/zeta.py","area":"src","preview":"zeta = 2"}\n',
  );
  expect(result.stdout.trim()).toBe(`Wrote 2 rows to ${f.output}`);
});

test("retains explicit exceptions, literal tilde paths, authored area precedence, and ASCII JSONL", () => {
  const f = fixture();
  const special = "audit\u0085name\u2028line\u2029😀.py";
  for (const path of [
    "src/runtime.py",
    "tests/security.py",
    "~literal/src/code.py",
    special,
  ])
    write(f.repository, path);
  write(f.repository, "Dockerfile", "FROM scratch");
  write(f.repository, "package-lock.json", "{}");
  const result = run(
    f,
    "make-repo-rank-input",
    scopes(f, [
      "src",
      "src/runtime.py",
      "tests/security.py",
      "~literal/src",
      special,
      "Dockerfile",
      "package-lock.json",
    ]),
  );
  succeeds(result);
  expect(rows(f).map((row) => row.path)).toEqual([
    "Dockerfile",
    special,
    "package-lock.json",
    "src/runtime.py",
    "tests/security.py",
    "~literal/src/code.py",
  ]);
  expect(rows(f).find((row) => row.path === "src/runtime.py")?.area).toBe(
    "src",
  );
  expect(rows(f).find((row) => row.path === "Dockerfile")?.preview).toBe(
    "FROM scratch",
  );
  expect(readFileSync(f.output).every((byte) => byte < 128)).toBe(true);
});

test("preserves legacy home expansion and configured preview budgets", () => {
  const f = fixture();
  write(f.repository, "src/source.ps1", "Write-Output 'café 😀'");
  succeeds(
    run(
      f,
      "make-repo-rank-input",
      [
        "--repo",
        "~/repository",
        "--scope",
        "~/repository/src",
        "--area",
        "selected",
        "--preview-bytes",
        "8",
      ],
      { HOME: f.root, USERPROFILE: f.root },
    ),
  );
  expect(rows(f)).toEqual([
    { path: "src/source.ps1", area: "selected", preview: "Write-Ou" },
  ]);
  succeeds(run(f, "make-repo-rank-input", ["--preview-bytes", "-1"]));
  expect(rows(f)[0]?.preview).toBe("");
});

test("caps directly requested source reads and never reads unsupported explicit files", () => {
  const f = fixture();
  for (const path of ["src/payload.py", "payload.bin"]) {
    const filename = write(
      f.repository,
      path,
      "header-without-a-nul".repeat(256) + "\0binary",
    );
    const descriptor = openSync(filename, "r+");
    try {
      ftruncateSync(descriptor, 256 * 1024 * 1024);
    } finally {
      closeSync(descriptor);
    }
  }
  succeeds(
    run(
      f,
      "make-repo-rank-input",
      scopes(f, ["src", "src/payload.py", "payload.bin"]),
    ),
  );
  expect(rows(f)).toEqual([
    { path: "payload.bin", area: "payload.bin", preview: "" },
    { path: "src/payload.py", area: "src", preview: "" },
  ]);
});

test("directory ranking excludes symlink leaves and keeps the existing explicit-file resolution", () => {
  const f = fixture();
  const source = write(f.repository, "src/runtime.py");
  const outside = write(f.root, "outside.py", "outside = True");
  symlinkSync(source, join(f.repository, "src", "inside.py"));
  symlinkSync(outside, join(f.repository, "src", "outside.py"));
  succeeds(run(f, "make-repo-rank-input", ["--scope", "src"]));
  expect(rows(f).map((row) => row.path)).toEqual(["src/runtime.py"]);
  succeeds(run(f, "make-repo-rank-input", scopes(f, ["src/inside.py"])));
  expect(rows(f).map((row) => row.path)).toEqual(["src/runtime.py"]);
});

test.each(["src/alias.py", "alias/runtime.py", "alias/../src/runtime.py"])(
  "strict scopes reject the symbolic link in %s before writing",
  (scope) => {
    const f = fixture();
    const source = write(f.repository, "src/runtime.py");
    symlinkSync(source, join(f.repository, "src", "alias.py"));
    symlinkSync(dirname(source), join(f.repository, "alias"), "junction");
    preserves(
      f,
      run(f, "make-repo-scope-input", scopes(f, [scope])),
      "must not contain symbolic links",
    );
  },
);

test.each(["make-repo-rank-input", "make-repo-scope-input"])(
  "%s rejects scope escape and missing paths without replacing output",
  (command) => {
    const f = fixture();
    write(f.root, "outside.py");
    preserves(
      f,
      run(f, command, scopes(f, ["../outside.py"])),
      "Scope must be inside repo",
    );
    preserves(
      f,
      run(f, command, scopes(f, ["missing.py"])),
      "Scope path not found",
    );
  },
);

test.each(["[]", '[""]', "{}", "not json", Buffer.from([0xff])])(
  "rejects invalid scope files without replacing output: %s",
  (contents) => {
    const f = fixture();
    const path = write(f.root, "scopes.json", contents);
    const result = run(f, "make-repo-scope-input", ["--scopes-file", path]);
    preserves(
      f,
      result,
      contents === "not json" || Buffer.isBuffer(contents)
        ? "Unable to read scopes file"
        : "non-empty JSON string array",
    );
  },
);

test("scope enumeration retains tracked ignored and binary paths, but excludes unstaged ignored paths", () => {
  const f = fixture();
  git(f.repository, "init", "-q");
  write(f.repository, ".gitignore", "vendor/\n.env\n");
  for (const name of [
    "src/handler.py",
    "src/tests/check.py",
    "src/examples/demo.py",
    "src/Dockerfile",
    "src/.env",
    "src/vendor/dependency.py",
  ])
    write(f.repository, name);
  write(f.repository, "src/logo.png", Buffer.from([0x89, 0, 1]));
  git(
    f.repository,
    "add",
    "--force",
    "src/vendor/dependency.py",
    "src/logo.png",
  );
  write(f.repository, "src/vendor/cache.py");
  succeeds(run(f, "make-repo-scope-input", scopes(f, ["src"])));
  expect(rows(f)).toEqual(
    [
      "src/Dockerfile",
      "src/examples/demo.py",
      "src/handler.py",
      "src/logo.png",
      "src/tests/check.py",
      "src/vendor/dependency.py",
    ].map((path) => ({ path })),
  );
  succeeds(run(f, "make-repo-scope-input", scopes(f, ["src/.env"])));
  expect(rows(f)).toEqual([{ path: "src/.env" }]);
});

test("plain-directory scope enumeration honors nested ignore rules and hides Git metadata", () => {
  const f = fixture();
  write(f.repository, ".gitignore", "node_modules/\n.env\n");
  write(f.repository, "src/nested/.gitignore", "*.generated\n");
  for (const path of [
    "src/source.py",
    "src/.env",
    "src/node_modules/dependency.js",
    "src/nested/source.py",
    "src/nested/output.generated",
    "src/.git/config",
  ])
    write(f.repository, path);
  succeeds(run(f, "make-repo-scope-input", scopes(f, ["src"])));
  expect(rows(f)).toEqual(
    ["src/nested/.gitignore", "src/nested/source.py", "src/source.py"].map(
      (path) => ({ path }),
    ),
  );
});

test("missing tools allow plain enumeration only when no ignore rules apply", () => {
  const f = fixture();
  write(f.repository, "src/handler.py");
  succeeds(
    run(f, "make-repo-scope-input", scopes(f, ["src"]), { [pathVariable]: "" }),
  );
  expect(rows(f)).toEqual([{ path: "src/handler.py" }]);
  for (const rule of [
    ".gitignore",
    "src/.ignore",
    "src/nested/.rgignore",
    ".git/info/exclude",
  ]) {
    writeFileSync(f.output, "previous\n");
    const path = write(f.repository, rule, "secret\n");
    preserves(
      f,
      run(f, "make-repo-scope-input", scopes(f, ["src"]), {
        [pathVariable]: "",
      }),
      "without Git or ripgrep",
    );
    rmSync(path);
  }
});

test("selected revision previews include deleted and symlink blobs independently of the worktree", () => {
  const f = fixture();
  git(f.repository, "init", "-q");
  write(f.repository, "src/source.py", "value = 1");
  write(f.repository, "src/deleted.py");
  const base = commit(f.repository);
  write(f.repository, "src/source.py", "value = 2");
  write(f.repository, "src/added.py", "added = True");
  rmSync(join(f.repository, "src", "deleted.py"));
  const link = write(f.repository, "src/link.py", "source.py");
  git(f.repository, "add", ".");
  const blob = git(f.repository, "hash-object", link);
  git(
    f.repository,
    "update-index",
    "--cacheinfo",
    `120000,${blob},src/link.py`,
  );
  git(f.repository, "commit", "-qm", "Selected changes");
  const head = git(f.repository, "rev-parse", "HEAD");
  git(f.repository, "checkout", "--force", "-q", base);
  succeeds(run(f, "make-diff-rank-input", ["--base", base, "--head", head]));
  expect(rows(f)).toEqual([
    { path: "src/added.py", area: "diff", preview: "added = True" },
    { path: "src/deleted.py", area: "diff", preview: "" },
    { path: "src/link.py", area: "diff", preview: "source.py" },
    { path: "src/source.py", area: "diff", preview: "value = 2" },
  ]);
});

test("local patches combine staged, unstaged, and untracked files while retaining deleted rows", () => {
  const f = fixture();
  git(f.repository, "init", "-q");
  write(f.repository, "src/source.py", "value = 1");
  write(f.repository, "src/deleted.py");
  commit(f.repository);
  write(f.repository, "src/source.py", "value = 2");
  write(f.repository, "src/staged.py", "staged = True");
  git(f.repository, "add", "src/staged.py");
  write(f.repository, "src/untracked.py", "untracked = True");
  write(f.repository, "src/binary.py", "text\0binary");
  rmSync(join(f.repository, "src", "deleted.py"));
  succeeds(
    run(f, "make-diff-rank-input", [
      "--base",
      "HEAD",
      "--mode",
      "local-patch",
      "--area",
      "patch",
    ]),
  );
  expect(rows(f).map((row) => [row.path, row.area, row.preview])).toEqual([
    ["src/deleted.py", "patch", ""],
    ["src/source.py", "patch", "value = 2"],
    ["src/staged.py", "patch", "staged = True"],
    ["src/untracked.py", "patch", "untracked = True"],
  ]);
});

test("Git selection inherits repository variables while committed blob reads remain isolated", () => {
  const f = fixture();
  const other = join(f.root, "other");
  mkdirSync(other);
  for (const [repository, name] of [
    [f.repository, "selected.py"],
    [other, "other.py"],
  ]) {
    git(repository!, "init", "-q");
    git(repository!, "commit", "--allow-empty", "-qm", "Base");
    write(repository!, name!);
    commit(repository!);
  }
  preserves(
    f,
    run(f, "make-diff-rank-input", ["--base", "HEAD^"], {
      GIT_DIR: join(other, ".git"),
    }),
    "Unable to read committed diff blob: HEAD:other.py",
  );
  succeeds(run(f, "make-diff-rank-input", ["--base", "HEAD^"]));
  expect(rows(f).map((row) => row.path)).toEqual(["selected.py"]);
});

test.each(["repo", "explicit-file", "revisions", "local-patch"])(
  "preserves BOM-marked UTF-16 previews in %s mode",
  (mode) => {
    const f = fixture();
    git(f.repository, "init", "-q");
    git(f.repository, "commit", "--allow-empty", "-qm", "Base");
    const base = git(f.repository, "rev-parse", "HEAD");
    const source = "Write-Output 'café 😀'\n";
    const text = Buffer.from(source, "utf16le");
    write(
      f.repository,
      "src/le.ps1",
      Buffer.concat([Buffer.from([255, 254]), text]),
    );
    write(
      f.repository,
      "src/be.ps1",
      Buffer.concat([Buffer.from([254, 255]), Buffer.from(text).swap16()]),
    );
    write(f.repository, "src/utf8.ps1", source);
    write(f.repository, "src/binary.ps1", "text\0binary");
    write(
      f.repository,
      "src/decoded-nul.ps1",
      Buffer.concat([
        Buffer.from([255, 254]),
        Buffer.from("text\0binary", "utf16le"),
      ]),
    );
    const expected = ["src/be.ps1", "src/le.ps1", "src/utf8.ps1"];
    let command = "make-repo-rank-input",
      args: string[];
    if (mode === "explicit-file")
      args = scopes(f, [...expected, "src/binary.ps1", "src/decoded-nul.ps1"]);
    else if (mode === "repo") args = ["--scope", "src"];
    else {
      command = "make-diff-rank-input";
      args = ["--base", base, "--mode", mode];
      if (mode === "revisions") {
        args.push("--head", commit(f.repository));
        git(f.repository, "checkout", "-q", base);
      }
    }
    succeeds(run(f, command, args));
    expect(
      Object.fromEntries(rows(f).map((row) => [row.path, row.preview])),
    ).toEqual({
      ...Object.fromEntries(expected.map((path) => [path, source.trim()])),
      ...(mode === "explicit-file"
        ? { "src/binary.ps1": "", "src/decoded-nul.ps1": "" }
        : {}),
    });
  },
);

test("root commits and unrelated shallow tips use direct revision ranges", () => {
  const f = fixture();
  git(f.repository, "init", "-q", "-b", "main");
  write(f.repository, "src/base.py");
  const head = commit(f.repository);
  const empty = execFileSync("git", ["hash-object", "-t", "tree", "--stdin"], {
    cwd: f.repository,
    input: "",
    encoding: "utf8",
  }).trim();
  succeeds(run(f, "make-diff-rank-input", ["--base", empty, "--head", head]));
  expect(rows(f).map((row) => row.path)).toEqual(["src/base.py"]);
  git(f.repository, "checkout", "-qb", "feature");
  write(f.repository, "src/feature.py", "feature = True\n");
  commit(f.repository);
  git(f.repository, "checkout", "-q", "main");
  write(f.repository, "src/upstream.py", "upstream = True\n");
  commit(f.repository);
  const shallow = join(f.root, "shallow");
  git(
    f.root,
    "clone",
    "--no-local",
    "--depth=1",
    "--branch",
    "feature",
    f.repository,
    shallow,
  );
  git(shallow, "fetch", "--depth=1", "origin", "main:refs/remotes/origin/main");
  expect(
    spawnSync("git", ["merge-base", "origin/main", "HEAD"], { cwd: shallow })
      .status,
  ).toBe(1);
  succeeds(
    run({ ...f, repository: shallow }, "make-diff-rank-input", [
      "--base",
      "origin/main",
    ]),
  );
  expect(rows(f).map((row) => row.path)).toEqual([
    "src/feature.py",
    "src/upstream.py",
  ]);
});

test("preview failures retain the previous output", () => {
  const f = fixture();
  write(f.repository, "bad.json", '{"\\ud800":1}');
  preserves(
    f,
    run(f, "make-repo-rank-input"),
    "UTF-8 cannot encode an unpaired surrogate",
  );
});

test("preview integers retain Python's digit limits and Unicode version", () => {
  const f = fixture();
  write(f.repository, "source.py");
  const oversized = "9".repeat(4301);
  const limited = run(
    f,
    "make-repo-rank-input",
    ["--preview-bytes", oversized],
    { PYTHONINTMAXSTRDIGITS: "4300" },
  );
  expect(limited.status).toBe(2);
  expect(limited.stderr).toContain("invalid int value");
  expect(readFileSync(f.output, "utf8")).toBe("previous\n");
  succeeds(
    run(f, "make-repo-rank-input", ["--preview-bytes", oversized], {
      PYTHONINTMAXSTRDIGITS: "0",
    }),
  );
  expect(rows(f)[0]!.preview).toBe("value = 1");
  for (const [value, message] of [
    ["\u{10d41}", "invalid int value"],
    ["-\u{10d41}", "expected one argument"],
  ]) {
    const result = run(f, "make-repo-rank-input", ["--preview-bytes", value!]);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(message!);
  }
  succeeds(run(f, "make-repo-rank-input", ["--preview-bytes", "٠_٨"]));
  expect(rows(f)[0]!.preview).toBe("value =");
});

test("invalid diff choices preserve the argument diagnostic and output", () => {
  const f = fixture();
  const result = run(f, "make-diff-rank-input", [
    "--base",
    "HEAD",
    "--mode",
    "wrong",
  ]);
  expect(result.status).toBe(2);
  expect(result.stderr).toContain(
    "argument --mode: invalid choice: 'wrong' (choose from revisions, local-patch)",
  );
  expect(readFileSync(f.output, "utf8")).toBe("previous\n");
});

test.skipIf(process.platform !== "linux")(
  "preserves raw filename bytes through scoped JSON and JSONL",
  () => {
    const f = fixture();
    const path = Buffer.concat([
      Buffer.from(f.repository + "/raw-"),
      Buffer.from([255]),
      Buffer.from(".py"),
    ]);
    writeFileSync(path, "value = 1\n");
    for (const command of ["make-repo-rank-input", "make-repo-scope-input"]) {
      succeeds(run(f, command, scopes(f, ["raw-\udcff.py"])));
      expect(rows(f)[0]!.path).toBe("raw-\udcff.py");
      expect(readFileSync(f.output, "ascii")).toContain(
        '"path":"raw-\\udcff.py"',
      );
    }
  },
);
