import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function write(
  repository: string,
  name: string,
  contents: string | Buffer = "example\n",
) {
  const path = join(repository, name);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
  return path;
}
function git(repository: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    {
      cwd: repository,
      encoding: "utf8",
    },
  ).trim();
}
function fixture(populate = true) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "scan-inventory-")));
  roots.push(root);
  const repository = join(root, "repository"),
    output = join(root, "artifacts", "in_scope_files.txt");
  mkdirSync(repository);
  if (populate) {
    git(repository, "init", "-q");
    for (const name of [
      "app/routes.py",
      "app/name with spaces.py",
      "app/résumé.py",
      "app/évidence.py",
      "tests/demo.py",
      "fixtures/example.py",
      ".hidden.py",
      ".hidden-directory/handler.py",
    ])
      write(repository, name);
    write(repository, "app/binary.dat", Buffer.from([0, 255, 1]));
    write(repository, ".gitignore", "ignored/\n*.skip\n");
    write(repository, "ignored/secret.py");
    write(repository, "app/ignored.skip");
  }
  write(dirname(output), "in_scope_files.txt", "previous.py\n");
  return { root, repository, output };
}
type Fixture = ReturnType<typeof fixture>;
function run(
  f: Fixture,
  scope = ".",
  extra: string[] = [],
  env: NodeJS.ProcessEnv = {},
) {
  return spawnSync(
    node,
    [
      helper,
      "generate-in-scope-files",
      "--repo",
      f.repository,
      "--scope",
      scope,
      "--out",
      f.output,
      ...extra,
    ],
    {
      encoding: "utf8",
      maxBuffer: Infinity,
      env: { ...process.env, PYTHON: join(f.root, "missing-python"), ...env },
    },
  );
}
function expectedInventory(repository: string, scope: string) {
  const result = spawnSync(
    "rg",
    [
      "--files",
      "--hidden",
      "--glob",
      "!.git/**",
      "--path-separator=/",
      "--",
      scope,
    ],
    { cwd: repository },
  );
  expect([0, 1]).toContain(result.status!);
  return Buffer.concat(
    result.stdout
      .toString("utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => Buffer.from(line + "\n"))
      .sort(Buffer.compare),
  );
}
function preserved(
  f: Fixture,
  result: ReturnType<typeof run>,
  message: string,
) {
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toContain(message);
  expect(readFileSync(f.output, "utf8")).toBe("previous.py\n");
  expect(readdirSync(dirname(f.output))).toEqual(["in_scope_files.txt"]);
}
function commit(f: Fixture): string {
  git(f.repository, "add", ".");
  git(f.repository, "commit", "-qm", "fixture");
  return git(f.repository, "rev-parse", "HEAD");
}
function shim(f: Fixture, program: string, source: string): string {
  const tools = join(f.root, "tools");
  const script = write(tools, `${program}.cjs`, source);
  const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
  const executable = write(
    tools,
    program,
    `#!/bin/sh\nexec ${quote(node)} ${quote(script)} "$@"\n`,
  );
  chmodSync(executable, 0o755);
  return tools;
}

test.each([".", "./", "app", "./app", "app/routes.py"])(
  "preserves the standard ripgrep bytes for scope %s",
  (scope) => {
    const f = fixture(),
      result = run(f, scope);
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(f.output)).toEqual(
      expectedInventory(f.repository, scope),
    );
    expect(readdirSync(dirname(f.output))).toEqual(["in_scope_files.txt"]);
    if (scope === ".") {
      const rows = readFileSync(f.output, "utf8").split("\n");
      for (const path of [
        "./.hidden.py",
        "./tests/demo.py",
        "./fixtures/example.py",
        "./app/binary.dat",
        "./app/name with spaces.py",
        "./app/résumé.py",
      ])
        expect(rows).toContain(path);
      expect(rows).not.toContain("./ignored/secret.py");
    }
  },
);
test("uses repository-relative paths for an absolute scope", () => {
  const f = fixture(),
    result = run(f, join(f.repository, "app"));
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.output)).toEqual(
    expectedInventory(f.repository, "app"),
  );
});
test("keeps ignored tracked files and excludes ignored untracked files", () => {
  const f = fixture();
  write(f.repository, "ignored/tracked.py");
  git(f.repository, "add", "--force", "--", "ignored/tracked.py");
  const result = run(f);
  expect(result.status, result.stderr).toBe(0);
  const rows = readFileSync(f.output, "utf8").split("\n");
  expect(rows).toContain("./ignored/tracked.py");
  expect(rows).not.toContain("./ignored/secret.py");
  expect(rows).not.toContain("./app/ignored.skip");
});
test("overrides a ripgrep configuration's path separator", () => {
  const f = fixture(),
    config = write(f.root, "ripgrep.conf", "--path-separator=\\\n");
  const result = run(f, ".", [], { RIPGREP_CONFIG_PATH: config });
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.output, "utf8")).toContain("./app/routes.py\n");
});
test("replaces an old inventory with an empty inventory", () => {
  const f = fixture(false),
    result = run(f);
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout.trim()).toBe("Recorded 0 in-scope files.");
  expect(readFileSync(f.output).length).toBe(0);
});
test.each([
  ["missing", "--scope: path does not exist"],
  ["../outside", "--scope: path must remain inside --repo"],
  ["", "--scope: expected a non-empty file or directory"],
])("preserves output for invalid scope %s", (scope, message) => {
  const f = fixture();
  mkdirSync(join(f.root, "outside"));
  preserved(f, run(f, scope), message);
});
test("rejects a scope symlink outside the repository and an output symlink", () => {
  const f = fixture(),
    outside = join(f.root, "outside");
  mkdirSync(outside);
  symlinkSync(
    outside,
    join(f.repository, "external"),
    process.platform === "win32" ? "junction" : "dir",
  );
  preserved(f, run(f, "external"), "--scope: path must remain inside --repo");
  if (process.platform !== "win32") {
    const linked = join(f.root, "linked.txt");
    symlinkSync(f.output, linked);
    preserved(
      f,
      run(f, ".", ["--out", linked]),
      "--out: refusing to replace a symbolic link",
    );
  }
});
test("preserves output when ripgrep is unavailable", () => {
  const f = fixture();
  preserved(
    f,
    run(f, ".", [], { PATH: join(f.root, "missing-tools") }),
    "could not run ripgrep",
  );
});
test.skipIf(process.platform === "win32")(
  "preserves an old inventory after ripgrep writes partial stdout then fails",
  () => {
    const f = fixture(),
      PATH = shim(
        f,
        "rg",
        "process.stdout.write('partial.py\\n'); process.stderr.write('simulated ripgrep failure'); process.exitCode = 2;",
      );
    preserved(
      f,
      run(f, ".", [], { PATH }),
      "ripgrep exited with status 2: simulated ripgrep failure",
    );
  },
);
test.skipIf(process.platform === "win32")(
  "sorts inventories larger than the child-process default output buffer",
  () => {
    const f = fixture(false),
      PATH = shim(
        f,
        "rg",
        "for (let i=12000;i>0;i--) process.stdout.write('./'+'x'.repeat(100)+'-'+String(i).padStart(5,'0')+'.py\\n');",
      );
    const result = run(f, ".", [], { PATH });
    expect(result.status, result.stderr).toBe(0);
    expect(statSync(f.output).size).toBeGreaterThan(1024 * 1024);
    const rows = readFileSync(f.output, "utf8").trim().split("\n");
    expect(rows.length).toBe(12000);
    expect(rows).toEqual([...rows].sort());
  },
);
test("selects committed source blobs, deleted files, and PowerShell independently of the current worktree", () => {
  const f = fixture(),
    base = commit(f);
  write(f.repository, "app/routes.py", "selected = True\n");
  write(f.repository, "app/name with spaces.py", Buffer.from([0, 255, 1]));
  rmSync(join(f.repository, "app/évidence.py"));
  for (const name of ["config.json", "build.ps1", "module.psm1", "module.psd1"])
    write(f.repository, name, `new ${name}\n`);
  write(f.repository, "tests/demo.py", "excluded = True\n");
  const head = commit(f);
  write(f.repository, "app/routes.py", Buffer.from([0]));
  write(f.repository, "app/name with spaces.py", "current = True\n");
  const result = run(f, ".", ["--diff-base", base, "--diff-head", head]);
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.output, "utf8").trim().split("\n")).toEqual([
    "app/routes.py",
    "app/évidence.py",
    "build.ps1",
    "config.json",
    "module.psd1",
    "module.psm1",
  ]);
});
test("combines staged, unstaged, and untracked changes and drops vanished staged additions", () => {
  const f = fixture();
  commit(f);
  write(f.repository, "app/routes.py", "unstaged = True\n");
  write(f.repository, "app/staged.py");
  write(f.repository, "app/index-only.py");
  git(f.repository, "add", "app/staged.py", "app/index-only.py");
  rmSync(join(f.repository, "app/index-only.py"));
  write(f.repository, "app/untracked.py");
  write(f.repository, "app/untracked-binary.py", Buffer.from([0, 255, 1]));
  const result = run(f, ".", [
    "--diff-base",
    "HEAD",
    "--diff-mode",
    "local-patch",
  ]);
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.output, "utf8")).toBe(
    "app/routes.py\napp/staged.py\napp/untracked.py\n",
  );
});
test.each(["revisions", "local-patch"])(
  "includes BOM-marked UTF-16 text in %s mode",
  (mode) => {
    const f = fixture(),
      base = commit(f);
    const text = "Write-Output 'café 😀'\n";
    const le = Buffer.from(text, "utf16le");
    write(
      f.repository,
      "app/utf16-le.ps1",
      Buffer.concat([Buffer.from([255, 254]), le]),
    );
    write(
      f.repository,
      "app/utf16-be.ps1",
      Buffer.concat([Buffer.from([254, 255]), Buffer.from(le).swap16()]),
    );
    write(f.repository, "app/utf8.ps1", text);
    write(f.repository, "app/binary.ps1", Buffer.from("text\0binary"));
    write(
      f.repository,
      "app/decoded-nul.ps1",
      Buffer.concat([
        Buffer.from([255, 254]),
        Buffer.from("text\0binary", "utf16le"),
      ]),
    );
    write(f.repository, "tests/excluded.ps1", le);
    const head = mode === "revisions" ? commit(f) : "HEAD";
    const result = run(f, ".", [
      "--diff-base",
      base,
      "--diff-head",
      head,
      "--diff-mode",
      mode,
    ]);
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(f.output, "utf8")).toBe(
      "app/utf16-be.ps1\napp/utf16-le.ps1\napp/utf8.ps1\n",
    );
  },
);
test("preserves output on invalid Git revisions and narrowed diff scopes", () => {
  const f = fixture();
  preserved(
    f,
    run(f, ".", ["--diff-base", "missing"]),
    "could not resolve the selected Git changes",
  );
  preserved(
    f,
    run(f, "app", ["--diff-base", "HEAD"]),
    "diff scans must use the repository root",
  );
});
test("retains local-patch preview encoding failures instead of only sniffing binary bytes", () => {
  const f = fixture();
  commit(f);
  write(f.repository, "app/invalid.json", '{"\\ud800":1}');
  preserved(
    f,
    run(f, ".", ["--diff-base", "HEAD", "--diff-mode", "local-patch"]),
    "UTF-8 cannot encode an unpaired surrogate",
  );
  const head = commit(f);
  const result = run(f, ".", ["--diff-base", `${head}^`]);
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.output, "utf8")).toBe("app/invalid.json\n");
});
test("uses rename destinations and omits committed symlink modes", () => {
  const f = fixture(),
    base = commit(f);
  git(f.repository, "mv", "app/routes.py", "app/renamed.py");
  write(f.repository, "app/link.py", "renamed.py");
  git(f.repository, "add", ".");
  const blob = git(f.repository, "hash-object", "app/link.py");
  git(
    f.repository,
    "update-index",
    "--cacheinfo",
    `120000,${blob},app/link.py`,
  );
  git(f.repository, "commit", "-qm", "rename and link");
  const result = run(f, ".", ["--diff-base", base]);
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.output, "utf8")).toBe("app/renamed.py\n");
});
test("inherits the selected Git index for local-patch enumeration", () => {
  const f = fixture();
  commit(f);
  const alternative = join(f.root, "alternate-index");
  const environment = { ...process.env, GIT_INDEX_FILE: alternative };
  const execute = (...args: string[]) =>
    execFileSync("git", args, { cwd: f.repository, env: environment });
  execute("read-tree", "HEAD");
  execute("update-index", "--force-remove", "app/routes.py");
  const result = run(
    f,
    ".",
    ["--diff-base", "HEAD", "--diff-mode", "local-patch"],
    { GIT_INDEX_FILE: alternative },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.output, "utf8")).toBe("app/routes.py\n");
});
test.skipIf(process.platform !== "linux")(
  "preserves raw POSIX inventory bytes but rejects unencodable diff rows",
  () => {
    const f = fixture();
    commit(f);
    execFileSync(node, [
      "-e",
      "require('fs').writeFileSync(Buffer.concat([Buffer.from(process.argv[1]+'/app/raw-'),Buffer.from([255]),Buffer.from('.py')]),'value = 1');",
      f.repository,
    ]);
    const result = run(f);
    expect(result.status, result.stderr).toBe(0);
    expect(
      readFileSync(f.output).includes(
        Buffer.concat([
          Buffer.from("./app/raw-"),
          Buffer.from([255]),
          Buffer.from(".py\n"),
        ]),
      ),
    ).toBe(true);
    writeFileSync(f.output, "previous.py\n");
    preserved(
      f,
      run(f, ".", ["--diff-base", "HEAD", "--diff-mode", "local-patch"]),
      "UTF-8 cannot encode an unpaired surrogate",
    );
  },
);
test.skipIf(process.platform === "win32")(
  "rejects newline diff paths without corrupting an inventory",
  () => {
    const f = fixture(),
      base = commit(f);
    write(f.repository, "app/line\nbreak.py");
    commit(f);
    preserved(
      f,
      run(f, ".", ["--diff-base", base]),
      "cannot fit in the file inventory",
    );
  },
);
test("rejects invalid CLI choices and lists the unchanged defaults", () => {
  const f = fixture();
  preserved(f, run(f, ".", ["--diff-mode", "unknown"]), "invalid choice");
  const result = spawnSync(
    node,
    [helper, "generate-in-scope-files", "--help"],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toContain("default: HEAD");
  expect(result.stdout).toContain("default: revisions");
});
test.skipIf(process.platform === "win32")(
  "runs inventory through the published helper launcher",
  () => {
    const f = fixture();
    const result = spawnSync(
      join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
      [
        "--helper",
        "generate-in-scope-files",
        "--repo",
        f.repository,
        "--scope",
        ".",
        "--out",
        f.output,
      ],
      { encoding: "utf8", env: { ...process.env, CODEX_MCP_NODE_PATH: node } },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(f.output)).toEqual(
      expectedInventory(f.repository, "."),
    );
  },
);
