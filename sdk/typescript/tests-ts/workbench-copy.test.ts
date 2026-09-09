import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/workbench-copy-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "workbench-copy-")));
const fixture = join(directory, "fixture.cjs"),
  windowsPolicy = join(directory, "windows-policy.cjs"),
  node = Bun.which("node")!;
const environment = {
  ...process.env,
  PYTHON: "/unavailable/python",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "Fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
};
let childPath = process.env["PATH"];
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-copy-fixture.ts", import.meta.url),
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
  const owner = fileURLToPath(
    new URL(
      "../../../plugins/codex-security/mcp-app/src/workbench-copy.ts",
      import.meta.url,
    ),
  );
  buildSync({
    stdin: {
      // Expose the private policy only in this isolated Windows binding model.
      contents:
        readFileSync(owner, "utf8").replace(
          'import { unixBinding, windowsBinding } from "./native";',
          "const windowsBinding = () => globalThis.copyWindowsBinding; const unixBinding = () => undefined;",
        ) + "\nexport { symlink as testSymlink };\n",
      resolveDir: dirname(owner),
      loader: "ts",
    },
    outfile: windowsPolicy,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "process.platform": '"win32"',
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
function root() {
  return realpathSync(mkdtempSync(join(directory, "target Σ ")));
}
function write(
  path: string,
  name: string,
  content: string | Buffer = "contents\n",
) {
  const target = join(path, name);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
  return target;
}
function git(path: string, ...args: string[]) {
  const child = spawnSync(
    "git",
    ["-c", "protocol.file.allow=always", "-C", path, ...args],
    { env: environment, encoding: "utf8" },
  );
  expect(child.status, child.stderr).toBe(0);
  return child.stdout.trim();
}
function repository() {
  const path = root();
  git(path, "init", "-q", "-b", "main");
  git(path, "config", "core.autocrlf", "false");
  write(path, "tracked.txt");
  write(path, "scope/source.bin", Buffer.from([0, 255, 10]));
  write(path, ".gitignore", "*.tmp\n");
  git(path, "add", ".");
  git(path, "commit", "-qm", "fixture");
  return path;
}
const encoded = (value: string, status = 0) => ({
  stdout: Buffer.from(value).toString("base64"),
  status,
});

test("directory copies preserve bytes, lexical exclusions, and empty directories", () => {
  const source = root(),
    destination = join(root(), "parents", "copy");
  write(source, "scope/keep", Buffer.from([0, 255, 10]));
  write(source, "scope/skip");
  write(source, "skip/inside");
  write(source, "skip-extra");
  mkdirSync(join(source, "empty"));
  expect(
    run({
      kind: "directory",
      source,
      destination,
      excluded: [
        join(source, "scope", "skip"),
        join(source, "skip"),
        join(source, "missing"),
        join(source, "..", "outside"),
      ],
    })[0]?.result,
  ).toBeNull();
  expect(readFileSync(join(destination, "scope/keep"))).toEqual(
    Buffer.from([0, 255, 10]),
  );
  expect(existsSync(join(destination, "scope/skip"))).toBe(false);
  expect(existsSync(join(destination, "skip"))).toBe(false);
  expect(existsSync(join(destination, "skip-extra"))).toBe(true);
  expect(statSync(join(destination, "empty")).isDirectory()).toBe(true);
});

test("relative directory roots retain Path exclusions without resolving dot-dot components", () => {
  const source = root(),
    destination = join(root(), "copy");
  write(source, "keep");
  write(source, "nested/skip");
  expect(
    run({
      kind: "directory",
      source: ".",
      cwd: source,
      destination,
      excluded: ["nested/skip", "../keep", "."],
    })[0]?.result,
  ).toBeNull();
  expect(existsSync(join(destination, "keep"))).toBe(true);
  expect(existsSync(join(destination, "nested/skip"))).toBe(false);
});

test.skipIf(process.platform === "win32")(
  "directory copies preserve regular modes, cached access times, and dangling byte symlinks",
  () => {
    const source = root(),
      destination = join(root(), "copy");
    const file = write(source, "file", "data"),
      raw = Buffer.concat([Buffer.from(source + "/raw-"), Buffer.from([255])]);
    writeFileSync(raw, "raw");
    chmodSync(file, 0o751);
    chmodSync(source, 0o711);
    const seconds = 1_700_000_000;
    utimesSync(file, seconds, seconds + 1);
    symlinkSync(Buffer.from([0x6d, 0xff]), join(source, "link"));
    const before = statSync(file, { bigint: true });
    expect(
      run({ kind: "directory", source, destination })[0]?.result,
    ).toBeNull();
    const copied = statSync(join(destination, "file"), { bigint: true });
    expect(copied.mode & 0o7777n).toBe(0o751n);
    expect(copied.atimeNs).toBe(before.atimeNs);
    expect(copied.mtimeNs).toBe(before.mtimeNs);
    expect(statSync(destination).mode & 0o7777).toBe(0o711);
    expect(
      readlinkSync(join(destination, "link"), { encoding: "buffer" }),
    ).toEqual(Buffer.from([0x6d, 0xff]));
    expect(
      readFileSync(
        Buffer.concat([Buffer.from(destination + "/raw-"), Buffer.from([255])]),
      ).toString(),
    ).toBe("raw");
  },
);

test("missing sources and existing destinations fail before writing files", () => {
  const source = root(),
    destination = root();
  write(source, "file");
  const responses = run(
    {
      kind: "directory",
      source: join(source, "missing"),
      destination: join(destination, "copy"),
    },
    { kind: "directory", source, destination },
  );
  expect(responses[0]?.error).toContain("missing");
  expect(responses[1]?.error).toContain(destination);
  expect(existsSync(join(destination, "file"))).toBe(false);
  expect(existsSync(join(destination, "copy"))).toBe(false);
});

test.skipIf(process.platform === "win32")(
  "metadata copies preserve nanoseconds and the directory-versus-Git access-time ordering",
  () => {
    const source = repository(),
      tree = join(root(), "tree"),
      worktree = join(root(), "worktree");
    const original = join(source, "tracked.txt");
    const stamp = {
      path: original,
      atimeNs: "1600000000123456789",
      mtimeNs: "1700000000987654321",
    };
    const [directory, git] = run(
      {
        kind: "directory",
        source,
        destination: tree,
        excluded: [join(source, ".git")],
        stamp,
        inspect: [join(tree, "tracked.txt")],
      },
      {
        kind: "git",
        source,
        destination: worktree,
        stamp,
        inspect: [original, join(worktree, "tracked.txt")],
      },
    );
    expect(directory?.metadata).toEqual([
      { atimeNs: stamp.atimeNs, mtimeNs: stamp.mtimeNs },
    ]);
    expect(git?.metadata?.[0]).toEqual(git?.metadata?.[1]);
    expect(git?.metadata?.[1]?.mtimeNs).toBe(stamp.mtimeNs);
  },
);

test.skipIf(process.platform === "win32")(
  "copytree collects nested copy failures, completes siblings, and applies final directory metadata",
  () => {
    const source = root(),
      destination = join(root(), "copy");
    write(source, "before");
    write(source, "nested/after");
    chmodSync(source, 0o711);
    const fifo = spawnSync("mkfifo", [join(source, "nested/pipe")]);
    expect(fifo.status).toBe(0);
    const response = run({ kind: "directory", source, destination })[0]!;
    expect(response.error).toBe(
      `[('${join(source, "nested/pipe")}', '${join(destination, "nested/pipe")}', '\`${join(source, "nested/pipe")}\` is a named pipe')]`,
    );
    expect(readFileSync(join(destination, "before"), "utf8")).toBe(
      "contents\n",
    );
    expect(readFileSync(join(destination, "nested/after"), "utf8")).toBe(
      "contents\n",
    );
    expect(statSync(destination).mode & 0o7777).toBe(0o711);
  },
);

test.skipIf(process.platform === "win32")(
  "copy failures retain undecodable filename bytes in every error field",
  () => {
    const source = root(),
      destination = join(root(), "copy");
    const raw = Buffer.concat([
      Buffer.from(source + "/file-"),
      Buffer.from([255]),
    ]);
    writeFileSync(raw, "unreadable");
    write(source, "sibling");
    chmodSync(raw, 0);
    try {
      const result = run({ kind: "directory", source, destination })[0]!;
      expect(result.error).toContain("file-\\udcff");
      expect(result.error).toContain("file-\\\\udcff");
      expect(result.error).not.toContain("\ufffd");
      expect(readFileSync(join(destination, "sibling"), "utf8")).toBe(
        "contents\n",
      );
    } finally {
      chmodSync(raw, 0o600);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "final copystat errors retain Path and DirEntry representations",
  () => {
    const source = root(),
      destination = join(root(), "copy");
    mkdirSync(join(source, "empty"));
    const error = run({
      kind: "directory",
      source,
      destination,
      copyStatError: { errno: 5, path: null },
    })[0]?.error;
    expect(error).toBe(
      `[(<DirEntry 'empty'>, '${join(destination, "empty")}', '[Errno 5] Input/output error'), (PosixPath('${source}'), PosixPath('${destination}'), '[Errno 5] Input/output error')]`,
    );
  },
);

test("Git copies select tracked and untracked files, omit ignored and missing entries, and preserve scoped layout", () => {
  const source = repository(),
    destination = join(root(), "copy");
  write(source, "scope/untracked");
  write(source, "scope/ignored.tmp");
  write(source, "scope/excluded");
  write(source, "scope/missing");
  git(source, "add", "scope/missing");
  rmSync(join(source, "scope/missing"));
  const copied = join(destination, "scope");
  expect(
    run({
      kind: "git",
      source: join(source, "scope"),
      destination,
      excluded: [join(source, "scope/excluded")],
    })[0]?.result,
  ).toBe(copied);
  expect(readFileSync(join(copied, "source.bin"))).toEqual(
    Buffer.from([0, 255, 10]),
  );
  expect(existsSync(join(copied, "untracked"))).toBe(true);
  for (const name of ["ignored.tmp", "excluded", "missing"])
    expect(existsSync(join(copied, name))).toBe(false);
  expect(existsSync(join(destination, "tracked.txt"))).toBe(false);
  expect(existsSync(join(destination, ".git"))).toBe(false);
});

test("Git copies nested repositories with an absolute Git directory pointer", () => {
  const source = repository(),
    nested = join(source, "nested"),
    destination = join(root(), "copy");
  mkdirSync(nested);
  git(nested, "init", "-q");
  write(nested, "file");
  write(nested, ".gitignore", "*.tmp\n");
  write(nested, "ignored.tmp");
  git(nested, "add", ".");
  git(nested, "commit", "-qm", "nested");
  expect(run({ kind: "git", source, destination })[0]?.result).toBe(
    destination,
  );
  expect(readFileSync(join(destination, "nested/.git"), "utf8")).toBe(
    `gitdir: ${git(nested, "rev-parse", "--absolute-git-dir")}${process.platform === "win32" ? "\r\n" : "\n"}`,
  );
  expect(readFileSync(join(destination, "nested/file"), "utf8")).toBe(
    "contents\n",
  );
  expect(existsSync(join(destination, "nested/ignored.tmp"))).toBe(false);
});

test.skipIf(process.platform === "win32")(
  "nested Git pointer encoding errors retain the copied files and newly opened empty pointer",
  () => {
    const source = repository(),
      destination = join(root(), "copy"),
      nested = join(source, "nested");
    mkdirSync(nested);
    write(nested, "file");
    const response = run({
      kind: "git",
      source,
      destination,
      git: [
        encoded(source + "\n"),
        encoded("nested\0"),
        {
          stdout: Buffer.concat([
            Buffer.from(nested + "/git-"),
            Buffer.from([255, 10]),
          ]).toString("base64"),
        },
        encoded(nested + "\n"),
        encoded("file\0"),
      ],
    })[0]!;
    expect(response.error).toContain(
      "'utf-8' codec can't encode character '\\udcff'",
    );
    expect(response.error).toContain("surrogates not allowed");
    expect(readFileSync(join(destination, "nested/file"), "utf8")).toBe(
      "contents\n",
    );
    expect(readFileSync(join(destination, "nested/.git"))).toEqual(
      Buffer.alloc(0),
    );
  },
);

test.skipIf(process.platform === "win32")(
  "Git copies retain raw names, symlinks, and the original unsupported-type partial output",
  () => {
    const source = repository(),
      destination = join(root(), "copy");
    const raw = Buffer.concat([
      Buffer.from(source + "/raw-"),
      Buffer.from([255]),
    ]);
    writeFileSync(raw, "raw");
    symlinkSync("scope/source.bin", join(source, "link"));
    expect(run({ kind: "git", source, destination })[0]?.result).toBe(
      destination,
    );
    expect(readlinkSync(join(destination, "link"))).toBe("scope/source.bin");
    expect(
      readFileSync(
        Buffer.concat([Buffer.from(destination + "/raw-"), Buffer.from([255])]),
      ).toString(),
    ).toBe("raw");
    expect(spawnSync("mkfifo", [join(source, "pipe")]).status).toBe(0);
    const failed = join(root(), "copy");
    const response = run({
      kind: "git",
      source,
      destination: failed,
      git: [encoded(source + "\n"), encoded("tracked.txt\0pipe\0")],
    })[0]!;
    expect(response).toMatchObject({
      error: "Unsupported Git working-tree file type: pipe",
      systemExit: true,
    });
    expect(existsSync(join(failed, "tracked.txt"))).toBe(false);
  },
);

test("Git inspection failures and duplicate records retain original ordering and partial-copy behavior", () => {
  const source = repository(),
    destination = join(root(), "copy");
  const failure = run({
    kind: "git",
    source,
    destination,
    git: [encoded(source + "\n"), encoded("", 1)],
  })[0]!;
  expect(failure).toMatchObject({
    error: "Could not inspect files in the selected Git working tree.",
    systemExit: true,
  });
  expect(existsSync(destination)).toBe(false);
  expect(failure.calls.map((args) => args.slice(6))).toEqual([
    ["rev-parse", "--show-toplevel"],
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "."],
  ]);
  const duplicate = run({
    kind: "git",
    source,
    destination,
    git: [encoded(source + "\n"), encoded("tracked.txt\0tracked.txt\0")],
  })[0]!;
  expect(duplicate.result).toBe(destination);
  expect(readFileSync(join(destination, "tracked.txt"), "utf8")).toBe(
    "contents\n",
  );
});

test("excluding a repository root still creates an empty scoped target", () => {
  const source = repository(),
    destination = join(root(), "copy");
  expect(
    run({
      kind: "git",
      source: join(source, "scope"),
      destination,
      excluded: [source],
    })[0]?.result,
  ).toBe(join(destination, "scope"));
  expect(statSync(join(destination, "scope")).isDirectory()).toBe(true);
  expect(existsSync(join(destination, "scope/source.bin"))).toBe(false);
});

test.skipIf(process.platform === "win32")(
  "Git copy refuses to overwrite its source when a tracked directory becomes a symlink",
  () => {
    const source = repository(),
      destination = join(root(), "copy");
    const contents = "keep the source bytes\n";
    write(source, "source.bin", contents);
    rmSync(join(source, "scope"), { recursive: true });
    symlinkSync(source, join(source, "scope"));
    const result = run({ kind: "git", source, destination })[0]!;
    expect(result.error).toBe(
      `PosixPath('${join(source, "scope/source.bin")}') and PosixPath('${join(destination, "scope/source.bin")}') are the same file`,
    );
    expect(readFileSync(join(source, "source.bin"), "utf8")).toBe(contents);
    expect(readlinkSync(join(destination, "scope"))).toBe(source);
  },
);

test.skipIf(process.platform !== "win32")(
  "Windows CopyFile2 uses separate directory and Git flags and falls back only for supported errors",
  () => {
    const source = repository();
    const request = (kind: Request["kind"], errors?: number[]): Request => ({
      kind,
      source,
      destination: join(root(), "copy"),
      excluded: [join(source, ".git")],
      copyFileErrors: errors,
    });
    const [tree, worktree, denied, privilege, failure] = run(
      request("directory"),
      request("git"),
      request("git", [5]),
      request("git", [1314]),
      request("git", [32]),
    );
    expect(tree?.copies.every((copy) => copy.flags === 8)).toBe(true);
    expect(worktree?.copies.every((copy) => copy.flags === 0x808)).toBe(true);
    expect(denied?.error).toBeUndefined();
    expect(privilege?.error).toBeUndefined();
    expect(failure?.error).toContain("[WinError 32]");
    expect(failure?.error).not.toContain(source);
  },
);

test("Windows symlink inference keeps the original dirname and MAX_PATH decisions", () => {
  const cases = [
    { destination: "\\link", target: "folder", probe: "folder" },
    { destination: "/link", target: "folder", probe: "folder" },
    { destination: "link", target: "folder", probe: "folder" },
    { destination: "C:\\link", target: "folder", probe: "C:\\folder" },
    {
      destination: "C:/work\\link",
      target: "folder",
      probe: "C:/work\\folder",
    },
    { destination: "link", target: "x".repeat(259), probe: "x".repeat(259) },
    { destination: "link", target: "x".repeat(260), probe: null },
  ];
  const script = `
    const cases = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
    const { testSymlink } = require(process.argv[1]);
    console.log(JSON.stringify(cases.map(value => {
      const probes = [], flags = [];
      globalThis.copyWindowsBinding = {
        openWindowsFile(path) {
          const text = path.toString('utf16le'); probes.push(text);
          return { error: 0, handle: {
            attributes: () => ({ error: 0, attributes: text === value.probe ? 16 : 0 }),
            close: () => 0,
          }};
        },
        createWindowsSymlink(target, destination, flag) { flags.push(flag); return 0; },
      };
      testSymlink(value.target, value.destination);
      return { probes, flags };
    })));
  `;
  const child = spawnSync(node, ["-e", script, windowsPolicy], {
    input: JSON.stringify(cases),
    encoding: "utf8",
    env: { ...environment, PATH: childPath },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  expect(JSON.parse(child.stdout)).toEqual(
    cases.map((value) => ({
      probes: value.probe === null ? [] : [value.probe],
      flags: [value.probe === null ? 2 : 3],
    })),
  );
});

test.skipIf(process.platform !== "win32")(
  "Windows copytree ignores final directory time failures after copying files",
  () => {
    const source = root(),
      destination = join(root(), "copy");
    write(source, "file");
    expect(
      run({ kind: "directory", source, destination, timesError: 5 })[0]?.result,
    ).toBeNull();
    expect(readFileSync(join(destination, "file"), "utf8")).toBe("contents\n");
  },
);

test.skipIf(process.platform !== "win32")(
  "Windows link copying infers directory targets and remembers the unsupported unprivileged flag",
  () => {
    const source = root(),
      destination = join(root(), "copy"),
      target = join(root(), "dangling-directory");
    symlinkSync(join(root(), "missing"), target, "dir");
    symlinkSync(target, join(source, "one"), "dir");
    symlinkSync(target, join(source, "two"), "dir");
    const result = run({
      kind: "directory",
      source,
      destination,
      symlinkErrors: [87, 1314, 1314],
    })[0]!;
    expect(result.links.map((link) => link.flags)).toEqual([3, 1, 1]);
    expect(result.links.every((link) => link.target.endsWith(target))).toBe(
      true,
    );
    expect(result.error).toContain("[WinError 1314]");
    expect(result.error).toContain(" -> ");
  },
);
