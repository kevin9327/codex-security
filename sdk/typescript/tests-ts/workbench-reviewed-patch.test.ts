import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import type { RemediationScan } from "../../../plugins/codex-security/mcp-app/src/workbench-target";
import type { ReviewedPatchDigests } from "../../../plugins/codex-security/mcp-app/src/workbench-reviewed-patch";
import { PLUGIN_ROOT } from "./plugin-root";
import type {
  Request,
  Response,
} from "./support/workbench-reviewed-patch-fixture";

const root = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-reviewed-patch-")),
);
const fixture = join(root, "fixture.cjs"),
  node = Bun.which("node")!;
const environment: NodeJS.ProcessEnv = {
  ...process.env,
  PYTHON: "/unavailable/python",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "Fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
};
for (const key of [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
  "GIT_CONFIG_COUNT",
])
  delete environment[key];
let childPath = environment["PATH"];
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL(
          "./support/workbench-reviewed-patch-fixture.ts",
          import.meta.url,
        ),
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
  });
  if (process.platform !== "win32") {
    const bin = join(root, "bin");
    mkdirSync(bin);
    symlinkSync(Bun.which("git")!, join(bin, "git"));
    childPath = bin;
  }
});
afterAll(() => rmSync(root, { recursive: true, force: true }));
function directory(prefix: string) {
  return realpathSync(mkdtempSync(join(root, prefix)));
}
function git(target: string, ...args: string[]) {
  const child = spawnSync(
    "git",
    ["-c", "protocol.file.allow=always", "-C", target, ...args],
    { encoding: "utf8", env: environment },
  );
  expect(child.status, child.stderr).toBe(0);
  return child.stdout.trim();
}
function run(
  request: Request,
  temporary: string,
  extra: NodeJS.ProcessEnv = {},
): Response {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson([request]),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: {
      ...environment,
      PATH: childPath,
      TMPDIR: temporary,
      TEMP: temporary,
      TMP: temporary,
      ...extra,
    },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const response = (parseJson(child.stdout) as unknown as Response[])[0]!;
  response.descriptors =
    response.descriptors === null ? null : Number(response.descriptors);
  response.calls = response.calls.map((call) => ({
    ...call,
    status: call.status === null ? null : Number(call.status),
  }));
  expect(response.descriptors).toBe(process.platform === "linux" ? 0 : null);
  expect(
    readdirSync(temporary).filter((name) =>
      name.startsWith("codex-security-remediation-"),
    ),
  ).toEqual([]);
  return response;
}
const hash = (value: string | Buffer) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;
const patch = (before = "before\n", after = "after\n") =>
  `diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-${before}+${after}`;
function prepare(
  options: {
    git?: boolean;
    scope?: boolean;
    crlf?: boolean;
    readonly?: boolean;
    insideScan?: boolean;
  } = {},
) {
  const repo = directory("repository-"),
    target = options.scope ? join(repo, "scope") : repo,
    scanDir = options.insideScan ? join(target, "scan") : directory("scan-"),
    temporary = directory("temporary-");
  mkdirSync(target, { recursive: true });
  mkdirSync(scanDir, { recursive: true, mode: 0o700 });
  const before = options.crlf ? "before\r\n" : "before\n",
    after = options.crlf ? "after\r\n" : "after\n";
  writeFileSync(join(target, "file"), before);
  writeFileSync(join(target, "kept"), "kept\n");
  if (options.readonly) {
    mkdirSync(join(target, "readonly"));
    writeFileSync(join(target, "readonly", "kept"), "read only\n");
    chmodSync(join(target, "readonly", "kept"), 0o400);
    chmodSync(join(target, "readonly"), 0o500);
  }
  let revision = "unversioned";
  if (options.git) {
    git(repo, "init", "-q", "-b", "main");
    git(repo, "config", "core.autocrlf", "false");
    git(repo, "add", ".");
    git(repo, "commit", "-qm", "fixture");
    revision = git(repo, "rev-parse", "HEAD");
  }
  const scan: RemediationScan = {
    target_path: target,
    target_inode: null,
    target_revision: revision,
    scan_dir: scanDir,
  };
  const snapshot = run(
    { operation: "snapshot", scan, deriveIdentity: true },
    temporary,
  );
  expect(snapshot.error).toBeUndefined();
  scan.target_inode = snapshot.identity;
  const [, base] = snapshot.result as [string, string];
  const bytes = patch(before, after);
  writeFileSync(join(scanDir, "patch.diff"), bytes);
  const remediation: ReviewedPatchDigests = {
    base_revision: revision,
    base_content_digest: base,
    patch_digest: hash(bytes),
  };
  const applied = (extra: NodeJS.ProcessEnv = {}) =>
    run({ operation: "applied", scan, remediation }, temporary, extra);
  return {
    repo,
    target,
    scan,
    scanDir,
    temporary,
    remediation,
    after,
    applied,
  };
}
const applies = (response: Response) =>
  response.calls.filter((call) => call.args.includes("apply"));

test("reviewed directory patches return the current digest and exclude scan artifacts", () => {
  const fixture = prepare({ insideScan: true });
  writeFileSync(join(fixture.target, "file"), fixture.after);
  const current = run(
    { operation: "snapshot", scan: fixture.scan },
    fixture.temporary,
  );
  const response = fixture.applied();
  expect(response.result).toBe(current.result![1]);
  expect(applies(response)).toHaveLength(1);
  expect(applies(response)[0]!.args).toContain("--no-index");
  expect(readFileSync(join(fixture.target, "file"), "utf8")).toBe("after\n");
});

test.each([false, true])(
  "directory patches retain autocrlf retry behavior for CRLF=%p",
  (crlf) => {
    const fixture = prepare({ crlf });
    writeFileSync(join(fixture.target, "file"), fixture.after);
    const response = fixture.applied({
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.autocrlf",
      GIT_CONFIG_VALUE_0: "true",
    });
    expect(response.error).toBeUndefined();
    expect(applies(response)).toHaveLength(crlf ? 1 : 2);
    if (!crlf)
      expect(applies(response)[1]!.args).toContain("core.autocrlf=input");
  },
);

test("unchanged checkouts fail before opening the patch", () => {
  const fixture = prepare();
  unlinkSync(join(fixture.scanDir, "patch.diff"));
  const response = fixture.applied();
  expect(response.error).toBe(
    "The selected checkout is unchanged; apply the reviewed patch before recording it as applied.",
  );
  expect(response.systemExit).toBe(true);
  expect(applies(response)).toEqual([]);
});

test.each(["digest", "missing", "symlink"] as const)(
  "invalid scan-local patch %p is rejected before copying",
  (kind) => {
    const fixture = prepare();
    writeFileSync(join(fixture.target, "file"), fixture.after);
    if (kind === "digest") fixture.remediation.patch_digest = hash("different");
    else {
      unlinkSync(join(fixture.scanDir, "patch.diff"));
      if (kind === "symlink") {
        const external = join(directory("outside-"), "patch.diff");
        writeFileSync(external, patch());
        symlinkSync(external, join(fixture.scanDir, "patch.diff"), "file");
      }
    }
    const response = fixture.applied();
    expect(response.error).toBe(
      kind === "digest"
        ? "Patch digest does not match the scan-local patch file."
        : "Patch path must identify a scan-local regular file.",
    );
    expect(response.systemExit).toBe(true);
    expect(applies(response)).toEqual([]);
  },
);

test.each([false, true])(
  "wrong patches and unrelated changes preserve source bytes (extra=%p)",
  (extra) => {
    const fixture = prepare();
    writeFileSync(join(fixture.target, "file"), fixture.after);
    if (extra) writeFileSync(join(fixture.target, "kept"), "extra\n");
    else {
      const wrong = patch("before\n", "other\n");
      writeFileSync(join(fixture.scanDir, "patch.diff"), wrong);
      fixture.remediation.patch_digest = hash(wrong);
    }
    const response = fixture.applied();
    expect(response.error).toContain(
      extra
        ? "changes outside the reviewed patch"
        : "does not contain the reviewed remediation patch",
    );
    expect(applies(response)).toHaveLength(extra ? 2 : 1);
    expect(readFileSync(join(fixture.target, "file"), "utf8")).toBe("after\n");
    expect(readFileSync(join(fixture.target, "kept"), "utf8")).toBe(
      extra ? "extra\n" : "kept\n",
    );
  },
);

test.each([false, true])(
  "read-only copies are cleaned after success or rejection (wrong=%p)",
  (wrong) => {
    const fixture = prepare({ readonly: true });
    try {
      writeFileSync(join(fixture.target, "file"), fixture.after);
      if (wrong) {
        const bytes = patch("before\n", "other\n");
        writeFileSync(join(fixture.scanDir, "patch.diff"), bytes);
        fixture.remediation.patch_digest = hash(bytes);
      }
      const response = fixture.applied();
      if (wrong) expect(response.error).toContain("does not contain");
      else expect(response.error).toBeUndefined();
      expect(
        readFileSync(join(fixture.target, "readonly", "kept"), "utf8"),
      ).toBe("read only\n");
      if (process.platform !== "win32")
        expect(statSync(join(fixture.target, "readonly")).mode & 0o777).toBe(
          0o500,
        );
    } finally {
      chmodSync(join(fixture.target, "readonly"), 0o700);
      chmodSync(join(fixture.target, "readonly", "kept"), 0o600);
    }
  },
);

test("missing target identity wins over patch validation", () => {
  const fixture = prepare();
  writeFileSync(join(fixture.target, "file"), fixture.after);
  fixture.scan.target_inode = null;
  const response = fixture.applied();
  expect(response.error).toContain("does not record checkout identity");
  expect(applies(response)).toEqual([]);
});

test.each([false, true])(
  "Git reverse application uses the original index and selected scope (scope=%p)",
  (scope) => {
    const fixture = prepare({ git: true, scope });
    writeFileSync(join(fixture.target, "file"), fixture.after);
    const originalIndex = git(fixture.repo, "ls-files", "--stage");
    const response = fixture.applied();
    expect(response.error).toBeUndefined();
    const args = applies(response)[0]!.args;
    expect(args).toContain("--git-dir");
    expect(args).toContain("--work-tree");
    expect(args).not.toContain("--no-index");
    if (scope) expect(args).toContain("--directory=scope");
    expect(git(fixture.repo, "ls-files", "--stage")).toBe(originalIndex);
  },
);

test("changed Git HEAD is rejected before reading the patch", () => {
  const fixture = prepare({ git: true });
  writeFileSync(join(fixture.target, "file"), fixture.after);
  git(fixture.repo, "add", ".");
  git(fixture.repo, "commit", "-qm", "changed revision");
  unlinkSync(join(fixture.scanDir, "patch.diff"));
  const response = fixture.applied();
  expect(response.error).toContain("Repository HEAD changed");
  expect(applies(response)).toEqual([]);
});

test("an unusable TMPDIR falls through to TEMP without leaving a checkout", () => {
  const fixture = prepare();
  writeFileSync(join(fixture.target, "file"), fixture.after);
  const blocked = join(directory("temporary-file-"), "not-directory");
  writeFileSync(blocked, "kept");
  const response = fixture.applied({ TMPDIR: blocked });
  expect(response.error).toBeUndefined();
  expect(readFileSync(blocked, "utf8")).toBe("kept");
});

test("cleanup unlinks copied symlinks without changing their targets", () => {
  const fixture = prepare(),
    external = join(directory("external-"), "kept");
  writeFileSync(external, "outside\n");
  symlinkSync(external, join(fixture.target, "link"), "file");
  const base = run(
    { operation: "snapshot", scan: fixture.scan },
    fixture.temporary,
  );
  fixture.remediation.base_content_digest = (
    base.result as [string, string]
  )[1];
  writeFileSync(join(fixture.target, "file"), fixture.after);
  expect(fixture.applied().error).toBeUndefined();
  expect(readFileSync(external, "utf8")).toBe("outside\n");
  expect(existsSync(join(fixture.target, "link"))).toBe(true);
});
