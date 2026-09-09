import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
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
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/workbench-files-fixture";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "workbench-remediation-guards-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!,
  git = Bun.which("git")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
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
])
  delete environment[key];
let childPath = process.env["PATH"];
beforeAll(() => {
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/workbench-files-fixture.ts", import.meta.url),
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
    const bin = join(directory, "bin");
    mkdirSync(bin);
    symlinkSync(git, join(bin, "git"));
    childPath = bin;
  }
});
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function root(name: string): string {
  const path = join(directory, name);
  mkdirSync(path, { mode: 0o700 });
  return path;
}
function run(...requests: Request[]) {
  const child = spawnSync(node, [fixture], {
    input: stringifyJson(requests),
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...environment, PATH: childPath },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const response = parseJson(child.stdout) as unknown as Response;
  expect(response.node).toBe(nodeVersion);
  for (const outcome of response.outcomes)
    expect(outcome.descriptors).toBe(process.platform === "linux" ? 0n : null);
  return response.outcomes;
}
const digest = (bytes: Buffer | string) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

test("remediation digests retain whitespace normalization and validation precedence", () => {
  const valid = digest("patch"),
    [normalized, uppercase, overlong, empty] = run(
      {
        operation: "sha256",
        value: `\u001c ${valid} \u0085`,
        label: "Reviewed patch",
      },
      { operation: "sha256", value: valid.toUpperCase() },
      { operation: "sha256", value: `${valid}0` },
      { operation: "sha256", value: null },
    );
  expect(normalized!.result).toBe(valid);
  expect(uppercase!.error).toBe(
    "Patch digest must use sha256:<64 lowercase hex characters>.",
  );
  expect(overlong!.error).toBe(
    "Text value must be no longer than 71 characters.",
  );
  expect(empty!.systemExit).toBe(true);
});

test("remediation paths normalize before artifact validation and preserve root errors", () => {
  const scan = root("paths");
  mkdirSync(join(scan, "nested"));
  writeFileSync(join(scan, "nested/file"), "patch");
  const [normalized, dot, traversal, missingRoot, backslash] = run(
    { operation: "relativeFile", root: scan, value: " ./nested//./file/ " },
    { operation: "relativeFile", root: scan, value: "." },
    {
      operation: "relativeFile",
      root: join(scan, "missing"),
      value: "../outside",
    },
    { operation: "relativeFile", root: join(scan, "missing"), value: "patch" },
    { operation: "relativeFile", root: scan, value: "nested\\file" },
  );
  expect(normalized!.result).toBe("nested/file");
  expect(dot!.error).toBe(".: expected a regular non-symlink file.");
  expect(traversal!.error).toBe(
    "Patch path must identify a scan-local regular file.",
  );
  expect(backslash!.error).toBe(traversal!.error);
  expect(missingRoot!.error).toBe(
    "Scan directory must be an existing canonical non-symlink directory.",
  );
});

test("patch verification hashes every byte and closes files after rejection or consumer failure", () => {
  const scan = root("patch"),
    bytes = Buffer.concat([
      Buffer.alloc(3 * 1024 * 1024, 97),
      Buffer.from([0, 255, 122]),
    ]);
  writeFileSync(join(scan, "patch"), bytes);
  writeFileSync(join(scan, "empty"), "");
  const [matched, mismatch, empty, consumer, missing] = run(
    {
      operation: "matchingPatch",
      root: scan,
      relative: "./patch",
      digest: digest(bytes),
    },
    {
      operation: "matchingPatch",
      root: scan,
      relative: "patch",
      digest: digest(bytes.subarray(0, -1)),
    },
    {
      operation: "matchingPatch",
      root: scan,
      relative: "empty",
      digest: digest(""),
    },
    { operation: "open", root: scan, relative: "patch", readerThrow: true },
    {
      operation: "matchingPatch",
      root: scan,
      relative: "missing",
      digest: "invalid",
    },
  );
  expect(matched!.result).toBeNull();
  expect(empty!.result).toBeNull();
  expect(mismatch!.error).toBe(
    "Patch digest does not match the scan-local patch file.",
  );
  expect(consumer!.error).toBe("Synthetic reader consumer failed.");
  expect(consumer!.systemExit).toBe(false);
  expect(missing!.error).toBe(
    "Patch path must identify a scan-local regular file.",
  );
  expect(readFileSync(join(scan, "patch"))).toEqual(bytes);
  if (process.platform !== "win32") {
    symlinkSync("patch", join(scan, "link"));
    const results = run(
      ...Array.from(
        { length: 8 },
        (): Request => ({
          operation: "matchingPatch",
          root: scan,
          relative: "link",
          digest: digest(bytes),
        }),
      ),
    );
    expect(
      results.every(
        (value) => value.error === missing!.error && value.systemExit,
      ),
    ).toBe(true);
  }
});

function command(target: string, ...args: string[]): string {
  const child = spawnSync(git, ["-C", target, ...args], {
    env: environment,
    encoding: "utf8",
  });
  expect(child.status, child.stderr).toBe(0);
  return child.stdout.trim();
}
test("checkout guards check revision first and prefer applied content when both flags are set", () => {
  const target = root("target"),
    scan = root("scan");
  writeFileSync(join(target, "source.txt"), "before");
  command(target, "init", "-q");
  command(target, "add", "source.txt");
  command(target, "commit", "-qm", "Synthetic fixture");
  const identity = run({ operation: "targetIdentity", path: target })[0]!;
  expect(identity.error).toBeUndefined();
  const revision = command(target, "rev-parse", "HEAD"),
    row = {
      target_path: target,
      target_inode: (identity.result as unknown[])[3],
      target_revision: revision,
      scan_dir: scan,
    };
  const snapshot = run({ operation: "checkoutSnapshot", scan: row })[0]!;
  expect(snapshot.error).toBeUndefined();
  const hash = (snapshot.result as string[])[1]!;
  const remediation = {
    base_revision: revision,
    base_content_digest: "wrong",
    applied_content_digest: hash,
  };
  const request: Request = {
    operation: "unchanged",
    scan: row,
    remediation,
    requireAppliedContent: true,
    requireBaseContent: true,
  };
  expect(run(request)[0]!.result).toBeNull();
  const [base, nullApplied, wrongRevision] = run(
    { ...request, requireAppliedContent: false },
    {
      ...request,
      remediation: { ...remediation, applied_content_digest: null },
    },
    { ...request, remediation: { ...remediation, base_revision: "different" } },
  );
  expect(base!.error).toBe(
    "Working-tree contents changed. Regenerate the remediation patch against the current checkout.",
  );
  expect(nullApplied!.result).toBeNull();
  expect(wrongRevision!.error).toBe(
    "Repository HEAD changed. Regenerate the remediation patch against the current checkout.",
  );
  writeFileSync(join(target, "source.txt"), "after");
  expect(run(request)[0]!.error).toBe(base!.error);
  expect(
    run({
      ...request,
      requireAppliedContent: false,
      requireBaseContent: false,
    })[0]!.result,
  ).toBeNull();
});
