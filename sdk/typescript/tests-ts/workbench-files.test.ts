import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
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

const directory = realpathSync(mkdtempSync(join(tmpdir(), "workbench-files-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
const nodeVersion = spawnSync(node, ["-p", "process.versions.node"], {
  encoding: "utf8",
}).stdout.trim();
beforeAll(() =>
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
  }),
);
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
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
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
const reportPath = "findings/sample/sample.md";
const details = { writeup: { reportPath }, artifactPaths: ["../outside"] };

test("canonical scan roots preserve privacy checks and caller path spelling", () => {
  const scan = root("canonical");
  const [absolute, relative, file, absent] = run(
    { operation: "canonical", root: scan },
    { operation: "canonical", root: ".", cwd: scan },
    { operation: "canonical", root: fixture },
    { operation: "canonical", root: join(scan, "absent") },
  );
  expect(absolute!.result).toBe(scan);
  expect(relative!.result).toBe(scan);
  expect(file!.error).toBe(
    "Scan directory must be an existing canonical non-symlink directory.",
  );
  expect(absent!.error).toBe(file!.error);
  if (process.platform !== "win32") {
    chmodSync(scan, 0o755);
    expect(run({ operation: "canonical", root: scan })[0]!.error).toContain(
      "chmod 700",
    );
    chmodSync(scan, 0o700);
    expect(
      run({
        operation: "canonical",
        root: scan,
        uid: process.geteuid!() + 1,
      })[0]!.error,
    ).toBe("Scan directory must be owned by the current user.");
  }
});

test("shared writable ancestors require their existing sticky-bit protection", () => {
  if (process.platform === "win32") return;
  const parent = root("parent"),
    scan = join(parent, "scan");
  mkdirSync(scan, { mode: 0o700 });
  chmodSync(parent, 0o777);
  const rejected = run({ operation: "canonical", root: scan })[0]!;
  expect(rejected.error).toContain("without the sticky bit");
  const sticky = spawnSync(node, [
    "-e",
    "require('node:fs').chmodSync(process.argv[1], 0o1777)",
    parent,
  ]);
  expect(sticky.status).toBe(0);
  expect(run({ operation: "canonical", root: scan })[0]!.result).toBe(scan);
});

test("artifact availability and required lookup preserve missing, directory, and outside errors", () => {
  const scan = root("paths"),
    file = join(scan, "report.md");
  writeFileSync(file, "report");
  const results = run(
    { operation: "available", root: scan, path: file },
    { operation: "available", root: scan, path: "report.md", cwd: scan },
    { operation: "artifact", root: scan, path: "missing", required: false },
    { operation: "artifact", root: scan, path: "missing" },
    { operation: "artifact", root: scan, path: "." },
    { operation: "artifact", root: scan, path: fixture },
    { operation: "artifact", root: scan, path: file },
  );
  expect(results[0]!.result).toBe(file);
  expect(results[1]!.result).toBeNull();
  expect(results[2]!.result).toBeNull();
  expect(results[3]!.error).toBe(
    "missing: expected a regular file inside the scan directory.",
  );
  expect(results[4]!.error).toBe(".: expected a regular non-symlink file.");
  expect(results[5]!.error).toContain("inside the scan directory");
  expect(results[6]!.result).toBe(file);
});

test("scan-local readers reject symlinks and traversal and keep their distinct privacy rules", () => {
  const scan = root("readers");
  writeFileSync(join(scan, "file"), "contents");
  const requests: Request[] = [
    { operation: "open", root: scan, relative: "./file" },
    { operation: "open", root: scan, relative: "../file" },
    { operation: "regular", root: scan, relative: "missing" },
    { operation: "regular", root: scan, relative: "." },
  ];
  if (process.platform !== "win32") {
    symlinkSync("file", join(scan, "link"));
    requests.push(
      { operation: "open", root: scan, relative: "link" },
      { operation: "regular", root: scan, relative: "link" },
    );
  }
  const results = run(...requests);
  expect(results[0]!.result).toBe(Buffer.from("contents").toString("base64"));
  expect(results[1]!.error).toBe(
    "Patch path must identify a scan-local regular file.",
  );
  expect(results[2]!.result).toBe(false);
  expect(results[3]!.result).toBe(false);
  if (results.length > 4) {
    expect(results[4]!.error).toBe(results[1]!.error);
    expect(results[5]!.result).toBe(false);
  }
  if (process.platform !== "win32") {
    chmodSync(scan, 0o755);
    const [patch, finding] = run(
      { operation: "open", root: scan, relative: "file" },
      { operation: "regular", root: scan, relative: "file" },
    );
    expect(patch!.error).toContain("chmod 700");
    expect(finding!.result).toBe(true);
  }
});

test("JSON reading preserves workbench values and its basename-scoped errors", () => {
  const scan = root("json"),
    path = join(scan, "value.json");
  writeFileSync(
    path,
    '{"integer":9007199254740993,"surrogate":"\\ud800","line":1}\r\n',
  );
  const value = run({ operation: "json", path })[0]!.result as Record<
    string,
    unknown
  >;
  expect(value["integer"]).toBe(9007199254740993n);
  expect(value["surrogate"]).toBe("\ud800");
  writeFileSync(path, '{"value":NaN}');
  expect(run({ operation: "json", path })[0]!.error).toBe(
    "value.json: invalid JSON: non-finite JSON number 'NaN' is not supported",
  );
  writeFileSync(path, "[]");
  expect(run({ operation: "json", path })[0]!.error).toBe(
    "value.json: expected a JSON object.",
  );
  writeFileSync(path, Buffer.from([0xff]));
  expect(run({ operation: "json", path })[0]).toMatchObject({
    error:
      "value.json: invalid JSON: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
    systemExit: true,
  });
});

test("invalid path values retain workbench error categories and directory JSON errors name the file", () => {
  const scan = root("path-errors"),
    invalid = "bad\0path";
  const [canonical, available, artifact, json, directory] = run(
    { operation: "canonical", root: scan + "\0" },
    { operation: "available", root: scan, path: join(scan, invalid) },
    { operation: "artifact", root: scan, path: invalid, required: false },
    { operation: "json", path: join(scan, invalid) },
    { operation: "json", path: scan },
  );
  expect(canonical!.error).toBe("stat: embedded null character in path");
  expect(canonical!.systemExit).toBe(false);
  expect(available!.result).toBeNull();
  expect(artifact!.error).toBe(
    invalid + ": expected a regular file inside the scan directory.",
  );
  expect(json!.error).toBe(invalid + ": invalid JSON: embedded null byte");
  expect(json!.systemExit).toBe(true);
  expect(directory!.error).toContain(
    process.platform === "win32" ? scan.replaceAll("\\", "\\\\") : scan,
  );
  const [missingParent, notDirectory] = run(
    {
      operation: "artifact",
      root: scan,
      path: "missing/" + invalid,
      required: false,
    },
    { operation: "available", root: scan, path: fixture + "/child/" + invalid },
  );
  expect(missingParent!.result).toBeNull();
  expect(notDirectory!.error).toContain("Not a directory");
  expect(notDirectory!.systemExit).toBe(false);
});

test("patch previews verify the entire digest, count headers, and decode invalid UTF-8", () => {
  const scan = root("preview"),
    patch = Buffer.concat([
      Buffer.from("--- a/file\n+++ b/file\n-old\n+new\n context\n"),
      Buffer.from([0xff]),
    ]);
  writeFileSync(join(scan, "patch.diff"), patch);
  const [verified, mismatch, missing] = run(
    {
      operation: "preview",
      root: scan,
      relative: "patch.diff",
      digest: digest(patch),
    },
    {
      operation: "preview",
      root: scan,
      relative: "patch.diff",
      digest: digest("different"),
    },
    { operation: "preview", root: scan, relative: null, digest: digest(patch) },
  );
  expect(verified!.result).toEqual([
    patch.toString("utf8"),
    { additions: 1n, deletions: 1n, fileCount: 1n, previewTruncated: false },
  ]);
  expect(mismatch!.result).toEqual([null, null]);
  expect(missing!.result).toEqual([null, null]);
});

test("multi-megabyte patch lines count once and preview truncation does not truncate hashing", () => {
  const scan = root("large-preview"),
    bytes = Buffer.concat([
      Buffer.from("diff --git a/file b/file\n+"),
      Buffer.alloc(2 * 1024 * 1024, 0x78),
      Buffer.from("\n-other\n+next"),
    ]);
  writeFileSync(join(scan, "patch.diff"), bytes);
  const result = run({
    operation: "preview",
    root: scan,
    relative: "patch.diff",
    digest: digest(bytes),
  })[0]!.result as [string, Record<string, unknown>];
  expect(result[0]).toBe(
    bytes.subarray(0, 16_000).toString("utf8") +
      "\n... patch preview truncated ...",
  );
  expect(result[1]).toEqual({
    additions: 2n,
    deletions: 1n,
    fileCount: 1n,
    previewTruncated: true,
  });
});

test("finding artifact lists derive the writeup and ordered proof files", () => {
  const scan = root("finding"),
    poc = join(scan, "findings/sample/poc");
  mkdirSync(join(poc, "fixtures"), { recursive: true });
  writeFileSync(join(scan, reportPath), "report");
  writeFileSync(join(poc, "README.md"), "readme");
  writeFileSync(join(poc, "reproduce.py"), "print('fixture')");
  writeFileSync(join(poc, "fixtures/payload.txt"), "payload");
  if (process.platform !== "win32") {
    symlinkSync(fixture, join(poc, "outside"));
    symlinkSync(directory, join(poc, "outside-directory"));
  }
  const [absolute, relative] = run(
    { operation: "finding", root: scan, details },
    { operation: "finding", root: ".", cwd: scan, details },
  );
  expect(absolute!.result).toEqual([
    reportPath,
    "findings/sample/poc/README.md",
    "findings/sample/poc/reproduce.py",
    "findings/sample/poc/fixtures/payload.txt",
  ]);
  expect(relative!.result).toEqual(absolute!.result);
  expect(
    run({
      operation: "finding",
      root: scan,
      details: { writeup: { reportPath: "findings/sample/other.md" } },
    })[0]!.result,
  ).toEqual([]);
});

test("finding discovery retains the existing forty-artifact and eighty-directory bounds", () => {
  const scan = root("artifact-bound"),
    poc = join(scan, "findings/sample/poc");
  mkdirSync(poc, { recursive: true });
  writeFileSync(join(scan, reportPath), "report");
  for (let index = 0; index < 45; index++)
    writeFileSync(join(poc, String(index).padStart(2, "0")), "fixture");
  const list = run({ operation: "finding", root: scan, details })[0]!
    .result as string[];
  expect(list).toHaveLength(40);
  expect(list.at(-1)).toBe("findings/sample/poc/38");
  const deep = root("directory-bound"),
    start = join(deep, "findings/sample/poc");
  mkdirSync(start, { recursive: true });
  let child = start;
  for (let index = 1; index <= 80; index++) {
    child = join(child, "d");
    mkdirSync(child);
    if (index >= 79) writeFileSync(join(child, "file"), "fixture");
  }
  const found = run({ operation: "finding", root: deep, details })[0]!
    .result as string[];
  expect(found).toEqual(["findings/sample/poc/" + "d/".repeat(79) + "file"]);
});
