import { spawnSync } from "node:child_process";
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import {
  windowsFileSystem,
  widePath,
} from "../../../plugins/codex-security/native/windows-files.mjs";
import type {
  WindowsBinding,
  WindowsHandle,
} from "../../../plugins/codex-security/native/windows-binding.mjs";
import { windowsFileIdentity } from "../../../plugins/codex-security/mcp-app/src/helpers/windows-scan-files";
import { PLUGIN_ROOT } from "./plugin-root";
import type { Request, Response } from "./support/export-output-fixture";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "export-output-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
let sequence = 0;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/export-output-fixture.ts", import.meta.url),
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
afterAll(() => rmSync(directory, { recursive: true, force: true }));
function setup(
  artifacts: unknown[] = [{ path: "findings.json" }, { path: "coverage.json" }],
) {
  const root = join(directory, `case-${++sequence}`),
    scanDir = join(root, "scan");
  mkdirSync(join(scanDir, "exports"), { recursive: true, mode: 0o700 });
  writeFileSync(
    join(scanDir, "scan-manifest.json"),
    JSON.stringify({ scan: { artifacts } }),
  );
  writeFileSync(join(scanDir, "findings.json"), "sealed findings");
  writeFileSync(join(scanDir, "coverage.json"), "sealed coverage");
  return { root, scanDir, output: join(scanDir, "exports/findings.csv") };
}
function request(
  scanDir: string,
  output: string,
  options: Partial<Request> = {},
): Request {
  return {
    scanDir,
    output,
    format: "csv",
    contents: Buffer.from("export\n").toString("base64"),
    ...options,
  };
}
function run(requests: Request[]): Response[] {
  const child = spawnSync(node, [fixture], {
    input: JSON.stringify(requests),
    cwd: directory,
    encoding: "utf8",
    maxBuffer: Infinity,
    env: { ...process.env, PATH: "", PYTHON: "/unavailable/python" },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  const results = JSON.parse(child.stdout) as Response[];
  if (process.platform === "linux")
    for (const result of results) expect(result.leaked).toBe(0);
  return results;
}
function success(response: Response): void {
  expect(response.error).toBeUndefined();
}
const content = (path: string) => readFileSync(path, "utf8");

test("writes each reserved export path and serializes SARIF before validating the scan", () => {
  for (const [format, name] of [
    ["csv", "findings.csv"],
    ["json", "findings.json"],
    ["sarif", "results.sarif"],
  ]) {
    const { scanDir } = setup(),
      output = join(scanDir, "exports", name!);
    success(run([request(scanDir, output, { format })])[0]!);
    expect(content(output)).toBe("export\n");
    expect(content(join(scanDir, "findings.json"))).toBe("sealed findings");
  }
  const { scanDir } = setup(),
    output = join(scanDir, "exports/results.sarif");
  const sarif = '{"version":"2.1.0","runs":[],"10":1.0,"2":"😀"}';
  success(run([request(scanDir, output, { sarif })])[0]!);
  expect(content(output)).toBe(
    '{\n  "10": 1.0,\n  "2": "\\ud83d\\ude00",\n  "runs": [],\n  "version": "2.1.0"\n}\n',
  );
  const invalid = run([
    request(join(directory, "missing"), output, { sarif: '{"bad":NaN}' }),
  ])[0]!;
  expect(invalid.error).toContain("cannot encode canonical JSON");
});

test("external output requires a valid scan directory but does not read its manifest", () => {
  const { root, scanDir } = setup(),
    output = join(root, "external.csv");
  unlinkSync(join(scanDir, "scan-manifest.json"));
  success(run([request(scanDir, output)])[0]!);
  expect(content(output)).toBe("export\n");
  const invalid = run([request(join(root, "missing"), output)])[0]!;
  expect(invalid.error).toBe(
    "scan directory: expected an existing non-symlink directory",
  );
  expect(content(output)).toBe("export\n");
});

test("format and output restrictions precede manifest reads and do not create paths", () => {
  const { scanDir, root } = setup();
  unlinkSync(join(scanDir, "scan-manifest.json"));
  const responses = run([
    request(join(root, "missing"), join(root, "out"), { format: "CSV" }),
    request(scanDir, join(scanDir, "findings.json"), { format: "json" }),
    request(scanDir, join(scanDir, "exports/other.csv")),
    request(scanDir, scanDir),
  ]);
  expect(responses.map((item) => item.error)).toEqual([
    "unsupported export format: CSV",
    "JSON output path cannot overwrite a scan artifact",
    "CSV output path cannot overwrite a scan artifact",
    "CSV output path cannot overwrite a scan artifact",
  ]);
  expect(existsSync(join(root, "out"))).toBe(false);
  expect(existsSync(join(scanDir, "exports/other.csv"))).toBe(false);
});

test("normalizes relative paths and dot segments before checking canonical export paths", () => {
  const { scanDir, output } = setup();
  const spelling =
    relative(directory, scanDir) + "/exports/../exports//./findings.csv";
  success(run([request(scanDir, spelling)])[0]!);
  expect(content(output)).toBe("export\n");
  const external = join(scanDir, "..", "outside.csv");
  success(run([request(scanDir, external)])[0]!);
  expect(content(join(scanDir, "..", "outside.csv"))).toBe("export\n");
});

test("validates every declared artifact path before inspecting or opening export files", () => {
  const { scanDir, output } = setup([
    { path: "findings.json" },
    null,
    { path: "../outside" },
  ]);
  writeFileSync(output, "existing");
  const result = run([
    request(scanDir, output, { trace: true, failOutputStat: true }),
  ])[0]!;
  expect(result.error).toBe(
    "manifest.scan.artifacts[2].path: expected a safe repository-relative POSIX path",
  );
  expect(content(output)).toBe("existing");
  if (process.platform !== "win32")
    expect(result.events).toEqual([
      { open: "scan-manifest.json" },
      { close: "scan-manifest.json" },
    ]);
  const valid = setup([null, 1, "ignored", { path: "findings.json" }]);
  success(run([request(valid.scanDir, valid.output)])[0]!);
  expect(content(valid.output)).toBe("export\n");
});

test("declared reserved export paths remain protected even when their files are absent", () => {
  for (const path of [
    "exports/findings.csv",
    "exports/./findings.csv",
    "exports//findings.csv",
  ]) {
    const { scanDir, output } = setup([{ path }]);
    const result = run([request(scanDir, output)])[0]!;
    expect(result.error).toBe(
      "CSV output path cannot overwrite a sealed scan artifact",
    );
    expect(existsSync(output)).toBe(false);
  }
});

test("existing output is checked against opened artifacts while absent output skips their reads", () => {
  const first = setup([{ path: "missing.json" }]);
  success(run([request(first.scanDir, first.output, { trace: true })])[0]!);
  expect(content(first.output)).toBe("export\n");
  const second = setup([{ path: "missing.json" }]);
  writeFileSync(second.output, "existing");
  const failed = run([
    request(second.scanDir, second.output, { trace: true }),
  ])[0]!;
  expect(failed.error).toBe(
    "sealed artifact missing.json: expected a file inside the scan directory",
  );
  expect(content(second.output)).toBe("existing");
  const third = setup();
  writeFileSync(third.output, "existing");
  const result = run([
    request(third.scanDir, third.output, { trace: true }),
  ])[0]!;
  success(result);
  if (process.platform !== "win32")
    expect(result.events.slice(0, 8)).toEqual([
      { open: "scan-manifest.json" },
      { close: "scan-manifest.json" },
      { open: "findings.json" },
      { identity: "findings.json" },
      { close: "findings.json" },
      { open: "coverage.json" },
      { identity: "coverage.json" },
      { close: "coverage.json" },
    ]);
  expect(content(third.output)).toBe("export\n");
});

test("rejects output hard links to sealed artifacts but replaces external hard links safely", () => {
  const { scanDir, output, root } = setup();
  const sealed = join(scanDir, "findings.json");
  linkSync(sealed, output);
  const result = run([request(scanDir, output, { trace: true })])[0]!;
  expect(result.error).toBe(
    "CSV output path cannot overwrite a sealed scan artifact",
  );
  expect(content(sealed)).toBe("sealed findings");
  expect(content(output)).toBe("sealed findings");
  const external = join(root, "external.csv");
  linkSync(sealed, external);
  success(run([request(scanDir, external)])[0]!);
  expect(content(external)).toBe("export\n");
  expect(content(sealed)).toBe("sealed findings");
  expect(statSync(external).ino).not.toBe(statSync(sealed).ino);
});

test.skipIf(process.platform === "win32")(
  "checks opened artifact identity after a concurrent path replacement",
  () => {
    const { scanDir, output } = setup();
    linkSync(join(scanDir, "findings.json"), output);
    const result = run([
      request(scanDir, output, {
        trace: true,
        replaceAfterOpen: "findings.json",
      }),
    ])[0]!;
    expect(result.error).toBe(
      "CSV output path cannot overwrite a sealed scan artifact",
    );
    expect(content(join(scanDir, "findings.json"))).toBe("replacement");
    expect(content(join(scanDir, "findings.json.retained"))).toBe(
      "sealed findings",
    );
    expect(content(output)).toBe("sealed findings");
    expect(result.events.at(-1)).toEqual({ close: "findings.json" });
  },
);

test.skipIf(process.platform === "win32")(
  "descriptor identity and close failures propagate without writing output",
  () => {
    for (const options of [
      { failIdentity: "findings.json" },
      { failClose: "findings.json" },
    ]) {
      const { scanDir, output } = setup();
      writeFileSync(output, "existing");
      const result = run([
        request(scanDir, output, { trace: true, ...options }),
      ])[0]!;
      expect(result.error).toBe(
        "failIdentity" in options
          ? "synthetic identity failure"
          : "synthetic close failure",
      );
      expect(result.events.at(-1)).toEqual({ close: "findings.json" });
      expect(content(output)).toBe("existing");
    }
  },
);

test("output inspection errors retain their export context", () => {
  const { scanDir, output } = setup();
  writeFileSync(output, "existing");
  const result = run([request(scanDir, output, { failOutputStat: true })])[0]!;
  if (process.platform === "win32") success(result);
  else {
    expect(result.error).toBe(
      "exports/findings.csv: unable to inspect export output",
    );
    expect(content(output)).toBe("existing");
  }
});

test.skipIf(process.platform === "win32")(
  "rejects direct and ancestor symlink aliases of the scan directory",
  () => {
    const { scanDir, output, root } = setup();
    const direct = join(root, "direct"),
      parent = join(directory, `parent-${sequence}`);
    symlinkSync(scanDir, direct, "dir");
    symlinkSync(root, parent, "dir");
    writeFileSync(output, "existing");
    for (const alias of [direct, join(parent, "scan")]) {
      const result = run([
        request(scanDir, join(alias, "exports/findings.csv")),
      ])[0]!;
      expect(result.error).toBe(
        "export output path: symbolic links cannot alias the scan directory",
      );
      expect(content(output)).toBe("existing");
    }
  },
);

test.skipIf(process.platform === "win32")(
  "external paths retain filename acceptance and reject missing or aliased parents",
  () => {
    const { scanDir, root } = setup();
    const output = join(root, "report: line\n\\name.csv");
    success(run([request(scanDir, output)])[0]!);
    expect(content(output)).toBe("export\n");
    const missing = run([request(scanDir, join(root, "missing/out.csv"))])[0]!;
    expect(missing.error).toBe(
      "scan directory: expected an existing non-symlink directory",
    );
    const file = join(root, "file");
    writeFileSync(file, "existing");
    const invalid = run([request(scanDir, join(file, "child/out.csv"))])[0]!;
    expect(invalid.error).toBe(
      "export output path: unable to inspect output directory",
    );
    const alias = join(root, "external-alias");
    const real = join(root, "external");
    mkdirSync(real);
    symlinkSync(real, alias, "dir");
    const symbolic = run([request(scanDir, join(alias, "out.csv"))])[0]!;
    expect(symbolic.error).toBe(
      "scan directory: expected an existing non-symlink directory",
    );
  },
);

test.skipIf(process.platform === "win32")(
  "output symlinks remain untouched and unrelated hard links are replaced atomically",
  () => {
    const linked = setup(),
      target = join(linked.root, "target.csv");
    writeFileSync(target, "protected");
    symlinkSync(target, linked.output);
    const failed = run([request(linked.scanDir, linked.output)])[0]!;
    expect(failed.error).toContain("non-symlink");
    expect(lstatSync(linked.output).isSymbolicLink()).toBe(true);
    expect(content(target)).toBe("protected");
    unlinkSync(linked.output);
    linkSync(target, linked.output);
    success(run([request(linked.scanDir, linked.output)])[0]!);
    expect(content(linked.output)).toBe("export\n");
    expect(content(target)).toBe("protected");
  },
);

test("Windows identity access retains 128-bit file IDs and closes each path handle", () => {
  const events: unknown[] = [],
    fileId = Buffer.alloc(16);
  fileId.writeBigUInt64LE(7n);
  fileId.writeBigUInt64LE(11n, 8);
  const handle = {
    identity: () => ({ error: 0, volume: "9007199254740993", fileId }),
    close: () => {
      events.push("close");
      return 0;
    },
  } as unknown as WindowsHandle;
  const native = {
    windowsAbsolutePath: (path: Buffer) => ({ error: 0, value: path }),
    openWindowsFile: (
      _path: Buffer,
      _access: number,
      _share: number,
      _disposition: number,
      attributes: number,
    ) => {
      events.push(attributes);
      return { error: 0, handle };
    },
  } as unknown as WindowsBinding;
  const files = windowsFileSystem(native);
  expect(
    windowsFileIdentity(files.identity(widePath("C:\\scan\\output"), false)),
  ).toEqual([9007199254740993n, 7n | (11n << 64n)]);
  expect(events).toEqual([0x02000000 | 0x00200000, "close"]);
  events.length = 0;
  expect(files.sameFile(widePath("C:\\first"), widePath("C:\\second"))).toBe(
    true,
  );
  expect(events).toEqual([0x02000000, "close", 0x02000000, "close"]);
});
