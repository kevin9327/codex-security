import { spawnSync } from "node:child_process";
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
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";

const root = realpathSync(mkdtempSync(join(tmpdir(), "deep-scan-config-")));
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
  node = Bun.which("node")!;
const typedFixture = join(root, "typed.cjs");
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/deep-scan-config-fixture.ts", import.meta.url),
      ),
    ],
    outfile: typedFixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: { "import.meta.url": JSON.stringify(pathToFileURL(helper).href) },
  }),
);
afterAll(() => rmSync(root, { recursive: true, force: true }));
function directory() {
  return realpathSync(mkdtempSync(join(root, "case-")));
}
function config(contents?: string | Buffer) {
  const cwd = directory(),
    home = join(cwd, "codex-home"),
    path = join(home, "codex-security", "config.toml");
  if (contents !== undefined) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, contents);
  }
  return { cwd, home, path };
}
function environment(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    CODEX_HOME: home,
    PYTHON: "/unavailable/python",
    PATH: "",
  };
  delete env["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"];
  delete env["PYTHONINTMAXSTRDIGITS"];
  return env;
}
function run(
  home: string,
  args = ["--available-parallelism", "8"],
  env: NodeJS.ProcessEnv = {},
  cwd?: string,
) {
  return spawnSync(node, [helper, "deep-scan-config", ...args], {
    encoding: "utf8",
    env: { ...environment(home), ...env },
    cwd,
    maxBuffer: Infinity,
  });
}
function success(home: string, args?: string[]) {
  const result = run(home, args);
  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return result.stdout;
}
const defaults =
  '{"maxDiscoveryRuns": 40, "maxTimeHours": 96, "stopAfterConsecutiveErrors": 3, "stopAfterNoNew": 4, "subagents": 3, "workers": 4}';
const newline = process.platform === "win32" ? "\r\n" : "\n";

test("missing configuration and auto workers retain fixed defaults at every capacity", () => {
  const absent = config();
  for (const available of ["1", "16", "9007199254740993"])
    expect(success(absent.home, ["--available-parallelism", available])).toBe(
      defaults + newline,
    );
  const auto = config('[deep_scan]\nworkers = "auto"\n');
  expect(success(auto.home, ["--available-parallelism", "1"])).toBe(
    defaults + newline,
  );
  const fixed = config("[deep_scan]\nworkers = 6\n");
  expect(
    JSON.parse(success(fixed.home, ["--available-parallelism", "1"])),
  ).toMatchObject({ workers: 6 });
});

test("resolves overrides, whitespace fallbacks, relative paths and home expansion", () => {
  const files = config("[deep_scan]\nworkers = 2\n"),
    isolated = join(files.cwd, "isolated.toml");
  writeFileSync(isolated, "[deep_scan]\nworkers = 7\n");
  const override = run(files.home, undefined, {
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: ` \u001c${isolated}\u2000`,
  });
  expect(override.status, override.stderr).toBe(0);
  expect(JSON.parse(override.stdout).workers).toBe(7);
  expect(
    JSON.parse(
      run(files.home, undefined, {
        CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: "\u001c \u2000",
      }).stdout,
    ).workers,
  ).toBe(2);
  expect(
    JSON.parse(
      run(
        files.home,
        undefined,
        { CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: "isolated.toml" },
        files.cwd,
      ).stdout,
    ).workers,
  ).toBe(7);
  if (process.platform !== "win32") {
    expect(
      JSON.parse(
        run(files.home, undefined, {
          HOME: files.cwd,
          CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: "~/isolated.toml",
        }).stdout,
      ).workers,
    ).toBe(7);
    const link = join(files.cwd, "missing-link");
    symlinkSync("missing.toml", link);
    expect(
      run(files.home, undefined, { CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: link })
        .stdout,
    ).toBe(defaults + newline);
  }
});

test("preserves integer, integral float and arbitrary precision JSON bytes", () => {
  const integer = config(
    "[deep_scan]\nworkers = 9007199254740993\nsubagents = 0\nmax_time_hours = 1\n",
  );
  expect(success(integer.home)).toContain('"workers": 9007199254740993');
  expect(success(integer.home)).toContain('"maxTimeHours": 1,');
  const floating = config("[deep_scan]\nmax_time_hours = 1.0\n");
  expect(success(floating.home)).toContain('"maxTimeHours": 1.0,');
  const small = config("[deep_scan]\nmax_time_hours = 0.00001\n");
  expect(success(small.home)).toContain('"maxTimeHours": 1e-05,');
  for (const [home, type] of [
    [integer.home, "bigint"],
    [floating.home, "number"],
  ]) {
    const result = spawnSync(node, [typedFixture], {
      input: "[1, 1.5, true, 0]",
      encoding: "utf8",
      env: environment(home!),
      maxBuffer: Infinity,
    });
    expect(result.status, result.stderr).toBe(0);
    const values = JSON.parse(result.stdout) as {
      maxTimeType?: string;
      error?: string;
      systemExit?: boolean;
    }[];
    expect(values.slice(0, 2).map((value) => value.maxTimeType)).toEqual([
      type,
      type,
    ]);
    expect(values.slice(2)).toEqual(
      Array(2).fill({
        error: "Available parallelism must be a positive integer.",
        systemExit: true,
      }),
    );
  }
});

test("validates integer fields without converting floats, booleans or strings", () => {
  for (const key of [
    "workers",
    "subagents",
    "stop_after_no_new",
    "stop_after_consecutive_errors",
    "max_discovery_runs",
  ]) {
    for (const value of [
      "true",
      "1.0",
      '"1"',
      "-1",
      ...(key === "subagents" ? [] : ["0"]),
    ]) {
      const files = config(`[deep_scan]\n${key} = ${value}\n`),
        result = run(files.home);
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe(
        `deep_scan.${key} must be ${key === "subagents" ? "a non-negative integer" : "a positive integer"}.${newline}`,
      );
    }
  }
  const ordering = config(
    "[deep_scan]\nsubagents = -1\nstop_after_no_new = 0\n",
  );
  expect(run(ordering.home).stderr).toBe(
    `deep_scan.stop_after_no_new must be a positive integer.${newline}`,
  );
  const thresholds = config("[deep_scan]\nstop_after_no_new = 9\n");
  expect(JSON.parse(success(thresholds.home))).toMatchObject({
    stopAfterNoNew: 9,
    stopAfterConsecutiveErrors: 3,
  });
});

test("keeps the discovery deadline positive, finite and at most ninety-six hours", () => {
  for (const value of [
    "0",
    "-0.0",
    "-0.5",
    "true",
    '"2"',
    "nan",
    "inf",
    "96.5",
    "99999999999999999999999999999999999999999999999999999999999999",
  ]) {
    const result = run(config(`[deep_scan]\nmax_time_hours = ${value}\n`).home);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe(
      `deep_scan.max_time_hours must be a positive finite number no greater than 96.${newline}`,
    );
  }
  expect(
    JSON.parse(success(config("[deep_scan]\nmax_time_hours = 0.5\n").home)),
  ).toMatchObject({ maxTimeHours: 0.5 });
  expect(
    success(config("[deep_scan]\nmax_time_hours = 96.0\n").home),
  ).toContain('"maxTimeHours": 96.0,');
});

test("reports table shape, unknown keys and TOML diagnostics without changing paths", () => {
  const invalid = config("deep_scan = []\n");
  expect(run(invalid.home).stderr).toBe(
    `Codex Security configuration [deep_scan] at ${invalid.path} must be a TOML table.${newline}`,
  );
  const unknown = config('[deep_scan]\n"😀" = 1\n"\ue000" = 1\na = 1\n');
  expect(run(unknown.home).stderr).toBe(
    `Unknown Codex Security Deep Scan configuration a, \ue000, 😀 in ${unknown.path}.${newline}`,
  );
  const syntax = config("[deep_scan]\nworkers =\n");
  expect(run(syntax.home).stderr).toBe(
    `Cannot read Codex Security configuration at ${syntax.path}: Invalid value (at line 2, column 10)${newline}`,
  );
  expect(
    success(config('other = true\n[elsewhere]\nvalue = "retained"\n').home),
  ).toBe(defaults + newline);
  const binary = config(Buffer.from([0xff]));
  expect(run(binary.home).stderr).toBe(
    `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte${newline}`,
  );
});

test("configuration I/O retains the original read-error boundary", () => {
  const files = config();
  mkdirSync(files.path, { recursive: true });
  const result = run(files.home);
  expect(result.status).toBe(1);
  expect(result.stderr).toContain(
    `Cannot read Codex Security configuration at ${files.path}:`,
  );
  if (process.platform !== "win32") {
    const denied = config("[deep_scan]\nworkers = 6\n");
    chmodSync(denied.path, 0);
    try {
      expect(run(denied.home).stderr).toBe(
        `Cannot read Codex Security configuration at ${denied.path}: [Errno 13] Permission denied: '${denied.path}'\n`,
      );
    } finally {
      chmodSync(denied.path, 0o600);
    }
    chmodSync(dirname(denied.path), 0);
    try {
      expect(run(denied.home).stderr).toBe(
        `PermissionError: [Errno 13] Permission denied: '${denied.path}'\n`,
      );
    } finally {
      chmodSync(dirname(denied.path), 0o700);
    }
  }
});

test("retains configured Python integer conversion errors before writing JSON", () => {
  const hexadecimal = config(`[deep_scan]\nworkers = 0x${"f".repeat(3572)}\n`);
  const output = run(hexadecimal.home);
  expect(output.status).toBe(1);
  expect(output.stdout).toBe("");
  expect(output.stderr).toBe(
    `ValueError: Exceeds the limit (4300 digits) for integer string conversion; use sys.set_int_max_str_digits() to increase the limit${newline}`,
  );
  expect(
    run(hexadecimal.home, undefined, { PYTHONINTMAXSTRDIGITS: "0" }).status,
  ).toBe(0);
  const decimal = config(`[deep_scan]\nworkers = ${"9".repeat(700)}\n`);
  const input = run(decimal.home, undefined, { PYTHONINTMAXSTRDIGITS: "640" });
  expect(input.status).toBe(1);
  expect(input.stdout).toBe("");
  expect(input.stderr).toBe(
    `ValueError: Exceeds the limit (640 digits) for integer string conversion: value has 700 digits; use sys.set_int_max_str_digits() to increase the limit${newline}`,
  );
});

test("the helper keeps required integer parsing and validates capacity before opening config", () => {
  const files = config("invalid =");
  const missing = run(files.home, []);
  expect(missing.status).toBe(2);
  expect(missing.stderr).toContain(
    "the following arguments are required: --available-parallelism",
  );
  for (const value of ["0", "-1"]) {
    const result = run(files.home, ["--available-parallelism", value]);
    expect(result.status).toBe(1);
    expect(result.stderr).toBe(
      `Available parallelism must be a positive integer.${newline}`,
    );
  }
  const fractional = run(files.home, ["--available-parallelism", "1.5"]);
  expect(fractional.status).toBe(2);
  expect(fractional.stderr).toContain("invalid int value: '1.5'");
  const defaultsHome = config().home;
  expect(success(defaultsHome, ["--available-p=+١_٢"])).toBe(
    defaults + newline,
  );
  const help = run(files.home, ["--help"]);
  expect(help.status).toBe(0);
  expect(help.stderr).toBe("");
  expect(help.stdout).toContain("--helper deep-scan-config");
});
