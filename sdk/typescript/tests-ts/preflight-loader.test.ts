import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import { parseToml } from "../../../plugins/codex-security/mcp-app/src/helpers/toml";
import type { Response } from "./support/preflight-loader-fixture";

const node = Bun.which("node")!;
const root = mkdtempSync(join(tmpdir(), "preflight-loader-"));
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const fixture = join(root, "fixture.cjs");
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/preflight-loader-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: { "import.meta.url": "__filename" },
  }),
);
afterAll(() => rmSync(root, { recursive: true, force: true }));
function write(path: string, contents: string | Buffer): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
  return path;
}
function run(args: string[], env: NodeJS.ProcessEnv = {}, cwd = root) {
  const result = spawnSync(node, [helper, "config-preflight", ...args], {
    encoding: "utf8",
    cwd,
    env: {
      ...process.env,
      CODEX_HOME: join(root, "empty-home"),
      ...env,
      PATH: "",
      PYTHON: join(root, "no-python"),
    },
  });
  expect(result.error).toBeUndefined();
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}
function payload(args: string[], env?: NodeJS.ProcessEnv) {
  const result = run(args, env);
  expect(result.status, result.stdout + result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as {
    profile: string;
    config_paths: string[];
    config_profile: string | null;
    config_profile_path: string | null;
    user_config_path: string | null;
    config_resolution: string;
    config_discovery: {
      cwd: string;
      project_root: string;
      project_trust_level: string | null;
      project_layers_loaded: boolean;
    } | null;
    results: {
      capability: string;
      actual?: unknown;
      source?: string;
      status: string;
    }[];
  };
}
function values(requests: object[]): Response[] {
  const result = spawnSync(node, [fixture], {
    encoding: "utf8",
    input: JSON.stringify(requests),
    env: { ...process.env, PATH: "" },
  });
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Response[];
}

test("retains bundled profile routes, requirements, and advisory severities", () => {
  const registry = parseToml(
    readFileSync(
      join(PLUGIN_ROOT, "preflight", "capability-profiles.toml"),
      "utf8",
    ),
  );
  expect(registry["version"]).toBe(1n);
  const profiles = registry["profiles"] as Record<
    string,
    { requirements: { capability: string; severity: string }[] }
  >;
  expect(Object.keys(profiles).sort()).toEqual([
    "deep_security_scan",
    "security_diff_scan",
    "security_scan",
  ]);
  expect(profiles["deep_security_scan"]!.requirements).toEqual([]);
  expect(
    profiles["security_scan"]!.requirements.map((row) => row.capability),
  ).not.toContain("goals_enabled");
  expect(
    profiles["security_diff_scan"]!.requirements.map((row) => row.capability),
  ).toContain("goals_enabled");
  for (const [skill, profile] of [
    ["security-scan", "security_scan"],
    ["security-diff-scan", "security_diff_scan"],
    ["deep-security-scan", "deep_security_scan"],
  ] as const)
    expect(
      payload(["--skill", skill!, "--config", join(root, "missing.toml")])
        .profile,
    ).toBe(profile);
});

test("loads trusted project layers in parent order and strips their profile selection", () => {
  const repository = join(root, "trusted-repository"),
    cwd = join(repository, "nested", "leaf");
  mkdirSync(cwd, { recursive: true });
  write(join(repository, ".git"), "gitdir: synthetic\n");
  const home = join(root, "trusted-home");
  write(
    join(home, "config.toml"),
    `profile = "base"\n[profiles.base.features]\ngoals = false\n[projects.${JSON.stringify(repository)}]\ntrust_level = "trusted"`,
  );
  const parent = write(
    join(repository, ".codex", "config.toml"),
    'profile = "ignored"\n[profiles.ignored.features]\ngoals = false\n[features]\ngoals = false',
  );
  const child = write(
    join(repository, "nested", ".codex", "config.toml"),
    "[features]\ngoals = true",
  );
  const result = payload(["--profile", "security_diff_scan", "--cwd", cwd], {
    CODEX_HOME: home,
  });
  expect(result.config_discovery).toEqual({
    cwd,
    project_root: repository,
    project_trust_level: "trusted",
    project_layers_loaded: true,
  });
  expect(result.config_paths.slice(-3)).toEqual([
    parent,
    child,
    join(cwd, ".codex", "config.toml"),
  ]);
  expect(result.config_profile).toBe("base");
  expect(
    result.results.find((row) => row.capability === "goals_enabled"),
  ).toMatchObject({ actual: true, source: child });
  write(
    join(home, "config.toml"),
    `[projects.${JSON.stringify(repository)}]\ntrust_level = "untrusted"`,
  );
  const untrusted = payload(["--profile", "security_diff_scan", "--cwd", cwd], {
    CODEX_HOME: home,
  });
  expect(untrusted.config_discovery?.project_layers_loaded).toBe(false);
  expect(untrusted.config_paths).toHaveLength(2);
});

test("uses configured root markers and treats an empty marker list as the cwd", () => {
  const repository = join(root, "markers"),
    cwd = join(repository, "child");
  mkdirSync(cwd, { recursive: true });
  write(join(repository, "project.marker"), "");
  const home = join(root, "marker-home"),
    config = join(home, "config.toml");
  for (const [markers, expected] of [
    ['["project.marker"]', repository],
    ["[]", cwd],
    ['["absent"]', cwd],
    ['["\\u0000"]', cwd],
  ]) {
    write(config, `project_root_markers = ${markers}`);
    expect(
      payload(["--profile", "deep_security_scan", "--cwd", cwd], {
        CODEX_HOME: home,
      }).config_discovery?.project_root,
    ).toBe(expected);
  }
  write(config, 'project_root_markers = ["marker", 1]');
  expect(
    JSON.parse(
      run(["--profile", "deep_security_scan", "--cwd", cwd], {
        CODEX_HOME: home,
      }).stdout,
    ),
  ).toEqual({
    status: "error",
    error: "project_root_markers must be an array of strings",
  });
});

test("loads an explicit profile file only when it is a file and keeps CLI selection independent of embedded profiles", () => {
  const home = join(root, "profile-home"),
    cwd = join(root, "profile-target");
  mkdirSync(cwd);
  write(
    join(home, "config.toml"),
    'profile = "missing"\n[features]\ngoals = false',
  );
  const selected = write(
    join(home, "work.config.toml"),
    "[features]\ngoals = true",
  );
  const args = [
    "--profile",
    "security_diff_scan",
    "--cwd",
    cwd,
    "--codex-config-profile",
    "work",
  ];
  const result = payload(args, { CODEX_HOME: home });
  expect(result.config_profile).toBe("work");
  expect(result.config_profile_path).toBe(selected);
  expect(result.user_config_path).toBe(selected);
  expect(
    result.results.find((row) => row.capability === "goals_enabled"),
  ).toMatchObject({ actual: true, source: selected });
  rmSync(selected);
  mkdirSync(selected);
  const absent = payload(args, { CODEX_HOME: home });
  expect(absent.config_profile_path).toBeNull();
  expect(absent.config_paths).toHaveLength(2);
  for (const name of ["", "../work", "work profile", "work\n"])
    expect(
      JSON.parse(run([...args.slice(0, -1), name], { CODEX_HOME: home }).stdout)
        .error,
    ).toContain("invalid config profile name");
});

test("manual layers retain relative path spelling and bypass cwd and profile-file discovery", () => {
  write(join(root, "manual-a.toml"), "[features]\ngoals = false");
  write(join(root, "manual-b.toml"), "[features]\ngoals = true");
  const result = payload([
    "--profile",
    "security_diff_scan",
    "--config",
    "./manual-a.toml",
    "--config=manual-b.toml",
    "--cwd",
    "missing-directory",
    "--codex-config-profile",
    "quoted profile",
  ]);
  expect(result.config_paths).toEqual(["manual-a.toml", "manual-b.toml"]);
  expect(result.config_discovery).toBeNull();
  expect(result.user_config_path).toBeNull();
  expect(result.config_resolution).toBe("manual-layers");
  expect(result.config_profile).toBe("quoted profile");
  expect(
    result.results.find((row) => row.capability === "goals_enabled"),
  ).toMatchObject({ actual: true, source: "manual-b.toml" });
});

test("keeps repeated assignments, nonfinite JSON, and invalid-value diagnostics", () => {
  const config = write(join(root, "assignments.toml"), "");
  const args = ["--profile", "security_diff_scan", "--config", config];
  const result = payload([
    ...args,
    "--runtime-check",
    "delegation_available=false",
    "--runtime-check",
    "delegation_available=TRUE",
    "--effective-config",
    "features.goals=false",
    "--effective-config",
    "features.goals=true",
  ]);
  expect(
    result.results.find((row) => row.capability === "delegated_workers"),
  ).toMatchObject({ actual: true });
  expect(
    result.results.find((row) => row.capability === "goals_enabled"),
  ).toMatchObject({ actual: true, source: "effective-config" });
  const cases = [
    [["--runtime-check", "missing"], "expected NAME=VALUE, got 'missing'"],
    [["--runtime-check", "name=yes"], "expected true or false, got 'yes'"],
    [
      ["--effective-config", "name=["],
      "expected JSON value for 'name', got '['",
    ],
    [
      ["--available-plugin-skill", "plugin:skill"],
      "expected plugin-local skill name, got 'plugin:skill'; omit the plugin prefix",
    ],
  ] as const;
  for (const [options, error] of cases) {
    const response = run([...args, ...options]);
    expect(response.status).toBe(2);
    expect(JSON.parse(response.stdout)).toEqual({ status: "error", error });
  }
  expect(payload([...args, "--effective-config", "unused=NaN"]).profile).toBe(
    "security_diff_scan",
  );
});

test("distinguishes missing config files from directories and invalid TOML", () => {
  const directory = join(root, "config-directory");
  mkdirSync(directory);
  const malformed = write(join(root, "malformed.toml"), "value = [");
  for (const [path, expected] of [
    [
      directory,
      process.platform === "win32"
        ? "[Errno 13] Permission denied"
        : "Is a directory",
    ],
    ...(process.platform === "win32"
      ? []
      : [[join(malformed, "child"), "Not a directory"]]),
    [malformed, "Invalid value (at end of document)"],
  ]) {
    const result = run(["--profile", "deep_security_scan", "--config", path!]);
    expect(result.status).toBe(2);
    const error = JSON.parse(result.stdout) as {
      status: string;
      error: string;
    };
    expect(error.status).toBe("error");
    expect(error.error).toContain(expected!);
    if (path === directory && process.platform !== "win32")
      expect(error.error).toBe(`[Errno 21] Is a directory: '${directory}'`);
  }
  expect(
    payload([
      "--profile",
      "deep_security_scan",
      "--config",
      join(root, "absent.toml"),
    ]).profile,
  ).toBe("deep_security_scan");
});

test("loads a config beyond the Windows legacy path limit instead of using defaults", () => {
  const config = write(
    join(
      root,
      ...Array.from({ length: 6 }, (_, index) => `${index}-${"x".repeat(48)}`),
      "config.toml",
    ),
    "[features]\ngoals = false",
  );
  const result = payload([
    "--profile",
    "security_diff_scan",
    "--config",
    config,
  ]);
  expect(
    result.results.find((row) => row.capability === "goals_enabled"),
  ).toMatchObject({ actual: false, source: config });
});

test("preserves strict UTF-8 errors including partial multibyte sequences", () => {
  expect(
    values([
      { bytes: [0x61, 0xc3, 0xa9] },
      { bytes: [0x80] },
      { bytes: [0xff] },
      { bytes: [0xe0, 0x80, 0x80] },
      { bytes: [0xed, 0xa0, 0x80] },
      { bytes: [0xf4, 0x90, 0x80, 0x80] },
      { bytes: [0xe2, 0x82] },
      { bytes: [0x61, 0xe2, 0x82, 0x20] },
    ]),
  ).toEqual([
    { text: "aé" },
    {
      error:
        "'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte",
    },
    {
      error:
        "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
    },
    {
      error:
        "'utf-8' codec can't decode byte 0xe0 in position 0: invalid continuation byte",
    },
    {
      error:
        "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
    },
    {
      error:
        "'utf-8' codec can't decode byte 0xf4 in position 0: invalid continuation byte",
    },
    {
      error:
        "'utf-8' codec can't decode bytes in position 0-1: unexpected end of data",
    },
    {
      error:
        "'utf-8' codec can't decode bytes in position 1-2: invalid continuation byte",
    },
  ]);
  const invalid = write(join(root, "invalid-utf8.toml"), Buffer.from([0x80]));
  expect(
    JSON.parse(
      run(["--profile", "deep_security_scan", "--config", invalid]).stdout,
    ).error,
  ).toBe(
    "'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte",
  );
});

test("retains TOML dates as scalars, compares aware instants, and rejects JSON serialization", () => {
  const results = values([
    { source: "0001-01-01", other: "0001-01-01T00:00:00" },
    { source: "12:30:00" },
    {
      source: "2000-01-02T03:04:05.000001-00:30",
      other: "2000-01-02T03:34:05.000001Z",
    },
    {
      source: "1969-12-31T23:59:59.999999Z",
      other: "1970-01-01T00:59:59.999999+01:00",
    },
    { source: "2000-01-01T00:00:00", other: "2000-01-01T00:00:00Z" },
  ]);
  expect(results[0]).toEqual({
    repr: "datetime.date(1, 1, 1)",
    table: false,
    equal: false,
    jsonError: "Object of type date is not JSON serializable",
  });
  expect(results[1]).toMatchObject({
    repr: "datetime.time(12, 30)",
    table: false,
    jsonError: "Object of type time is not JSON serializable",
  });
  expect(results[2]).toMatchObject({
    repr: "datetime.datetime(2000, 1, 2, 3, 4, 5, 1, tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=84600)))",
    equal: true,
  });
  expect(results[3]?.equal).toBe(true);
  expect(results[4]?.equal).toBe(false);
  const config = write(
    join(root, "date.toml"),
    "[features]\ngoals = 2000-01-01",
  );
  const response = run(["--profile", "security_diff_scan", "--config", config]);
  expect(response.status).toBe(1);
  expect(response.stdout).toBe("");
  expect(response.stderr).toContain(
    "Object of type date is not JSON serializable",
  );
});

test("rejects missing registry fields instead of returning ready or invalid JSON", () => {
  const emptyProfile =
    '[profiles.test]\ndescription = "Test"\nrequirements = []';
  const cases = [
    [`version = 1\n${emptyProfile}`, "capabilities"],
    [`[capabilities]\n${emptyProfile}`, "version"],
    [
      "version = 1\n[capabilities]\n[profiles.test]\nrequirements = []",
      "description",
    ],
    [
      'version = 1\n[capabilities.required]\nkind = "runtime"\ncheck = "available"\n[profiles.test]\ndescription = "Test"\n[[profiles.test.requirements]]\ncapability = "required"\nseverity = "warn"',
      "reason",
    ],
  ] as const;
  for (const [contents, missing] of cases) {
    const registry = write(join(root, `missing-${missing}.toml`), contents);
    const result = run([
      "--registry",
      registry,
      "--profile",
      "test",
      "--config",
      "absent.toml",
    ]);
    expect(result.status).toBe(2);
    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toEqual({
      status: "error",
      error: `'${missing}'`,
    });
  }
});

test("keeps numeric registry references distinct from string table keys", () => {
  const prefix =
    'version = 1\n[capabilities]\n[profiles."1"]\ndescription = "Test"\nrequirements = []\n';
  const cases = [
    [
      prefix + '[[routes]]\nskill = 1\nprofile = "1"',
      ["--skill", "1"],
      "no capability profile route for skill '1'",
    ],
    [
      prefix + '[[routes]]\nskill = "test"\nprofile = 1',
      ["--skill", "test"],
      "unknown capability profile: 1",
    ],
    [
      'version = 1\n[capabilities."1"]\nkind = "runtime"\ncheck = "available"\n[profiles.test]\ndescription = "Test"\n[[profiles.test.requirements]]\ncapability = 1\nseverity = "warn"\nreason = "Test"',
      ["--profile", "test"],
      "profile 'test' references unknown capability 1",
    ],
  ] as const;
  for (const [contents, selector, error] of cases) {
    const registry = write(join(root, "numeric-registry.toml"), contents);
    const response = run([
      ...selector,
      "--registry",
      registry,
      "--config",
      "absent.toml",
    ]);
    expect(response.status).toBe(2);
    expect(response.stderr).toBe("");
    expect(JSON.parse(response.stdout)).toEqual({ status: "error", error });
  }
});

test("resolves an empty profile through the None skill route", () => {
  const registry = write(
    join(root, "none-route.toml"),
    'version = 1\n[capabilities]\n[profiles.test]\ndescription = "Test"\nrequirements = []\n[[routes]]\nskill = "None"\nprofile = "test"\n',
  );
  expect(
    payload([
      "--registry",
      registry,
      "--profile",
      "",
      "--config",
      "absent.toml",
    ]).profile,
  ).toBe("test");
});

test("validates each option occurrence before later overrides and help", () => {
  for (const args of [
    [
      "--multi-agent-session-cap",
      "0",
      "--multi-agent-session-cap",
      "4",
      "--help",
    ],
    [
      "--profile",
      "deep_security_scan",
      "--skill",
      "deep-security-scan",
      "--help",
    ],
    ["--ski", "deep-security-scan", "--pro", "deep_security_scan", "--help"],
  ]) {
    const result = run(args);
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("error:");
  }
  expect(run(["--help", "--multi-agent-session-cap", "0"]).status).toBe(0);
  expect(
    payload([
      "--profile",
      "security_scan",
      "--profile",
      "deep_security_scan",
      "--config",
      "absent.toml",
    ]).profile,
  ).toBe("deep_security_scan");
});

test.skipIf(process.platform === "win32")(
  "follows cwd links during config discovery",
  () => {
    const target = join(root, "real-target");
    mkdirSync(target);
    write(join(target, ".git"), "");
    const linked = join(root, "linked-target");
    symlinkSync(target, linked, "dir");
    const result = payload([
      "--profile",
      "deep_security_scan",
      "--cwd",
      linked,
    ]);
    expect(result.config_discovery).toMatchObject({
      cwd: resolve(target),
      project_root: resolve(target),
    });
  },
);

test.skipIf(process.platform === "win32")(
  "keeps cwd symlink loops outside the structured error envelope",
  () => {
    const loop = join(root, "cwd-loop");
    symlinkSync(loop, loop);
    const result = run(["--profile", "deep_security_scan", "--cwd", loop]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Symlink loop");
  },
);

test.skipIf(process.platform !== "linux")(
  "reads raw-byte CODEX_HOME and retains its path in the result",
  () => {
    const prefix = join(root, "raw-home-");
    const home = Buffer.concat([Buffer.from(prefix), Buffer.from([0xff])]);
    mkdirSync(home);
    writeFileSync(
      Buffer.concat([home, Buffer.from("/config.toml")]),
      "[features]\ngoals = false",
    );
    const result = spawnSync(
      "/bin/sh",
      [
        "-c",
        'task_codex_home="$1$(printf \'\\377\')"; shift; CODEX_HOME="$task_codex_home" exec "$@"',
        "preflight",
        prefix,
        node,
        helper,
        "config-preflight",
        "--profile",
        "security_diff_scan",
        "--cwd",
        root,
      ],
      { encoding: "utf8", env: { ...process.env, PATH: "" } },
    );
    expect(result.status, result.stderr).toBe(0);
    const data = JSON.parse(result.stdout) as {
      user_config_path: string;
      results: { capability: string; actual: unknown; source: string }[];
    };
    const config = `${prefix}\udcff/config.toml`;
    expect(data.user_config_path).toBe(config);
    expect(
      data.results.find((row) => row.capability === "goals_enabled"),
    ).toMatchObject({ actual: false, source: config });
  },
);

test.skipIf(process.platform !== "linux")(
  "preserves a raw-byte HOME when using the default Codex directory",
  () => {
    const prefix = join(root, "raw-default-home-");
    const home = Buffer.concat([Buffer.from(prefix), Buffer.from([0xff])]);
    mkdirSync(Buffer.concat([home, Buffer.from("/.codex")]), {
      recursive: true,
    });
    writeFileSync(
      Buffer.concat([home, Buffer.from("/.codex/config.toml")]),
      "[features]\ngoals = false",
    );
    const result = spawnSync(
      "/bin/sh",
      [
        "-c",
        'task_home="$1$(printf \'\\377\')"; shift; unset CODEX_HOME; HOME="$task_home" exec "$@"',
        "preflight",
        prefix,
        node,
        helper,
        "config-preflight",
        "--profile",
        "security_diff_scan",
        "--cwd",
        root,
      ],
      { encoding: "utf8", env: { ...process.env, PATH: "" } },
    );
    expect(result.status, result.stderr).toBe(0);
    const data = JSON.parse(result.stdout) as {
      user_config_path: string;
      results: { capability: string; actual: unknown; source: string }[];
    };
    const config = `${prefix}\udcff/.codex/config.toml`;
    expect(data.user_config_path).toBe(config);
    expect(
      data.results.find((row) => row.capability === "goals_enabled"),
    ).toMatchObject({ actual: false, source: config });
  },
);
