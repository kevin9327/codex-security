import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  mkdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { constants } from "node:os";
import { basename, delimiter, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { loadBinding, output } from "./binding.mjs";
import {
  loadProcessBinding,
  type ProcessRequest,
  type ProcessResult,
} from "./process-binding.mjs";

const windows = process.platform === "win32";
const encode = (value: string): Buffer =>
  Buffer.from(value, windows ? "utf16le" : "utf8");
const raw = (prefix: string): Buffer =>
  Buffer.concat([
    encode(prefix),
    windows
      ? Buffer.from([0, 0xd8])
      : process.platform === "darwin"
        ? Buffer.from("é")
        : Buffer.from([0xff]),
  ]);
const fixture = join(output, `process-fixture${windows ? ".exe" : ""}`);
const inheritedInput = Buffer.from([0, 1, 0xff, 0x80, 10]);

function success(result: ProcessResult, code = 0): Buffer {
  assert.equal(result.error, 0);
  assert.equal(result.returnCode, code);
  return result.stdout;
}

export function rawProcessProof(root: string): unknown {
  const reports: Record<string, unknown> = {};
  for (const mode of process.platform === "linux"
    ? ["regular", "fallback"]
    : ["regular"]) {
    const directory = join(root, `process-${mode}`);
    mkdirSync(directory);
    const result = spawnSync(
      fixture,
      [
        "launch",
        process.execPath,
        fileURLToPath(import.meta.url),
        realpathSync.native(directory),
        mode,
      ],
      {
        input: inheritedInput,
        timeout: 60_000,
      },
    );
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr.toString());
    reports[mode] = JSON.parse(result.stdout.toString()) as unknown;
  }
  return reports;
}

function worker(root: string, descriptor: string): unknown {
  // Prove the sentinel reached Node before testing that rawProcess closes it.
  if (windows) {
    const result = spawnSync(fixture, [
      "check-inherited",
      String(process.pid),
      descriptor,
    ]);
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr.toString());
  } else {
    const result = loadBinding().duplicate(Number(descriptor));
    assert.equal(result.errno, 0);
    closeSync(result.value);
  }
  const native = loadProcessBinding();
  const before = BigInt(Date.now()) * 1000n;
  const micros = native.wallClockMicroseconds();
  const after = BigInt(Date.now() + 1) * 1000n;
  assert.equal(typeof micros, "bigint");
  // The OS and JavaScript clocks can have different sampling precision.
  assert.ok(before - 1_000_000n <= micros && micros < after + 1_000_000n);
  const directory = raw(`${root}${sep}process-cwd-`);
  const program = Buffer.concat([
    directory,
    encode(sep),
    raw("process-exe-"),
    encode(windows ? ".exe" : ""),
  ]);
  const run = (
    args: Buffer[],
    options: Partial<ProcessRequest> = {},
  ): ProcessResult =>
    native.rawProcess({ program, args, input: Buffer.alloc(0), ...options });
  const edits = [
    {
      name: encode(windows ? "process_set" : "PROCESS_SET"),
      value: raw("changed-"),
    },
    { name: encode("PROCESS_REMOVE"), value: null },
    { name: raw("PROCESS_EDIT_"), value: raw("value-") },
    { name: raw("PROCESS_REMOVE_RAW_"), value: null },
  ];
  const argumentsToCheck = [
    encode(descriptor),
    raw("arg-"),
    encode(""),
    encode("space and\ttab"),
    encode('a"quote\\'),
    encode("trailing slash \\"),
    windows ? Buffer.from([0xff, 0xdf]) : Buffer.from([0xff, 0x80]),
  ];
  const inspect = run([encode("inspect"), ...argumentsToCheck], {
    environment: edits,
  });
  const fields = Object.fromEntries(
    success(inspect)
      .toString()
      .trim()
      .split("\n")
      .map((line) => line.split("=")),
  );
  assert.equal(fields["cwd"], directory.toString("hex"));
  for (const [index, arg] of argumentsToCheck.entries())
    assert.equal(fields[`arg${index}`], arg.toString("hex"));
  assert.equal(fields["inherited"], raw("inherited-").toString("hex"));
  assert.equal(fields["set"], raw("changed-").toString("hex"));
  assert.equal(fields["removed"], "true");
  assert.equal(fields["edited"], raw("value-").toString("hex"));
  assert.equal(fields["removedRaw"], "true");
  assert.equal(fields["closed"], "true");
  if (!windows) assert.equal(fields["signals"], "true");
  const explicit = run([encode("inspect"), encode(descriptor)], {
    cwd: directory,
  });
  assert.equal(
    Object.fromEntries(
      success(explicit)
        .toString()
        .trim()
        .split("\n")
        .map((line) => line.split("=")),
    )["cwd"],
    directory.toString("hex"),
  );
  assert.deepEqual(
    success(run([encode("input")], { input: null })),
    inheritedInput,
  );
  assert.deepEqual(success(run([encode("input")])), Buffer.alloc(0));
  const input = Buffer.alloc(1_048_577, 0xfe);
  const flood = run([encode("flood")], { input });
  assert.deepEqual(
    success(flood),
    Buffer.concat([Buffer.alloc(262_144, 65), input]),
  );
  assert.deepEqual(flood.stderr, Buffer.alloc(262_144, 66));
  assert.equal(success(run([encode("exit")], { input }), 7).length, 0);
  assert.equal(
    success(run([encode("signal")]), windows ? 4_294_967_295 : -15).length,
    0,
  );
  const missing = run([], {
    program: encode(join(root, "missing-executable")),
  });
  assert.equal(missing.error, windows ? 2 : constants.errno.ENOENT);
  assert.equal(missing.returnCode, null);
  assert.equal(missing.stdout.length + missing.stderr.length, 0);
  const cwdError = run([], { cwd: encode(join(root, "missing-directory")) });
  assert.equal(cwdError.error, windows ? 267 : constants.errno.ENOENT);
  assert.throws(() => run([windows ? Buffer.from([0, 0]) : Buffer.from([0])]));
  if (windows) assert.throws(() => run([Buffer.from([1])]));
  assert.throws(() =>
    run([], {
      environment: [{ name: encode("bad=name"), value: encode("value") }],
    }),
  );

  const first = join(root, "process-search-first");
  const second = join(root, "process-search-second");
  mkdirSync(first);
  mkdirSync(second);
  const name = `process-search${windows ? ".exe" : ""}`;
  copyFileSync(fixture, join(second, name));
  if (windows) {
    // CreateProcess does not use the replacement environment's PATH or child cwd for lookup.
    const request = {
      program: encode(name),
      cwd: encode(second),
      environment: [{ name: encode("PATH"), value: encode(second) }],
    };
    assert.equal(run([encode("exit")], request).error, 2);
    assert.equal(
      success(
        run([encode("exit")], {
          program: encode(join(second, name)),
          cwd: directory,
        }),
        7,
      ).length,
      0,
    );
    const batch = join(root, "process-batch.cmd");
    writeFileSync(batch, "@exit /b 9\r\n");
    assert.equal(success(run([], { program: encode(batch) }), 9).length, 0);
  } else {
    writeFileSync(join(first, name), "exit 99\n", { mode: 0o755 });
    const search = (path: string): Partial<ProcessRequest> => ({
      program: encode(name),
      environment: [{ name: encode("PATH"), value: encode(path) }],
    });
    assert.equal(run([], search(first)).error, constants.errno.ENOEXEC);
    assert.equal(
      success(run([encode("exit")], search(`${first}${delimiter}${second}`)), 7)
        .length,
      0,
    );
    chmodSync(join(first, name), 0o644);
    assert.equal(run([], search(first)).error, constants.errno.EACCES);
    assert.equal(
      success(run([encode("exit")], search(`${first}${delimiter}${second}`)), 7)
        .length,
      0,
    );
    assert.equal(
      success(run([encode("exit")], { ...search(""), cwd: encode(second) }), 7)
        .length,
      0,
    );
    assert.equal(
      success(
        run([encode("exit")], {
          program: encode(`.${sep}${name}`),
          cwd: encode(second),
        }),
        7,
      ).length,
      0,
    );
    const defaultPath = run([encode("-c"), encode("exit 11")], {
      program: encode("sh"),
      environment: [{ name: encode("PATH"), value: null }],
    });
    assert.equal(success(defaultPath, 11).length, 0);
  }
  return {
    fixture: basename(fixture),
    rawArgumentsAndCwd: true,
    rawEnvironmentEdits: true,
    inheritedAndEmptyInput: true,
    concurrentBytePipes: true,
    earlyInputClose: true,
    inheritedDescriptorsClosed: true,
    restoredSignals: !windows,
    exitAndSpawnCodes: true,
    executableSearch: true,
  };
}

if (process.argv[2] === "process-worker")
  console.log(JSON.stringify(worker(process.argv[3]!, process.argv[4]!)));
