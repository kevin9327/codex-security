import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { output } from "./binding.mjs";
import { gitRecord } from "./proof-inventory-windows.mjs";
import { loadWindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";

export function worklistsWindowsProof(helper: string): void {
  const git = JSON.parse(readFileSync(gitRecord, "utf8")) as string;
  const files = windowsFileSystem(loadWindowsBinding());
  const root = mkdtempSync(join(tmpdir(), "worklists-proof-"));
  const repository = join(root, "repository 東京");
  const destination = join(root, "出力.jsonl");
  const scopesFile = join(root, "scopes-\udfff.json");
  const transport = join(root, "arguments.bin");
  files.mkdir(widePath(join(repository, "src")));
  const write = (name: string, contents: string | Buffer) =>
    files.writeFile(
      widePath(join(repository, name)),
      typeof contents === "string" ? Buffer.from(contents) : contents,
    );
  const scopes = (paths: string[]) => {
    files.writeFile(widePath(scopesFile), Buffer.from(JSON.stringify(paths)));
    return ["--scopes-file", scopesFile];
  };
  const run = (command: string, args: string[] = [], path = "") => {
    writeFileSync(
      transport,
      widePath(
        [
          "--helper",
          command,
          "--repo",
          repository,
          "--out",
          destination,
          ...args,
          "",
        ].join("\0"),
      ),
    );
    return spawnSync(
      join(output, "windows-wide-launcher.exe"),
      [process.execPath, helper, transport, "command"],
      {
        encoding: "utf8",
        maxBuffer: Infinity,
        timeout: 30_000,
        env: {
          ...process.env,
          PATH: path,
          PYTHON: join(root, "missing-python"),
        },
      },
    );
  };
  const rows = () => {
    const bytes = files.readFile(widePath(destination));
    assert.ok(bytes.every((byte) => byte < 128));
    return bytes
      .toString("ascii")
      .trimEnd()
      .split("\r\n")
      .filter(Boolean)
      .map((row) => JSON.parse(row) as { path: string; preview?: string });
  };
  const success = (result: ReturnType<typeof run>) => {
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.ok(result.stdout.includes(destination), result.stdout);
  };
  const previous = Buffer.from("previous\r\n");
  const preserve = (
    command: string,
    args: string[],
    message: string,
    path = "",
  ) => {
    files.writeFile(widePath(destination), previous);
    const result = run(command, args, path);
    assert.equal(result.status, 1, result.stderr);
    assert.ok(result.stderr.includes(message), result.stderr);
    assert.deepEqual(files.readFile(widePath(destination)), previous);
  };
  const command = (...args: string[]) =>
    execFileSync(
      git,
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        ...args,
      ],
      {
        cwd: repository,
        encoding: "utf8",
        env: { ...process.env, PATH: dirname(git) },
      },
    ).trim();
  try {
    const source = "Write-Output 'café 😀'\n";
    const encoded = Buffer.from(source, "utf16le");
    write("src/東京.ps1", Buffer.concat([Buffer.from([255, 254]), encoded]));
    write("src/raw-\ud800.py", "value = 1\n");
    write("src/binary.ps1", "text\0binary");
    success(run("make-repo-rank-input"));
    assert.deepEqual(
      rows().map((row) => [row.path, row.preview]),
      [
        ["src/raw-\ud800.py", "value = 1"],
        ["src/東京.ps1", source.trim()],
      ],
    );
    success(run("make-repo-scope-input", scopes(["src"])));
    assert.deepEqual(
      rows().map((row) => row.path),
      ["src/binary.ps1", "src/raw-\ud800.py", "src/東京.ps1"],
    );
    success(run("make-repo-rank-input", scopes(["src/binary.ps1"])));
    assert.equal(rows()[0]!.preview, "");
    preserve(
      "make-repo-rank-input",
      ["--scope", "src/東京.ps1:stream"],
      "alternate data stream",
    );
    preserve(
      "make-repo-scope-input",
      scopes(["src/東京.ps1:stream"]),
      "alternate data stream",
    );
    symlinkSync(join(repository, "src"), join(repository, "alias"), "junction");
    preserve(
      "make-repo-scope-input",
      scopes(["alias/東京.ps1"]),
      "must not contain symbolic links",
    );
    files.unlink(widePath(join(repository, "alias")));
    files.unlink(widePath(join(repository, "src/raw-\ud800.py")));
    command("init", "-q");
    command("add", ".");
    command("commit", "-qm", "Base");
    const base = command("rev-parse", "HEAD");
    write(
      "src/東京.ps1",
      Buffer.concat([Buffer.from([254, 255]), Buffer.from(encoded).swap16()]),
    );
    write("src/added.py", "added = True\n");
    files.unlink(widePath(join(repository, "src/binary.ps1")));
    command("add", ".");
    command("commit", "-qm", "Selected changes");
    const head = command("rev-parse", "HEAD");
    command("checkout", "-q", base);
    success(
      run(
        "make-diff-rank-input",
        ["--base", base, "--head", head],
        dirname(git),
      ),
    );
    assert.deepEqual(
      rows().map((row) => [row.path, row.preview]),
      [
        ["src/added.py", "added = True"],
        ["src/binary.ps1", ""],
        ["src/東京.ps1", source.trim()],
      ],
    );
    preserve(
      "make-diff-rank-input",
      ["--base", "missing"],
      "missing",
      dirname(git),
    );
    write("bad.json", '{"\\ud800":1}');
    preserve(
      "make-repo-rank-input",
      [],
      "UTF-8 cannot encode an unpaired surrogate",
    );
    files.unlink(widePath(join(repository, "bad.json")));
    files.writeFile(widePath(destination), previous);
    files.chmod(widePath(destination), 0o400);
    try {
      assert.equal(run("make-repo-rank-input").status, 1);
      assert.deepEqual(files.readFile(widePath(destination)), previous);
    } finally {
      files.chmod(widePath(destination), 0o600);
    }
    console.log(JSON.stringify({ worklistWindowsCases: 10 }));
  } finally {
    const remove = (path: string): void => {
      const encoded = widePath(path),
        info = files.stat(encoded, false);
      if (info.isDirectory() && !info.isReparsePoint())
        for (const entry of files.entriesWithTypes(encoded))
          remove(join(path, pathText(entry.name)));
      files.chmod(encoded, 0o700);
      files.unlink(encoded);
    };
    remove(root);
  }
}
