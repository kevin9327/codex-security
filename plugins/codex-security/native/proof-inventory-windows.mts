import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { output } from "./binding.mjs";
import { loadWindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";

export const gitRecord = join(output, "inventory-git.json");
export function prepareInventoryWindows(): void {
  const git = execFileSync("where.exe", ["git"], { encoding: "utf8" })
    .trim()
    .split(/\r?\n/u)[0]!;
  writeFileSync(gitRecord, JSON.stringify(git));
}

/** Exercise real Git and wide filesystem paths after Python is removed from PATH. */
export function inventoryWindowsProof(helper: string): void {
  const git = JSON.parse(readFileSync(gitRecord, "utf8")) as string;
  const files = windowsFileSystem(loadWindowsBinding());
  const root = mkdtempSync(join(tmpdir(), "inventory-proof-"));
  const repository = join(root, "repository 東京");
  const destination = join(root, "output-\ud800", "inventory-\udfff.txt");
  const transport = join(root, "arguments.bin");
  const environment = { ...process.env, PATH: dirname(git) };
  files.mkdir(widePath(repository));
  files.mkdir(widePath(dirname(destination)));
  const write = (name: string, bytes: Buffer) =>
    files.writeFile(widePath(join(repository, name)), bytes);
  const command = (...args: string[]) =>
    execFileSync(
      git,
      [
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.com",
        ...args,
      ],
      { cwd: repository, env: environment, encoding: "utf8" },
    ).trim();
  const run = (args: string[], path = environment.PATH) => {
    writeFileSync(
      transport,
      widePath(
        [
          "--helper",
          "generate-in-scope-files",
          "--repo",
          repository,
          "--scope",
          ".",
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
        env: { ...environment, PATH: path },
        timeout: 30_000,
      },
    );
  };
  const previous = Buffer.from("previous.py\n");
  const preserve = (args: string[], expected: string, path?: string) => {
    files.writeFile(widePath(destination), previous);
    const result = run(args, path);
    assert.equal(result.status, 2, result.stderr);
    assert.ok(result.stderr.includes(expected), result.stderr);
    assert.deepEqual(files.readFile(widePath(destination)), previous);
    assert.deepEqual(
      files
        .entriesWithTypes(widePath(dirname(destination)))
        .map((entry) => pathText(entry.name)),
      ["inventory-\udfff.txt"],
    );
  };
  try {
    command("init", "-q");
    command("commit", "--allow-empty", "-qm", "base");
    const base = command("rev-parse", "HEAD");
    const text = Buffer.from("Write-Output 'café 😀'\n", "utf16le");
    write("東京.ps1", Buffer.concat([Buffer.from([255, 254]), text]));
    write(
      "big-endian.ps1",
      Buffer.concat([Buffer.from([254, 255]), Buffer.from(text).swap16()]),
    );
    write("binary.ps1", Buffer.from("text\0binary"));
    write(
      "decoded-nul.ps1",
      Buffer.concat([
        Buffer.from([255, 254]),
        Buffer.from("text\0binary", "utf16le"),
      ]),
    );
    for (const mode of ["local-patch", "revisions"]) {
      if (mode === "revisions") {
        command("add", ".");
        command("commit", "-qm", "encoded source");
      }
      files.writeFile(widePath(destination), previous);
      const result = run(["--diff-base", base, "--diff-mode", mode]);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
      assert.equal(
        files.readFile(widePath(destination)).toString("utf8"),
        "big-endian.ps1\n東京.ps1\n",
      );
    }
    preserve(
      ["--diff-base", "missing"],
      "could not resolve the selected Git changes",
    );
    preserve([], "could not run ripgrep", "");
    preserve(["--scope", "東京.ps1:stream"], "NTFS alternate data streams");
    write("broken.json", Buffer.from('{"\\ud800":1}'));
    preserve(
      ["--diff-base", "HEAD", "--diff-mode", "local-patch"],
      "UTF-8 cannot encode an unpaired surrogate",
    );
    files.unlink(widePath(join(repository, "broken.json")));
    files.writeFile(widePath(destination), previous);
    files.chmod(widePath(destination), 0o400);
    try {
      const result = run(["--diff-base", base]);
      assert.equal(result.status, 2, result.stderr);
      assert.deepEqual(files.readFile(widePath(destination)), previous);
      assert.deepEqual(
        files
          .entriesWithTypes(widePath(dirname(destination)))
          .map((entry) => pathText(entry.name)),
        ["inventory-\udfff.txt"],
      );
    } finally {
      files.chmod(widePath(destination), 0o600);
    }
    console.log(JSON.stringify({ inventoryWindowsCases: 7 }));
  } finally {
    const remove = (path: string): void => {
      const encoded = widePath(path);
      if (files.stat(encoded).isDirectory())
        for (const entry of files.entriesWithTypes(encoded))
          remove(join(path, pathText(entry.name)));
      files.chmod(encoded, 0o700);
      files.unlink(encoded);
    };
    remove(root);
  }
}
