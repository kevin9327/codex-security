import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { binaryPath, output } from "./binding.mjs";
import { Connection, type SqliteBinding } from "./sqlite.mjs";
import { loadWindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";

const cases = [
  {
    name: "ordinary",
    source: "source.sqlite3",
    destination: "snapshot.sqlite3",
  },
  {
    name: "unicode",
    source: "source # percent% 東京.sqlite3",
    destination: "snapshot.sqlite3",
  },
  ...["\ud800", "\udc80", "\udfff"].flatMap((unit, index) => [
    {
      name: `source-${index}`,
      source: `source-${unit}.sqlite3`,
      destination: "snapshot.sqlite3",
    },
    {
      name: `destination-${index}`,
      source: "source.sqlite3",
      destination: `directory-${unit}\\snapshot-${unit}.sqlite3`,
    },
  ]),
  {
    name: "home",
    source: "source.sqlite3",
    destination: "nested\\snapshot.sqlite3",
    home: true,
  },
  {
    name: "verbatim",
    source: "source.sqlite3",
    destination: "snapshot.sqlite3",
    verbatim: true,
  },
];
interface Result {
  name: string;
  status: number;
  rows: unknown;
  files: string[];
}
const oraclePath = join(output, "snapshot-windows-oracle.json");

export function prepareSnapshotOracle(): void {
  const result = spawnSync(
    "python",
    [
      "-c",
      String.raw`
import json, os, shutil, sqlite3, sys, tempfile
from pathlib import Path
from contextlib import closing
results = []
with tempfile.TemporaryDirectory(prefix="snapshot-oracle-") as base:
    for spec in json.loads(sys.stdin.buffer.read()):
        root = Path(base, spec["name"]); root.mkdir()
        seed = root / "seed.sqlite3"
        with closing(sqlite3.connect(seed)) as db:
            db.execute("CREATE TABLE records(value TEXT)")
            db.execute("INSERT INTO records(rowid,value) VALUES(41,'sealed')")
            db.commit()
        source = root / spec["source"]; destination = root / spec["destination"]
        shutil.copyfile(seed, source)
        source_arg, destination_arg = str(source), str(destination)
        if spec.get("home"):
            os.environ["USERPROFILE"] = str(root)
            source_arg, destination_arg = "~/"+spec["source"], "~/"+spec["destination"]
        if spec.get("verbatim"):
            source_arg, destination_arg = "\\\\?\\"+source_arg, "\\\\?\\"+destination_arg
        status = 0
        try:
            source_path = Path(source_arg).expanduser().resolve(strict=True)
            destination_path = Path(destination_arg).expanduser().absolute()
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True) as reader:
                with sqlite3.connect(destination_path) as writer:
                    reader.backup(writer)
            destination_path.chmod(0o600)
        except (OSError, ValueError, sqlite3.Error): status = 1
        finally:
            if "writer" in locals(): writer.close(); del writer
            if "reader" in locals(): reader.close(); del reader
        rows = None
        if status == 0:
            with closing(sqlite3.connect(destination)) as db:
                rows = db.execute("SELECT rowid,value FROM records").fetchall()
        results.append(dict(name=spec["name"], status=status, rows=rows, files=sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())))
print(json.dumps(results))
`,
    ],
    { input: JSON.stringify(cases), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  writeFileSync(oraclePath, result.stdout);
  console.log(result.stdout.trim());
}

export function snapshotWindowsProof(helper: string): void {
  const native = createRequire(import.meta.url)(binaryPath) as SqliteBinding;
  const windows = loadWindowsBinding();
  const files = windowsFileSystem(windows);
  const expected = JSON.parse(readFileSync(oraclePath, "utf8")) as Result[];
  const base = mkdtempSync(join(tmpdir(), "snapshot-proof-"));
  const results: Result[] = [];
  const relativeFiles = (root: string, prefix = ""): string[] =>
    files.entriesWithTypes(widePath(root)).flatMap((entry) => {
      const name = pathText(entry.name),
        path = join(root, name);
      return files.stat(widePath(path)).isDirectory()
        ? relativeFiles(path, `${prefix}${name}/`)
        : [`${prefix}${name}`];
    });
  try {
    const modePath = widePath(join(base, "mode-\ud800"));
    files.writeFile(modePath, Buffer.from("mode fixture"));
    const attributes = () => {
      const opened = windows.openWindowsFile(modePath, 0, 7, 3, 0);
      assert.equal(opened.error, 0);
      try {
        return opened.handle!.attributes().attributes;
      } finally {
        assert.equal(opened.handle!.close(), 0);
      }
    };
    const before = attributes();
    files.chmod(modePath, 0o400);
    assert.equal(attributes(), before | 1);
    files.chmod(modePath, 0o600);
    assert.equal(attributes(), before & ~1);
    assert.throws(() => files.chmod(widePath(join(base, "missing")), 0o600));
    const transport = join(base, "arguments.bin");
    for (const spec of cases) {
      const root = join(base, spec.name);
      files.mkdir(widePath(root));
      const seed = join(root, "seed.sqlite3");
      const db = new Connection(native, seed);
      db.exec(
        "CREATE TABLE records(value TEXT); INSERT INTO records(rowid,value) VALUES(41,'sealed')",
      );
      db.close();
      const source = join(root, spec.source),
        destination = join(root, spec.destination);
      files.writeFile(widePath(source), files.readFile(widePath(seed)));
      const argument = (path: string, relative: string) =>
        "home" in spec
          ? `~/${relative}`
          : "verbatim" in spec
            ? win32.toNamespacedPath(path)
            : path;
      writeFileSync(
        transport,
        widePath(
          [
            "--helper",
            "snapshot-sqlite",
            argument(source, spec.source),
            argument(destination, spec.destination),
            "",
          ].join("\0"),
        ),
      );
      const result = spawnSync(
        join(output, "windows-wide-launcher.exe"),
        [process.execPath, helper, transport, "command"],
        {
          cwd: root,
          env: { ...process.env, USERPROFILE: root, PATH: "" },
          encoding: "utf8",
          timeout: 10_000,
        },
      );
      assert.equal(result.stdout, "");
      if (result.status === 0) assert.equal(result.stderr, "");
      let rows: unknown = null;
      if (result.status === 0) {
        const copied = new Connection(native, destination, { readOnly: true });
        try {
          rows = copied
            .prepare("SELECT rowid,value FROM records")
            .all()
            .map((row) => [Number(row.get(0)), row.get(1)]);
        } finally {
          copied.close();
        }
      }
      results.push({
        name: spec.name,
        status: result.status!,
        rows,
        files: relativeFiles(root).sort(),
      });
    }
    assert.deepEqual(results, expected);
    console.log(JSON.stringify({ snapshotWindowsCases: results.length }));
  } finally {
    const remove = (path: string): void => {
      const encoded = widePath(path);
      if (files.stat(encoded).isDirectory())
        for (const entry of files.entriesWithTypes(encoded))
          remove(join(path, pathText(entry.name)));
      files.unlink(encoded);
    };
    remove(base);
  }
}
