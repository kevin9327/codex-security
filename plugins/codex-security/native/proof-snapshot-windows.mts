import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
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
// Recorded from CPython 3.12.10 / SQLite 3.49.1 on Windows x64 and arm64.
// Both architectures produced identical results for these exact cases.
const expected: Result[] = [
  {
    name: "ordinary",
    status: 0,
    rows: [[41, "sealed"]],
    files: ["seed.sqlite3", "snapshot.sqlite3", "source.sqlite3"],
  },
  {
    name: "unicode",
    status: 0,
    rows: [[41, "sealed"]],
    files: [
      "seed.sqlite3",
      "snapshot.sqlite3",
      "source # percent% \u6771\u4eac.sqlite3",
    ],
  },
  {
    name: "source-0",
    status: 1,
    rows: null,
    files: ["seed.sqlite3", "source-\ud800.sqlite3"],
  },
  {
    name: "destination-0",
    status: 1,
    rows: null,
    files: ["seed.sqlite3", "source.sqlite3"],
  },
  {
    name: "source-1",
    status: 1,
    rows: null,
    files: ["seed.sqlite3", "source-\udc80.sqlite3"],
  },
  {
    name: "destination-1",
    status: 1,
    rows: null,
    files: ["seed.sqlite3", "source.sqlite3"],
  },
  {
    name: "source-2",
    status: 1,
    rows: null,
    files: ["seed.sqlite3", "source-\udfff.sqlite3"],
  },
  {
    name: "destination-2",
    status: 1,
    rows: null,
    files: ["seed.sqlite3", "source.sqlite3"],
  },
  {
    name: "home",
    status: 0,
    rows: [[41, "sealed"]],
    files: ["nested/snapshot.sqlite3", "seed.sqlite3", "source.sqlite3"],
  },
  {
    name: "verbatim",
    status: 1,
    rows: null,
    files: ["seed.sqlite3", "source.sqlite3"],
  },
];

export function snapshotWindowsProof(helper: string): void {
  const native = createRequire(import.meta.url)(binaryPath) as SqliteBinding;
  const windows = loadWindowsBinding();
  const files = windowsFileSystem(windows);
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
