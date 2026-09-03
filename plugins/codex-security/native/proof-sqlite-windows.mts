import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, win32 } from "node:path";
import { pathToFileURL } from "node:url";
import { output } from "./binding.mjs";
import { Connection, type SqliteBinding } from "./sqlite.mjs";
import { loadWindowsBinding } from "./windows-binding.mjs";
import { pathText, widePath, windowsFileSystem } from "./windows-files.mjs";

const cases = [
  { name: "ordinary", relative: "data.sqlite3" },
  { name: "unicode", relative: "unicode-🔐-東京.sqlite3" },
  { name: "high", relative: "raw-\ud800.sqlite3" },
  { name: "low", relative: "raw-\udc80.sqlite3" },
  { name: "tail", relative: "raw-\udfff.sqlite3" },
  { name: "parent", relative: "raw-\ud800\\data.sqlite3" },
  { name: "verbatim", relative: "data.sqlite3", verbatim: true },
  { name: "long", relative: "segment\\".repeat(40) + "data.sqlite3" },
  { name: "uri", relative: "uri-# space.sqlite3", uri: true },
  { name: "uri-disabled", relative: "uri-disabled.sqlite3", uriName: true },
];
interface Result {
  name: string;
  error: number | null;
  files: string[];
}
interface Oracle {
  python: string;
  sqlite: string;
  results: Result[];
}
const oraclePath = join(output, "sqlite-windows-oracle.json");

export function prepareWindowsOracle(): void {
  assert.equal(process.platform, "win32");
  // Temporary migration parity preparation; retire this after recording Windows results.
  const oracle = execFileSync(
    "python",
    [
      "-c",
      String.raw`
import json, sqlite3, sys, tempfile
from contextlib import closing
from pathlib import Path
results = []
with tempfile.TemporaryDirectory(prefix="codex-sqlite-oracle-") as root:
    for case in json.loads(sys.stdin.buffer.read()):
        path = Path(root, case["name"], case["relative"])
        path.parent.mkdir(parents=True)
        value = path.as_uri() if case.get("uri") or case.get("uriName") else str(path)
        if case.get("verbatim"):
            value = "\\\\?\\" + value
        error = None
        try:
            with closing(sqlite3.connect(value, uri=case.get("uri", False))) as db:
                db.execute("CREATE TABLE probe(value)")
                db.execute("INSERT INTO probe VALUES(1)")
                db.commit()
        except sqlite3.Error as failure:
            error = failure.sqlite_errorcode & 255
        results.append(dict(name=case["name"], error=error, files=sorted(p.name for p in path.parent.iterdir())))
print(json.dumps(dict(python=sys.version.split()[0], sqlite=sqlite3.sqlite_version, results=results)))
`,
    ],
    { input: JSON.stringify(cases), encoding: "utf8" },
  );
  writeFileSync(oraclePath, oracle);
  console.log(oracle.trim());
}

export function windowsSqliteProof(native: SqliteBinding): number {
  const expected = JSON.parse(readFileSync(oraclePath, "utf8")) as Oracle;
  const files = windowsFileSystem(loadWindowsBinding());
  const root = mkdtempSync(join(tmpdir(), "codex-sqlite-paths-"));
  const results: Result[] = [];
  function remove(path: string): void {
    const encoded = widePath(path);
    if (files.stat(encoded).isDirectory())
      for (const child of files.entriesWithTypes(encoded))
        remove(join(path, pathText(child.name)));
    files.unlink(encoded);
  }
  try {
    for (const spec of cases) {
      const path = join(root, spec.name, spec.relative);
      const parent = dirname(path);
      files.mkdir(widePath(parent));
      const value =
        spec.uri || spec.uriName
          ? pathToFileURL(path).href
          : spec.verbatim
            ? win32.toNamespacedPath(path)
            : path;
      let error: number | null = null;
      try {
        const db = new Connection(native, value, { uri: spec.uri });
        try {
          db.exec("CREATE TABLE probe(value); INSERT INTO probe VALUES(1)");
          assert.equal(db.prepare("SELECT value FROM probe").get()!.get(0), 1n);
        } finally {
          db.close();
        }
      } catch (failure) {
        const code = (failure as { sqliteErrorCode?: number }).sqliteErrorCode;
        if (code === undefined) throw failure;
        error = code;
      }
      results.push({
        name: spec.name,
        error,
        files: files
          .entriesWithTypes(widePath(parent))
          .map((entry) => pathText(entry.name))
          .sort(),
      });
    }
    assert.deepEqual(results, expected.results);
    return results.length;
  } finally {
    remove(root);
  }
}
