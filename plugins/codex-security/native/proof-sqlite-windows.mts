import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, win32 } from "node:path";
import { pathToFileURL } from "node:url";
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
// Recorded from CPython 3.12.10 / SQLite 3.49.1 on Windows x64 and arm64.
// Both architectures produced identical results for these exact cases.
const expected: Result[] = [
  {
    name: "ordinary",
    error: null,
    files: ["data.sqlite3"],
  },
  {
    name: "unicode",
    error: null,
    files: ["unicode-\ud83d\udd10-\u6771\u4eac.sqlite3"],
  },
  {
    name: "high",
    error: null,
    files: ["raw-\ufffd\ufffd.sqlite3"],
  },
  {
    name: "low",
    error: null,
    files: ["raw-\ufffd\ufffd.sqlite3"],
  },
  {
    name: "tail",
    error: null,
    files: ["raw-\ufffd\ufffd.sqlite3"],
  },
  {
    name: "parent",
    error: 14,
    files: [],
  },
  {
    name: "verbatim",
    error: null,
    files: ["data.sqlite3"],
  },
  {
    name: "long",
    error: null,
    files: ["data.sqlite3"],
  },
  {
    name: "uri",
    error: null,
    files: ["uri-# space.sqlite3"],
  },
  {
    name: "uri-disabled",
    error: 14,
    files: [],
  },
];

export function windowsSqliteProof(native: SqliteBinding): number {
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
    assert.deepEqual(results, expected);
    return results.length;
  } finally {
    remove(root);
  }
}
