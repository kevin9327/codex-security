import assert from "node:assert/strict";
import { fork, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  rmSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { binaryPath } from "./binding.mjs";
import {
  prepareWindowsOracle,
  windowsSqliteProof,
} from "./proof-sqlite-windows.mjs";
import { setTimeout as sleep } from "node:timers/promises";
import {
  Connection,
  completeStatement,
  filenameBytes,
  type SqliteBinding,
  type Parameter,
} from "./sqlite.mjs";

const script = fileURLToPath(import.meta.url);
const native = createRequire(import.meta.url)(binaryPath) as SqliteBinding;
const open = (
  filename: string | Buffer,
  options?: ConstructorParameters<typeof Connection>[2],
) => new Connection(native, filename, options);
if (process.argv[2] === "windows-oracle") {
  prepareWindowsOracle();
} else if (process.argv[2] === "writer" || process.argv[2] === "lock") {
  const db = open(process.argv[3]!);
  if (process.argv[2] === "lock") {
    db.exec("BEGIN IMMEDIATE");
    process.send?.({ locked: true });
    await sleep(150);
    db.commit();
    db.close();
    process.disconnect();
  } else {
    let stopped = false,
      generation = 0;
    process.on("message", () => {
      stopped = true;
    });
    while (!stopped) {
      db.exec("BEGIN IMMEDIATE");
      db.prepare("UPDATE paired SET generation = ?").run([
        BigInt(++generation),
      ]);
      db.commit();
      process.send?.({ generation });
      await sleep(1);
    }
    db.close();
    process.disconnect();
  }
} else {
  const root = mkdtempSync(join(tmpdir(), "codex-sqlite-proof-"));
  const source = join(root, "source.sqlite3");
  const db = open(source);
  const children: ChildProcess[] = [];
  const sqliteCode = (code: number) => (error: unknown) =>
    (error as { sqliteErrorCode?: number }).sqliteErrorCode === code;
  const value = (db: Connection, sql: string, parameters: Parameter[] = []) =>
    db.prepare(sql).get(parameters)!.get(0);
  async function start(role: string, filename: string): Promise<ChildProcess> {
    const child = fork(script, [role, filename], {
      execPath: process.execPath,
      env: { ...process.env, PATH: "" },
      stdio: ["ignore", "ignore", "inherit", "ipc"],
    });
    children.push(child);
    await new Promise<void>((resolve, reject) => {
      child.once("message", () => resolve());
      child.once("error", reject);
      child.once("exit", (code) => {
        if (code) reject(new Error(`worker ${role} exited ${code}`));
      });
    });
    return child;
  }
  try {
    assert.equal(value(db, "PRAGMA foreign_keys"), 0n);
    assert.equal(value(db, "PRAGMA busy_timeout"), 5000n);
    db.exec(
      "PRAGMA foreign_keys=ON; BEGIN IMMEDIATE; CREATE TABLE migrations(version INTEGER PRIMARY KEY, label TEXT); INSERT INTO migrations VALUES(1,'initial'); CREATE TABLE parent(id TEXT PRIMARY KEY); CREATE TABLE child(parent TEXT REFERENCES parent(id), value BLOB); CREATE TABLE paired(id INTEGER PRIMARY KEY, generation INTEGER); INSERT INTO paired VALUES(1,0),(2,0); CREATE TABLE implicit_rows(value TEXT); INSERT INTO implicit_rows(rowid,value) VALUES(10,'first'),(90,'second'); CREATE TABLE text_key_rows(id TEXT PRIMARY KEY,value TEXT); INSERT INTO text_key_rows(rowid,id,value) VALUES(12,'a','A'),(95,'b','B'); CREATE TABLE padding(id INTEGER PRIMARY KEY, value BLOB); PRAGMA user_version=41; PRAGMA application_id=314159; COMMIT;",
    );
    assert.equal(value(db, "PRAGMA journal_mode=WAL"), "wal");
    assert.throws(
      () =>
        db
          .prepare("INSERT INTO child VALUES(?,?)")
          .run(["absent", Buffer.from("blob")]),
      sqliteCode(19),
    );
    assert.equal(db.inTransaction, true);
    db.rollback();
    db.prepare("INSERT INTO parent VALUES(?)").run(["implicit"]);
    assert.equal(db.inTransaction, true);
    db.rollback();
    assert.equal(value(db, "SELECT count(*) FROM parent"), 0n);
    db.transaction(() => {
      db.prepare("INSERT INTO parent VALUES(?)").run(["kept"]);
    });
    assert.throws(() =>
      db.transaction(() => {
        db.prepare("INSERT INTO parent VALUES(?)").run(["rolled-back"]);
        throw new Error("rollback");
      }),
    );
    assert.equal(value(db, "SELECT count(*) FROM parent"), 1n);
    for (const [sql, expected, type] of [
      ["SELECT CAST(1 AS REAL)", 1, "real"],
      ["SELECT 1", 1n, "integer"],
    ] as const) {
      const result = value(db, sql);
      assert.equal(result, expected);
      assert.equal(value(db, "SELECT typeof(?)", [result]), type);
    }
    assert.equal(value(db, "SELECT typeof(?)", [true]), "integer");
    if (false) {
      // @ts-expect-error Transaction callbacks cannot return a Promise.
      db.transaction(async () => 1);
    }
    const asynchronous = () => {
      db.prepare("INSERT INTO parent VALUES('async-rollback')").run();
      return Promise.resolve(1);
    };
    assert.throws(
      () => db.transaction(asynchronous as unknown as () => number),
      /require a synchronous callback/,
    );
    assert.equal(db.inTransaction, false);
    assert.equal(
      value(db, "SELECT count(*) FROM parent WHERE id='async-rollback'"),
      0n,
    );
    db.exec(
      "BEGIN; SAVEPOINT inner_tx; INSERT INTO parent VALUES('savepoint'); ROLLBACK TO inner_tx; RELEASE inner_tx; COMMIT;",
    );
    assert.equal(value(db, "SELECT count(*) FROM parent"), 1n);
    const update = db
      .prepare("UPDATE parent SET id=id WHERE id=?")
      .run(["kept"]);
    assert.equal(update.rowcount, 1n);
    db.commit();
    assert.equal(
      db.prepare("UPDATE parent SET id=id WHERE id=?").run(["missing"])
        .rowcount,
      0n,
    );
    db.commit();
    const row = db
      .prepare(
        "SELECT ? AS Number, ? AS Number, ? AS Blob, ? AS EmptyBlob, ? AS Text, NULL AS Missing, ? AS Float",
      )
      .get([
        9223372036854775807n,
        -9223372036854775808n,
        Buffer.from([0, 255, 128]),
        Buffer.alloc(0),
        "a\0b Ω",
        1.25,
      ])!;
    assert.equal(row.get("number"), 9223372036854775807n);
    assert.equal(row.get(1), -9223372036854775808n);
    assert.deepEqual(row.get("blob"), Buffer.from([0, 255, 128]));
    assert.deepEqual(row.get("emptyblob"), Buffer.alloc(0));
    assert.equal(row.get("text"), "a\0b Ω");
    assert.equal(row.get("missing"), null);
    assert.equal(row.get(-1), 1.25);
    assert.throws(() => row.get(0.5), /No such SQLite row column/);
    assert.throws(() => db.prepare("SELECT ?").get([9223372036854775808n]));
    assert.throws(() => db.prepare("SELECT ?").get(["\ud800"]));
    assert.throws(() => db.prepare("SELECT cast(x'ff' as text)").get());
    assert.equal(value(db, "SELECT typeof(?)", [Buffer.alloc(0)]), "blob");
    assert.equal(
      db
        .prepare("SELECT :name AS value, :name AS again")
        .get({ name: "named" })!
        .get("again"),
      "named",
    );
    assert.throws(() => db.prepare("SELECT ?").get([]));
    assert.throws(() => db.prepare("SELECT 1; SELECT 2").get());
    assert.equal(
      value(db, "SELECT json_extract('{\"value\":3}', '$.value')"),
      3n,
    );
    assert.equal(
      completeStatement(
        native,
        "CREATE TRIGGER t AFTER INSERT ON parent BEGIN SELECT ';'; END;",
      ),
      true,
    );
    assert.equal(
      completeStatement(
        native,
        "CREATE TRIGGER t AFTER INSERT ON parent BEGIN SELECT ';';",
      ),
      false,
    );
    db.function("normalize_key", 1, true, (input) =>
      String(input).toLowerCase(),
    );
    assert.equal(value(db, "SELECT normalize_key(?)", ["ABC"]), "abc");
    db.function("exact_integer", 1, true, (input) => input);
    assert.equal(
      value(db, "SELECT exact_integer(?)", [9223372036854775807n]),
      9223372036854775807n,
    );
    db.function("empty_blob", 0, true, () => Buffer.alloc(0));
    assert.equal(value(db, "SELECT typeof(empty_blob())"), "blob");
    db.function("failure", 0, false, () => {
      throw new Error("private callback error");
    });
    assert.throws(() => value(db, "SELECT failure()"), sqliteCode(1));
    assert.equal(value(db, "SELECT 7"), 7n);
    const conflict = open(source);
    conflict.raw.busyTimeout(0);
    db.exec("BEGIN IMMEDIATE");
    try {
      assert.throws(
        () => conflict.prepare("INSERT INTO parent VALUES('locked')").run(),
        sqliteCode(5),
      );
      conflict.rollback();
    } finally {
      db.rollback();
    }
    conflict.prepare("INSERT INTO parent VALUES('released')").run();
    conflict.commit();
    conflict.close();
    const lock = await start("lock", source);
    const started = Date.now();
    db.prepare("INSERT INTO parent VALUES('waited')").run();
    db.commit();
    assert.ok(Date.now() - started >= 50);
    await new Promise<void>((resolve) =>
      lock.exitCode !== null ? resolve() : lock.once("exit", () => resolve()),
    );
    db.transaction(() => {
      const insert = db.prepare("INSERT INTO padding(value) VALUES(?)");
      for (let i = 0; i < 256; i++) insert.run([Buffer.alloc(4096, 65)]);
    });
    db.prepare("DELETE FROM padding WHERE id>16").run();
    db.commit();
    const freePages = value(db, "PRAGMA freelist_count");
    assert.equal(typeof freePages, "bigint");
    assert.ok((freePages as bigint) > 0n);
    const ro = open(source, { readOnly: true });
    assert.throws(
      () => ro.prepare("INSERT INTO parent VALUES('readonly')").run(),
      sqliteCode(8),
    );
    ro.rollback();
    const writer = await start("writer", source);
    let generation = 0;
    writer.on("message", (message: { generation: number }) => {
      generation = message.generation;
    });
    let snapshots = 0;
    try {
      for (let index = 0; index < 20; index++) {
        const target = join(root, `snapshot-${index}.sqlite3`),
          dest = open(target);
        dest.exec(
          "CREATE TABLE old(value); INSERT INTO old VALUES('replace me');",
        );
        await ro.backup(dest);
        dest.close();
        const standalone = join(root, `standalone-${index}.sqlite3`);
        copyFileSync(target, standalone);
        const copy = open(standalone, { readOnly: true });
        try {
          const paired = copy
            .prepare(
              "SELECT min(generation) AS low,max(generation) AS high,count(*) AS n FROM paired",
            )
            .get()!;
          assert.equal(paired.get("n"), 2n);
          assert.equal(paired.get("low"), paired.get("high"));
          assert.equal(value(copy, "PRAGMA integrity_check"), "ok");
          assert.equal(value(copy, "PRAGMA user_version"), 41n);
          assert.equal(value(copy, "PRAGMA application_id"), 314159n);
          assert.equal(
            value(copy, "SELECT count(*) FROM sqlite_master WHERE name='old'"),
            0n,
          );
          assert.equal(value(copy, "PRAGMA freelist_count"), freePages);
          assert.deepEqual(
            copy
              .prepare("SELECT rowid,value FROM implicit_rows ORDER BY rowid")
              .all()
              .map((r) => r.values),
            [
              [10n, "first"],
              [90n, "second"],
            ],
          );
          assert.deepEqual(
            copy
              .prepare(
                "SELECT rowid,id,value FROM text_key_rows ORDER BY rowid",
              )
              .all()
              .map((r) => r.values),
            [
              [12n, "a", "A"],
              [95n, "b", "B"],
            ],
          );
          snapshots++;
        } finally {
          copy.close();
        }
      }
      await sleep(10);
      assert.ok(generation > 0);
      assert.ok(statSync(source + "-wal").size > 0);
    } finally {
      ro.close();
    }
    const target = join(root, "busy-destination.sqlite3"),
      dest = open(target);
    dest.exec("CREATE TABLE old(value)");
    dest.raw.busyTimeout(0);
    await start("lock", target);
    const backupStarted = Date.now();
    await db.backup(dest);
    assert.ok(Date.now() - backupStarted >= 200);
    dest.close();
    const lifecycle = open(":memory:");
    let recursive: ReturnType<typeof lifecycle.raw.prepare>;
    lifecycle.function("recursive_close", 0, false, () => {
      recursive.finalize();
      return null;
    });
    recursive = lifecycle.raw.prepare("SELECT recursive_close()");
    assert.throws(() => recursive.step(), sqliteCode(1));
    try {
      recursive.finalize();
    } catch (error) {
      assert(sqliteCode(1)(error));
    }
    lifecycle.function("connection_close", 0, false, () => {
      lifecycle.close();
      return null;
    });
    assert.throws(
      () => value(lifecycle, "SELECT connection_close()"),
      sqliteCode(1),
    );
    assert.equal(value(lifecycle, "SELECT 1"), 1n);
    lifecycle.exec("CREATE TABLE test(value)");
    const statement = lifecycle.raw.prepare("SELECT 1");
    lifecycle.close();
    assert.throws(() => statement.step());
    statement.finalize();
    lifecycle.close();
    if (process.platform === "linux") {
      const rawPath = Buffer.concat([
        Buffer.from(join(root, "raw-")),
        Buffer.from([255]),
        Buffer.from(".sqlite3"),
      ]);
      const rawDb = open(rawPath);
      rawDb.exec("CREATE TABLE x(value)");
      rawDb.close();
      assert.ok(existsSync(rawPath));
      const rawString = open(join(root, "raw-\udcff.sqlite3"));
      assert.equal(
        value(rawString, "SELECT count(*) FROM sqlite_master WHERE name='x'"),
        1n,
      );
      rawString.close();
    }
    assert.equal(filenameBytes("\ud800", true).toString("hex"), "eda080");
    assert.equal(filenameBytes("\udcff", false).toString("hex"), "ff");
    const uriName =
      pathToFileURL(join(root, "uri.sqlite3")).href + "?mode=memory";
    assert.throws(() => open(uriName), sqliteCode(14));
    const uriDb = open(uriName, { uri: true });
    uriDb.close();
    const windowsPaths =
      process.platform === "win32" ? windowsSqliteProof(native) : undefined;
    const report = {
      node: process.version,
      sqlite: native.sqliteVersion(),
      nodeApi: process.versions["napi"],
      pythonOnRuntimePath: false,
      transactions: true,
      implicitDmlRollback: true,
      savepoints: true,
      rowcount: true,
      rowsAndInt64: true,
      blobs: true,
      utf8Failures: true,
      foreignKeys: true,
      busyTimeout: true,
      crossProcessBusyWait: true,
      scalarFunctions: true,
      readOnly: true,
      concurrentWalSnapshots: snapshots,
      writerGeneration: generation,
      replacedNonemptyDestination: true,
      implicitAndIndexedRowidsPreserved: true,
      freelistPreserved: true,
      standaloneSnapshots: true,
      backupBusyRetry: true,
      closedConnectionLifetime: true,
      rawPosixFilename: process.platform === "linux",
      windowsPaths,
      numericTypes: true,
      synchronousTransactions: true,
    };
    console.log(JSON.stringify(report));
  } finally {
    for (const child of children) {
      if (child.connected) child.send("stop");
    }
    await Promise.all(
      children.map(
        (child) =>
          new Promise<void>((resolve) =>
            child.exitCode !== null || child.signalCode !== null
              ? resolve()
              : child.once("exit", () => resolve()),
          ),
      ),
    );
    db.close();
    rmSync(root, { recursive: true, force: true });
  }
}
