import { setTimeout as sleep } from "node:timers/promises";

/** INTEGER remains bigint; REAL remains number, including integral REAL values. */
export type SqlValue = null | bigint | number | string | Buffer;
export type Parameter = SqlValue | boolean;
export type Parameters =
  | readonly Parameter[]
  | Readonly<Record<string, Parameter>>;
interface NativeStatement {
  readonly columns: string[];
  readonly parameterNames: (string | null)[];
  bind(values: SqlValue[]): void;
  step(): SqlValue[] | null;
  finalize(): void;
}
interface NativeBackup {
  step(pages: number): { status: number; remaining: number; pageCount: number };
  finish(): void;
}
interface NativeConnection {
  readonly inTransaction: boolean;
  readonly changes: bigint;
  readonly lastInsertRowid: bigint;
  close(): void;
  limit(category: number, value: number): number;
  busyTimeout(milliseconds: number): void;
  exec(sql: string): void;
  prepare(sql: string): NativeStatement;
  backup(destination: NativeConnection): NativeBackup;
  function(
    name: string,
    arguments_: number,
    deterministic: boolean,
    callback: (args: SqlValue[]) => SqlValue,
  ): void;
}
export interface SqliteBinding {
  SqliteConnection: new (
    filename: Buffer,
    readOnly: boolean,
    uri: boolean,
  ) => NativeConnection;
  completeStatement(sql: string): boolean;
  sqliteVersion(): string;
}
export function filenameBytes(
  value: string,
  windows = process.platform === "win32",
): Buffer {
  const pieces: Buffer[] = [];
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) {
      if (windows)
        pieces.push(
          Buffer.from([
            0xe0 | (point >> 12),
            0x80 | ((point >> 6) & 63),
            0x80 | (point & 63),
          ]),
        );
      else if (point >= 0xdc80 && point <= 0xdcff)
        pieces.push(Buffer.from([point - 0xdc00]));
      else throw new TypeError("Filesystem path cannot be encoded as UTF-8");
    } else pieces.push(Buffer.from(character));
  }
  return Buffer.concat(pieces);
}
export function completeStatement(native: SqliteBinding, sql: string): boolean {
  return native.completeStatement(text(sql));
}
function text(value: string): string {
  if (Buffer.from(value, "utf8").toString("utf8") !== value)
    throw new TypeError("SQLite strings must be valid UTF-8");
  return value;
}
function parameter(value: Parameter): SqlValue {
  if (typeof value === "string") return text(value);
  if (typeof value === "boolean") return value ? 1n : 0n;
  return value;
}
const asciiLower = (value: string) =>
  value.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
export class Row {
  constructor(
    readonly columns: readonly string[],
    readonly values: readonly SqlValue[],
  ) {}
  get(name: string | number): SqlValue {
    const index =
      typeof name === "number"
        ? name < 0
          ? this.values.length + name
          : name
        : this.columns.findIndex(
            (column) => asciiLower(column) === asciiLower(name),
          );
    if (!Number.isInteger(index) || index < 0 || index >= this.values.length)
      throw new RangeError("No such SQLite row column");
    return this.values[index]!;
  }
  toObject(): Record<string, SqlValue> {
    return Object.fromEntries(
      this.columns.map((column) => [column, this.get(column)]),
    );
  }
}
// CPython's legacy mode begins only INSERT/UPDATE/DELETE/REPLACE, after comments.
function isDml(sql: string): boolean {
  const leading = sql.replace(
    /^(?:[\t\n\v\f\r ]+|--[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)+/,
    "",
  );
  return /^(?:insert|update|delete|replace)\b/i.test(leading);
}
export class Statement {
  constructor(
    private readonly owner: Connection,
    readonly sql: string,
  ) {}
  private open(parameters: Parameters): NativeStatement {
    const statement = this.owner.raw.prepare(text(this.sql));
    try {
      if (
        this.owner.legacyTransactions &&
        isDml(this.sql) &&
        !this.owner.inTransaction
      )
        this.owner.raw.exec("BEGIN");
      const names = statement.parameterNames;
      const values = Array.isArray(parameters)
        ? parameters
        : names.map((name) => {
            if (name === null)
              throw new TypeError("Positional parameters require an array");
            const key = name.slice(1);
            if (!Object.hasOwn(parameters, key))
              throw new TypeError(`Missing SQLite parameter ${key}`);
            return (parameters as Readonly<Record<string, Parameter>>)[key]!;
          });
      statement.bind(values.map(parameter));
      return statement;
    } catch (error) {
      statement.finalize();
      throw error;
    }
  }
  *iterate(parameters: Parameters = []): Generator<Row> {
    const statement = this.open(parameters);
    try {
      for (;;) {
        const values = statement.step();
        if (values === null) return;
        yield new Row(statement.columns, values);
      }
    } finally {
      statement.finalize();
    }
  }
  all(parameters: Parameters = []): Row[] {
    return [...this.iterate(parameters)];
  }
  get(parameters: Parameters = []): Row | undefined {
    for (const row of this.iterate(parameters)) return row;
    return undefined;
  }
  run(parameters: Parameters = []): { rowcount: bigint; lastrowid: bigint } {
    for (const _ of this.iterate(parameters)) {
      /* Consume RETURNING rows. */
    }
    return {
      rowcount: isDml(this.sql) ? this.owner.raw.changes : -1n,
      lastrowid: this.owner.raw.lastInsertRowid,
    };
  }
}
export class Connection {
  readonly raw: NativeConnection;
  constructor(
    native: SqliteBinding,
    filename: string | Buffer,
    readonly options: {
      readOnly?: boolean;
      uri?: boolean;
      legacyTransactions?: boolean;
    } = {},
  ) {
    this.raw = new native.SqliteConnection(
      typeof filename === "string" ? filenameBytes(filename) : filename,
      options.readOnly ?? false,
      options.uri ?? false,
    );
    try {
      this.raw.busyTimeout(5000);
      this.raw.exec("PRAGMA foreign_keys=OFF");
    } catch (error) {
      this.raw.close();
      throw error;
    }
  }
  get legacyTransactions(): boolean {
    return this.options.legacyTransactions ?? true;
  }
  get inTransaction(): boolean {
    return this.raw.inTransaction;
  }
  get variableLimit(): number {
    // SQLITE_LIMIT_VARIABLE_NUMBER; a negative value reads the current limit.
    return this.raw.limit(9, -1);
  }
  close(): void {
    this.raw.close();
  }
  prepare(sql: string): Statement {
    return new Statement(this, sql);
  }
  exec(sql: string): void {
    this.raw.exec(text(sql));
  }
  commit(): void {
    if (this.inTransaction) this.raw.exec("COMMIT");
  }
  rollback(): void {
    if (this.inTransaction) this.raw.exec("ROLLBACK");
  }
  transaction<T>(
    callback: () => T &
      (Extract<T, PromiseLike<unknown>> extends never ? unknown : never),
  ): T {
    try {
      const value = callback();
      if (
        value !== null &&
        (typeof value === "object" || typeof value === "function") &&
        "then" in value &&
        typeof value.then === "function"
      )
        throw new TypeError(
          "SQLite transactions require a synchronous callback",
        );
      this.commit();
      return value;
    } catch (error) {
      this.rollback();
      throw error;
    }
  }
  function(
    name: string,
    arity: number,
    deterministic: boolean,
    callback: (...args: SqlValue[]) => Parameter,
  ): void {
    this.raw.function(text(name), arity, deterministic, (args) =>
      parameter(callback(...args)),
    );
  }
  async backup(destination: Connection): Promise<void> {
    const operation = this.raw.backup(destination.raw);
    try {
      for (;;) {
        const result = operation.step(-1);
        if (result.status === 101) return;
        if (result.status === 5 || result.status === 6) await sleep(250);
      }
    } finally {
      operation.finish();
    }
  }
}
