// SPDX-License-Identifier: MIT
// Copyright (c) 2021 Taneli Hukkinen
// Adapted from CPython 3.12.13 Lib/tomllib (_parser.py and _re.py).
// See scripts/licenses/TOMLI-MIT.txt. Preserve TOML 1.0 and its diagnostics.
import { JsonFloat, objectFromEntries, pythonRepr } from "./python-json.js";

export class TomlDecodeError extends Error {}

export class TomlDate {
  constructor(
    readonly kind: "date" | "datetime" | "time",
    readonly iso: string,
  ) {}
}

type Table = Map<string, Value>;
type Value = string | boolean | bigint | JsonFloat | TomlDate | Value[] | Table;
type Key = string[];
type Flag = "frozen" | "explicit";
interface FlagNode {
  flags: Set<Flag>;
  recursive: Set<Flag>;
  nested: Map<string, FlagNode>;
}

class Flags {
  readonly nodes = new Map<string, FlagNode>();
  readonly pending: Key[] = [];

  finalize(): void {
    for (const key of this.pending) this.set(key, "explicit");
    this.pending.length = 0;
  }

  unset(key: Key): void {
    let nodes = this.nodes;
    for (const part of key.slice(0, -1)) {
      const node = nodes.get(part);
      if (!node) return;
      nodes = node.nested;
    }
    nodes.delete(key.at(-1)!);
  }

  set(key: Key, flag: Flag, recursive = false): void {
    let nodes = this.nodes;
    for (let index = 0; index < key.length; index++) {
      const part = key[index]!;
      let node = nodes.get(part);
      if (!node) {
        node = { flags: new Set(), recursive: new Set(), nested: new Map() };
        nodes.set(part, node);
      }
      if (index === key.length - 1)
        (recursive ? node.recursive : node.flags).add(flag);
      nodes = node.nested;
    }
  }

  has(key: Key, flag: Flag): boolean {
    let nodes = this.nodes;
    for (let index = 0; index < key.length; index++) {
      const node = nodes.get(key[index]!);
      if (!node) return false;
      if (node.recursive.has(flag)) return true;
      if (index === key.length - 1) return node.flags.has(flag);
      nodes = node.nested;
    }
    return false;
  }
}

function nest(table: Table, key: Key, accessLists = true): Table {
  for (const part of key) {
    if (!table.has(part)) table.set(part, new Map());
    let value = table.get(part);
    if (accessLists && Array.isArray(value)) value = value.at(-1);
    if (!(value instanceof Map)) throw new Error("Cannot overwrite a value");
    table = value;
  }
  return table;
}

const whitespace = new Set(" \t");
const arrayWhitespace = new Set(" \t\n");
const bare = new Set(
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
);
const keyStart = new Set([...bare, '"', "'"]);
const escapes = new Map([
  ["b", "\b"],
  ["t", "\t"],
  ["n", "\n"],
  ["f", "\f"],
  ["r", "\r"],
  ['"', '"'],
  ["\\", "\\"],
]);
const timePattern =
  "([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\\.([0-9]{1,6})[0-9]*)?";
const localTime = new RegExp(timePattern, "y");
const dateTime = new RegExp(
  "([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])" +
    "(?:[Tt ]" +
    timePattern +
    "(?:([Zz])|([+-])([01][0-9]|2[0-3]):([0-5][0-9]))?)?",
  "y",
);
const numberPattern =
  /0(?:x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*|b[01](?:_?[01])*|o[0-7](?:_?[0-7])*)|[+-]?(?:0|[1-9](?:_?[0-9])*)((?:\.[0-9](?:_?[0-9])*)?(?:[eE][+-]?[0-9](?:_?[0-9])*)?)/y;

function integer(source: string): bigint {
  const clean = source.replaceAll("_", "");
  const digits = clean.replace(/^[+-]/u, "");
  if (!/^0[xob]/u.test(digits) && digits.length > 4300)
    throw new Error(
      `Exceeds the limit (4300 digits) for integer string conversion: value has ${digits.length} digits; use sys.set_int_max_str_digits() to increase the limit`,
    );
  return BigInt(clean);
}

function tuple(key: Key): string {
  return `(${key.map(pythonRepr).join(", ")}${key.length === 1 ? "," : ""})`;
}

function illegal(char: string, multiline = false): boolean {
  const code = char.charCodeAt(0);
  return (
    (code < 32 || code === 127) &&
    char !== "\t" &&
    !(multiline && char === "\n")
  );
}

function materialize(table: Table): Record<string, unknown> {
  const root = objectFromEntries(table);
  const pending: (Record<string, unknown> | unknown[])[] = [root];
  while (pending.length) {
    const parent = pending.pop()!;
    for (const [key, child] of Object.entries(parent)) {
      const value =
        child instanceof Map
          ? objectFromEntries(child)
          : Array.isArray(child)
            ? [...child]
            : null;
      if (value === null) continue;
      if (Array.isArray(parent)) parent[Number(key)] = value;
      else parent[key] = value;
      pending.push(value);
    }
  }
  return root;
}

export function parseToml(
  text: string,
  parseInteger: (source: string) => bigint = integer,
): Record<string, unknown> {
  const src = text.replaceAll("\r\n", "\n");
  const data: Table = new Map();
  const flags = new Flags();
  let header: Key = [];

  function error(pos: number, message: string): never {
    const before = src.slice(0, pos);
    const coordinate =
      pos >= src.length
        ? "end of document"
        : `line ${before.split("\n").length}, column ${Array.from(before.slice(before.lastIndexOf("\n") + 1)).length + 1}`;
    throw new TomlDecodeError(`${message} (at ${coordinate})`);
  }

  function skip(pos: number, chars = whitespace): number {
    while (pos < src.length && chars.has(src[pos]!)) pos++;
    return pos;
  }

  function until(
    pos: number,
    expected: string,
    multiline = false,
    eofError = true,
  ): number {
    let end = src.indexOf(expected, pos);
    if (end === -1) {
      end = src.length;
      if (eofError) error(end, `Expected ${pythonRepr(expected)}`);
    }
    while (pos < end) {
      if (illegal(src[pos]!, multiline))
        error(pos, `Found invalid character ${pythonRepr(src[pos])}`);
      pos++;
    }
    return end;
  }

  function comment(pos: number): number {
    return src[pos] === "#" ? until(pos + 1, "\n", false, false) : pos;
  }

  function arraySpace(pos: number): number {
    while (true) {
      const before = pos;
      pos = comment(skip(pos, arrayWhitespace));
      if (before === pos) return pos;
    }
  }

  function escape(pos: number, multiline: boolean): [number, string] {
    const point = src.codePointAt(pos + 1);
    const char = point === undefined ? undefined : String.fromCodePoint(point);
    pos += 1 + (char?.length ?? 1);
    if (multiline && char !== undefined && arrayWhitespace.has(char)) {
      if (char !== "\n") {
        pos = skip(pos);
        if (pos === src.length) return [pos, ""];
        if (src[pos] !== "\n") error(pos, "Unescaped '\\' in a string");
        pos++;
      }
      return [skip(pos, arrayWhitespace), ""];
    }
    if (char === "u" || char === "U") {
      const length = char === "u" ? 4 : 8;
      const hex = src.slice(pos, pos + length);
      if (hex.length !== length || !/^[0-9a-fA-F]+$/u.test(hex))
        error(pos, "Invalid hex value");
      pos += length;
      const point = Number.parseInt(hex, 16);
      if ((point >= 0xd800 && point <= 0xdfff) || point > 0x10ffff)
        error(pos, "Escaped character is not a Unicode scalar value");
      return [pos, String.fromCodePoint(point)];
    }
    if (char !== undefined && escapes.has(char))
      return [pos, escapes.get(char)!];
    return error(pos, "Unescaped '\\' in a string");
  }

  function basicString(pos: number, multiline: boolean): [number, string] {
    let result = "";
    let start = pos;
    while (true) {
      const char = src[pos];
      if (char === undefined) error(pos, "Unterminated string");
      if (char === '"') {
        if (!multiline) return [pos + 1, result + src.slice(start, pos)];
        if (src.startsWith('"""', pos))
          return [pos + 3, result + src.slice(start, pos)];
        pos++;
      } else if (char === "\\") {
        result += src.slice(start, pos);
        const parsed = escape(pos, multiline);
        pos = parsed[0];
        result += parsed[1];
        start = pos;
      } else {
        if (illegal(char, multiline))
          error(pos, `Illegal character ${pythonRepr(char)}`);
        pos++;
      }
    }
  }

  function literalString(pos: number): [number, string] {
    const start = pos + 1;
    const end = until(start, "'");
    return [end + 1, src.slice(start, end)];
  }

  function multilineString(pos: number, literal: boolean): [number, string] {
    pos += 3;
    if (src[pos] === "\n") pos++;
    let result: string;
    const delim = literal ? "'" : '"';
    if (literal) {
      const end = until(pos, "'''", true);
      result = src.slice(pos, end);
      pos = end + 3;
    } else [pos, result] = basicString(pos, true);
    for (let count = 0; count < 2 && src[pos] === delim; count++, pos++)
      result += delim;
    return [pos, result];
  }

  function keyPart(pos: number): [number, string] {
    const char = src[pos];
    if (char !== undefined && bare.has(char)) {
      const end = skip(pos, bare);
      return [end, src.slice(pos, end)];
    }
    if (char === "'") return literalString(pos);
    if (char === '"') return basicString(pos + 1, false);
    return error(pos, "Invalid initial character for a key part");
  }

  function key(pos: number): [number, Key] {
    let part: string;
    [pos, part] = keyPart(pos);
    const result = [part];
    pos = skip(pos);
    while (src[pos] === ".") {
      [pos, part] = keyPart(skip(pos + 1));
      result.push(part);
      pos = skip(pos);
    }
    return [pos, result];
  }

  function pair(pos: number): [number, Key, Value] {
    const parsedKey = key(pos);
    pos = parsedKey[0];
    if (src[pos] !== "=")
      error(pos, "Expected '=' after a key in a key/value pair");
    const parsedValue = value(skip(pos + 1));
    return [parsedValue[0], parsedKey[1], parsedValue[1]];
  }

  function array(pos: number): [number, Value[]] {
    const result: Value[] = [];
    pos = arraySpace(pos + 1);
    if (src[pos] === "]") return [pos + 1, result];
    while (true) {
      const parsed = value(pos);
      result.push(parsed[1]);
      pos = arraySpace(parsed[0]);
      if (src[pos] === "]") return [pos + 1, result];
      if (src[pos] !== ",") error(pos, "Unclosed array");
      pos = arraySpace(pos + 1);
      if (src[pos] === "]") return [pos + 1, result];
    }
  }

  function getNest(
    table: Table,
    path: Key,
    pos: number,
    accessLists = true,
  ): Table {
    try {
      return nest(table, path, accessLists);
    } catch {
      return error(pos, "Cannot overwrite a value");
    }
  }

  function inlineTable(pos: number): [number, Table] {
    const result: Table = new Map();
    const inlineFlags = new Flags();
    pos = skip(pos + 1);
    if (src[pos] === "}") return [pos + 1, result];
    while (true) {
      let path: Key;
      let child: Value;
      [pos, path, child] = pair(pos);
      if (inlineFlags.has(path, "frozen"))
        error(pos, `Cannot mutate immutable namespace ${tuple(path)}`);
      const parent = getNest(result, path.slice(0, -1), pos, false);
      const stem = path.at(-1)!;
      if (parent.has(stem))
        error(pos, `Duplicate inline table key ${pythonRepr(stem)}`);
      parent.set(stem, child);
      pos = skip(pos);
      if (src[pos] === "}") return [pos + 1, result];
      if (src[pos] !== ",") error(pos, "Unclosed inline table");
      if (child instanceof Map || Array.isArray(child))
        inlineFlags.set(path, "frozen", true);
      pos = skip(pos + 1);
    }
  }

  function floating(source: string): JsonFloat {
    const clean = source.replaceAll("_", "");
    const numeric = clean.endsWith("inf")
      ? clean[0] === "-"
        ? -Infinity
        : Infinity
      : Number(clean);
    return new JsonFloat(Object.is(numeric, -0) ? "-0.0" : String(numeric));
  }

  function clock(parts: (string | undefined)[]): string {
    const micros = parts[3]?.padEnd(6, "0") ?? "000000";
    return `${parts[0]}:${parts[1]}:${parts[2]}${micros === "000000" ? "" : `.${micros}`}`;
  }

  function value(pos: number): [number, Value] {
    const char = src[pos];
    if (char === '"')
      return src.startsWith('"""', pos)
        ? multilineString(pos, false)
        : basicString(pos + 1, false);
    if (char === "'")
      return src.startsWith("'''", pos)
        ? multilineString(pos, true)
        : literalString(pos);
    if (src.startsWith("true", pos)) return [pos + 4, true];
    if (src.startsWith("false", pos)) return [pos + 5, false];
    if (char === "[") return array(pos);
    if (char === "{") return inlineTable(pos);
    dateTime.lastIndex = pos;
    const date = dateTime.exec(src);
    if (date) {
      const year = Number(date[1]);
      const month = Number(date[2]);
      const day = Number(date[3]);
      const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
      const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
      if (year === 0 || day > days[month - 1]!)
        error(pos, "Invalid date or datetime");
      let iso = `${date[1]}-${date[2]}-${date[3]}`;
      if (date[4] !== undefined) {
        iso += `T${clock(date.slice(4, 8))}`;
        if (date[9])
          iso +=
            Number(date[10]) === 0 && Number(date[11]) === 0
              ? "+00:00"
              : `${date[9]}${date[10]}:${date[11]}`;
        else if (date[8]) iso += "+00:00";
      }
      return [
        dateTime.lastIndex,
        new TomlDate(date[4] === undefined ? "date" : "datetime", iso),
      ];
    }
    localTime.lastIndex = pos;
    const time = localTime.exec(src);
    if (time)
      return [localTime.lastIndex, new TomlDate("time", clock(time.slice(1)))];
    numberPattern.lastIndex = pos;
    const numeric = numberPattern.exec(src);
    if (numeric)
      return [
        numberPattern.lastIndex,
        numeric[1] ? floating(numeric[0]) : parseInteger(numeric[0]),
      ];
    const special = /^[+-]?(?:inf|nan)/u.exec(src.slice(pos));
    if (special) return [pos + special[0].length, floating(special[0])];
    return error(pos, "Invalid value");
  }

  let pos = 0;
  while (true) {
    pos = skip(pos);
    const char = src[pos];
    if (char === undefined) break;
    if (char === "\n") {
      pos++;
      continue;
    }
    if (keyStart.has(char)) {
      let path: Key;
      let child: Value;
      [pos, path, child] = pair(pos);
      for (let index = 1; index < path.length; index++) {
        const container = [...header, ...path.slice(0, index)];
        if (flags.has(container, "explicit"))
          error(pos, `Cannot redefine namespace ${tuple(container)}`);
        flags.pending.push(container);
      }
      const parentPath = [...header, ...path.slice(0, -1)];
      if (flags.has(parentPath, "frozen"))
        error(pos, `Cannot mutate immutable namespace ${tuple(parentPath)}`);
      const parent = getNest(data, parentPath, pos);
      const stem = path.at(-1)!;
      if (parent.has(stem)) error(pos, "Cannot overwrite a value");
      if (child instanceof Map || Array.isArray(child))
        flags.set([...header, ...path], "frozen", true);
      parent.set(stem, child);
      pos = skip(pos);
    } else if (char === "[") {
      flags.finalize();
      const list = src[pos + 1] === "[";
      [pos, header] = key(skip(pos + (list ? 2 : 1)));
      if (list) {
        if (flags.has(header, "frozen"))
          error(pos, `Cannot mutate immutable namespace ${tuple(header)}`);
        flags.unset(header);
        flags.set(header, "explicit");
        const parent = getNest(data, header.slice(0, -1), pos);
        const stem = header.at(-1)!;
        if (!parent.has(stem)) parent.set(stem, []);
        const array = parent.get(stem);
        if (!Array.isArray(array)) error(pos, "Cannot overwrite a value");
        array.push(new Map());
        if (!src.startsWith("]]", pos))
          error(pos, "Expected ']]' at the end of an array declaration");
        pos += 2;
      } else {
        if (flags.has(header, "explicit") || flags.has(header, "frozen"))
          error(pos, `Cannot declare ${tuple(header)} twice`);
        flags.set(header, "explicit");
        getNest(data, header, pos);
        if (src[pos] !== "]")
          error(pos, "Expected ']' at the end of a table declaration");
        pos++;
      }
      pos = skip(pos);
    } else if (char !== "#") error(pos, "Invalid statement");
    pos = comment(pos);
    if (pos >= src.length) break;
    if (src[pos] !== "\n")
      error(pos, "Expected newline or end of document after a statement");
    pos++;
  }
  return materialize(data);
}
