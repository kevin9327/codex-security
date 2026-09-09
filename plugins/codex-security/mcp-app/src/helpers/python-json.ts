import { decodePythonUtf8, UnicodeDecodeError } from "./utf8";
import otherCategory from "@unicode/unicode-15.0.0/General_Category/Other/regex.js";
import separatorCategory from "@unicode/unicode-15.0.0/General_Category/Separator/regex.js";
import { TomlDate } from "./toml-date.js";

// Preserve Python's integer/float distinction and arbitrary-size JSON integers.
export class JsonFloat {
  constructor(readonly source: string) {}
}

type Row = Record<string, unknown>;
const keyOrder = new WeakMap<Row, string[]>();
export function object(value: unknown): value is Row {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof JsonFloat) &&
    !(value instanceof TomlDate)
  );
}
export function objectEntries(value: Row): [string, unknown][] {
  const keys = new Set([...(keyOrder.get(value) ?? []), ...Object.keys(value)]);
  return [...keys]
    .filter((key) => Object.hasOwn(value, key))
    .map((key) => [key, value[key]]);
}

export function objectFromEntries(
  entries: Iterable<readonly [string, unknown]>,
): Row {
  const row = Object.create(null) as Row;
  const keys = new Set<string>();
  for (const [key, value] of entries) {
    row[key] = value;
    keys.add(key);
  }
  keyOrder.set(row, [...keys]);
  return row;
}

export function copyJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(copyJson);
  if (object(value))
    return objectFromEntries(
      objectEntries(value).map(([key, child]) => [key, copyJson(child)]),
    );
  return value;
}

/** Update a parsed object with Python's insertion order, including numeric keys. */
export function assignJson(target: Row, source: Row): void {
  const keys = new Set(objectEntries(target).map(([key]) => key));
  for (const [key, value] of objectEntries(source)) {
    target[key] = value;
    keys.add(key);
  }
  keyOrder.set(target, [...keys]);
}

// Retain the original JSON mapping operations: missing fields must not become SQL NULL.
export function jsonTypeName(value: unknown): string {
  if (value === null) return "NoneType";
  if (Array.isArray(value)) return "list";
  if (value instanceof JsonFloat || typeof value === "number") return "float";
  if (typeof value === "bigint") return "int";
  if (typeof value === "boolean") return "bool";
  return typeof value === "string" ? "str" : "dict";
}
export function jsonGet(
  value: unknown,
  key: string,
  fallback: unknown = null,
): unknown {
  if (!object(value))
    throw new TypeError(
      `'${jsonTypeName(value)}' object has no attribute 'get'`,
    );
  return Object.hasOwn(value, key) ? value[key] : fallback;
}
export function jsonItem(value: unknown, key: string): unknown {
  if (object(value)) {
    if (!Object.hasOwn(value, key)) throw new Error(pythonRepr(key));
    return value[key];
  }
  if (Array.isArray(value))
    throw new TypeError("list indices must be integers or slices, not str");
  if (typeof value === "string")
    throw new TypeError("string indices must be integers, not 'str'");
  throw new TypeError(`'${jsonTypeName(value)}' object is not subscriptable`);
}
export function jsonContains(value: unknown, key: string): boolean {
  if (object(value)) return Object.hasOwn(value, key);
  if (Array.isArray(value)) return value.includes(key);
  if (typeof value === "string") return value.includes(key);
  throw new TypeError(
    `argument of type '${jsonTypeName(value)}' is not iterable`,
  );
}
// json.dumps(..., ensure_ascii=True, indent=2), with compact persistence support.
export function stringifyJson(
  value: unknown,
  options: {
    compact?: boolean;
    allowNan?: boolean;
    sortKeys?: boolean;
    separators?: readonly [string, string];
  } = {},
): string {
  const quote = (text: string) =>
    JSON.stringify(text).replace(
      /[\u007f-\uffff]/g,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
  function encode(item: unknown, depth: number): string {
    if (item instanceof TomlDate)
      throw new TypeError(
        `Object of type ${item.kind} is not JSON serializable`,
      );
    if (typeof item === "string") return quote(item);
    if (item instanceof JsonFloat) {
      const number = Number(item.source);
      if (options.allowNan === false && !Number.isFinite(number))
        throw new Error(
          `Out of range float values are not JSON compliant: ${pythonRepr(item)}`,
        );
      if (Number.isNaN(number)) return "NaN";
      if (!Number.isFinite(number))
        return number < 0 ? "-Infinity" : "Infinity";
      return pythonRepr(item);
    }
    if (
      options.allowNan === false &&
      typeof item === "number" &&
      !Number.isFinite(item)
    )
      throw new Error(
        `Out of range float values are not JSON compliant: ${pythonRepr(new JsonFloat(String(item)))}`,
      );
    if (typeof item === "bigint") return String(item);
    if (Array.isArray(item) || object(item)) {
      const array = Array.isArray(item);
      const entries = array
        ? item.map((child) => encode(child, depth + 1))
        : (options.sortKeys
            ? objectEntries(item).sort(([a], [b]) => {
                const left = Array.from(a, (c) => c.codePointAt(0)!);
                const right = Array.from(b, (c) => c.codePointAt(0)!);
                for (let i = 0; i < Math.min(left.length, right.length); i++)
                  if (left[i] !== right[i]) return left[i]! - right[i]!;
                return left.length - right.length;
              })
            : objectEntries(item)
          ).map(
            ([key, child]) =>
              `${quote(key)}${options.separators?.[1] ?? ": "}${encode(child, depth + 1)}`,
          );
      const [open, close] = array ? ["[", "]"] : ["{", "}"];
      if (entries.length === 0) return open + close;
      if (options.compact)
        return open + entries.join(options.separators?.[0] ?? ", ") + close;
      const prefix = "  ".repeat(depth + 1);
      return `${open}\n${prefix}${entries.join(`${options.separators?.[0] ?? ","}\n${prefix}`)}\n${"  ".repeat(depth)}${close}`;
    }
    return JSON.stringify(item);
  }
  return encode(value, 0);
}

export class JsonSyntaxError extends Error {}

export function pythonValueError(message: string): Error {
  return Object.assign(new Error(message), { name: "ValueError" });
}

// json.loads(bytes) detects UTF-8/16/32 and decodes with surrogatepass.
export function parseJsonBytes(
  bytes: Buffer,
  rejectDuplicates = false,
  parseInteger?: (source: string) => bigint,
  parseConstant?: (source: string) => unknown,
): unknown {
  let width = 1;
  let little = true;
  let offset = 0;
  const prefix = bytes.subarray(0, 4).toString("hex");
  if (prefix === "fffe0000" || prefix === "0000feff") {
    width = 4;
    little = prefix === "fffe0000";
    offset = 4;
  } else if (prefix.startsWith("fffe") || prefix.startsWith("feff")) {
    width = 2;
    little = prefix.startsWith("fffe");
    offset = 2;
  } else if (prefix.startsWith("efbbbf")) {
    offset = 3;
  } else if (bytes.length >= 4) {
    if (bytes[0] === 0) {
      width = bytes[1] === 0 ? 4 : 2;
      little = false;
    } else if (bytes[1] === 0) {
      width = bytes[2] || bytes[3] ? 2 : 4;
    }
  } else if (bytes.length === 2 && (bytes[0] === 0 || bytes[1] === 0)) {
    width = 2;
    little = bytes[0] !== 0;
  }
  let text = "";
  if (width === 1) {
    text = decodePythonUtf8(bytes.subarray(offset), true);
  } else {
    const encoding = `utf-${width * 8}-${little ? "le" : "be"}`;
    for (let index = offset; index < bytes.length; index += width) {
      if (index + width > bytes.length)
        throw new UnicodeDecodeError(
          encoding,
          bytes,
          index,
          bytes.length,
          "truncated data",
        );
      const point =
        width === 2
          ? little
            ? bytes.readUInt16LE(index)
            : bytes.readUInt16BE(index)
          : little
            ? bytes.readUInt32LE(index)
            : bytes.readUInt32BE(index);
      if (point > 0x10ffff)
        throw new UnicodeDecodeError(
          encoding,
          bytes,
          index,
          index + width,
          "code point not in range(0x110000)",
        );
      text += String.fromCodePoint(point);
    }
  }
  // json.loads(bytes) decodes one BOM, then sends the text directly to its decoder.
  if (text.startsWith("\ufeff"))
    throw new JsonSyntaxError("Expecting value: line 1 column 1 (char 0)");
  return parseJson(text, rejectDuplicates, parseInteger, parseConstant);
}

export function parseJson(
  input: string | Buffer,
  rejectDuplicates = false,
  parseInteger: (source: string) => bigint = BigInt,
  parseConstant: (source: string) => unknown = (source) =>
    new JsonFloat(source),
): unknown {
  if (Buffer.isBuffer(input))
    return parseJsonBytes(input, rejectDuplicates, parseInteger, parseConstant);
  const source = input;
  // Scan strings directly: repeated escapes can exhaust V8's regex stack.
  const lexer =
    /"|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|-?Infinity|NaN|[^ \t\r\n]/gu;
  const tokens: RegExpExecArray[] = [];
  let token: RegExpExecArray | null;
  while ((token = lexer.exec(source)) !== null) {
    if (token[0] === '"') {
      let end = lexer.lastIndex;
      while (end < source.length) {
        const character = source[end++]!;
        if (character === "\\") end++;
        else if (character === '"') {
          token[0] = source.slice(token.index, end);
          break;
        }
      }
      lexer.lastIndex = Math.min(end, source.length);
    }
    tokens.push(token);
  }
  let index = 0;
  const position = () => tokens[index]?.index ?? source.length;
  function error(message: string, offset = position()): never {
    const before = source.slice(0, offset);
    const line = before.split("\n").length;
    const column =
      Array.from(before.slice(before.lastIndexOf("\n") + 1)).length + 1;
    throw new JsonSyntaxError(
      `${message}: line ${line} column ${column} (char ${Array.from(before).length})`,
    );
  }
  if (source.startsWith("\ufeff"))
    error("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0);
  const take = () => tokens[index++]?.[0];
  function expect(token: string): void {
    if (tokens[index]?.[0] !== token) error(`Expecting '${token}' delimiter`);
    index++;
  }
  function string(token: string, start: number): string {
    const unterminated = token.length === 1;
    const contents = unterminated ? source.slice(start) : token;
    const end = contents.length - (unterminated ? 0 : 1);
    for (let offset = 1; offset < end; offset++) {
      const character = contents[offset]!;
      if (character.charCodeAt(0) < 0x20)
        error("Invalid control character at", start + offset);
      if (character !== "\\") continue;
      const escape = contents[++offset];
      if (escape === undefined) break;
      if (escape === "u") {
        if (!/^[0-9a-fA-F]{4}$/u.test(contents.slice(offset + 1, offset + 5)))
          error("Invalid \\uXXXX escape", start + offset);
        offset += 4;
      } else if (!'"\\/bfnrt'.includes(escape)) {
        error("Invalid \\escape", start + offset - 1);
      }
    }
    if (unterminated) error("Unterminated string starting at", start);
    return JSON.parse(token) as string;
  }
  function value(): unknown {
    const start = position();
    const token = take();
    if (token === "{") {
      const row = Object.create(null) as Row;
      const keys: string[] = [];
      function finish(): Row {
        index++;
        const unique = new Set<string>();
        for (const key of keys) {
          if (rejectDuplicates && unique.has(key))
            throw new Error(`duplicate JSON object key: ${key}`);
          unique.add(key);
        }
        keyOrder.set(row, [...unique]);
        return row;
      }
      if (tokens[index]?.[0] === "}") return finish();
      while (true) {
        const keyStart = position();
        const key = take();
        if (!key?.startsWith('"'))
          error("Expecting property name enclosed in double quotes", keyStart);
        const name = string(key, keyStart);
        expect(":");
        row[name] = value();
        keys.push(name);
        if (tokens[index]?.[0] === "}") return finish();
        expect(",");
      }
    }
    if (token === "[") {
      const values: unknown[] = [];
      if (tokens[index]?.[0] === "]") {
        index++;
        return values;
      }
      while (true) {
        values.push(value());
        if (tokens[index]?.[0] === "]") {
          index++;
          return values;
        }
        expect(",");
      }
    }
    if (token?.startsWith('"')) return string(token, start);
    if (token === "true") return true;
    if (token === "false") return false;
    if (token === "null") return null;
    if (token !== undefined && /^-?[0-9]+$/u.test(token))
      return parseInteger(token);
    if (token === "NaN" || token === "Infinity" || token === "-Infinity")
      return parseConstant(token);
    if (
      token !== undefined &&
      (/^-?(?:[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|Infinity)$/u.test(
        token,
      ) ||
        token === "NaN")
    )
      return new JsonFloat(token);
    return error("Expecting value", start);
  }
  const result = value();
  if (index !== tokens.length) error("Extra data");
  return result;
}

export function pythonRepr(value: unknown): string {
  if (value instanceof TomlDate) return value.repr();
  if (typeof value === "string") {
    const quote = value.includes("'") && !value.includes('"') ? '"' : "'";
    return (
      quote +
      Array.from(value, (character) => {
        if (character === quote || character === "\\") return `\\${character}`;
        if (character === "\n") return "\\n";
        if (character === "\r") return "\\r";
        if (character === "\t") return "\\t";
        if (
          character !== " " &&
          (otherCategory.test(character) || separatorCategory.test(character))
        ) {
          const point = character.codePointAt(0)!;
          return point <= 0xff
            ? `\\x${point.toString(16).padStart(2, "0")}`
            : point <= 0xffff
              ? `\\u${point.toString(16).padStart(4, "0")}`
              : `\\U${point.toString(16).padStart(8, "0")}`;
        }
        return character;
      }).join("") +
      quote
    );
  }
  if (value === null) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  if (value instanceof JsonFloat) {
    const number = Number(value.source);
    if (Number.isNaN(number)) return "nan";
    if (!Number.isFinite(number)) return number < 0 ? "-inf" : "inf";
    if (Object.is(number, -0)) return "-0.0";
    const magnitude = Math.abs(number);
    if (magnitude !== 0 && (magnitude < 0.0001 || magnitude >= 1e16))
      return number.toExponential().replace(/e([+-])([0-9])$/u, "e$10$2");
    return number.toString() + (Number.isInteger(number) ? ".0" : "");
  }
  if (Array.isArray(value)) return `[${value.map(pythonRepr).join(", ")}]`;
  if (object(value))
    return `{${objectEntries(value)
      .map(([key, item]) => `${pythonRepr(key)}: ${pythonRepr(item)}`)
      .join(", ")}}`;
  return String(value);
}
