import { decodeUtf8 } from "./utf8";

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
    !(value instanceof JsonFloat)
  );
}
export function objectEntries(value: Row): [string, unknown][] {
  const keys = new Set([...(keyOrder.get(value) ?? []), ...Object.keys(value)]);
  return [...keys].map((key) => [key, value[key]]);
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

// json.dumps(..., ensure_ascii=True, indent=2), with compact persistence support.
export function stringifyJson(
  value: unknown,
  options: { compact?: boolean; allowNan?: boolean } = {},
): string {
  const quote = (text: string) =>
    JSON.stringify(text).replace(
      /[\u007f-\uffff]/g,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
  function encode(item: unknown, depth: number): string {
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
        : objectEntries(item).map(
            ([key, child]) => `${quote(key)}: ${encode(child, depth + 1)}`,
          );
      const [open, close] = array ? ["[", "]"] : ["{", "}"];
      if (entries.length === 0) return open + close;
      if (options.compact) return open + entries.join(", ") + close;
      const prefix = "  ".repeat(depth + 1);
      return `${open}\n${prefix}${entries.join(`,\n${prefix}`)}\n${"  ".repeat(depth)}${close}`;
    }
    return JSON.stringify(item);
  }
  return encode(value, 0);
}

export class JsonSyntaxError extends Error {}

// json.loads(bytes) detects UTF-8/16/32 and decodes with surrogatepass.
export function parseJsonBytes(bytes: Buffer): unknown {
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
    let start = offset;
    for (let index = offset; index + 2 < bytes.length; index++) {
      const second = bytes[index + 1]!;
      const third = bytes[index + 2]!;
      if (
        bytes[index] === 0xed &&
        second >= 0xa0 &&
        second <= 0xbf &&
        third >= 0x80 &&
        third <= 0xbf
      ) {
        text += decodeUtf8(bytes.subarray(start, index));
        text += String.fromCharCode(
          0xd000 | ((second & 0x3f) << 6) | (third & 0x3f),
        );
        index += 2;
        start = index + 1;
      }
    }
    text += decodeUtf8(bytes.subarray(start));
  } else {
    if ((bytes.length - offset) % width !== 0)
      throw new Error(`Truncated UTF-${width * 8} JSON input`);
    for (let index = offset; index < bytes.length; index += width) {
      const point =
        width === 2
          ? little
            ? bytes.readUInt16LE(index)
            : bytes.readUInt16BE(index)
          : little
            ? bytes.readUInt32LE(index)
            : bytes.readUInt32BE(index);
      text += String.fromCodePoint(point);
    }
  }
  return parseJson(text);
}

export function parseJson(source: string, rejectDuplicates = false): unknown {
  const tokens = [
    ...source.matchAll(
      /"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|-?Infinity|NaN|[^ \t\r\n]/gu,
    ),
  ];
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
    if (token !== undefined && /^-?[0-9]+$/u.test(token)) return BigInt(token);
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
  if (typeof value === "string") {
    const quote = value.includes("'") && !value.includes('"') ? '"' : "'";
    return (
      quote +
      Array.from(value, (character) => {
        if (character === quote || character === "\\") return `\\${character}`;
        if (character === "\n") return "\\n";
        if (character === "\r") return "\\r";
        if (character === "\t") return "\\t";
        if (character !== " " && /[\p{C}\p{Z}]/u.test(character)) {
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
