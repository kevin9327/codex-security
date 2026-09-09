// Adapted from CPython 3.12 Lib/re/_compiler.py, _constants.py and _casefix.py.
// Copyright (c) 1997-2001 by Secret Labs AB. All rights reserved.
// See ../../scripts/licenses/PYTHON-NUMERICS.txt for the retained Python licenses.

import simpleLower from "@unicode/unicode-15.0.0/Simple_Case_Mapping/Lowercase/code-points.js";
import simpleUpper from "@unicode/unicode-15.0.0/Simple_Case_Mapping/Uppercase/code-points.js";
import specialLower from "@unicode/unicode-15.0.0/Special_Casing/Lowercase/code-points.js";
import specialUpper from "@unicode/unicode-15.0.0/Special_Casing/Uppercase/code-points.js";
import {
  PatternError,
  PatternFlag as F,
  patternWidth,
  type ParsedPattern,
  type PatternNode,
  type PatternSetItem,
} from "./python-regex-ir";

// This instruction numbering is shared by CPython 3.12 and the native SRE engine.
const O = {
  FAILURE: 0,
  SUCCESS: 1,
  ANY: 2,
  ANY_ALL: 3,
  ASSERT: 4,
  ASSERT_NOT: 5,
  AT: 6,
  BRANCH: 7,
  CATEGORY: 8,
  CHARSET: 9,
  BIGCHARSET: 10,
  GROUPREF: 11,
  GROUPREF_EXISTS: 12,
  IN: 13,
  INFO: 14,
  JUMP: 15,
  LITERAL: 16,
  MARK: 17,
  MAX_UNTIL: 18,
  MIN_UNTIL: 19,
  NOT_LITERAL: 20,
  NEGATE: 21,
  RANGE: 22,
  REPEAT: 23,
  REPEAT_ONE: 24,
  MIN_REPEAT_ONE: 26,
  ATOMIC_GROUP: 27,
  POSSESSIVE_REPEAT: 28,
  POSSESSIVE_REPEAT_ONE: 29,
  GROUPREF_IGNORE: 30,
  IN_IGNORE: 31,
  LITERAL_IGNORE: 32,
  NOT_LITERAL_IGNORE: 33,
  GROUPREF_UNI_IGNORE: 38,
  IN_UNI_IGNORE: 39,
  LITERAL_UNI_IGNORE: 40,
  NOT_LITERAL_UNI_IGNORE: 41,
  RANGE_UNI_IGNORE: 42,
} as const;
const anchors = {
  AT_BEGINNING: 0,
  AT_BEGINNING_LINE: 1,
  AT_BEGINNING_STRING: 2,
  AT_BOUNDARY: 3,
  AT_NON_BOUNDARY: 4,
  AT_END: 5,
  AT_END_LINE: 6,
  AT_END_STRING: 7,
  AT_UNI_BOUNDARY: 10,
  AT_UNI_NON_BOUNDARY: 11,
} as const;
const categories = {
  CATEGORY_DIGIT: 0,
  CATEGORY_NOT_DIGIT: 1,
  CATEGORY_SPACE: 2,
  CATEGORY_NOT_SPACE: 3,
  CATEGORY_WORD: 4,
  CATEGORY_NOT_WORD: 5,
} as const;
const maxCode = 0xffffffff;
const typeFlags = F.ASCII | F.UNICODE | F.LOCALE;
const combineFlags = (flags: number, add: number, remove: number) =>
  ((add & typeFlags ? flags & ~typeFlags : flags) | add) & ~remove;
const unicodeLower = (point: number) =>
  specialLower.get(point)?.[0] ?? simpleLower.get(point) ?? point;
const unicodeUpper = (point: number) =>
  specialUpper.get(point)?.[0] ?? simpleUpper.get(point) ?? point;
const unicodeCased = (point: number) =>
  unicodeLower(point) !== point || unicodeUpper(point) !== point;
const asciiLower = (point: number) =>
  point >= 65 && point <= 90 ? point + 32 : point;
const asciiCased = (point: number) =>
  (point >= 65 && point <= 90) || (point >= 97 && point <= 122);

// Different lowercase characters with equal uppercase spellings in Unicode 15.
const caseGroups = [
  [0x69, 0x131],
  [0x73, 0x17f],
  [0xb5, 0x3bc],
  [0x345, 0x3b9, 0x1fbe],
  [0x390, 0x1fd3],
  [0x3b0, 0x1fe3],
  [0x3b2, 0x3d0],
  [0x3b5, 0x3f5],
  [0x3b8, 0x3d1],
  [0x3ba, 0x3f0],
  [0x3c0, 0x3d6],
  [0x3c1, 0x3f1],
  [0x3c2, 0x3c3],
  [0x3c6, 0x3d5],
  [0x432, 0x1c80],
  [0x434, 0x1c81],
  [0x43e, 0x1c82],
  [0x441, 0x1c83],
  [0x442, 0x1c84, 0x1c85],
  [0x44a, 0x1c86],
  [0x463, 0x1c87],
  [0x1c88, 0xa64b],
  [0x1e61, 0x1e9b],
  [0xfb05, 0xfb06],
];
const extraCases = new Map(
  caseGroups.flatMap((group) =>
    group.map(
      (point) => [point, group.filter((other) => other !== point)] as const,
    ),
  ),
);
type CharsetItem =
  | PatternSetItem
  | ["RANGE_UNI_IGNORE", [number, number]]
  | ["CHARSET" | "BIGCHARSET", number[]];
interface Casing {
  lower: (point: number) => number;
  cased: (point: number) => boolean;
  extras: boolean;
}
const casing = (flags: number): Casing | undefined =>
  !(flags & F.IGNORECASE)
    ? undefined
    : flags & F.UNICODE
      ? { lower: unicodeLower, cased: unicodeCased, extras: true }
      : { lower: asciiLower, cased: asciiCased, extras: false };
function bitmap(bytes: Uint8Array): number[] {
  const result: number[] = [];
  for (let index = 0; index < bytes.length; index += 32) {
    let word = 0;
    for (let bit = 0; bit < 32; bit++) if (bytes[index + bit]) word |= 1 << bit;
    result.push(word >>> 0);
  }
  return result;
}
function optimizeCharset(
  charset: PatternSetItem[],
  fix?: Casing,
): [CharsetItem[], boolean] {
  const out: CharsetItem[] = [],
    tail: CharsetItem[] = [];
  let map = new Uint8Array(256),
    hasCased = false;
  const outside = Symbol("outside character map");
  const write = (point: number) => {
    if (point >= map.length) throw outside;
    map[point] = 1;
  };
  for (const item of charset) {
    let current: CharsetItem = item;
    for (;;) {
      try {
        const [op, value]: CharsetItem = current;
        if (op === "LITERAL") {
          const point: number = fix ? fix.lower(value) : value;
          current = ["LITERAL", point];
          write(point);
          if (fix?.extras)
            for (const other of extraCases.get(point) ?? []) write(other);
          if (fix && !hasCased && fix.cased(point)) hasCased = true;
        } else if (op === "RANGE") {
          for (let point = value[0]; point <= value[1]; point++) {
            const lower = fix ? fix.lower(point) : point;
            write(lower);
            if (fix?.extras)
              for (const other of extraCases.get(lower) ?? []) write(other);
          }
          if (fix && !hasCased)
            for (let point = value[0]; point <= value[1]; point++)
              if (fix.cased(point)) {
                hasCased = true;
                break;
              }
        } else if (op === "NEGATE") out.push(current);
        else tail.push(current);
      } catch (error) {
        if (error !== outside) throw error;
        if (map.length === 256) {
          const expanded = new Uint8Array(65536);
          expanded.set(map);
          map = expanded;
          continue;
        }
        if (fix) {
          if (current[0] === "RANGE") {
            if (fix.extras) current = ["RANGE_UNI_IGNORE", current[1]];
            hasCased = true;
          } else if (current[0] === "LITERAL" && fix.cased(current[1]))
            hasCased = true;
        }
        tail.push(current);
      }
      break;
    }
  }
  const runs: [number, number][] = [];
  for (let index = 0; index < map.length; ) {
    const start = map.indexOf(1, index);
    if (start < 0) break;
    const zero = map.indexOf(0, start),
      end = zero < 0 ? map.length : zero;
    runs.push([start, end]);
    if (runs.length > 2) break;
    index = end;
  }
  if (runs.length <= 2) {
    for (const [start, end] of runs)
      out.push(
        end - start === 1 ? ["LITERAL", start] : ["RANGE", [start, end - 1]],
      );
    out.push(...tail);
    return [hasCased || out.length < charset.length ? out : charset, hasCased];
  }
  if (map.length === 256) out.push(["CHARSET", bitmap(map)]);
  else {
    const blocks = new Map<string, number>(),
      mapping = Buffer.alloc(256),
      data: number[] = [];
    for (let index = 0; index < map.length; index += 256) {
      const chunk = map.subarray(index, index + 256),
        key = Buffer.from(chunk).toString("base64");
      let block = blocks.get(key);
      if (block === undefined) {
        block = blocks.size;
        blocks.set(key, block);
        data.push(...bitmap(chunk));
      }
      mapping[index / 256] = block;
    }
    const words = [blocks.size];
    for (let index = 0; index < mapping.length; index += 4)
      words.push(mapping.readUInt32LE(index));
    out.push(["BIGCHARSET", [...words, ...data]]);
  }
  return [[...out, ...tail], hasCased];
}
function simple(nodes: PatternNode[]): boolean {
  if (nodes.length !== 1) return false;
  const [op, value] = nodes[0]!;
  if (op === "SUBPATTERN") return value[0] === null && simple(value[3]);
  return (
    op === "LITERAL" || op === "NOT_LITERAL" || op === "ANY" || op === "IN"
  );
}

/** Compile the private parser IR for the native engine's full-match operation. */
export function compilePythonPattern(parsed: ParsedPattern): Uint32Array {
  const [minimum, maximum] = parsed.width;
  // Full matching uses widths; the engine's search-only prefix tables are unnecessary.
  const code: number[] = [
    O.INFO,
    4,
    0,
    Number(minimum < BigInt(maxCode) ? minimum : BigInt(maxCode)),
    Number(maximum < BigInt(maxCode) ? maximum : BigInt(maxCode)),
  ];
  const charsetCode = (charset: CharsetItem[], flags: number) => {
    for (const [op, value] of charset) {
      code.push(O[op]);
      if (op === "LITERAL") code.push(value);
      else if (
        op === "RANGE" ||
        op === "RANGE_UNI_IGNORE" ||
        op === "CHARSET" ||
        op === "BIGCHARSET"
      )
        code.push(...value);
      else if (op === "CATEGORY")
        code.push(categories[value] + (flags & F.UNICODE ? 10 : 0));
    }
    code.push(O.FAILURE);
  };
  const compile = (nodes: PatternNode[], flags: number): void => {
    const fix = casing(flags);
    for (const [op, value] of nodes) {
      if (op === "LITERAL" || op === "NOT_LITERAL") {
        if (!fix || !fix.cased(value)) code.push(O[op], value);
        else {
          const lower = fix.lower(value),
            extra = fix.extras ? extraCases.get(lower) : undefined;
          if (extra === undefined)
            code.push(
              O[`${op}_${fix.extras ? "UNI_IGNORE" : "IGNORE"}`],
              lower,
            );
          else {
            code.push(O.IN_UNI_IGNORE);
            const skip = code.length;
            code.push(0);
            if (op === "NOT_LITERAL") code.push(O.NEGATE);
            for (const point of [lower, ...extra]) code.push(O.LITERAL, point);
            code.push(O.FAILURE);
            code[skip] = code.length - skip;
          }
        }
      } else if (op === "IN") {
        const [charset, hasCased] = optimizeCharset(value, fix);
        code.push(
          !hasCased ? O.IN : fix?.extras ? O.IN_UNI_IGNORE : O.IN_IGNORE,
        );
        const skip = code.length;
        code.push(0);
        charsetCode(charset, flags);
        code[skip] = code.length - skip;
      } else if (op === "ANY") code.push(flags & F.DOTALL ? O.ANY_ALL : O.ANY);
      else if (
        op === "MAX_REPEAT" ||
        op === "MIN_REPEAT" ||
        op === "POSSESSIVE_REPEAT"
      ) {
        if (flags & F.TEMPLATE)
          throw new PatternError(
            `internal: unsupported template operator ${op}`,
          );
        const operations =
          op === "MAX_REPEAT"
            ? [O.REPEAT, O.MAX_UNTIL, O.REPEAT_ONE]
            : op === "MIN_REPEAT"
              ? [O.REPEAT, O.MIN_UNTIL, O.MIN_REPEAT_ONE]
              : [O.POSSESSIVE_REPEAT, O.SUCCESS, O.POSSESSIVE_REPEAT_ONE];
        const isSimple = simple(value[2]);
        code.push(operations[isSimple ? 2 : 0]!);
        const skip = code.length;
        code.push(0, value[0], value[1]);
        compile(value[2], flags);
        if (isSimple) code.push(O.SUCCESS);
        code[skip] = code.length - skip;
        if (!isSimple) code.push(operations[1]!);
      } else if (op === "SUBPATTERN") {
        const [group, add, remove, children] = value;
        if (group) code.push(O.MARK, (group - 1) * 2);
        compile(children, combineFlags(flags, add, remove));
        if (group) code.push(O.MARK, (group - 1) * 2 + 1);
      } else if (op === "ATOMIC_GROUP") {
        code.push(O.ATOMIC_GROUP);
        const skip = code.length;
        code.push(0);
        compile(value, flags);
        code.push(O.SUCCESS);
        code[skip] = code.length - skip;
      } else if (op === "ASSERT" || op === "ASSERT_NOT") {
        code.push(O[op]);
        const skip = code.length;
        code.push(0);
        if (value[0] >= 0) code.push(0);
        else {
          const [low, high] = patternWidth(value[1], parsed.groupWidths);
          if (low > BigInt(maxCode))
            throw new PatternError("looks too much behind");
          if (low !== high)
            throw new PatternError("look-behind requires fixed-width pattern");
          code.push(Number(low));
        }
        compile(value[1], flags);
        code.push(O.SUCCESS);
        code[skip] = code.length - skip;
      } else if (op === "AT") {
        // Python 3.12's \B rejects the empty subject; newer engines accept it.
        // Keep the guard at every anchor, including anchors inside assertions.
        if (value === "AT_NON_BOUNDARY")
          code.push(
            O.ASSERT_NOT,
            7,
            0,
            O.AT,
            anchors.AT_BEGINNING_STRING,
            O.AT,
            anchors.AT_END_STRING,
            O.SUCCESS,
          );
        let at: number = anchors[value];
        if (flags & F.MULTILINE) {
          if (value === "AT_BEGINNING") at = anchors.AT_BEGINNING_LINE;
          if (value === "AT_END") at = anchors.AT_END_LINE;
        }
        if (flags & F.UNICODE) {
          if (value === "AT_BOUNDARY") at = anchors.AT_UNI_BOUNDARY;
          if (value === "AT_NON_BOUNDARY") at = anchors.AT_UNI_NON_BOUNDARY;
        }
        code.push(O.AT, at);
      } else if (op === "BRANCH") {
        code.push(O.BRANCH);
        const tails: number[] = [];
        for (const branch of value[1]) {
          const skip = code.length;
          code.push(0);
          compile(branch, flags);
          code.push(O.JUMP);
          tails.push(code.length);
          code.push(0);
          code[skip] = code.length - skip;
        }
        code.push(O.FAILURE);
        for (const tail of tails) code[tail] = code.length - tail;
      } else if (op === "GROUPREF")
        code.push(
          !fix
            ? O.GROUPREF
            : fix.extras
              ? O.GROUPREF_UNI_IGNORE
              : O.GROUPREF_IGNORE,
          value - 1,
        );
      else if (op === "GROUPREF_EXISTS") {
        code.push(O.GROUPREF_EXISTS, value[0] - 1);
        const yes = code.length;
        code.push(0);
        compile(value[1], flags);
        if (value[2]?.length) {
          code.push(O.JUMP);
          const no = code.length;
          code.push(0);
          code[yes] = code.length - yes + 1;
          compile(value[2], flags);
          code[no] = code.length - no;
        } else code[yes] = code.length - yes + 1;
      }
    }
  };
  compile(parsed.nodes, parsed.flags);
  code.push(O.SUCCESS);
  return Uint32Array.from(code);
}
