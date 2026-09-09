// Adapted from CPython 3.12 Lib/re/_parser.py and _constants.py.
// Copyright (c) 1998-2001 by Secret Labs AB. All rights reserved.
// See ../../scripts/licenses/PYTHON-NUMERICS.txt for the retained Python licenses.

export const PatternFlag = {
  TEMPLATE: 1,
  IGNORECASE: 2,
  LOCALE: 4,
  MULTILINE: 8,
  DOTALL: 16,
  UNICODE: 32,
  VERBOSE: 64,
  DEBUG: 128,
  ASCII: 256,
} as const;
export const MAX_REPEAT = 0xffffffff;
export const MAX_GROUPS = 0x3fffffff;
export const MAX_WIDTH = 1n << 64n;
export type PatternWidth = readonly [minimum: bigint, maximum: bigint];
export type PatternCategory =
  | "CATEGORY_DIGIT"
  | "CATEGORY_NOT_DIGIT"
  | "CATEGORY_SPACE"
  | "CATEGORY_NOT_SPACE"
  | "CATEGORY_WORD"
  | "CATEGORY_NOT_WORD";
export type PatternAnchor =
  | "AT_BEGINNING"
  | "AT_BEGINNING_STRING"
  | "AT_END"
  | "AT_END_STRING"
  | "AT_BOUNDARY"
  | "AT_NON_BOUNDARY";
export type PatternSetItem =
  | ["LITERAL", number]
  | ["RANGE", [number, number]]
  | ["CATEGORY", PatternCategory]
  | ["NEGATE", null];
export type PatternNode =
  | ["LITERAL" | "NOT_LITERAL" | "GROUPREF", number]
  | ["ANY", null]
  | ["AT", PatternAnchor]
  | ["IN", PatternSetItem[]]
  | ["BRANCH", [null, PatternNode[][]]]
  | ["SUBPATTERN", [number | null, number, number, PatternNode[]]]
  | ["ATOMIC_GROUP", PatternNode[]]
  | ["ASSERT" | "ASSERT_NOT", [1 | -1, PatternNode[]]]
  | [
      "MAX_REPEAT" | "MIN_REPEAT" | "POSSESSIVE_REPEAT",
      [number, number, PatternNode[]],
    ]
  | ["GROUPREF_EXISTS", [number, PatternNode[], PatternNode[] | null]];
export interface ParsedPattern {
  nodes: PatternNode[];
  flags: number;
  groupNames: Map<string, number>;
  groupWidths: (PatternWidth | null)[];
  width: PatternWidth;
  warnings: string[];
}

export class PatternError extends Error {
  override name = "error";
  readonly lineno: number | null;
  readonly colno: number | null;
  constructor(
    readonly msg: string,
    readonly pattern: string | null = null,
    readonly pos: number | null = null,
  ) {
    let message = msg,
      line: number | null = null,
      column: number | null = null;
    if (pattern !== null && pos !== null) {
      const before = Array.from(pattern).slice(0, pos);
      line = before.filter((c) => c === "\n").length + 1;
      column = pos - before.lastIndexOf("\n");
      message += ` at position ${pos}`;
      if (pattern.includes("\n"))
        message += ` (line ${line}, column ${column})`;
    }
    super(message);
    this.lineno = line;
    this.colno = column;
  }
}

export function patternWidth(
  nodes: readonly PatternNode[],
  groups: readonly (PatternWidth | null)[],
): PatternWidth {
  let low = 0n,
    high = 0n;
  for (const [op, value] of nodes) {
    let minimum = 0n,
      maximum = 0n;
    if (
      op === "LITERAL" ||
      op === "NOT_LITERAL" ||
      op === "ANY" ||
      op === "IN"
    ) {
      minimum = maximum = 1n;
    } else if (op === "BRANCH") {
      minimum = MAX_WIDTH;
      for (const branch of value[1]) {
        const [a, b] = patternWidth(branch, groups);
        if (a < minimum) minimum = a;
        if (b > maximum) maximum = b;
      }
    } else if (op === "SUBPATTERN" || op === "ATOMIC_GROUP") {
      [minimum, maximum] = patternWidth(
        op === "SUBPATTERN" ? value[3] : value,
        groups,
      );
    } else if (
      op === "MAX_REPEAT" ||
      op === "MIN_REPEAT" ||
      op === "POSSESSIVE_REPEAT"
    ) {
      const [a, b] = patternWidth(value[2], groups);
      minimum = a * BigInt(value[0]);
      maximum = value[1] === MAX_REPEAT && b ? MAX_WIDTH : b * BigInt(value[1]);
    } else if (op === "GROUPREF") {
      [minimum, maximum] = groups[value]!;
    } else if (op === "GROUPREF_EXISTS") {
      [minimum, maximum] = patternWidth(value[1], groups);
      if (value[2] === null) minimum = 0n;
      else {
        const [a, b] = patternWidth(value[2], groups);
        if (a < minimum) minimum = a;
        if (b > maximum) maximum = b;
      }
    }
    low += minimum;
    high += maximum;
  }
  return [
    low < MAX_WIDTH ? low : MAX_WIDTH,
    high < MAX_WIDTH ? high : MAX_WIDTH,
  ];
}

// Python performs these checks during compilation, after successful parsing.
export function validateLookbehindWidths(parsed: ParsedPattern): void {
  const visit = (nodes: readonly PatternNode[]): void => {
    for (const [op, value] of nodes) {
      if (op === "ASSERT" || op === "ASSERT_NOT") {
        if (value[0] < 0) {
          const [low, high] = patternWidth(value[1], parsed.groupWidths);
          if (low > 0xffffffffn)
            throw new PatternError("looks too much behind");
          if (low !== high)
            throw new PatternError("look-behind requires fixed-width pattern");
        }
        visit(value[1]);
      } else if (op === "SUBPATTERN") visit(value[3]);
      else if (op === "ATOMIC_GROUP") visit(value);
      else if (op === "BRANCH") value[1].forEach(visit);
      else if (
        op === "MAX_REPEAT" ||
        op === "MIN_REPEAT" ||
        op === "POSSESSIVE_REPEAT"
      )
        visit(value[2]);
      else if (op === "GROUPREF_EXISTS") {
        visit(value[1]);
        if (value[2]) visit(value[2]);
      }
    }
  };
  visit(parsed.nodes);
}
