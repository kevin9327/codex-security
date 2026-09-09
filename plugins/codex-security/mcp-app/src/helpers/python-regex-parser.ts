// String-pattern parser adapted from CPython 3.12 Lib/re/_parser.py.
// Copyright (c) 1998-2001 by Secret Labs AB. All rights reserved.
// See ../../scripts/licenses/PYTHON-NUMERICS.txt for the retained Python licenses.
import { pythonRepr } from "./python-json";
import {
  patternCharacterName,
  patternIdentifier,
  patternLetter,
} from "./python-regex-unicode";
import {
  MAX_GROUPS,
  MAX_REPEAT,
  PatternError,
  PatternFlag,
  patternWidth,
  type ParsedPattern,
  type PatternNode,
  type PatternSetItem,
  type PatternWidth,
} from "./python-regex-ir";

const digits = "0123456789",
  octal = "01234567",
  hex = "0123456789abcdefABCDEF";
const whitespace = " \t\n\r\v\f";
const special = ".\\[{()*+?^$|";
const flags: Record<string, number> = {
  i: PatternFlag.IGNORECASE,
  L: PatternFlag.LOCALE,
  m: PatternFlag.MULTILINE,
  s: PatternFlag.DOTALL,
  x: PatternFlag.VERBOSE,
  a: PatternFlag.ASCII,
  t: PatternFlag.TEMPLATE,
  u: PatternFlag.UNICODE,
};
const typeFlags = PatternFlag.ASCII | PatternFlag.LOCALE | PatternFlag.UNICODE;
const globalFlags = PatternFlag.DEBUG | PatternFlag.TEMPLATE;
const escapes: Record<string, number> = {
  "\\a": 7,
  "\\b": 8,
  "\\f": 12,
  "\\n": 10,
  "\\r": 13,
  "\\t": 9,
  "\\v": 11,
  "\\\\": 92,
};
const categories: Record<string, PatternNode> = {
  "\\A": ["AT", "AT_BEGINNING_STRING"],
  "\\b": ["AT", "AT_BOUNDARY"],
  "\\B": ["AT", "AT_NON_BOUNDARY"],
  "\\Z": ["AT", "AT_END_STRING"],
  "\\d": ["IN", [["CATEGORY", "CATEGORY_DIGIT"]]],
  "\\D": ["IN", [["CATEGORY", "CATEGORY_NOT_DIGIT"]]],
  "\\s": ["IN", [["CATEGORY", "CATEGORY_SPACE"]]],
  "\\S": ["IN", [["CATEGORY", "CATEGORY_NOT_SPACE"]]],
  "\\w": ["IN", [["CATEGORY", "CATEGORY_WORD"]]],
  "\\W": ["IN", [["CATEGORY", "CATEGORY_NOT_WORD"]]],
};
const length = (text: string) => Array.from(text).length;
const member = (text: string, character: string | null) =>
  character !== null && length(character) === 1 && text.includes(character);
const alpha = (text: string) =>
  Array.from(text).every((character) => patternLetter.test(character));
const repeated = (node: PatternNode) =>
  node[0] === "MAX_REPEAT" ||
  node[0] === "MIN_REPEAT" ||
  node[0] === "POSSESSIVE_REPEAT";
function namedError(
  name: "OverflowError" | "ValueError",
  message: string,
): never {
  const error = new Error(message);
  error.name = name;
  throw error;
}
function integer(source: string): bigint {
  if (source.length > 4300)
    namedError(
      "ValueError",
      `Exceeds the limit (4300 digits) for integer string conversion: value has ${source.length} digits; use sys.set_int_max_str_digits() to increase the limit`,
    );
  return BigInt(source);
}
function unique(items: PatternSetItem[]): PatternSetItem[] {
  return [
    ...new Map(items.map((item) => [`${item[0]}:${item[1]}`, item])).values(),
  ];
}
function sameSet(a: PatternSetItem, b: PatternSetItem): boolean {
  return (
    a[0] === b[0] &&
    (a[0] === "RANGE" && b[0] === "RANGE"
      ? a[1][0] === b[1][0] && a[1][1] === b[1][1]
      : a[1] === b[1])
  );
}
function sameNode(a: PatternNode, b: PatternNode): boolean {
  if (a[0] !== b[0]) return false;
  if (a[0] === "IN" && b[0] === "IN")
    return (
      a[1].length === b[1].length &&
      a[1].every((item, i) => sameSet(item, b[1][i]!))
    );
  // Python SubPattern operands compare by identity, unlike charset tuples.
  return a[1] === b[1];
}

class Tokenizer {
  readonly characters: string[];
  index = 0;
  next: string | null = null;
  constructor(readonly pattern: string) {
    this.characters = Array.from(pattern);
    this.advance();
  }
  private advance(): void {
    let index = this.index;
    let character = this.characters[index];
    if (character === undefined) {
      this.next = null;
      return;
    }
    if (character === "\\") {
      const escaped = this.characters[++index];
      if (escaped === undefined)
        throw new PatternError(
          "bad escape (end of pattern)",
          this.pattern,
          this.characters.length - 1,
        );
      character += escaped;
    }
    this.index = index + 1;
    this.next = character;
  }
  get position(): number {
    return this.index - (this.next === null ? 0 : length(this.next));
  }
  get(): string | null {
    const value = this.next;
    this.advance();
    return value;
  }
  match(value: string): boolean {
    if (this.next !== value) return false;
    this.advance();
    return true;
  }
  seek(index: number): void {
    this.index = index;
    this.advance();
  }
  take(maximum: number, characters: string): string {
    let text = "";
    while (length(text) < maximum && member(characters, this.next))
      text += this.get();
    return text;
  }
  until(terminator: string, name: string): string {
    let text = "";
    for (;;) {
      const character = this.get();
      if (character === null)
        throw this.error(
          text ? `missing ${terminator}, unterminated name` : `missing ${name}`,
          length(text),
        );
      if (character === terminator) {
        if (!text) throw this.error(`missing ${name}`, 1);
        return text;
      }
      text += character;
    }
  }
  error(message: string, offset = 0): PatternError {
    return new PatternError(message, this.pattern, this.position - offset);
  }
  groupName(name: string, offset: number): void {
    if (!patternIdentifier(name))
      throw this.error(
        `bad character in group name ${pythonRepr(name)}`,
        length(name) + offset,
      );
  }
}

class Parser {
  readonly source: Tokenizer;
  readonly groupNames = new Map<string, number>();
  readonly groupWidths: (PatternWidth | null)[] = [null];
  readonly groupReferences = new Map<number, number>();
  readonly warnings: string[] = [];
  flags = 0;
  lookbehindGroups: number | null = null;
  constructor(pattern: string) {
    this.source = new Tokenizer(pattern);
  }
  checkGroup(group: number): boolean {
    return group < this.groupWidths.length && this.groupWidths[group] !== null;
  }
  checkLookbehindGroup(group: number): void {
    if (this.lookbehindGroups !== null) {
      if (!this.checkGroup(group))
        throw this.source.error("cannot refer to an open group");
      if (group >= this.lookbehindGroups)
        throw this.source.error(
          "cannot refer to group defined in the same lookbehind subpattern",
        );
    }
  }
  escape(escape: string, inClass = false): PatternNode {
    const source = this.source,
      character = Array.from(escape)[1]!;
    const category = categories[escape];
    if (category && (!inClass || category[0] === "IN")) return category;
    if (escapes[escape] !== undefined) return ["LITERAL", escapes[escape]!];
    if (character === "x" || character === "u" || character === "U") {
      const count = character === "x" ? 2 : character === "u" ? 4 : 8;
      escape += source.take(count, hex);
      if (length(escape) !== count + 2)
        throw source.error(`incomplete escape ${escape}`, length(escape));
      const code = Number.parseInt(escape.slice(2), 16);
      if (code <= 0x10ffff) return ["LITERAL", code];
    } else if (character === "N") {
      if (!source.match("{")) throw source.error("missing {");
      const name = source.until("}", "character name"),
        code = patternCharacterName(name);
      if (code === undefined)
        throw source.error(
          `undefined character name ${pythonRepr(name)}`,
          length(name) + 4,
        );
      return ["LITERAL", code];
    } else if ((inClass && member(octal, character)) || character === "0") {
      escape += source.take(2, octal);
      const code = Number.parseInt(escape.slice(1), 8);
      if (code > 0xff)
        throw source.error(
          `octal escape value ${escape} outside of range 0-0o377`,
          length(escape),
        );
      return ["LITERAL", code];
    } else if (!inClass && member(digits, character)) {
      if (member(digits, source.next)) {
        escape += source.get();
        if (
          member(octal, escape[1]!) &&
          member(octal, escape[2]!) &&
          member(octal, source.next)
        ) {
          escape += source.get();
          const code = Number.parseInt(escape.slice(1), 8);
          if (code > 0xff)
            throw source.error(
              `octal escape value ${escape} outside of range 0-0o377`,
              length(escape),
            );
          return ["LITERAL", code];
        }
      }
      const group = Number(escape.slice(1));
      if (group >= this.groupWidths.length)
        throw source.error(
          `invalid group reference ${group}`,
          length(escape) - 1,
        );
      if (!this.checkGroup(group))
        throw source.error("cannot refer to an open group", length(escape));
      this.checkLookbehindGroup(group);
      return ["GROUPREF", group];
    } else if (
      !(inClass && member(digits, character)) &&
      !/^[a-zA-Z]$/.test(character)
    ) {
      return ["LITERAL", character.codePointAt(0)!];
    }
    throw source.error(`bad escape ${escape}`, length(escape));
  }
  alternation(verbose: boolean, nested: number): PatternNode[] {
    const items: PatternNode[][] = [];
    do {
      items.push(
        this.sequence(verbose, nested + 1, nested === 0 && items.length === 0),
      );
      if (!this.source.match("|")) break;
      if (!nested) verbose = Boolean(this.flags & PatternFlag.VERBOSE);
    } while (true);
    if (items.length === 1) return items[0]!;
    const nodes: PatternNode[] = [];
    for (;;) {
      const first = items[0]![0];
      if (!first || !items.every((item) => item[0] && sameNode(item[0], first)))
        break;
      items.forEach((item) => item.shift());
      nodes.push(first);
    }
    const set: PatternSetItem[] = [];
    for (const item of items) {
      const node = item[0];
      if (item.length !== 1 || !node)
        return [...nodes, ["BRANCH", [null, items]]];
      if (node[0] === "LITERAL") set.push(["LITERAL", node[1]]);
      else if (node[0] === "IN" && node[1][0]?.[0] !== "NEGATE")
        set.push(...node[1]);
      else return [...nodes, ["BRANCH", [null, items]]];
    }
    return [...nodes, ["IN", unique(set)]];
  }
  characterClass(): PatternNode {
    const source = this.source,
      here = source.position - 1;
    const set: PatternSetItem[] = [];
    if (source.next === "[")
      this.warnings.push(`Possible nested set at position ${source.position}`);
    const negate = source.match("^");
    for (;;) {
      const character = source.get();
      if (character === null)
        throw source.error(
          "unterminated character set",
          source.position - here,
        );
      if (character === "]" && set.length) break;
      let first: PatternNode;
      if (character.startsWith("\\")) first = this.escape(character, true);
      else {
        if (
          set.length &&
          member("-&~|", character) &&
          source.next === character
        ) {
          const kind = {
            "-": "difference",
            "&": "intersection",
            "~": "symmetric difference",
            "|": "union",
          }[character];
          this.warnings.push(
            `Possible set ${kind} at position ${source.position - 1}`,
          );
        }
        first = ["LITERAL", character.codePointAt(0)!];
      }
      if (source.match("-")) {
        const last = source.get();
        if (last === null)
          throw source.error(
            "unterminated character set",
            source.position - here,
          );
        if (last === "]") {
          set.push(
            first[0] === "IN" ? first[1][0]! : (first as ["LITERAL", number]),
            ["LITERAL", 45],
          );
          break;
        }
        let second: PatternNode;
        if (last.startsWith("\\")) second = this.escape(last, true);
        else {
          if (last === "-")
            this.warnings.push(
              `Possible set difference at position ${source.position - 2}`,
            );
          second = ["LITERAL", last.codePointAt(0)!];
        }
        if (
          first[0] !== "LITERAL" ||
          second[0] !== "LITERAL" ||
          second[1] < first[1]
        )
          throw source.error(
            `bad character range ${character}-${last}`,
            length(character) + 1 + length(last),
          );
        set.push(["RANGE", [first[1], second[1]]]);
      } else
        set.push(
          first[0] === "IN" ? first[1][0]! : (first as ["LITERAL", number]),
        );
    }
    const items = unique(set);
    if (items.length === 1 && items[0]![0] === "LITERAL")
      return [negate ? "NOT_LITERAL" : "LITERAL", items[0]![1]];
    if (negate) items.unshift(["NEGATE", null]);
    return ["IN", items];
  }
  repeat(character: string, nodes: PatternNode[]): void {
    const source = this.source,
      here = source.position;
    let minimum = character === "+" ? 1 : 0,
      maximum = character === "?" ? 1 : MAX_REPEAT;
    if (character === "{") {
      if (source.next === "}") {
        nodes.push(["LITERAL", 123]);
        return;
      }
      let low = "",
        high = "";
      while (member(digits, source.next)) low += source.get();
      if (source.match(","))
        while (member(digits, source.next)) high += source.get();
      else high = low;
      if (!source.match("}")) {
        nodes.push(["LITERAL", 123]);
        source.seek(here);
        return;
      }
      if (low) {
        const value = integer(low);
        if (value >= BigInt(MAX_REPEAT))
          namedError("OverflowError", "the repetition number is too large");
        minimum = Number(value);
      }
      if (high) {
        const value = integer(high);
        if (value >= BigInt(MAX_REPEAT))
          namedError("OverflowError", "the repetition number is too large");
        maximum = Number(value);
        if (maximum < minimum)
          throw source.error(
            "min repeat greater than max repeat",
            source.position - here,
          );
      }
    }
    const previous = nodes.at(-1);
    if (!previous || previous[0] === "AT")
      throw source.error(
        "nothing to repeat",
        source.position - here + length(character),
      );
    if (repeated(previous))
      throw source.error(
        "multiple repeat",
        source.position - here + length(character),
      );
    const item =
      previous[0] === "SUBPATTERN" &&
      previous[1][0] === null &&
      !previous[1][1] &&
      !previous[1][2]
        ? previous[1][3]
        : [previous];
    nodes[nodes.length - 1] = [
      source.match("?")
        ? "MIN_REPEAT"
        : source.match("+")
          ? "POSSESSIVE_REPEAT"
          : "MAX_REPEAT",
      [minimum, maximum, item],
    ];
  }
  inlineFlags(character: string): [number, number] | null {
    const source = this.source;
    let add = 0,
      remove = 0;
    if (character !== "-") {
      for (;;) {
        const flag = flags[character]!;
        if (character === "L")
          throw source.error(
            "bad inline flags: cannot use 'L' flag with a str pattern",
          );
        add |= flag;
        if (flag & typeFlags && (add & typeFlags) !== flag)
          throw source.error(
            "bad inline flags: flags 'a', 'u' and 'L' are incompatible",
          );
        const next = source.get();
        if (next === null) throw source.error("missing -, : or )");
        character = next;
        if (member(")-:", character)) break;
        if (flags[character] === undefined)
          throw source.error(
            alpha(character) ? "unknown flag" : "missing -, : or )",
            length(character),
          );
      }
    }
    if (character === ")") {
      this.flags |= add;
      return null;
    }
    if (add & globalFlags)
      throw source.error("bad inline flags: cannot turn on global flag", 1);
    if (character === "-") {
      let next = source.get();
      if (next === null) throw source.error("missing flag");
      if (flags[next] === undefined)
        throw source.error(
          alpha(next) ? "unknown flag" : "missing flag",
          length(next),
        );
      for (;;) {
        const flag = flags[next]!;
        if (flag & typeFlags)
          throw source.error(
            "bad inline flags: cannot turn off flags 'a', 'u' and 'L'",
          );
        remove |= flag;
        next = source.get();
        if (next === null) throw source.error("missing :");
        if (next === ":") break;
        if (flags[next] === undefined)
          throw source.error(
            alpha(next) ? "unknown flag" : "missing :",
            length(next),
          );
      }
    }
    if (remove & globalFlags)
      throw source.error("bad inline flags: cannot turn off global flag", 1);
    if (add & remove)
      throw source.error("bad inline flags: flag turned on and off", 1);
    return [add, remove];
  }
  sequence(verbose: boolean, nested: number, first = false): PatternNode[] {
    const source = this.source,
      nodes: PatternNode[] = [];
    while (source.next !== null && !member("|)", source.next)) {
      const character = source.get()!;
      if (verbose) {
        if (member(whitespace, character)) continue;
        if (character === "#") {
          let next: string | null;
          do {
            next = source.get();
          } while (next !== null && next !== "\n");
          continue;
        }
      }
      if (character.startsWith("\\")) nodes.push(this.escape(character));
      else if (!member(special, character))
        nodes.push(["LITERAL", character.codePointAt(0)!]);
      else if (character === "[") nodes.push(this.characterClass());
      else if (member("*+?{", character)) this.repeat(character, nodes);
      else if (character === ".") nodes.push(["ANY", null]);
      else if (character === "^") nodes.push(["AT", "AT_BEGINNING"]);
      else if (character === "$") nodes.push(["AT", "AT_END"]);
      else if (character === "(") {
        const start = source.position - 1;
        let capture = true,
          atomic = false,
          name: string | null = null,
          add = 0,
          remove = 0;
        if (source.match("?")) {
          let option = source.get();
          if (option === null) throw source.error("unexpected end of pattern");
          if (option === "P") {
            if (source.match("<")) {
              name = source.until(">", "group name");
              source.groupName(name, 1);
            } else if (source.match("=")) {
              name = source.until(")", "group name");
              source.groupName(name, 1);
              const group = this.groupNames.get(name);
              if (group === undefined)
                throw source.error(
                  `unknown group name ${pythonRepr(name)}`,
                  length(name) + 1,
                );
              if (!this.checkGroup(group))
                throw source.error(
                  "cannot refer to an open group",
                  length(name) + 1,
                );
              this.checkLookbehindGroup(group);
              nodes.push(["GROUPREF", group]);
              continue;
            } else {
              option = source.get();
              if (option === null)
                throw source.error("unexpected end of pattern");
              throw source.error(
                `unknown extension ?P${option}`,
                length(option) + 2,
              );
            }
          } else if (option === ":") capture = false;
          else if (option === "#") {
            while (true) {
              if (source.next === null)
                throw source.error(
                  "missing ), unterminated comment",
                  source.position - start,
                );
              if (source.get() === ")") break;
            }
            continue;
          } else if (member("=!<", option)) {
            let direction: 1 | -1 = 1;
            const previous = this.lookbehindGroups;
            if (option === "<") {
              option = source.get();
              if (option === null)
                throw source.error("unexpected end of pattern");
              if (!member("=!", option))
                throw source.error(
                  `unknown extension ?<${option}`,
                  length(option) + 2,
                );
              direction = -1;
              if (previous === null)
                this.lookbehindGroups = this.groupWidths.length;
            }
            const item = this.alternation(verbose, nested + 1);
            if (direction < 0 && previous === null)
              this.lookbehindGroups = null;
            if (!source.match(")"))
              throw source.error(
                "missing ), unterminated subpattern",
                source.position - start,
              );
            nodes.push([
              option === "=" ? "ASSERT" : "ASSERT_NOT",
              [direction, item],
            ]);
            continue;
          } else if (option === "(") {
            const condition = source.until(")", "group name");
            let group: number;
            if (!/^[0-9]+$/.test(condition)) {
              source.groupName(condition, 1);
              const existing = this.groupNames.get(condition);
              if (existing === undefined)
                throw source.error(
                  `unknown group name ${pythonRepr(condition)}`,
                  length(condition) + 1,
                );
              group = existing;
            } else {
              const number = integer(condition);
              if (!number)
                throw source.error("bad group number", length(condition) + 1);
              if (number >= BigInt(MAX_GROUPS))
                throw source.error(
                  `invalid group reference ${number}`,
                  length(condition) + 1,
                );
              group = Number(number);
              if (!this.groupReferences.has(group))
                this.groupReferences.set(
                  group,
                  source.position - length(condition) - 1,
                );
            }
            this.checkLookbehindGroup(group);
            const yes = this.sequence(verbose, nested + 1);
            let no: PatternNode[] | null = null;
            if (source.match("|")) {
              no = this.sequence(verbose, nested + 1);
              if (source.next === "|")
                throw source.error(
                  "conditional backref with more than two branches",
                );
            }
            if (!source.match(")"))
              throw source.error(
                "missing ), unterminated subpattern",
                source.position - start,
              );
            nodes.push(["GROUPREF_EXISTS", [group, yes, no]]);
            continue;
          } else if (option === ">") {
            capture = false;
            atomic = true;
          } else if (flags[option] !== undefined || option === "-") {
            const parsed = this.inlineFlags(option);
            if (parsed === null) {
              if (!first || nodes.length)
                throw source.error(
                  "global flags not at the start of the expression",
                  source.position - start,
                );
              verbose = Boolean(this.flags & PatternFlag.VERBOSE);
              continue;
            }
            [add, remove] = parsed;
            capture = false;
          } else
            throw source.error(
              `unknown extension ?${option}`,
              length(option) + 1,
            );
        }
        let group: number | null = null;
        if (capture) {
          group = this.groupWidths.length;
          this.groupWidths.push(null);
          if (this.groupWidths.length > MAX_GROUPS)
            throw new PatternError("too many groups");
          if (name !== null) {
            const previous = this.groupNames.get(name);
            if (previous !== undefined)
              throw source.error(
                `redefinition of group name ${pythonRepr(name)} as group ${group}; was group ${previous}`,
                length(name) + 1,
              );
            this.groupNames.set(name, group);
          }
        }
        const innerVerbose = Boolean(
          (verbose || add & PatternFlag.VERBOSE) &&
            !(remove & PatternFlag.VERBOSE),
        );
        const item = this.alternation(innerVerbose, nested + 1);
        if (!source.match(")"))
          throw source.error(
            "missing ), unterminated subpattern",
            source.position - start,
          );
        if (group !== null)
          this.groupWidths[group] = patternWidth(item, this.groupWidths);
        nodes.push(
          atomic
            ? ["ATOMIC_GROUP", item]
            : ["SUBPATTERN", [group, add, remove, item]],
        );
      }
    }
    return nodes.flatMap((node): PatternNode[] =>
      node[0] === "SUBPATTERN" &&
      node[1][0] === null &&
      !node[1][1] &&
      !node[1][2]
        ? node[1][3]
        : [node],
    );
  }
}

export function parsePythonPattern(pattern: string): ParsedPattern {
  const parser = new Parser(pattern),
    nodes = parser.alternation(false, 0);
  if (!(parser.flags & PatternFlag.ASCII)) parser.flags |= PatternFlag.UNICODE;
  else if (parser.flags & PatternFlag.UNICODE)
    namedError("ValueError", "ASCII and UNICODE flags are incompatible");
  if (parser.source.next !== null)
    throw parser.source.error("unbalanced parenthesis");
  for (const [group, position] of parser.groupReferences)
    if (group >= parser.groupWidths.length)
      throw new PatternError(
        `invalid group reference ${group}`,
        pattern,
        position,
      );
  return {
    nodes,
    flags: parser.flags,
    groupNames: parser.groupNames,
    groupWidths: parser.groupWidths,
    width: patternWidth(nodes, parser.groupWidths),
    warnings: parser.warnings,
  };
}
