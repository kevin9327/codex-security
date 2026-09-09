import decimalDigit from "@unicode/unicode-15.0.0/General_Category/Decimal_Number/regex.js";
import { pythonRepr } from "./python-json";
import { ArgumentError } from "./rank-worklists";

// Preserve the existing argparse float converter, including decimal Unicode digits.
export function workbenchFloatArgument(value: string, option: string): number {
  const text = Array.from(
    value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, ""),
    (character) => {
      if (!decimalDigit.test(character)) return character;
      const point = character.codePointAt(0)!;
      let start = point;
      while (decimalDigit.test(String.fromCodePoint(start - 1))) start--;
      return String((point - start) % 10);
    },
  ).join("");
  if (
    !/^[+-]?(?:inf(?:inity)?|nan|(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:e[+-]?\d(?:_?\d)*)?)$/i.test(
      text,
    )
  )
    throw new ArgumentError(
      `argument --${option}: invalid float value: ${pythonRepr(value)}`,
    );
  if (/^[+-]?inf/i.test(text))
    return text.startsWith("-") ? -Infinity : Infinity;
  if (/^[+-]?nan$/i.test(text)) return NaN;
  return Number(text.replaceAll("_", ""));
}
