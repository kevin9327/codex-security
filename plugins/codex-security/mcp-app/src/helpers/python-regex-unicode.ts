import names from "@unicode/unicode-15.0.0/Names/index.js";
import control from "@unicode/unicode-15.0.0/Names/Control/index.js";
import correction from "@unicode/unicode-15.0.0/Names/Correction/index.js";
import figment from "@unicode/unicode-15.0.0/Names/Figment/index.js";
import alternate from "@unicode/unicode-15.0.0/Names/Alternate/index.js";
import abbreviation from "@unicode/unicode-15.0.0/Names/Abbreviation/index.js";
import start from "@unicode/unicode-15.0.0/Binary_Property/XID_Start/regex.js";
import continuation from "@unicode/unicode-15.0.0/Binary_Property/XID_Continue/regex.js";
export { default as patternLetter } from "@unicode/unicode-15.0.0/General_Category/Letter/regex.js";

export function patternIdentifier(name: string): boolean {
  const characters = Array.from(name);
  return (
    characters.length > 0 &&
    (characters[0] === "_" || start.test(characters[0]!)) &&
    characters.slice(1).every((character) => continuation.test(character))
  );
}

let byName: Map<string, number> | undefined;
export function patternCharacterName(name: string): number | undefined {
  if (!byName) {
    byName = new Map();
    for (const [code, name] of names)
      if (name === name.toUpperCase()) byName.set(name, code);
    for (const aliases of [
      control,
      correction,
      figment,
      alternate,
      abbreviation,
    ])
      for (const [code, names] of Object.entries(aliases))
        for (const name of names) byName.set(name, Number(code));
    const leading = "G GG N D DD R M B BB S SS  J JJ C K T P H".split(" ");
    const vowel =
      "A AE YA YAE EO E YEO YE O WA WAE OE YO U WEO WE WI YU EU YI I".split(
        " ",
      );
    const trailing =
      " G GG GS N NJ NH D L LG LM LB LS LT LP LH M B BS S SS NG J C K T P H".split(
        " ",
      );
    for (const [l, first] of leading.entries())
      for (const [v, middle] of vowel.entries())
        for (const [t, last] of trailing.entries())
          byName.set(
            `HANGUL SYLLABLE ${first}${middle}${last}`,
            0xac00 + (l * 21 + v) * 28 + t,
          );
  }
  if (!/^[\x00-\x7f]*$/.test(name)) return undefined;
  const unified = /^CJK UNIFIED IDEOGRAPH-([0-9A-F]{4,5})$/.exec(name);
  if (unified) {
    const code = Number.parseInt(unified[1]!, 16);
    return names.get(code)?.startsWith("CJK Ideograph") ? code : undefined;
  }
  // Python's algorithmic names require uppercase; other names and aliases do not.
  const upper = name.toUpperCase();
  if (upper.startsWith("HANGUL SYLLABLE ") && name !== upper) return undefined;
  return byName.get(upper);
}
