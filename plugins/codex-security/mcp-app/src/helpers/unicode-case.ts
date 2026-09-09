import lowerMappings from "@unicode/unicode-15.0.0/Simple_Case_Mapping/Lowercase/symbols.js";
import upperMappings from "@unicode/unicode-15.0.0/Simple_Case_Mapping/Uppercase/symbols.js";
import specialLower from "@unicode/unicode-15.0.0/Special_Casing/Lowercase/symbols.js";
import specialUpper from "@unicode/unicode-15.0.0/Special_Casing/Uppercase/symbols.js";
import cased from "@unicode/unicode-15.0.0/Binary_Property/Cased/regex.js";
import caseIgnorable from "@unicode/unicode-15.0.0/Binary_Property/Case_Ignorable/regex.js";

// Python's lowercase mapping includes contextual final sigma and is Unicode15.
export function lowercase(value: string): string {
  const characters = Array.from(value);
  return characters
    .map((character, index) => {
      if (character === "Σ") {
        let before = index - 1,
          after = index + 1;
        while (before >= 0 && caseIgnorable.test(characters[before]!)) before--;
        while (
          after < characters.length &&
          caseIgnorable.test(characters[after]!)
        )
          after++;
        if (
          before >= 0 &&
          cased.test(characters[before]!) &&
          (after === characters.length || !cased.test(characters[after]!))
        )
          return "ς";
      }
      return (
        specialLower.get(character) ?? lowerMappings.get(character) ?? character
      );
    })
    .join("");
}

export function uppercase(value: string): string {
  return Array.from(
    value,
    (character) =>
      specialUpper.get(character) ?? upperMappings.get(character) ?? character,
  ).join("");
}
