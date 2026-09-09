import { regexBinding } from "../native";
import { compilePythonPattern } from "./python-regex-compiler";
import { parsePythonPattern } from "./python-regex-parser";

/** Full-match a string with the scan contract's Python pattern semantics. */
export function fullPatternMatch(pattern: string, value: string): boolean {
  const code = compilePythonPattern(parsePythonPattern(pattern));
  const units = new Uint16Array(value.length);
  for (let index = 0; index < value.length; index++)
    units[index] = value.charCodeAt(index);
  return regexBinding().regexFullMatch(code, units);
}
