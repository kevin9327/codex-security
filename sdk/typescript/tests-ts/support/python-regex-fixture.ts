import { readFileSync } from "node:fs";
import { parsePythonPattern } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-regex-parser";
import {
  PatternError,
  validateLookbehindWidths,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-regex-ir";

export interface PatternCase {
  pattern: string;
  validateLookbehind?: boolean;
}
export function parseCase(item: PatternCase): unknown {
  try {
    const parsed = parsePythonPattern(item.pattern);
    if (item.validateLookbehind) validateLookbehindWidths(parsed);
    return {
      nodes: parsed.nodes,
      flags: parsed.flags,
      groupNames: [...parsed.groupNames],
      groupWidths: parsed.groupWidths.map(
        (width) => width?.map(String) ?? null,
      ),
      width: parsed.width.map(String),
      warnings: parsed.warnings,
    };
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    return {
      type: error.name,
      message: error.message,
      ...(error instanceof PatternError
        ? {
            msg: error.msg,
            pos: error.pos,
            lineno: error.lineno,
            colno: error.colno,
          }
        : {}),
    };
  }
}

const cases = JSON.parse(readFileSync(0, "utf8")) as PatternCase[];
process.stdout.write(JSON.stringify(cases.map(parseCase)));
