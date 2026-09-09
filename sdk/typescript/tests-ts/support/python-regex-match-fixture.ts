import { readFileSync } from "node:fs";
import { fullPatternMatch } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-regex";
import { PatternError } from "../../../../plugins/codex-security/mcp-app/src/helpers/python-regex-ir";

export interface MatchCase {
  pattern: string;
  value: string;
}
export interface MatchResult {
  matched?: boolean;
  error?: string;
  kind?: string;
  position?: number | null;
}
const requests: MatchCase[] = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(
  JSON.stringify(
    requests.map(({ pattern, value }): MatchResult => {
      try {
        return { matched: fullPatternMatch(pattern, value) };
      } catch (error) {
        return {
          error: (error as Error).message,
          kind: (error as Error).name,
          ...(error instanceof PatternError ? { position: error.pos } : {}),
        };
      }
    }),
  ),
);
