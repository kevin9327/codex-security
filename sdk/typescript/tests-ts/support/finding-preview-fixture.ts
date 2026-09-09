import { readFileSync } from "node:fs";
import {
  boundedCodeEvidence,
  boundedFindingDetails,
  boundedFindingSection,
  boundedJsonText,
  boundedJsonValue,
  mergedCodeEvidence,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/finding-preview";
import { mergedRootCause } from "../../../../plugins/codex-security/mcp-app/src/helpers/finding-root-cause";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";

export interface Request {
  action?:
    | "details"
    | "root"
    | "evidence"
    | "merge-evidence"
    | "text"
    | "value"
    | "section";
  source: string;
  maximum?: number;
  depth?: number;
  maxDepth?: number;
  priority?: string[];
  reserved?: [string[], number][];
}
export interface Response {
  result?: string;
  remaining?: number;
  unchanged?: boolean;
  error?: string;
}

const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
const responses = requests.map((request): Response => {
  try {
    const value = parseJson(request.source);
    const before = stringifyJson(value, { compact: true });
    const budget: [number] = [request.maximum ?? 16_000];
    let result: unknown;
    switch (request.action ?? "details") {
      case "root":
        result = mergedRootCause(value as Record<string, unknown>);
        break;
      case "evidence":
        result = boundedCodeEvidence(value);
        break;
      case "merge-evidence":
        result = mergedCodeEvidence(value as Record<string, unknown>);
        break;
      case "text":
        result = boundedJsonText(value as string, budget[0]);
        break;
      case "value":
        result = boundedJsonValue(
          value,
          budget,
          request.depth ?? 0,
          request.maxDepth ?? 4,
        );
        break;
      case "section":
        result = boundedFindingSection(
          value,
          budget[0],
          request.priority ?? [],
          request.reserved ?? [],
        );
        break;
      case "details":
        result = boundedFindingDetails(value);
        break;
    }
    return {
      result: stringifyJson(result, { compact: true }),
      ...(request.action === "value" ? { remaining: budget[0] } : {}),
      unchanged: before === stringifyJson(value, { compact: true }),
    };
  } catch (error) {
    return { error: (error as Error).message };
  }
});
process.stdout.write(JSON.stringify(responses));
