import { readFileSync } from "node:fs";
import {
  populateUnsealedTargetBinding,
  populateUnsealedManifestEnvelope,
  populateUnsealedArtifactEnvelope,
  normalizeUnsealedOpenQuestions,
  normalizeUnsealedDeepRepositoryInventoryStrategy,
  validateCompletionBinding,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/contract-completion-binding";
import {
  parseJson,
  stringifyJson,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/python-json";
import { timestamp } from "../../../../plugins/codex-security/mcp-app/src/helpers/utc-timestamp";

type Table = Record<string, unknown>;
export interface Request {
  operation:
    | "target"
    | "manifest"
    | "artifacts"
    | "validate"
    | "complete"
    | "questions"
    | "strategy";
  source: string;
  startedAt?: string | null;
  microseconds?: string;
  failClock?: boolean;
  mutations?: { path: (string | number)[]; value: unknown }[];
}
export interface Response {
  after: string;
  error?: string;
  kind?: string;
  events: string[];
}
const requests = JSON.parse(readFileSync(0, "utf8")) as Request[];
const responses = requests.map((request): Response => {
  const payload = parseJson(request.source) as Table;
  const manifest = payload["manifest"] as Table,
    findings = payload["findings"] as Table,
    coverage = payload["coverage"] as Table,
    binding = payload["binding"] as Table | null;
  const previous = process.env["CODEX_SECURITY_STARTED_AT"],
    events: string[] = [];
  if (request.startedAt == null)
    delete process.env["CODEX_SECURITY_STARTED_AT"];
  else process.env["CODEX_SECURITY_STARTED_AT"] = request.startedAt;
  const now = () => {
    events.push("clock");
    if (request.failClock) throw new Error("synthetic clock failure");
    return timestamp(
      BigInt(request.microseconds ?? "1767225600123456"),
    ).replace("+00:00", "Z");
  };
  try {
    switch (request.operation) {
      case "target":
        populateUnsealedTargetBinding(payload["target"] as Table, binding!);
        break;
      case "manifest":
        populateUnsealedManifestEnvelope(
          manifest,
          manifest["scan"] as Table,
          binding,
          now,
        );
        break;
      case "artifacts":
        populateUnsealedArtifactEnvelope(manifest, findings, coverage, binding);
        break;
      case "validate":
        validateCompletionBinding(manifest, findings, coverage, binding);
        break;
      case "complete":
        populateUnsealedManifestEnvelope(
          manifest,
          manifest["scan"] as Table,
          binding,
          now,
        );
        populateUnsealedArtifactEnvelope(manifest, findings, coverage, binding);
        validateCompletionBinding(manifest, findings, coverage, binding);
        break;
      case "questions":
        normalizeUnsealedOpenQuestions(coverage);
        break;
      case "strategy":
        normalizeUnsealedDeepRepositoryInventoryStrategy(
          coverage,
          payload["expected"] as string | null,
        );
        break;
    }
    for (const mutation of request.mutations ?? []) {
      let parent: unknown = payload;
      for (const key of mutation.path.slice(0, -1))
        parent = (parent as Table)[key];
      (parent as Table)[mutation.path.at(-1)!] = mutation.value;
    }
    return { after: stringifyJson(payload), events };
  } catch (error) {
    return {
      after: stringifyJson(payload),
      events,
      error: (error as Error).message,
      kind: (error as Error).constructor.name,
    };
  } finally {
    if (previous === undefined) delete process.env["CODEX_SECURITY_STARTED_AT"];
    else process.env["CODEX_SECURITY_STARTED_AT"] = previous;
  }
});
process.stdout.write(JSON.stringify(responses));
