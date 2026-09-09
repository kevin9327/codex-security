import { readFileSync } from "node:fs";
import {
  createPublicationCopy,
  finishStagedFile,
  promoteStagedFile,
  publicationMatchesSnapshot,
  rollbackStagedFile,
  type StagedFilePromotion,
} from "../../../../plugins/codex-security/mcp-app/src/workbench-deep-publication";
import { WorkbenchValidationError } from "../../../../plugins/codex-security/mcp-app/src/workbench-validation";
import { filesystemErrorMessage } from "../../../../plugins/codex-security/mcp-app/src/helpers/file-errors";

export interface Request {
  kind: "promote" | "rollback" | "finish" | "copy" | "matches";
  source?: string;
  destination?: string;
  sourceIsPath?: boolean;
  destinationIsPath?: boolean;
  promotion?: StagedFilePromotion;
}
export interface Response {
  result?: StagedFilePromotion | boolean | null;
  error?: string;
  systemExit?: boolean;
}
let promotion: StagedFilePromotion | undefined;
function run(request: Request): Response {
  try {
    let result: Response["result"] = null;
    switch (request.kind) {
      case "promote":
        promotion = promoteStagedFile(
          request.source!,
          request.destination!,
          () => "00000000-0000-4000-8000-000000000000",
        );
        result = promotion;
        break;
      case "rollback":
        rollbackStagedFile(request.promotion ?? promotion!);
        break;
      case "finish":
        finishStagedFile(request.promotion ?? promotion!);
        break;
      case "copy":
        createPublicationCopy(
          request.source!,
          request.destination!,
          request.sourceIsPath,
          request.destinationIsPath,
        );
        break;
      case "matches":
        result = publicationMatchesSnapshot(
          request.source!,
          request.destination!,
        );
        break;
    }
    return { result };
  } catch (error) {
    return {
      error: (error as Error).message || filesystemErrorMessage(error),
      systemExit: error instanceof WorkbenchValidationError,
    };
  }
}
console.log(
  JSON.stringify((JSON.parse(readFileSync(0, "utf8")) as Request[]).map(run)),
);
