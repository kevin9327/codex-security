import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import {
  compactPreviewLine,
  fitPreviewLines,
  previewFor,
  previewForBytes,
  pythonOutline,
  selectPreviewLines,
  structuralOutline,
  truncateUtf8,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/rank-preview";
import { writeFile } from "../../../../plugins/codex-security/mcp-app/src/helpers/helper-files";
import { decodePosixBytes } from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";

export interface PreviewRequest {
  action?:
    | "bytes"
    | "file"
    | "outline"
    | "python"
    | "lines"
    | "compact"
    | "truncate"
    | "decode";
  path?: string;
  text?: string;
  hex?: string;
  budget?: number;
  maxRead?: number;
  size?: number;
  lines?: string[];
  countReads?: boolean;
  offset?: number;
}
export interface PreviewResult {
  value?: unknown;
  error?: string;
  reads?: number[];
}

const requests = JSON.parse(fs.readFileSync(0, "utf8")) as PreviewRequest[];
const results = requests.map((request): PreviewResult => {
  const path = request.path ?? "source.txt",
    text = request.text ?? "";
  const bytes =
    request.hex === undefined
      ? Buffer.from(text)
      : Buffer.from(request.hex, "hex");
  const data = bytes.subarray(request.offset ?? 0);
  const budget = request.budget ?? 4096;
  const reads: number[] = [];
  const originalRead = fs.readSync;
  try {
    if (
      request.action === "file" &&
      (request.hex !== undefined || request.text !== undefined)
    ) {
      writeFile(path, [data]);
      if (request.size !== undefined) fs.truncateSync(path, request.size);
    }
    if (request.countReads && process.platform !== "win32") {
      fs.readSync = ((descriptor: number, buffer: Buffer) => {
        reads.push(buffer.length);
        return originalRead(descriptor, buffer);
      }) as typeof fs.readSync;
      syncBuiltinESMExports();
    }
    const value =
      request.action === "file"
        ? previewFor(path, budget, request.maxRead)
        : request.action === "outline"
          ? structuralOutline(path, text)
          : request.action === "python"
            ? pythonOutline(text)
            : request.action === "compact"
              ? compactPreviewLine(text)
              : request.action === "decode"
                ? decodePosixBytes(data)
                : request.action === "truncate"
                  ? truncateUtf8(text, budget)
                  : request.action === "lines"
                    ? fitPreviewLines(
                        selectPreviewLines(request.lines ?? []),
                        budget,
                      )
                    : previewForBytes(path, data, budget);
    return { value, ...(request.countReads ? { reads } : {}) };
  } catch (error) {
    return { error: String(error) };
  } finally {
    fs.readSync = originalRead;
    syncBuiltinESMExports();
  }
});
process.stdout.write(JSON.stringify(results));
