import { isUtf8 } from "node:buffer";
import { readFile } from "./helper-files";
import { parseToml } from "./toml";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";

function readTomlFile(path: string): Buffer {
  if (process.platform !== "win32") return readFile(path);
  if (path.includes("\0")) throw new Error("embedded null byte");
  return windowsFileSystem(windowsBinding()).readFileCrt(widePath(path));
}

export function decodeTomlBytes(bytes: Buffer): string {
  if (isUtf8(bytes)) return bytes.toString("utf8");
  for (let start = 0; start < bytes.length; ) {
    const byte = bytes[start]!;
    if (byte < 0x80) {
      start++;
      continue;
    }
    const length =
      byte >= 0xc2 && byte <= 0xdf
        ? 2
        : byte >= 0xe0 && byte <= 0xef
          ? 3
          : byte >= 0xf0 && byte <= 0xf4
            ? 4
            : 0;
    let end = start + 1;
    let reason = length ? "" : "invalid start byte";
    for (let i = 1; i < length; i++) {
      if (start + i === bytes.length) {
        reason = "unexpected end of data";
        break;
      }
      const next = bytes[start + i]!;
      const minimum =
        i === 1 && byte === 0xe0
          ? 0xa0
          : i === 1 && byte === 0xf0
            ? 0x90
            : 0x80;
      const maximum =
        i === 1 && byte === 0xed
          ? 0x9f
          : i === 1 && byte === 0xf4
            ? 0x8f
            : 0xbf;
      if (next < minimum || next > maximum) {
        reason = "invalid continuation byte";
        break;
      }
      end++;
    }
    if (reason) {
      const location =
        end === start + 1
          ? `byte 0x${byte.toString(16).padStart(2, "0")} in position ${start}`
          : `bytes in position ${start}-${end - 1}`;
      throw new Error(`'utf-8' codec can't decode ${location}: ${reason}`);
    }
    start += length;
  }
  return bytes.toString("utf8");
}

export function readToml(
  path: string,
  required: boolean,
  parseInteger?: (source: string) => bigint,
) {
  try {
    return parseToml(decodeTomlBytes(readTomlFile(path)), parseInteger);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EISDIR")
      Object.assign(error as Error, { path });
    if (!required && (error as NodeJS.ErrnoException).code === "ENOENT")
      return Object.create(null) as Record<string, unknown>;
    throw error;
  }
}
