import { decodePythonUtf8 as decodeTomlBytes } from "./utf8";
export { decodePythonUtf8 as decodeTomlBytes } from "./utf8";
import { readFile } from "./helper-files";
import { parseToml } from "./toml";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";

function readTomlFile(path: string): Buffer {
  if (process.platform !== "win32") return readFile(path);
  if (path.includes("\0")) throw new Error("embedded null byte");
  return windowsFileSystem(windowsBinding()).readFileCrt(widePath(path));
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
