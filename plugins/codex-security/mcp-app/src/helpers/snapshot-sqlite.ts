import { realpathSync } from "node:fs";
import { dirname } from "node:path";
import { Connection, filenameBytes } from "../../../native/sqlite.mjs";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsJoin,
  windowsParts,
} from "../../../native/windows-files.mjs";
import { sqliteBinding, windowsBinding } from "../native";
import { chmod, mkdir } from "./helper-files";
import { decodePosixBytes } from "./posix-path";
import { ArgumentError, print } from "./rank-worklists";
import { pythonRepr } from "./python-json";
import { resolvedPath } from "./resolve-path";
import { expandHome, parsedPath } from "./resolve-security-md";

function absolutePath(path: string): string {
  if (process.platform === "win32") {
    const [drive, root] = windowsParts(path);
    if (drive && root) return path;
    const cwd = pathText(
      windowsFileSystem(windowsBinding()).absolute(widePath(drive || ".")),
    );
    return parsedPath(windowsJoin(cwd, path));
  }
  if (path.startsWith("/")) return path;
  const cwd = decodePosixBytes(
    realpathSync.native(".", { encoding: "buffer" }),
  );
  return parsedPath(`${cwd}/${path}`);
}

export function fileUri(path: string): string {
  const drive = process.platform === "win32" ? windowsParts(path)[0] : "";
  const localDrive = drive.length === 2 && drive[1] === ":";
  const prefix = localDrive ? `file:///${drive}` : drive ? "file:" : "file://";
  const tail = localDrive ? path.slice(2) : path;
  const bytes = filenameBytes(
    process.platform === "win32" ? tail.replaceAll("\\", "/") : tail,
  );
  return (
    prefix +
    Array.from(bytes, (byte) =>
      /[A-Za-z0-9_.~/-]/u.test(String.fromCharCode(byte))
        ? String.fromCharCode(byte)
        : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`,
    ).join("")
  );
}

function positionalArguments(args: string[]): string[] | undefined {
  const positional: string[] = [],
    extra: string[] = [];
  let options = true;
  for (const arg of args) {
    if (options && arg === "--") {
      options = false;
      continue;
    }
    const [option] = arg.split("=", 1);
    if (
      options &&
      (arg.startsWith("-h") ||
        (option!.startsWith("--") && "--help".startsWith(option!)))
    ) {
      if (arg.startsWith("--") ? arg.includes("=") : /^-h+=/u.test(arg))
        throw new ArgumentError(
          `argument -h/--help: ignored explicit argument ${pythonRepr(arg.slice(arg.indexOf("=") + 1))}`,
        );
      return;
    }
    const optional =
      options &&
      arg.startsWith("-") &&
      arg !== "-" &&
      !arg.includes(" ") &&
      !/^-(?:\p{Decimal_Number}+|\p{Decimal_Number}*\.\p{Decimal_Number}+)\n?$/u.test(
        arg,
      );
    if (optional || positional.length === 2) extra.push(arg);
    else positional.push(arg);
  }
  if (positional.length < 2)
    throw new ArgumentError(
      `the following arguments are required: ${["source", "destination"].slice(positional.length).join(", ")}`,
    );
  if (extra.length)
    throw new ArgumentError(`unrecognized arguments: ${extra.join(" ")}`);
  return positional;
}

export async function snapshotSqliteCommand(
  args: string[],
  posixHome = process.env["HOME"],
): Promise<number> {
  const usage =
    "usage: launch_codex_security_mcp[.cmd] --helper snapshot-sqlite [-h] source destination";
  try {
    const values = positionalArguments(args);
    if (values === undefined) {
      print(
        `${usage}\n\nCreate a transactionally consistent SQLite database snapshot.\n\npositional arguments:\n  source\n  destination\n\noptions:\n  -h, --help  show this help message and exit`,
      );
      return 0;
    }
    const expanded = (value: string) =>
      parsedPath(expandHome(parsedPath(value), posixHome));
    const source = resolvedPath(expanded(values[0]!));
    const destination = absolutePath(expanded(values[1]!));
    mkdir(dirname(destination));
    const native = sqliteBinding();
    const reader = new Connection(native, `${fileUri(source)}?mode=ro`, {
      uri: true,
    });
    try {
      const writer = new Connection(native, destination);
      try {
        await reader.backup(writer);
      } finally {
        writer.close();
      }
    } finally {
      reader.close();
    }
    chmod(destination, 0o600);
    return 0;
  } catch (error) {
    if (error instanceof ArgumentError) print(usage, true);
    print(`snapshot-sqlite: error: ${(error as Error).message}`, true);
    return error instanceof ArgumentError ? 2 : 1;
  }
}
