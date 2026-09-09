import { constants } from "node:os";
import { getSystemErrorName } from "node:util";
import { processBinding } from "./native";
import { decodePosixBytes, encodePosixPath } from "./helpers/posix-path";

const repositoryEnvironment = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
];
const windows = process.platform === "win32";
const encodeArgument = (value: string) =>
  windows ? Buffer.from(value, "utf16le") : encodePosixPath(value);

export interface GitContext {
  gitDir?: string;
  workTree?: string;
}

export interface GitResult {
  args: string[];
  returnCode: number;
  stdout: Buffer;
  stderr: Buffer;
}

/** Run Git with the workbench's repository isolation and raw byte streams. */
export function gitCommand(
  target: string,
  args: readonly string[],
  options: GitContext & { input?: Buffer; stdoutPath?: string } = {},
): GitResult {
  if ((options.gitDir === undefined) !== (options.workTree === undefined))
    throw new Error("git_dir and work_tree must be provided together");
  const command = [
    "git",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "i18n.logOutputEncoding=UTF-8",
    "-C",
    target,
  ];
  if (options.gitDir !== undefined && options.workTree !== undefined)
    command.push("--git-dir", options.gitDir, "--work-tree", options.workTree);
  command.push(...args);
  const result = processBinding().rawProcess({
    program: encodeArgument(command[0]!),
    args: command.slice(1).map(encodeArgument),
    input: options.input,
    stdoutPath:
      options.stdoutPath === undefined
        ? undefined
        : encodeArgument(options.stdoutPath),
    environment: [
      ...repositoryEnvironment.map((name) => ({
        name: encodeArgument(name),
        value: null,
      })),
      {
        name: encodeArgument("GIT_LITERAL_PATHSPECS"),
        value: encodeArgument("1"),
      },
    ],
  });
  if (result.error !== 0) {
    // Git is optional for directory scans, matching the Python probe's ENOENT result.
    if (
      windows
        ? result.error === 2 || result.error === 3
        : result.error === constants.errno.ENOENT
    )
      return {
        args: command,
        returnCode: 127,
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
      };
    const code = windows
      ? `Windows error ${result.error}`
      : getSystemErrorName(-result.error);
    throw Object.assign(
      new Error(`Could not start Git: ${code}`),
      windows ? { winerror: result.error } : { errno: result.error, code },
    );
  }
  return {
    args: command,
    returnCode: result.returnCode!,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

export function gitBytes(
  target: string,
  args: readonly string[],
  context: GitContext = {},
): Buffer | null {
  const result = gitCommand(target, args, context);
  return result.returnCode === 0 ? result.stdout : null;
}

export function gitOutput(
  target: string,
  args: readonly string[],
  context: GitContext = {},
): string | null {
  const result = gitCommand(target, args, context);
  const output = decodeFilename(result.stdout).replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );
  return result.returnCode === 0 && output !== "" ? output : null;
}

/** Read ordered raw blobs with one NUL-framed cat-file request. */
export function gitBlobBytes(
  target: string,
  names: readonly string[],
  context: GitContext = {},
): (Buffer | null)[] {
  if (names.length === 0) return [];
  const input = Buffer.concat(
    names.flatMap((name) => [encodeFilename(name), Buffer.from([0])]),
  );
  const result = gitCommand(target, ["cat-file", "--batch", "-Z"], {
    ...context,
    input,
  });
  if (result.returnCode !== 0) return names.map(() => null);
  try {
    return decodeGitBatchBlobs(result.stdout, names.length);
  } catch {
    return names.map(() => null);
  }
}

export function decodeGitBatchBlobs(
  output: Buffer,
  count: number,
): (Buffer | null)[] {
  const blobs: (Buffer | null)[] = [];
  let offset = 0;
  for (let index = 0; index < count; index++) {
    const terminator = output.indexOf(0, offset);
    if (terminator < 0) throw new Error("missing NUL terminator");
    const header = output.subarray(offset, terminator).toString("latin1");
    offset = terminator + 1;
    const last = header.lastIndexOf(" ");
    const previous = header.lastIndexOf(" ", last - 1);
    if (previous < 0 || header.slice(previous + 1, last) !== "blob") {
      blobs.push(null);
      continue;
    }
    const sizeText = header.slice(last + 1);
    if (!/^[\t\n\v\f\r ]*[+-]?[0-9](?:_?[0-9])*[\t\n\v\f\r ]*$/u.test(sizeText))
      throw new Error("invalid blob size");
    const size = BigInt(sizeText.replaceAll("_", "").trim());
    if (size < 0n) throw new Error("invalid blob size");
    const end = BigInt(offset) + size;
    if (end >= BigInt(output.length) || output[Number(end)] !== 0)
      throw new Error("missing blob terminator");
    blobs.push(output.subarray(offset, Number(end)));
    offset = Number(end) + 1;
  }
  return blobs;
}

// os.fsencode/fsdecode use UTF-8 surrogatepass on Windows; process arguments are UTF-16.
export function encodeFilename(value: string): Buffer {
  if (!windows) return encodePosixPath(value);
  return Buffer.concat(
    value.split(/([\ud800-\udfff])/u).map((part) => {
      const point = part.charCodeAt(0);
      return part.length === 1 && point >= 0xd800 && point <= 0xdfff
        ? Buffer.from([
            0xe0 | (point >> 12),
            0x80 | ((point >> 6) & 0x3f),
            0x80 | (point & 0x3f),
          ])
        : Buffer.from(part);
    }),
  );
}

export function decodeFilename(bytes: Buffer): string {
  if (!windows) return decodePosixBytes(bytes);
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let value = "";
  let start = 0;
  for (let index = 0; index + 2 < bytes.length; index++) {
    const second = bytes[index + 1]!;
    const third = bytes[index + 2]!;
    if (
      bytes[index] === 0xed &&
      second >= 0xa0 &&
      second <= 0xbf &&
      third >= 0x80 &&
      third <= 0xbf
    ) {
      value += utf8.decode(bytes.subarray(start, index));
      value += String.fromCharCode(
        0xd000 | ((second & 0x3f) << 6) | (third & 0x3f),
      );
      index += 2;
      start = index + 1;
    }
  }
  return value + utf8.decode(bytes.subarray(start));
}
