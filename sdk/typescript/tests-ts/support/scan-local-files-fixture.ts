import { createHash } from "node:crypto";
import fs from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { unixBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  decodePosixBytes,
  encodePosixPath,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/posix-path";
import {
  openScanLocalFile,
  readScanLocalBytes,
  removeScanLocalFileIfExists,
  requirePortableRelativePath,
  requireSafeRelativePath,
  requireScanDirectory,
  scanRootIdentity,
  sha256ScanLocalFile,
  validateScanLocalOutputPath,
  writeScanLocalBytes,
  type ScanLocalReader,
  type ScanRootIdentity,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-local-files";

export type Action =
  | { operation: "root" | "identity"; path?: string }
  | { operation: "mkdir" | "fifo"; path: string }
  | { operation: "file"; path: string; value?: string; size?: number }
  | { operation: "link"; path: string; target: string; directory?: boolean }
  | { operation: "rename"; path: string; destination: string }
  | { operation: "metadata" | "names"; path: string }
  | { operation: "chmod"; path: string; mode: number }
  | {
      operation: "write";
      relative: string;
      value?: string;
      size?: number;
      external?: boolean;
      expected?: boolean;
    }
  | { operation: "read" | "hash" | "open" | "remove"; relative: string }
  | { operation: "read-held" | "close" }
  | { operation: "validate"; path: string }
  | {
      operation: "race";
      value: "parent" | "root" | "leaf" | "flush" | "collision" | null;
    };
export type Request =
  | {
      mode: "paths";
      cases: { value: string; portable?: boolean; allowDot?: boolean }[];
    }
  | { mode: "files"; root: string; actions: Action[] };
const request = JSON.parse(fs.readFileSync(0, "utf8")) as Request;
const bytes = (value: string) =>
  process.platform === "win32" ? value : encodePosixPath(value);
const digest = (value: Buffer) =>
  createHash("sha256").update(value).digest("hex");
function result(action: () => unknown): unknown {
  try {
    return action() ?? null;
  } catch (error) {
    const value = error as Error & { code?: string };
    return {
      error: value.message,
      kind: value.constructor.name,
      code: value.code ?? null,
    };
  }
}
function readAll(reader: ScanLocalReader): { length: number; digest: string } {
  const chunks: Buffer[] = [];
  for (;;) {
    const chunk = Buffer.alloc(32 * 1024),
      count = reader.read(chunk);
    if (!count) {
      const value = Buffer.concat(chunks);
      return { length: value.length, digest: digest(value) };
    }
    chunks.push(chunk.subarray(0, count));
  }
}
function main() {
  if (request.mode === "paths")
    return request.cases.map((item) =>
      result(() =>
        (item.portable ? requirePortableRelativePath : requireSafeRelativePath)(
          item.value,
          "path",
          item.allowDot,
        ),
      ),
    );
  const root = request.root,
    parent = join(root, ".."),
    outside = join(parent, "outside"),
    moved = join(parent, "moved");
  fs.mkdirSync(bytes(root), { recursive: true });
  fs.mkdirSync(bytes(outside), { recursive: true });
  let identity: ScanRootIdentity | undefined, held: ScanLocalReader | undefined;
  let race: "parent" | "root" | "leaf" | "flush" | "collision" | null = null;
  const native = process.platform === "win32" ? undefined : unixBinding();
  const openAt = native?.openAt,
    open = fs.openSync,
    sync = fs.fsyncSync;
  if (native !== undefined)
    native.openAt = (directory, name, flags, mode) => {
      const part = decodePosixBytes(name);
      if (
        race === "leaf" &&
        part === "data" &&
        !(flags & fs.constants.O_DIRECTORY)
      ) {
        race = null;
        fs.renameSync(bytes(join(root, "data")), bytes(join(root, "old-data")));
        fs.writeFileSync(bytes(join(root, "data")), "swapped");
      }
      if (race === "collision" && flags & fs.constants.O_EXCL) {
        race = null;
        fs.writeFileSync(bytes(join(root, part)), "collision");
      }
      const value = openAt!(directory, name, flags, mode);
      if (
        race === "parent" &&
        part === "nested" &&
        flags & fs.constants.O_DIRECTORY &&
        !value.errno
      ) {
        race = null;
        fs.renameSync(bytes(join(root, "nested")), bytes(moved));
        fs.symlinkSync(outside, bytes(join(root, "nested")), "dir");
      }
      return value;
    };
  fs.openSync = (path, flags, mode) => {
    const text = Buffer.isBuffer(path) ? decodePosixBytes(path) : String(path);
    if (race === "root" && text === root) {
      race = null;
      fs.renameSync(bytes(root), bytes(moved));
      fs.mkdirSync(bytes(root));
    }
    return open(path, flags, mode);
  };
  fs.fsyncSync = (fd) => {
    if (race === "flush") {
      race = null;
      throw Object.assign(new Error("synthetic flush failure"), {
        errno: -5,
        code: "EIO",
      });
    }
    return sync(fd);
  };
  try {
    return request.actions.map((action) =>
      result(() => {
        switch (action.operation) {
          case "root":
            return requireScanDirectory(action.path ?? root);
          case "identity": {
            const current = scanRootIdentity(action.path ?? root);
            identity = current[1];
            return { root: current[0], identity: identity.map(String) };
          }
          case "mkdir":
            fs.mkdirSync(bytes(action.path), { recursive: true });
            return null;
          case "file":
            fs.writeFileSync(
              bytes(action.path),
              action.size === undefined
                ? Buffer.from(action.value ?? "")
                : Buffer.alloc(action.size, 0xa5),
            );
            return null;
          case "fifo": {
            const child = spawnSync("mkfifo", [action.path]);
            if (child.status !== 0) throw new Error(child.stderr.toString());
            return null;
          }
          case "link":
            fs.symlinkSync(
              action.target,
              bytes(action.path),
              action.directory
                ? process.platform === "win32"
                  ? "junction"
                  : "dir"
                : "file",
            );
            return null;
          case "rename":
            fs.renameSync(bytes(action.path), bytes(action.destination));
            return null;
          case "chmod":
            fs.chmodSync(bytes(action.path), action.mode);
            return null;
          case "metadata": {
            const value = fs.lstatSync(bytes(action.path), { bigint: true });
            return {
              mode: Number(value.mode & 0o777n),
              size: String(value.size),
              inode: String(value.ino),
              file: value.isFile(),
              link: value.isSymbolicLink(),
            };
          }
          case "names":
            return fs.readdirSync(bytes(action.path)).sort();
          case "write":
            writeScanLocalBytes(
              root,
              action.relative,
              action.size === undefined
                ? Buffer.from(action.value ?? "")
                : Buffer.alloc(action.size, 0xa5),
              {
                externalName: action.external,
                expectedRootIdentity: action.expected ? identity : undefined,
              },
            );
            return null;
          case "read": {
            const value = readScanLocalBytes(
              root,
              action.relative,
              "read artifact",
            );
            return { length: value.length, digest: digest(value) };
          }
          case "hash":
            return sha256ScanLocalFile(root, action.relative, "hash artifact");
          case "open":
            held = openScanLocalFile(root, action.relative, "read artifact");
            return String(held.size());
          case "read-held":
            return readAll(held!);
          case "close":
            held?.close();
            held = undefined;
            return null;
          case "remove":
            removeScanLocalFileIfExists(root, action.relative);
            return null;
          case "validate":
            validateScanLocalOutputPath(root, action.path, "output");
            return null;
          case "race":
            race = action.value;
            return null;
        }
      }),
    );
  } finally {
    fs.openSync = open;
    fs.fsyncSync = sync;
    if (native !== undefined) native.openAt = openAt!;
    held?.close();
  }
}
process.stdout.write(JSON.stringify(main()));
