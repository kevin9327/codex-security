import { win32 } from "node:path";
import type {
  WindowsBinding,
  WindowsHandle,
} from "../../../../plugins/codex-security/native/windows-binding.mjs";
import { windowsFlags as flags } from "../../../../plugins/codex-security/native/windows-flags.mjs";
import {
  pathText,
  widePath,
} from "../../../../plugins/codex-security/native/windows-files.mjs";

interface Entry {
  path: string;
  id: bigint;
  directory: boolean;
  bytes: Buffer;
  target?: string;
}
interface Opened {
  entry: Entry;
  access: number;
  share: number;
  closed: boolean;
  position: number;
}
export interface ModelOptions {
  shortRead?: number;
  shortWrite?: number;
  noWriteProgress?: boolean;
  writeError?: number;
  flushError?: number;
  renameError?: number;
  dispositionError?: number;
  collide?: number;
  replaceRootBeforeLock?: boolean;
  raceMoves?: boolean;
  finalMismatchAfterRename?: boolean;
  comparisonOpenError?: number;
  readError?: number;
}
const unavailable = (): never => {
  throw new Error("Unexpected model operation");
};
const key = (path: string) =>
  win32.normalize(path).toLowerCase().replace(/\\$/u, "") || "\\";
const plain = (path: Buffer) =>
  pathText(path)
    .replace(/^\\\\\?\\UNC\\/u, "\\\\")
    .replace(/^\\\\\?\\/u, "");

/** A Win32 sharing/handle model; it does not claim to execute Windows. */
export class WindowsScanModel {
  readonly entries = new Map<string, Entry>();
  readonly held: Opened[] = [];
  readonly events: { operation: string; path?: string; size?: number }[] = [];
  readonly options: ModelOptions;
  blockedMoves = 0;
  rootReplaced = false;
  private nextId = 1n;
  private renamed = false;
  constructor(options: ModelOptions = {}) {
    this.options = { ...options };
    for (const path of ["C:\\", "C:\\work", "C:\\work\\scan", "C:\\outside"])
      this.add(path, true);
    this.add("C:\\outside\\kept", false, Buffer.from("outside"));
  }
  add(
    path: string,
    directory: boolean,
    bytes = Buffer.alloc(0),
    target?: string,
  ): Entry {
    const entry: Entry = {
      path,
      id: this.nextId++,
      directory,
      bytes,
      ...(target === undefined ? {} : { target }),
    };
    this.entries.set(key(path), entry);
    return entry;
  }
  replaceRoot(): void {
    this.add("C:\\work\\scan", true);
  }
  attemptMove(path: string): boolean {
    if (
      this.held.some(
        (held) =>
          !held.closed &&
          key(held.entry.path) === key(path) &&
          !(held.share & flags.FILE_SHARE_DELETE),
      )
    ) {
      this.blockedMoves++;
      return false;
    }
    const entry = this.entries.get(key(path));
    if (entry !== undefined) {
      this.entries.delete(key(path));
      entry.path += "-moved";
      this.entries.set(key(entry.path), entry);
    }
    return true;
  }
  private open(
    path: string,
    access: number,
    share: number,
    disposition: number,
    attributes: number,
  ): { error: number; handle?: WindowsHandle } {
    this.events.push({ operation: "open", path });
    if (
      this.options.replaceRootBeforeLock &&
      !this.rootReplaced &&
      key(path) === key("C:\\work\\scan") &&
      share === (flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE)
    ) {
      this.rootReplaced = true;
      this.replaceRoot();
    }
    if (this.options.raceMoves && /\.tmp$/u.test(path))
      this.attemptMove("C:\\work");
    if (disposition === flags.CREATE_NEW && (this.options.collide ?? 0) > 0) {
      this.options.collide!--;
      return { error: 80 };
    }
    if (
      this.options.comparisonOpenError &&
      access & flags.GENERIC_READ &&
      !/\.tmp$/u.test(path)
    )
      return { error: this.options.comparisonOpenError };
    let entry = this.entries.get(key(path));
    if (disposition === flags.CREATE_NEW) {
      if (entry !== undefined) return { error: 80 };
      if (!this.entries.has(key(win32.dirname(path)))) return { error: 3 };
      entry = this.add(path, false);
    }
    if (entry === undefined) return { error: 2 };
    if (
      entry.target !== undefined &&
      !(attributes & flags.FILE_FLAG_OPEN_REPARSE_POINT)
    )
      entry = this.entries.get(key(entry.target));
    if (entry === undefined) return { error: 2 };
    for (const held of this.held) {
      if (held.closed || held.entry !== entry) continue;
      for (const [mode, permission] of [
        [flags.GENERIC_READ, flags.FILE_SHARE_READ],
        [flags.GENERIC_WRITE, flags.FILE_SHARE_WRITE],
        [flags.DELETE, flags.FILE_SHARE_DELETE],
      ] as const) {
        if (
          (access & mode && !(held.share & permission)) ||
          (held.access & mode && !(share & permission))
        )
          return { error: 32 };
      }
    }
    const opened: Opened = { entry, access, share, closed: false, position: 0 };
    this.held.push(opened);
    let pendingDelete = false;
    const handle: WindowsHandle = {
      close: () => {
        if (!opened.closed) {
          opened.closed = true;
          if (pendingDelete) this.entries.delete(key(opened.entry.path));
          this.events.push({ operation: "close", path: opened.entry.path });
        }
        return 0;
      },
      attributes: () => ({
        error: 0,
        attributes:
          (entry.directory
            ? flags.FILE_ATTRIBUTE_DIRECTORY
            : flags.FILE_ATTRIBUTE_NORMAL) |
          (entry.target ? flags.FILE_ATTRIBUTE_REPARSE_POINT : 0),
        reparseTag: entry.target ? 0xa000000c : 0,
      }),
      identity: () => {
        const fileId = Buffer.alloc(16);
        fileId.writeBigUInt64LE(entry.id);
        return { error: 0, volume: "1", fileId };
      },
      fileType: () => ({ error: 0, value: 1 }),
      finalPath: (mode) => ({
        error: 0,
        path: widePath(
          this.renamed &&
            this.options.finalMismatchAfterRename &&
            !entry.directory
            ? "C:\\outside\\wrong"
            : mode === flags.FILE_NAME_OPENED
              ? entry.path
              : entry.target ?? entry.path,
        ),
      }),
      read: (buffer, offset, length) => {
        this.events.push({ operation: "read", path: entry.path, size: length });
        if (this.options.readError)
          return { error: this.options.readError, value: 0 };
        const size = Math.min(
          length,
          entry.bytes.length - opened.position,
          this.options.shortRead ?? Infinity,
        );
        entry.bytes.copy(
          buffer,
          offset,
          opened.position,
          opened.position + size,
        );
        opened.position += size;
        return { error: 0, value: size };
      },
      write: (buffer, offset, length) => {
        this.events.push({
          operation: "write",
          path: entry.path,
          size: length,
        });
        if (this.options.raceMoves) this.attemptMove(entry.path);
        if (this.options.writeError)
          return { error: this.options.writeError, value: 0 };
        if (this.options.noWriteProgress) return { error: 0, value: 0 };
        const size = Math.min(length, this.options.shortWrite ?? Infinity);
        entry.bytes = Buffer.concat([
          entry.bytes,
          buffer.subarray(offset, offset + size),
        ]);
        return { error: 0, value: size };
      },
      seek: unavailable,
      size: () => ({ error: 0, value: String(entry.bytes.length) }),
      setEndOfFile: unavailable,
      flush: () => {
        this.events.push({ operation: "flush" });
        return this.options.flushError ?? 0;
      },
      rename: (destination) => {
        this.events.push({ operation: "rename", path: plain(destination) });
        if (this.options.renameError) return this.options.renameError;
        this.entries.delete(key(entry.path));
        entry.path = plain(destination);
        this.entries.set(key(entry.path), entry);
        this.renamed = true;
        return 0;
      },
      setDisposition: (value) => {
        this.events.push({ operation: "disposition", path: entry.path });
        if (!this.options.dispositionError) pendingDelete = value;
        return this.options.dispositionError ?? 0;
      },
      lock: unavailable,
      unlock: unavailable,
    };
    return { error: 0, handle };
  }
  readonly native: WindowsBinding = {
    errnoMessage: unavailable,
    windowsErrorMessage: (error) => widePath(`System error ${error}.\r\n`),
    windowsReadFileCrt: unavailable,
    windowsArguments: unavailable,
    windowsEnvironment: unavailable,
    windowsInvariantLowercase: (value) => ({
      error: 0,
      value: widePath(pathText(value).toLowerCase()),
    }),
    windowsAbsolutePath: (path) => ({
      error: 0,
      value: widePath(win32.resolve("C:\\work", plain(path))),
    }),
    windowsDirectoryEntries: unavailable,
    windowsReadLink: unavailable,
    openWindowsFile: (path, access, share, disposition, flags) =>
      this.open(plain(path), access, share, disposition, flags),
    createWindowsHardLink: unavailable,
    replaceWindowsPath: unavailable,
    unlinkWindowsPath: unavailable,
    createWindowsDirectory: (path) => {
      const name = plain(path);
      if (this.entries.has(key(name))) return 183;
      this.add(name, true);
      return 0;
    },
    createWindowsDirectories: unavailable,
    createWindowsPrivateDirectory: unavailable,
    setWindowsWritable: unavailable,
    readCopyStat: unavailable,
    setWindowsTimes: unavailable,
    copyFile2: unavailable,
    createWindowsSymlink: unavailable,
    copyFileCrt: unavailable,
    openWindowsCompletionFile: unavailable,
    openWindowsExclusiveFile: unavailable,
  };
  contents(path: string): string | null {
    return this.entries.get(key(path))?.bytes.toString("base64") ?? null;
  }
  get openHandles(): number {
    return this.held.filter((held) => !held.closed).length;
  }
  get temporaryFiles(): number {
    return [...this.entries.values()].filter((entry) =>
      /\.tmp$/u.test(entry.path),
    ).length;
  }
}
