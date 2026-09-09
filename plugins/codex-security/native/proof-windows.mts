import { rawProcessProof } from "./proof-process.mjs";
import assert from "node:assert/strict";
import { fork, type ChildProcess } from "node:child_process";
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { setImmediate } from "node:timers/promises";
import { wideProcessProof } from "./proof-windows-wide.mjs";
import { windowsFileSystem } from "./windows-files.mjs";
import { output } from "./binding.mjs";
import { loadProcessBinding } from "./process-binding.mjs";
import {
  loadWindowsBinding,
  windowsFlags as flags,
  type WindowsCompletionFile,
  type WindowsExclusiveFile,
  type WindowsHandle,
} from "./windows-binding.mjs";

assert.equal(process.platform, "win32", "Windows proof requires Windows");
const native = loadWindowsBinding();
const shareAll =
  flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE;
const directoryFlags =
  flags.FILE_FLAG_BACKUP_SEMANTICS | flags.FILE_FLAG_OPEN_REPARSE_POINT;
const readWrite = flags.GENERIC_READ | flags.GENERIC_WRITE;
const self = fileURLToPath(import.meta.url);
const pathBytes = (path: string) =>
  Buffer.from(win32.toNamespacedPath(path), "utf16le");
const checked = <T extends { error: number }>(result: T): T => {
  assert.equal(result.error, 0, `Win32 error ${result.error}`);
  return result;
};
const success = (error: number) => checked({ error });

function open(
  path: string | Buffer,
  access = readWrite | flags.DELETE | flags.FILE_READ_ATTRIBUTES,
  share = shareAll,
  disposition: number = flags.OPEN_EXISTING,
  attributes: number = flags.FILE_ATTRIBUTE_NORMAL,
): WindowsHandle {
  const result = checked(
    native.openWindowsFile(
      typeof path === "string" ? pathBytes(path) : path,
      access,
      share,
      disposition,
      attributes,
    ),
  );
  assert(result.handle);
  return result.handle;
}

function samePath(actual: Buffer, expected: string): void {
  assert.equal(
    win32.normalize(actual.toString("utf16le")).toLowerCase(),
    win32.toNamespacedPath(expected).toLowerCase(),
  );
}

function remove(path: string): void {
  const result = native.openWindowsFile(
    pathBytes(path),
    flags.DELETE,
    shareAll,
    flags.OPEN_EXISTING,
    directoryFlags,
  );
  if (result.error === 2 || result.error === 3) return;
  const handle = checked(result).handle!;
  try {
    success(handle.setDisposition(true));
  } finally {
    success(handle.close());
  }
}

function copyMetadataProof(root: string) {
  const source = join(root, "copy-source.EXE");
  const destination = join(root, "copy-destination.EXE");
  writeFileSync(source, "metadata payload");
  writeFileSync(`${source}:synthetic`, "alternate stream");
  const read = (path: string) => {
    const result = checked(native.readCopyStat(pathBytes(path), true));
    assert(result.metadata);
    return result.metadata;
  };
  checked(
    native.setWindowsTimes(
      pathBytes(source),
      1_700_000_000_123_456_700n,
      1_700_000_000_876_543_200n,
    ),
  );
  success(native.setWindowsWritable(pathBytes(source), false));
  const captured = read(source);
  assert.equal(captured.mode, 0o555);
  try {
    success(
      native.copyFile2(
        pathBytes(source),
        pathBytes(destination),
        flags.COPY_FILE_ALLOW_DECRYPTED_DESTINATION,
      ),
    );
    const copied = read(destination);
    assert.equal(copied.mode, captured.mode);
    assert.equal(copied.mtimeNs, captured.mtimeNs);
    assert.equal(readFileSync(destination, "utf8"), "metadata payload");
    assert.equal(
      readFileSync(`${destination}:synthetic`, "utf8"),
      "alternate stream",
    );
    success(native.setWindowsWritable(pathBytes(destination), true));
    checked(
      native.setWindowsTimes(
        pathBytes(destination),
        captured.atimeNs,
        captured.mtimeNs,
      ),
    );
    assert.equal(read(destination).atimeNs, captured.atimeNs);
    assert.equal(read(destination).mtimeNs, captured.mtimeNs);

    const held = open(destination);
    try {
      // Attribute-only access is unaffected by data-handle sharing modes.
      assert.deepEqual(
        native.setWindowsTimes(
          pathBytes(destination),
          captured.atimeNs,
          captured.mtimeNs,
        ),
        { error: 0, path: null },
      );
    } finally {
      success(held.close());
    }
    const missing = pathBytes(join(root, "copy-missing"));
    assert.deepEqual(native.readCopyStat(missing, true), {
      error: 2,
      metadata: null,
    });
    assert.deepEqual(
      native.setWindowsTimes(missing, captured.atimeNs, captured.mtimeNs),
      {
        error: 2,
        path: missing,
      },
    );
    assert.equal(native.copyFile2(missing, pathBytes(destination), 0), 2);
    assert.throws(() => native.readCopyStat(Buffer.from([0]), true));
    return {
      timestamps: true,
      copiedReadOnlyAndStreams: true,
      errorPathAndSharing: true,
    };
  } finally {
    success(native.setWindowsWritable(pathBytes(source), true));
    if (existsSync(destination))
      success(native.setWindowsWritable(pathBytes(destination), true));
  }
}

function readFileProof(root: string) {
  const path = join(root, "read-file-\ud800"),
    replacement = join(root, "read-file-\ufffd");
  const files = windowsFileSystem(native);
  const payload = Buffer.alloc(1024 * 1024 + 7, 255);
  payload.set([0, 10, 13, 26]);
  files.writeFile(pathBytes(path), payload);
  writeFileSync(replacement, "replacement sentinel");
  const opened = native.openWindowsReadFile(pathBytes(path));
  assert.equal(opened.errno, 0);
  assert(opened.file);
  const file = opened.file;
  let probe: WindowsHandle | undefined;
  try {
    assert.deepEqual(file.read(Buffer.alloc(0)), { errno: 0, value: 0 });
    const first = Buffer.alloc(1024 * 1024);
    assert.deepEqual(file.read(first), { errno: 0, value: first.length });
    assert.deepEqual(first, payload.subarray(0, first.length));
    const last = Buffer.alloc(20, 42);
    assert.deepEqual(file.read(last.subarray(3)), { errno: 0, value: 7 });
    assert.deepEqual(last.subarray(0, 3), Buffer.alloc(3, 42));
    assert.deepEqual(last.subarray(3, 10), payload.subarray(first.length));
    assert.deepEqual(last.subarray(10), Buffer.alloc(10, 42));
    assert.deepEqual(file.read(last), { errno: 0, value: 0 });
    assert.equal(native.unlinkWindowsPath(pathBytes(path)), 32);
    probe = open(path, readWrite, shareAll);
    success(probe.lock(true));
    const competing = native.openWindowsReadFile(pathBytes(path));
    assert.equal(competing.errno, 0);
    assert(competing.file);
    try {
      assert.deepEqual(competing.file.read(first), { errno: 13, value: -1 });
    } finally {
      assert.equal(competing.file.close(), 0);
    }
    success(probe.unlock());
    success(probe.close());
    probe = undefined;
    assert.equal(file.close(), 0);
    assert.equal(file.close(), 0);
    assert.deepEqual(file.read(last), { errno: 9, value: -1 });
    assert.deepEqual(native.openWindowsReadFile(pathBytes(root)), {
      errno: 13,
      file: null,
    });
    assert.deepEqual(
      native.openWindowsReadFile(pathBytes(join(root, "absent-read-file"))),
      { errno: 2, file: null },
    );
    assert.equal(readFileSync(replacement, "utf8"), "replacement sentinel");
    return { binaryChunks: true, rawPaths: true, crtErrorsAndSharing: true };
  } finally {
    file.close();
    probe?.close();
    remove(path);
    remove(replacement);
  }
}

function publicationPathProof(root: string) {
  const files = windowsFileSystem(native);
  const source = join(root, "publication-source-\ud800"),
    link = join(root, "publication-link-\udfff"),
    destination = join(root, "publication-destination-\ud800"),
    replacement = join(root, "publication-source-\ufffd"),
    directory = join(root, "publication-directory"),
    directoryLink = join(root, "publication-directory-link"),
    junction = join(root, "publication-junction"),
    missing = join(root, "publication-missing");
  const payload = Buffer.from([0, 255, 10, 13, 128]);
  try {
    files.writeFile(pathBytes(source), payload);
    writeFileSync(replacement, "replacement untouched");
    success(native.createWindowsHardLink(pathBytes(source), pathBytes(link)));
    assert(files.sameFile(pathBytes(source), pathBytes(link)));
    assert.deepEqual(files.readFile(pathBytes(link)), payload);
    assert.equal(
      native.createWindowsHardLink(pathBytes(source), pathBytes(link)),
      183,
    );
    assert.equal(
      native.createWindowsHardLink(pathBytes(missing), pathBytes(destination)),
      2,
    );
    files.writeFile(pathBytes(destination), Buffer.from("old output"));
    success(native.replaceWindowsPath(pathBytes(link), pathBytes(destination)));
    assert(files.sameFile(pathBytes(source), pathBytes(destination)));
    assert.equal(native.unlinkWindowsPath(pathBytes(link)), 2);
    assert.equal(
      native.replaceWindowsPath(pathBytes(missing), pathBytes(destination)),
      2,
    );
    assert.deepEqual(files.readFile(pathBytes(destination)), payload);
    files.writeFile(pathBytes(link), Buffer.from("replacement candidate"));
    const held = open(
      destination,
      flags.GENERIC_READ,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE,
    );
    try {
      // MoveFileExW reports access denied while the destination denies delete sharing.
      assert.equal(
        native.replaceWindowsPath(pathBytes(link), pathBytes(destination)),
        5,
      );
    } finally {
      success(held.close());
    }
    success(native.setWindowsWritable(pathBytes(destination), false));
    assert.equal(native.unlinkWindowsPath(pathBytes(destination)), 5);
    success(native.setWindowsWritable(pathBytes(destination), true));
    success(native.unlinkWindowsPath(pathBytes(destination)));
    assert.deepEqual(files.readFile(pathBytes(source)), payload);
    mkdirSync(directory);
    writeFileSync(join(directory, "sentinel"), "target retained");
    assert.equal(native.unlinkWindowsPath(pathBytes(directory)), 5);
    success(
      native.createWindowsSymlink(
        Buffer.from(basename(directory), "utf16le"),
        pathBytes(directoryLink),
        flags.SYMBOLIC_LINK_FLAG_DIRECTORY |
          flags.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
      ),
    );
    success(native.unlinkWindowsPath(pathBytes(directoryLink)));
    symlinkSync(directory, junction, "junction");
    success(native.unlinkWindowsPath(pathBytes(junction)));
    assert.equal(
      readFileSync(join(directory, "sentinel"), "utf8"),
      "target retained",
    );
    assert.equal(readFileSync(replacement, "utf8"), "replacement untouched");
    for (const invalid of [
      Buffer.from([0]),
      Buffer.from("bad\0path", "utf16le"),
    ]) {
      assert.throws(() =>
        native.createWindowsHardLink(invalid, pathBytes(destination)),
      );
      assert.throws(() =>
        native.replaceWindowsPath(pathBytes(source), invalid),
      );
      assert.throws(() => native.unlinkWindowsPath(invalid));
    }
    return {
      rawNamesAndHardLinks: true,
      replacementAndSharing: true,
      unlinkFilesAndDirectoryLinks: true,
      numericErrors: true,
    };
  } finally {
    for (const path of [source, link, destination, directoryLink, junction]) {
      native.setWindowsWritable(pathBytes(path), true);
      remove(path);
    }
  }
}

function privateDirectoryProof(root: string) {
  const files = windowsFileSystem(native);
  const paths = [join(root, "private-directory"), join(root, "private-\ud800")];
  const replacement = join(root, "private-\ufffd");
  mkdirSync(replacement);
  writeFileSync(join(replacement, "sentinel"), "replacement untouched");
  try {
    for (const path of paths) {
      const bytes = pathBytes(path);
      assert.deepEqual(native.createWindowsPrivateDirectory(bytes), {
        error: 0,
        path: null,
      });
      assert(files.stat(bytes).isDirectory());
      assert.deepEqual(native.createWindowsPrivateDirectory(bytes), {
        error: 183,
        path: bytes,
      });
      const acl = checked(
        loadProcessBinding().rawProcess({
          program: pathBytes(join(output, "windows-wide-launcher.exe")),
          args: [
            pathBytes(process.execPath),
            pathBytes(self),
            bytes,
            Buffer.from("private-directory-acl", "utf16le"),
          ],
        }),
      );
      assert.equal(acl.returnCode, 0, acl.stderr.toString());
      assert.equal(acl.stderr.length, 0);
      assert.equal(
        acl.stdout.toString().trim(),
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)",
      );
      const child = pathBytes(join(path, "contents"));
      files.writeFile(child, Buffer.from("private contents"));
      assert.equal(files.readFile(child).toString(), "private contents");
      files.unlink(child);
    }
    const missing = pathBytes(join(root, "missing-parent", "private"));
    assert.deepEqual(native.createWindowsPrivateDirectory(missing), {
      error: 3,
      path: missing,
    });
    for (const malformed of [
      Buffer.from([0]),
      Buffer.from("bad\0path", "utf16le"),
    ])
      assert.throws(() => native.createWindowsPrivateDirectory(malformed));
    assert.equal(
      readFileSync(join(replacement, "sentinel"), "utf8"),
      "replacement untouched",
    );
    return {
      protectedOwnerAcl: true,
      rawNames: true,
      existingAndMissingErrors: true,
    };
  } finally {
    for (const path of paths) remove(path);
  }
}

function copyPrimitivesProof(root: string) {
  const files = windowsFileSystem(native);
  const source = join(root, "copy-stream-\ud800.bin");
  const replacement = join(root, "copy-stream-\ufffd.bin");
  const destination = join(root, "copy-stream-destination-\udfff.bin");
  const link = join(root, "copy-link-\udfff");
  const dangling = join(root, "copy-dangling-\ud800");
  const directory = join(root, "copy-link-directory");
  const directoryLink = join(root, "copy-directory-link");
  const payload = Buffer.alloc(2 * 1024 * 1024 + 37);
  for (let index = 0; index < payload.length; index++)
    payload[index] = index % 256;
  const sourceBytes = pathBytes(source),
    destinationBytes = pathBytes(destination);
  const copy = () => native.copyFileCrt(sourceBytes, destinationBytes);
  try {
    files.writeFile(sourceBytes, payload);
    files.writeFile(
      pathBytes(replacement),
      Buffer.from("distinct replacement name"),
    );
    files.writeFile(
      destinationBytes,
      Buffer.alloc(payload.length + 1024, 0xff),
    );
    success(native.setWindowsWritable(sourceBytes, false));
    assert.deepEqual(copy(), { errno: 0, path: null });
    assert.deepEqual(native.windowsReadFileCrt(destinationBytes), {
      errno: 0,
      value: payload,
    });
    assert.equal(
      files.readFile(pathBytes(replacement)).toString(),
      "distinct replacement name",
    );

    success(native.setWindowsWritable(destinationBytes, false));
    assert.deepEqual(copy(), { errno: 13, path: destinationBytes });
    success(native.setWindowsWritable(destinationBytes, true));
    const missing = pathBytes(join(root, "copy-stream-missing"));
    assert.deepEqual(native.copyFileCrt(missing, destinationBytes), {
      errno: 2,
      path: missing,
    });
    assert.deepEqual(files.readFile(destinationBytes), payload);
    const missingParent = pathBytes(join(root, "copy-missing-parent", "file"));
    assert.deepEqual(native.copyFileCrt(sourceBytes, missingParent), {
      errno: 2,
      path: missingParent,
    });
    assert.deepEqual(native.copyFileCrt(sourceBytes, pathBytes(root)), {
      errno: 13,
      path: pathBytes(root),
    });
    assert.deepEqual(native.copyFileCrt(pathBytes(root), destinationBytes), {
      errno: 13,
      path: pathBytes(root),
    });

    const relative = Buffer.from(basename(source), "utf16le");
    success(
      native.createWindowsSymlink(
        relative,
        pathBytes(link),
        flags.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
      ),
    );
    assert.deepEqual(
      checked(native.windowsReadLink(pathBytes(link))).value,
      relative,
    );
    assert.deepEqual(files.readFile(pathBytes(link)), payload);
    assert.equal(
      native.createWindowsSymlink(
        relative,
        pathBytes(link),
        flags.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
      ),
      183,
    );
    const absent = Buffer.from("copy-missing-\ud800", "utf16le");
    success(
      native.createWindowsSymlink(
        absent,
        pathBytes(dangling),
        flags.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
      ),
    );
    assert.deepEqual(
      checked(native.windowsReadLink(pathBytes(dangling))).value,
      absent,
    );
    mkdirSync(directory);
    success(
      native.createWindowsSymlink(
        Buffer.from(basename(directory), "utf16le"),
        pathBytes(directoryLink),
        flags.SYMBOLIC_LINK_FLAG_DIRECTORY |
          flags.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
      ),
    );
    assert(files.stat(pathBytes(directoryLink)).isDirectory());
    assert(files.stat(pathBytes(directoryLink), false).isSymbolicLink());
    return {
      rawSymlinkTargets: true,
      binaryStreamingAndTruncation: true,
      crtOpenErrorsAndPaths: true,
    };
  } finally {
    for (const path of [source, destination])
      native.setWindowsWritable(pathBytes(path), true);
    for (const path of [
      link,
      dangling,
      directoryLink,
      source,
      destination,
      replacement,
    ])
      remove(path);
  }
}

async function completionFileProof(root: string) {
  assert(global.gc, "Run the Windows proof with --expose-gc");
  const path = join(root, "completion-\ud800.lock");
  const replacement = join(root, "completion-\ufffd.lock");
  const readonly = join(root, "completion-readonly.lock");
  const files = windowsFileSystem(native);
  const held = new Set<WindowsCompletionFile>();
  const completion = (path: Buffer): WindowsCompletionFile => {
    const result = native.openWindowsCompletionFile(path);
    assert.equal(result.errno, 0);
    assert(result.file);
    return result.file;
  };
  const keep = (file: WindowsCompletionFile) => {
    held.add(file);
    return file;
  };
  const close = (file: WindowsCompletionFile) => {
    assert.equal(file.close(), 0);
    held.delete(file);
  };
  let probe: WindowsHandle | undefined;
  writeFileSync(replacement, "replacement sentinel");
  writeFileSync(readonly, "readonly sentinel");
  try {
    const first = keep(completion(pathBytes(path)));
    assert.deepEqual(first.size(), { error: 0, value: "0" });
    assert.deepEqual(first.writeZero(), { errno: 0, value: 1 });
    assert.deepEqual(first.size(), { error: 0, value: "1" });
    const second = keep(completion(pathBytes(path)));
    assert.deepEqual(second.size(), { error: 0, value: "1" });
    probe = open(path, readWrite | flags.FILE_READ_ATTRIBUTES, shareAll);

    // writeZero advanced the CRT offset; locking uses that byte without seeking.
    assert.equal(first.locking(false), 0);
    assert.equal(second.locking(false), 0);
    assert.equal(probe.lock(true), 33);
    assert.equal(second.locking(true), 0);
    assert.deepEqual(second.writeZero(), { errno: 0, value: 1 });
    assert.equal(second.locking(false), 13);
    assert.equal(first.locking(true), 0);
    assert.deepEqual(first.writeZero(), { errno: 0, value: 1 });
    assert.deepEqual(first.size(), { error: 0, value: "2" });
    assert.deepEqual(files.readFile(pathBytes(path)), Buffer.from([0, 0]));

    success(probe.lock(true));
    assert.equal(first.seekStart(), 0);
    assert.deepEqual(first.writeZero(), { errno: 13, value: -1 });
    assert.equal(first.locking(false), 13);
    success(probe.unlock());
    assert.equal(first.seekStart(), 0);
    assert.equal(first.locking(false), 0);
    assert.equal(second.seekStart(), 0);
    assert.equal(second.locking(false), 13);
    assert.equal(probe.lock(true), 33);
    close(first);
    assert.equal(first.close(), 0);
    assert.deepEqual(first.size(), { error: 6, value: "0" });
    assert.equal(first.seekStart(), 9);
    assert.deepEqual(first.writeZero(), { errno: 9, value: -1 });
    assert.equal(first.locking(false), 9);
    assert.equal(first.locking(true), 9);
    assert.equal(second.locking(false), 0);
    assert.equal(second.locking(true), 0);
    close(second);

    const abandoned = () => {
      const file = completion(pathBytes(path));
      assert.equal(file.seekStart(), 0);
      assert.equal(file.locking(false), 0);
    };
    abandoned();
    await setImmediate();
    global.gc();
    await setImmediate();
    success(probe.lock(true));
    success(probe.unlock());
    success(probe.close());
    probe = undefined;

    success(native.setWindowsWritable(pathBytes(readonly), false));
    assert.deepEqual(native.openWindowsCompletionFile(pathBytes(readonly)), {
      errno: 13,
      file: null,
    });
    assert.deepEqual(native.openWindowsCompletionFile(pathBytes(root)), {
      errno: 13,
      file: null,
    });
    assert.deepEqual(
      native.openWindowsCompletionFile(
        pathBytes(join(root, "missing-completion-parent", "file")),
      ),
      {
        errno: 2,
        file: null,
      },
    );
    const device = keep(completion(Buffer.from("NUL", "utf16le")));
    assert.deepEqual(device.size(), { error: 0, value: "0" });
    close(device);
    assert.equal(readFileSync(replacement, "utf8"), "replacement sentinel");
    assert.equal(readFileSync(readonly, "utf8"), "readonly sentinel");
    return {
      rawNamesAndNontruncatingOpen: true,
      seedByteAndOffset: true,
      crtAndWin32Contention: true,
      closeAndGarbageCollectionRelease: true,
      closedErrorsAndNonDiskSize: true,
    };
  } finally {
    probe?.close();
    for (const file of held) file.close();
    native.setWindowsWritable(pathBytes(readonly), true);
    remove(path);
  }
}

async function exclusiveFileProof(root: string) {
  assert(global.gc, "Run the Windows proof with --expose-gc");
  const files = windowsFileSystem(native);
  const path = join(root, "exclusive-\ud800"),
    replacement = join(root, "exclusive-\ufffd"),
    probe = join(root, "exclusive-probe"),
    garbage = join(root, "exclusive-garbage");
  writeFileSync(replacement, "replacement untouched");
  const held = new Set<WindowsExclusiveFile>();
  const create = (path: string, mode: number, readWrite = false) => {
    const result = native.openWindowsExclusiveFile(
      pathBytes(path),
      mode,
      readWrite,
    );
    assert.equal(result.errno, 0);
    assert(result.file);
    held.add(result.file);
    return result.file;
  };
  try {
    const file = create(path, 0o666);
    assert.deepEqual(native.openWindowsExclusiveFile(pathBytes(path), 0o666), {
      errno: 17,
      file: null,
    });
    assert.deepEqual(file.write(Buffer.alloc(0)), { errno: 0, value: 0 });
    const payload = Buffer.alloc(1024 * 1024 + 17);
    for (let index = 0; index < payload.length; index++)
      payload[index] = index % 256;
    assert.deepEqual(file.write(payload), { errno: 0, value: payload.length });
    assert.deepEqual(file.write(Buffer.from("\r\n\0\x1a")), {
      errno: 0,
      value: 4,
    });
    const deletion = native.openWindowsFile(
      pathBytes(path),
      flags.DELETE,
      shareAll,
      flags.OPEN_EXISTING,
      flags.FILE_ATTRIBUTE_NORMAL,
    );
    assert.equal(deletion.error, 32);
    assert.equal(deletion.handle, undefined);
    assert.equal(file.close(), 0);
    assert.equal(file.close(), 0);
    assert.deepEqual(file.write(Buffer.from("closed")), {
      errno: 9,
      value: -1,
    });
    assert.deepEqual(
      files.readFile(pathBytes(path)),
      Buffer.concat([payload, Buffer.from("\r\n\0\x1a")]),
    );
    const candidate = create(probe, 0o600, true);
    assert.deepEqual(candidate.write(Buffer.from("blat")), {
      errno: 0,
      value: 4,
    });
    assert.equal(candidate.close(), 0);
    assert.equal(readFileSync(probe, "utf8"), "blat");
    assert.deepEqual(
      native.openWindowsExclusiveFile(
        pathBytes(join(root, "missing-exclusive-parent", "file")),
        0o600,
      ),
      { errno: 2, file: null },
    );
    for (const malformed of [
      Buffer.from([0]),
      Buffer.from("bad\0path", "utf16le"),
    ])
      assert.throws(() => native.openWindowsExclusiveFile(malformed, 0o600));
    (() => {
      const opened = native.openWindowsExclusiveFile(pathBytes(garbage), 0o600);
      assert.equal(opened.errno, 0);
      assert(opened.file);
      assert.deepEqual(opened.file.write(Buffer.from("collected")), {
        errno: 0,
        value: 9,
      });
    })();
    global.gc();
    await setImmediate();
    global.gc();
    await setImmediate();
    const released = open(garbage, flags.DELETE);
    success(released.setDisposition(true));
    success(released.close());
    assert.equal(readFileSync(replacement, "utf8"), "replacement untouched");
    return {
      exclusiveRawCreation: true,
      binaryWriteAndOffsets: true,
      crtErrorsAndDeleteSharing: true,
      probeModeAndGarbageCollection: true,
    };
  } finally {
    for (const file of held) file.close();
    for (const name of [path, probe, garbage]) remove(name);
  }
}

function handleProof(root: string) {
  const held = new Set<WindowsHandle>();
  const rawPaths: string[] = [];
  const keep = (handle: WindowsHandle) => {
    held.add(handle);
    return handle;
  };
  const close = (handle: WindowsHandle) => {
    success(handle.close());
    held.delete(handle);
  };
  try {
    const path = join(root, "data");
    const file = keep(open(path, undefined, undefined, flags.CREATE_NEW));
    const payload = Buffer.from("handle I/O 🔐\n");
    const input = Buffer.concat([
      Buffer.from("ignore"),
      payload,
      Buffer.from("tail"),
    ]);
    assert.equal(
      checked(file.write(input, 6, payload.length)).value,
      payload.length,
    );
    success(file.flush());
    assert.equal(checked(file.size()).value, String(payload.length));
    assert.equal(checked(file.fileType()).value, 1);
    assert.equal(
      checked(file.attributes()).attributes & flags.FILE_ATTRIBUTE_DIRECTORY,
      0,
    );
    assert.equal(checked(file.seek(0n, flags.FILE_BEGIN)).value, "0");
    const buffer = Buffer.alloc(payload.length + 6, 0x7e);
    assert.equal(
      checked(file.read(buffer, 3, payload.length)).value,
      payload.length,
    );
    assert.deepEqual(buffer.subarray(3, -3), payload);
    assert.deepEqual(buffer.subarray(0, 3), Buffer.from("~~~"));
    assert.deepEqual(buffer.subarray(-3), Buffer.from("~~~"));
    assert.equal(checked(file.read(buffer, 0, 1)).value, 0);
    assert.equal(
      checked(file.seek(0n, flags.FILE_CURRENT)).value,
      String(payload.length),
    );
    const far = (1n << 53n) + 5n;
    assert.equal(
      checked(file.seek(far, flags.FILE_BEGIN)).value,
      far.toString(),
    );
    assert.equal(
      checked(file.seek(-2n, flags.FILE_END)).value,
      String(payload.length - 2),
    );
    success(file.setEndOfFile());
    assert.equal(checked(file.size()).value, String(payload.length - 2));
    assert.equal(
      checked(file.seek(0n, flags.FILE_CURRENT)).value,
      String(payload.length - 2),
    );
    assert.equal(checked(file.read(buffer, 0, 1)).value, 0);
    assert.equal(
      checked(file.seek(1n, flags.FILE_CURRENT)).value,
      String(payload.length - 1),
    );
    success(file.setEndOfFile());
    assert.equal(checked(file.size()).value, String(payload.length - 1));
    assert.equal(
      checked(file.seek(0n, flags.FILE_CURRENT)).value,
      String(payload.length - 1),
    );
    assert.equal(file.seek(0n, 99).error, 87);
    samePath(checked(file.finalPath(0)).path, path);
    samePath(checked(file.finalPath(flags.FILE_NAME_OPENED)).path, path);

    const identity = checked(file.identity());
    assert.match(identity.volume, /^\d+$/u);
    assert.equal(identity.fileId.length, 16);
    const link = join(root, "hard-link");
    linkSync(path, link);
    const second = keep(open(link));
    assert.deepEqual(checked(second.identity()), identity);
    assert.equal(
      windowsFileSystem(native).sameFile(pathBytes(path), pathBytes(link)),
      true,
    );
    assert.equal(
      windowsFileSystem(native).sameFile(pathBytes(path), pathBytes(root)),
      false,
    );
    close(second);
    assert.equal(
      native.openWindowsFile(
        pathBytes(path),
        flags.GENERIC_READ,
        0,
        flags.OPEN_EXISTING,
        0,
      ).error,
      32,
    );
    assert.equal(
      native.openWindowsFile(
        pathBytes(join(root, "missing")),
        flags.GENERIC_READ,
        shareAll,
        flags.OPEN_EXISTING,
        0,
      ).error,
      2,
    );
    for (const [offset, length] of [
      [-1, 1],
      [0, -1],
      [0.5, 1],
      [0, NaN],
      [0, Infinity],
      [0, 2 ** 32],
      [buffer.length, 1],
    ]) {
      assert.throws(() => file.read(buffer, offset!, length!));
      assert.throws(() => file.write(buffer, offset!, length!));
    }
    for (const invalid of [
      Buffer.from([0x41]),
      Buffer.from("bad\0path", "utf16le"),
    ]) {
      assert.throws(() =>
        native.openWindowsFile(invalid, 0, 0, flags.OPEN_EXISTING, 0),
      );
    }
    assert.throws(() =>
      native.openWindowsFile(
        pathBytes(path),
        readWrite,
        shareAll,
        flags.OPEN_EXISTING,
        flags.FILE_FLAG_OVERLAPPED,
      ),
    );
    assert.throws(() => file.seek(1n << 63n, flags.FILE_BEGIN));
    const readOnly = keep(open(path, flags.GENERIC_READ));
    assert.equal(readOnly.write(buffer, 0, 1).error, 5);
    assert.equal(readOnly.flush(), 5);
    assert.equal(readOnly.setEndOfFile(), 5);
    close(readOnly);
    close(file);
    success(file.close());
    assert.equal(file.size().error, 6);
    assert.equal(file.read(buffer, 0, 1).error, 6);
    assert.equal(file.write(buffer, 0, 1).error, 6);
    assert.equal(file.seek(0n, flags.FILE_CURRENT).error, 6);
    assert.equal(file.setEndOfFile(), 6);
    assert.equal(file.flush(), 6);
    assert.equal(file.lock(true), 6);
    assert.equal(file.lock(false), 6);
    assert.equal(file.unlock(), 6);

    const ancestor = join(root, "ancestor");
    const scan = join(ancestor, "scan");
    const child = join(scan, "child");
    for (const directory of [ancestor, scan, child]) {
      success(native.createWindowsDirectory(pathBytes(directory)));
    }
    const directories = [ancestor, scan, child].map((directory) =>
      keep(
        open(
          directory,
          flags.GENERIC_READ,
          flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE,
          flags.OPEN_EXISTING,
          directoryFlags,
        ),
      ),
    );
    for (const directory of [ancestor, scan, child]) {
      assert.equal(
        native.openWindowsFile(
          pathBytes(directory),
          flags.DELETE,
          shareAll,
          flags.OPEN_EXISTING,
          directoryFlags,
        ).error,
        32,
      );
      assert.throws(() => renameSync(directory, directory + "-moved"));
    }
    for (const handle of directories.reverse()) close(handle);
    renameSync(ancestor, ancestor + "-moved");
    const target = join(root, "target");
    mkdirSync(target);
    writeFileSync(join(target, "sentinel"), "target unchanged");
    symlinkSync(target, ancestor, "junction");
    const junction = keep(
      open(
        ancestor,
        flags.FILE_READ_ATTRIBUTES,
        shareAll,
        flags.OPEN_EXISTING,
        directoryFlags,
      ),
    );
    const attributes = checked(junction.attributes());
    assert(attributes.attributes & flags.FILE_ATTRIBUTE_REPARSE_POINT);
    assert(attributes.attributes & flags.FILE_ATTRIBUTE_DIRECTORY);
    assert.equal(attributes.reparseTag, 0xa0000003);
    const files = windowsFileSystem(native);
    const junctionEntry = files
      .entriesWithTypes(pathBytes(root))
      .find((entry) =>
        entry.name.equals(Buffer.from(basename(ancestor), "utf16le")),
      );
    assert(junctionEntry?.isDirectory());
    assert.equal(junctionEntry?.isSymbolicLink(), true);
    const junctionStat = files.stat(pathBytes(ancestor), false);
    assert(junctionStat.isDirectory());
    assert(junctionStat.isReparsePoint());
    assert(!junctionStat.isSymbolicLink());
    const targetStat = files.stat(pathBytes(ancestor));
    assert(targetStat.isDirectory());
    assert(!targetStat.isReparsePoint());
    samePath(
      checked(junction.finalPath(flags.FILE_NAME_OPENED)).path,
      ancestor,
    );
    const followed = keep(
      open(
        ancestor,
        flags.FILE_READ_ATTRIBUTES,
        shareAll,
        flags.OPEN_EXISTING,
        flags.FILE_FLAG_BACKUP_SEMANTICS,
      ),
    );
    samePath(checked(followed.finalPath(0)).path, target);
    assert(
      !(
        checked(followed.attributes()).attributes &
        flags.FILE_ATTRIBUTE_REPARSE_POINT
      ),
    );
    close(followed);
    close(junction);
    remove(ancestor);
    assert.equal(
      readFileSync(join(target, "sentinel"), "utf8"),
      "target unchanged",
    );

    const source = join(root, "source");
    const moved = join(root, "moved-source");
    const destination = join(root, "destination");
    const exact = keep(open(source, undefined, undefined, flags.CREATE_NEW));
    const exactPayload = Buffer.from("exact handle");
    assert.equal(
      checked(exact.write(exactPayload, 0, exactPayload.length)).value,
      exactPayload.length,
    );
    success(exact.flush());
    const exactIdentity = checked(exact.identity());
    renameSync(source, moved);
    writeFileSync(source, "replacement source");
    writeFileSync(destination, "old destination");
    assert([80, 183].includes(exact.rename(pathBytes(destination), false)));
    success(exact.rename(pathBytes(destination), true));
    assert.equal(readFileSync(destination, "utf8"), "exact handle");
    assert.equal(readFileSync(source, "utf8"), "replacement source");
    assert(!existsSync(moved));
    assert.deepEqual(checked(exact.identity()), exactIdentity);
    samePath(checked(exact.finalPath(0)).path, destination);
    renameSync(destination, moved);
    writeFileSync(destination, "replacement destination");
    success(exact.setDisposition(true));
    close(exact);
    assert(!existsSync(moved));
    assert.equal(readFileSync(destination, "utf8"), "replacement destination");

    let longDirectory = root;
    for (let index = 0; index < 5; index++) {
      longDirectory = join(longDirectory, `part-${index}-${"x".repeat(55)}`);
      success(native.createWindowsDirectory(pathBytes(longDirectory)));
    }
    const rawDirectory = join(longDirectory, "directory-\udfff");
    success(native.createWindowsDirectory(pathBytes(rawDirectory)));
    rawPaths.push(rawDirectory);
    const rawPath = join(rawDirectory, "file-\ud800");
    // A lossy UTF-8 round trip would collide with this different filename.
    const replacement = join(longDirectory, "directory-\ufffd");
    mkdirSync(replacement);
    writeFileSync(join(replacement, "file-\ufffd"), "replacement sentinel");
    const raw = keep(open(rawPath, undefined, undefined, flags.CREATE_NEW));
    rawPaths.push(rawPath);
    assert.equal(
      checked(raw.write(exactPayload, 0, exactPayload.length)).value,
      exactPayload.length,
    );
    success(raw.flush());
    const finalName = checked(raw.finalPath(flags.FILE_NAME_OPENED)).path;
    assert(finalName.length / 2 > 260);
    assert(
      finalName.includes(
        Buffer.from("directory-\udfff\\file-\ud800", "utf16le"),
      ),
    );
    const reopened = keep(open(finalName));
    assert.deepEqual(checked(reopened.identity()), checked(raw.identity()));
    const rawContents = Buffer.alloc(exactPayload.length);
    assert.equal(
      checked(reopened.read(rawContents, 0, rawContents.length)).value,
      rawContents.length,
    );
    assert.deepEqual(rawContents, exactPayload);
    close(reopened);
    close(raw);
    assert.equal(
      readFileSync(join(replacement, "file-\ufffd"), "utf8"),
      "replacement sentinel",
    );
    return {
      handleReadWriteFlushSeekSizeAndEof: true,
      exact64BitPositionAnd128BitIdentity: true,
      numericMissingSharingAndClosedErrors: true,
      ancestorReplacementBlockedUntilClose: true,
      junctionMetadataAndFinalNames: true,
      exactHandleRenameAndDeleteAfterNameReplacement: true,
      rawUtf16AndLongPaths: true,
      invalidFfiRepresentationsRejected: true,
    };
  } finally {
    for (const handle of held) handle.close();
    for (const path of rawPaths.reverse()) remove(path);
  }
}

async function ownershipProof(root: string): Promise<boolean> {
  assert(global.gc, "Run the Windows proof with --expose-gc");
  const path = join(root, "garbage-collected-handle");
  open(path, readWrite, 0, flags.CREATE_NEW);
  await setImmediate();
  global.gc();
  await setImmediate();
  const reopened = open(path, readWrite, 0);
  success(reopened.close());
  return true;
}

interface Message {
  type: string;
  error?: number;
}
const send = (message: Message) =>
  new Promise<void>((resolve, reject) => {
    process.send!(message, (error) => (error ? reject(error) : resolve()));
  });

async function worker(path: string): Promise<void> {
  const handle = open(path, readWrite, shareAll, flags.OPEN_ALWAYS);
  process.on("disconnect", () => {
    handle.close();
    process.exit(0);
  });
  process.on("message", async (command: string) => {
    if (command === "probe") {
      const error = handle.lock(true);
      if (error === 0) success(handle.unlock());
      await send({ type: "probe", error });
    } else if (command === "lock") {
      await send({ type: "attempting" });
      success(handle.lock(false));
      await send({ type: "acquired" });
    } else if (command === "unlock") {
      success(handle.unlock());
      await send({ type: "released" });
    } else if (command === "close") {
      success(handle.close());
      await send({ type: "closed" });
    } else if (command === "exit") {
      success(handle.close());
      process.disconnect!();
    } else throw new Error(`Unknown worker command: ${command}`);
  });
  await send({ type: "ready" });
}

const peers = new Set<Peer>();
class Peer {
  readonly child: ChildProcess;
  readonly exited: Promise<void>;
  private messages: Message[] = [];
  private pending?: (message: Message) => void;
  private stderr = "";
  constructor(path: string) {
    this.child = fork(self, ["worker", path], {
      execPath: process.execPath,
      execArgv: [],
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    });
    peers.add(this);
    this.child.stderr!.on("data", (chunk: Buffer) => {
      this.stderr += chunk.toString();
    });
    const receive = (message: Message) => {
      if (this.pending) {
        const receive = this.pending;
        this.pending = undefined;
        receive(message);
      } else this.messages.push(message);
    };
    this.child.on("message", receive);
    this.exited = new Promise((resolve) =>
      this.child.once("exit", () => resolve()),
    );
  }
  send(command: string): void {
    this.child.send(command);
  }
  async next(type: string): Promise<Message> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const message = await Promise.race([
        this.messages.length
          ? Promise.resolve(this.messages.shift()!)
          : new Promise<Message>((resolve) => {
              this.pending = resolve;
            }),
        this.exited.then(() => {
          throw new Error(`Worker exited before ${type}: ${this.stderr}`);
        }),
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new Error(`Worker timed out before ${type}: ${this.stderr}`),
              ),
            30_000,
          );
        }),
      ]);
      assert.equal(message.type, type);
      return message;
    } finally {
      clearTimeout(timer);
    }
  }
  async stop(kill = false): Promise<void> {
    if (kill) this.child.kill("SIGKILL");
    else this.send("exit");
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.exited,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(`Worker did not exit: ${this.stderr}`)),
            30_000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    peers.delete(this);
    if (!kill) {
      assert.equal(this.child.exitCode, 0, this.stderr);
      assert.equal(this.stderr, "");
    }
  }
}

async function lockProof(root: string) {
  const path = join(root, "file-lock");
  const parent = open(path, readWrite, shareAll, flags.OPEN_ALWAYS);
  const other = open(path, readWrite, shareAll);
  try {
    success(parent.lock(true));
    const first = new Peer(path);
    await first.next("ready");
    first.send("probe");
    const contention = (await first.next("probe")).error!;
    assert.equal(contention, 33);
    first.send("lock");
    await first.next("attempting");
    success(parent.unlock());
    await first.next("acquired");
    assert.equal(parent.lock(true), 33);
    first.send("unlock");
    await first.next("released");
    success(parent.lock(true));
    first.send("lock");
    await first.next("attempting");
    success(parent.close());
    await first.next("acquired");
    const second = new Peer(path);
    await second.next("ready");
    second.send("lock");
    await second.next("attempting");
    await first.stop(true);
    await second.next("acquired");
    assert.equal(other.lock(true), 33);
    const third = new Peer(path);
    await third.next("ready");
    third.send("lock");
    await third.next("attempting");
    await second.stop(true);
    await third.next("acquired");
    third.send("close");
    await third.next("closed");
    success(other.lock(true));
    success(other.unlock());
    await third.stop();
    return {
      peerRuntime: "node",
      peerContentionError: contention,
      wholeFileExclusiveContention: true,
      blockingHandoff: true,
      unlockCloseAndBidirectionalProcessDeathRelease: true,
    };
  } finally {
    parent.close();
    other.close();
    for (const peer of peers) await peer.stop(true);
  }
}

if (process.argv[2] === "worker") {
  await worker(process.argv[3]!);
} else {
  const root = realpathSync.native(
    mkdtempSync(join(tmpdir(), "codex-security-windows-")),
  );
  try {
    const config = join(root, "config-é.toml");
    const contents = Buffer.from("[features]\r\ngoals = true\r\n\x1a");
    writeFileSync(config, contents);
    assert.deepEqual(
      native.windowsReadFileCrt(Buffer.from(config, "utf16le")),
      { errno: 0, value: contents },
    );
    assert.equal(
      native.windowsReadFileCrt(Buffer.from(config + "-missing", "utf16le"))
        .errno,
      2,
    );
    assert.equal(
      native.windowsReadFileCrt(Buffer.from(root, "utf16le")).errno,
      13,
    );
    assert.equal(native.errnoMessage(13).toString(), "Permission denied");
    assert(native.windowsErrorMessage(5).toString("utf16le").length > 0);
    assert.equal(native.windowsErrorMessage(0xdeadbeef).length, 0);
    const results: Record<string, unknown> = {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      nodeApi: 8,
    };
    const proofs: [string, (root: string) => unknown][] = [
      ["rawProcess", rawProcessProof],
      ["copyMetadata", copyMetadataProof],
      ["privateDirectories", privateDirectoryProof],
      ["publicationPaths", publicationPathProof],
      ["readFiles", readFileProof],
      ["copyPrimitives", copyPrimitivesProof],
      ["completionFiles", completionFileProof],
      ["exclusiveFiles", exclusiveFileProof],
      ["handles", handleProof],
      ["wideProcessAndPaths", wideProcessProof],
      ["garbageCollectionClosesHandle", ownershipProof],
      ["locks", lockProof],
    ];
    const failures: unknown[] = [];
    for (const [name, proof] of proofs) {
      try {
        results[name] = await proof(root);
      } catch (error) {
        console.error(`Windows proof failed: ${name}`, error);
        failures.push(error);
      }
    }
    results["fixture"] = basename(root);
    console.log(JSON.stringify(results, null, 2));
    if (failures.length)
      throw new AggregateError(failures, "Windows native proofs failed");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
