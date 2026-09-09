import fs from "node:fs";
import { join } from "node:path";
import { unixBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  scanRootIdentity,
  writeScanLocalBytes,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/scan-local-files";

const [operation, scanDir, outside, movedParent] = process.argv.slice(2);
if (operation === "ordinary") {
  writeScanLocalBytes(scanDir!, "artifact.bin", Buffer.from("unchanged\n"));
} else if (operation === "sparse") {
  const size = 32 * 1024 * 1024,
    payload = Buffer.alloc(size, "x"),
    file = fs.openSync(join(scanDir!, "artifact.bin"), "w");
  fs.ftruncateSync(file, size);
  fs.closeSync(file);
  const [canonical, identity] = scanRootIdentity(scanDir!);
  const read = fs.readSync;
  let largestRead = 0;
  fs.readSync = ((fd: number, buffer: Uint8Array, ...args: unknown[]) => {
    largestRead = Math.max(largestRead, buffer.byteLength);
    if (buffer.byteLength > 8 * 1024 * 1024)
      throw new Error("artifact comparison exceeded its memory budget");
    return Reflect.apply(read, fs, [fd, buffer, ...args]);
  }) as typeof fs.readSync;
  try {
    writeScanLocalBytes(canonical, "artifact.bin", payload, {
      expectedRootIdentity: identity,
    });
  } finally {
    fs.readSync = read;
  }
  if (!largestRead)
    throw new Error("artifact comparison did not read the file");
} else if (operation === "rename") {
  const [canonical, identity] = scanRootIdentity(scanDir!),
    native = unixBinding(),
    rename = native.renameAt;
  let swapped = false;
  native.renameAt = (...args) => {
    if (!swapped) {
      const parent = join(scanDir!, "artifacts");
      fs.renameSync(parent, movedParent!);
      fs.symlinkSync(outside!, parent, "dir");
      swapped = true;
    }
    return rename(...args);
  };
  try {
    writeScanLocalBytes(
      canonical,
      "artifacts/worker.bin",
      Buffer.from([0, 255, 10, 1]),
      {
        expectedRootIdentity: identity,
      },
    );
  } finally {
    native.renameAt = rename;
  }
} else throw new Error("Unknown file operation");
