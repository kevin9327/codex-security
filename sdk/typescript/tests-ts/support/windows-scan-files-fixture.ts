import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { WindowsScanModel, type ModelOptions } from "./windows-scan-model";
import { windowsBinding } from "../../../../plugins/codex-security/mcp-app/src/native";
import {
  windowsScanLocalFiles,
  windowsScanPathParts,
  streamMatchesPayload,
  type ScanRootIdentity,
  type ScanLocalReader,
} from "../../../../plugins/codex-security/mcp-app/src/helpers/windows-scan-files";

type Action =
  | { operation: "identity" | "replaceRoot" }
  | {
      operation: "add";
      path: string;
      directory?: boolean;
      value?: string;
      target?: string;
    }
  | {
      operation: "write";
      relative: string;
      value?: string;
      size?: number;
      expected?: boolean;
    }
  | { operation: "read"; relative: string; hold?: boolean }
  | { operation: "delete"; relative: string }
  | { operation: "move"; path: string }
  | { operation: "close" }
  | { operation: "option"; name: keyof ModelOptions; value: number | boolean };
export type Request =
  | { mode: "model"; options?: ModelOptions; actions: Action[] }
  | { mode: "paths"; paths: string[] }
  | {
      mode: "streams";
      cases: { expected: string; actual: string; shortRead?: number }[];
    }
  | { mode: "native"; root: string };
const digest = (value: Buffer) =>
  createHash("sha256").update(value).digest("hex");
const request = JSON.parse(readFileSync(0, "utf8")) as Request;
function readAll(reader: ScanLocalReader): Buffer {
  const chunks: Buffer[] = [];
  for (;;) {
    const chunk = Buffer.alloc(32 * 1024);
    const length = reader.read(chunk);
    if (length === 0) return Buffer.concat(chunks);
    chunks.push(chunk.subarray(0, length));
  }
}
function main() {
  if (request.mode === "paths")
    return request.paths.map((path) => {
      try {
        return { parts: windowsScanPathParts(path) };
      } catch (error) {
        return { error: (error as Error).message };
      }
    });
  if (request.mode === "streams")
    return request.cases.map(({ expected, actual, shortRead }) => {
      let offset = 0;
      const contents = Buffer.from(actual);
      return streamMatchesPayload(
        {
          read(buffer) {
            const length = Math.min(
              buffer.length,
              contents.length - offset,
              shortRead ?? Infinity,
            );
            contents.copy(buffer, 0, offset, offset + length);
            offset += length;
            return length;
          },
        },
        Buffer.from(expected),
      );
    });
  if (request.mode === "native") {
    const root = join(request.root, "scan");
    mkdirSync(root);
    const files = windowsScanLocalFiles(windowsBinding());
    const [, identity] = files.rootIdentity(root);
    const data = Buffer.alloc(1024 * 1024 + 13, 0xa5);
    files.atomicWrite(root, "exports/large.bin", data);
    const reader = files.openRead(root, "exports/large.bin", "native test");
    try {
      assert.equal(reader.size(), BigInt(data.length));
      assert.deepEqual(readAll(reader), data);
    } finally {
      reader.close();
    }
    files.atomicWrite(root, "exports/large.bin", data, identity);
    files.atomicWrite(root, "exports/large.bin", Buffer.from("replacement"));
    assert.equal(
      readFileSync(join(root, "exports/large.bin"), "utf8"),
      "replacement",
    );
    const outside = join(request.root, "outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "kept"), "outside");
    symlinkSync(outside, join(root, "linked"), "junction");
    assert.throws(() => files.atomicWrite(root, "linked/new", data), /reparse/);
    files.unlinkIfExists(root, "linked");
    assert.equal(readFileSync(join(outside, "kept"), "utf8"), "outside");
    files.unlinkIfExists(root, "exports/large.bin");
    files.unlinkIfExists(root, "exports/large.bin");
    return {
      readWriteReplaceDelete: true,
      rejectedJunctionAncestor: true,
      deletedJunctionLeaf: true,
    };
  }
  const model = new WindowsScanModel(request.options);
  const files = windowsScanLocalFiles(model.native);
  const root = "C:\\work\\scan";
  let identity: ScanRootIdentity | undefined, held: ScanLocalReader | undefined;
  const results = request.actions.map((action) => {
    try {
      switch (action.operation) {
        case "identity": {
          const result = files.rootIdentity(root);
          identity = result[1];
          return { root: result[0], identity: identity.map(String) };
        }
        case "replaceRoot":
          model.replaceRoot();
          return null;
        case "add":
          model.add(
            action.path,
            action.directory ?? false,
            Buffer.from(action.value ?? ""),
            action.target,
          );
          return null;
        case "write":
          files.atomicWrite(
            root,
            action.relative,
            action.size === undefined
              ? Buffer.from(action.value ?? "")
              : Buffer.alloc(action.size, 0xa5),
            action.expected ? identity : undefined,
          );
          return null;
        case "read": {
          const reader = files.openRead(root, action.relative, "test read");
          try {
            const value = readAll(reader);
            if (action.hold) held = reader;
            return {
              length: value.length,
              digest: digest(value),
              size: String(reader.size()),
            };
          } finally {
            if (!action.hold) reader.close();
          }
        }
        case "close":
          held?.close();
          held = undefined;
          return null;
        case "delete":
          files.unlinkIfExists(root, action.relative);
          return null;
        case "move":
          return model.attemptMove(action.path);
        case "option":
          Object.assign(model.options, { [action.name]: action.value });
          return null;
      }
    } catch (error) {
      return { error: (error as Error).message };
    }
  });
  return {
    results,
    entries: [...model.entries.values()].map((entry) => ({
      path: entry.path,
      directory: entry.directory,
      length: entry.bytes.length,
      digest: digest(entry.bytes),
    })),
    openHandles: model.openHandles,
    temporaryFiles: model.temporaryFiles,
    blockedMoves: model.blockedMoves,
    writes: model.events.filter((event) => event.operation === "write").length,
    flushes: model.events.filter((event) => event.operation === "flush").length,
    renames: model.events.filter((event) => event.operation === "rename")
      .length,
    maxRead: Math.max(
      0,
      ...model.events
        .filter((event) => event.operation === "read")
        .map((event) => event.size!),
    ),
    maxWrite: Math.max(
      0,
      ...model.events
        .filter((event) => event.operation === "write")
        .map((event) => event.size!),
    ),
  };
}
process.stdout.write(JSON.stringify(main()));
