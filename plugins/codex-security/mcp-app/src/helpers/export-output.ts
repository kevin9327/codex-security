import { lstatSync, realpathSync, statSync } from "node:fs";
import { windowsBinding } from "../native";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsJoin,
  windowsParts,
} from "../../../native/windows-files.mjs";
import { requireDict, requireList, requireString } from "./contract-validation";
import { fileInfo } from "./helper-files";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { object } from "./python-json";
import { relativePath } from "./rank-selection";
import { parsedPath } from "./resolve-security-md";
import { ContractError } from "./scan-contract-errors";
import { jsonBytes, readScanLocalJson } from "./scan-contract-json";
import {
  openScanLocalFile,
  requirePortableRelativePath,
  requireScanDirectory,
  writeScanLocalBytes,
  type ScanRootIdentity,
} from "./scan-local-files";
import { EXPORT_PATHS } from "./sealed-scan";
import { uppercase } from "./unicode-case";
import { windowsFileIdentity } from "./windows-scan-files";

const windows = process.platform === "win32";
const osError = (error: unknown) =>
  (error as { errno?: number }).errno !== undefined ||
  (error as { winerror?: number }).winerror !== undefined;
const missing = (error: unknown) =>
  (error as { code?: string }).code === "ENOENT";
const sameIdentity = (left: ScanRootIdentity, right: ScanRootIdentity) =>
  left[0] === right[0] && left[1] === right[1];

function root(path: string): string {
  return windows
    ? windowsParts(path).slice(0, 2).join("")
    : path.startsWith("//") && !path.startsWith("///")
      ? "//"
      : path.startsWith("/")
        ? "/"
        : "";
}
function parent(path: string): string {
  const prefix = root(path),
    tail = path.slice(prefix.length);
  return (
    prefix +
      tail.slice(0, Math.max(0, tail.lastIndexOf(windows ? "\\" : "/"))) || "."
  );
}
function* parents(path: string): Generator<string> {
  for (;;) {
    const next = parent(path);
    if (next === path) return;
    yield next;
    path = next;
  }
}
function normalized(path: string): string {
  const prefix = root(path),
    parts: string[] = [];
  for (const part of path
    .slice(prefix.length)
    .split(windows ? /[/\\]/u : /\//u)) {
    if (!part || part === ".") continue;
    if (part === ".." && parts.length && parts.at(-1) !== "..") parts.pop();
    else if (part !== ".." || !prefix.endsWith(windows ? "\\" : "/"))
      parts.push(part);
  }
  return prefix + parts.join(windows ? "\\" : "/") || ".";
}
function absoluteOutput(path: string): string {
  path = parsedPath(path);
  if (!windows) {
    const absolute = path.startsWith("/")
      ? path
      : `${decodePosixBytes(realpathSync.native(".", { encoding: "buffer" }))}/${path}`;
    return normalized(absolute);
  }
  const native = windowsBinding();
  const result = native.windowsAbsolutePath(widePath(normalized(path)));
  if (!result.error) return parsedPath(pathText(result.value));
  const [drive, prefix, tail] = windowsParts(path);
  if (drive && prefix) return normalized(path);
  if (drive || prefix) {
    const resolved = native.windowsAbsolutePath(widePath(drive + prefix));
    return normalized(
      resolved.error
        ? drive + "\\" + tail
        : windowsJoin(pathText(resolved.value), tail),
    );
  }
  return normalized(
    windowsJoin(
      pathText(windowsFileSystem(native).absolute(widePath("."))),
      path,
    ),
  );
}
function identityAt(path: string, follow = true): ScanRootIdentity {
  if (windows)
    return windowsFileIdentity(
      windowsFileSystem(windowsBinding()).identity(widePath(path), follow),
    );
  const metadata = follow
    ? statSync(encodePosixPath(path), { bigint: true })
    : lstatSync(encodePosixPath(path), { bigint: true });
  return [metadata.dev, metadata.ino];
}

/** Write an export without replacing canonical artifacts or aliases of sealed files. */
export function writeExportOutput(
  scanDir: string,
  output: string,
  exportFormat: string,
  contents: Buffer,
): void {
  if (!Object.hasOwn(EXPORT_PATHS, exportFormat))
    throw new ContractError(`unsupported export format: ${exportFormat}`);
  scanDir = requireScanDirectory(scanDir);
  output = absoluteOutput(output);
  let relativeOutput = relativePath(output, scanDir);
  if (relativeOutput === undefined) {
    for (const ancestor of parents(output)) {
      let insideScan: boolean;
      try {
        insideScan = sameIdentity(identityAt(ancestor), identityAt(scanDir));
      } catch (error) {
        if (missing(error)) continue;
        if (!osError(error)) throw error;
        throw new ContractError(
          "export output path: unable to inspect output directory",
        );
      }
      if (insideScan) {
        if (
          [ancestor, ...parents(ancestor)].some((path) =>
            fileInfo(path, false)?.isSymbolicLink(),
          )
        )
          throw new ContractError(
            "export output path: symbolic links cannot alias the scan directory",
          );
        relativeOutput = relativePath(output, ancestor)!;
        break;
      }
    }
    if (relativeOutput === undefined) {
      const directory = parent(output),
        name = output
          .slice(root(output).length)
          .split(windows ? /\\/u : /\//u)
          .at(-1)!;
      writeScanLocalBytes(directory, name, contents, { externalName: true });
      return;
    }
  }
  if (
    relativeOutput !== EXPORT_PATHS[exportFormat as keyof typeof EXPORT_PATHS]
  )
    throw new ContractError(
      `${uppercase(exportFormat)} output path cannot overwrite a scan artifact`,
    );
  const manifest = readScanLocalJson(
    scanDir,
    "scan-manifest.json",
    "scan-manifest.json",
  );
  const scan = requireDict(manifest, "scan", "manifest");
  const artifactPaths = requireList(scan, "artifacts", "manifest.scan").flatMap(
    (artifact, index) =>
      object(artifact)
        ? [
            requirePortableRelativePath(
              requireString(
                artifact,
                "path",
                `manifest.scan.artifacts[${index}]`,
              ),
              `manifest.scan.artifacts[${index}].path`,
            ),
          ]
        : [],
  );
  let outputIdentity: ScanRootIdentity | undefined;
  try {
    outputIdentity = identityAt(output, false);
  } catch (error) {
    if (!missing(error)) {
      if (!osError(error)) throw error;
      throw new ContractError(
        `${relativeOutput}: unable to inspect export output`,
      );
    }
  }
  for (const path of artifactPaths) {
    if (path === relativeOutput)
      throw new ContractError(
        `${uppercase(exportFormat)} output path cannot overwrite a sealed scan artifact`,
      );
    if (outputIdentity === undefined) continue;
    const file = openScanLocalFile(scanDir, path, `sealed artifact ${path}`);
    let artifactIdentity: ScanRootIdentity;
    try {
      artifactIdentity = file.identity();
    } finally {
      file.close();
    }
    if (sameIdentity(outputIdentity, artifactIdentity))
      throw new ContractError(
        `${uppercase(exportFormat)} output path cannot overwrite a sealed scan artifact`,
      );
  }
  writeScanLocalBytes(scanDir, relativeOutput, contents);
}

export function writeSarifOutput(
  scanDir: string,
  output: string,
  sarif: Record<string, unknown>,
): void {
  writeExportOutput(scanDir, output, "sarif", jsonBytes(sarif));
}
