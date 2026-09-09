import { createRequire } from "node:module";
import type { SqliteBinding } from "../../native/sqlite.mjs";
import type { ProcessBinding } from "../../native/process-binding.mjs";
import type { UnixBinding } from "../../native/binding.mjs";
import type { WindowsBinding } from "../../native/windows-binding.mjs";
import { nativeTarget } from "../../native/platform.mjs";

export function unixBinding(): UnixBinding {
  return createRequire(import.meta.url)(
    `./native/${nativeTarget}/unix.node`,
  ) as UnixBinding;
}

export function windowsBinding(): WindowsBinding {
  return createRequire(import.meta.url)(
    `./native/${nativeTarget}/windows.node`,
  ) as WindowsBinding;
}

export function sqliteBinding(): SqliteBinding {
  return createRequire(import.meta.url)(
    `./native/${nativeTarget}/${process.platform === "win32" ? "windows" : "unix"}.node`,
  ) as SqliteBinding;
}

export function processBinding(): ProcessBinding {
  return createRequire(import.meta.url)(
    `./native/${nativeTarget}/${process.platform === "win32" ? "windows" : "unix"}.node`,
  ) as ProcessBinding;
}
