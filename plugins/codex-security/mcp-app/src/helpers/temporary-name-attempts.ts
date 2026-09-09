import { libc } from "../../../native/platform.mjs";

// CPython tempfile uses the C runtime's TMP_MAX for name-collision retries.
export const temporaryNameAttempts =
  process.platform === "win32"
    ? 2147483647
    : process.platform === "darwin"
      ? 308915776
      : libc === "musl"
        ? 10000
        : 238328;
