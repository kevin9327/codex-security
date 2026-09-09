import { isUtf8 } from "node:buffer";

export function decodeUtf8(bytes: Buffer): string {
  // Node 20's fatal TextDecoder can silently replace invalid input bytes.
  if (!isUtf8(bytes))
    throw new TypeError("The encoded data was not valid for encoding utf-8");
  return bytes.toString("utf8");
}

export class UnicodeDecodeError extends Error {
  constructor(
    encoding: string,
    bytes: Buffer,
    start: number,
    end: number,
    reason: string,
  ) {
    const location =
      end === start + 1
        ? `byte 0x${bytes[start]!.toString(16).padStart(2, "0")} in position ${start}`
        : `bytes in position ${start}-${end - 1}`;
    super(`'${encoding}' codec can't decode ${location}: ${reason}`);
  }
}

// Strict by default; json.loads(bytes) additionally permits encoded surrogates.
export function decodePythonUtf8(bytes: Buffer, surrogatePass = false): string {
  if (isUtf8(bytes)) return bytes.toString("utf8");
  let decoded = "",
    segment = 0;
  for (let start = 0; start < bytes.length; ) {
    const byte = bytes[start]!;
    if (byte < 0x80) {
      start++;
      continue;
    }
    const length =
      byte >= 0xc2 && byte <= 0xdf
        ? 2
        : byte >= 0xe0 && byte <= 0xef
          ? 3
          : byte >= 0xf0 && byte <= 0xf4
            ? 4
            : 0;
    const encodedSurrogate =
      surrogatePass &&
      byte === 0xed &&
      bytes[start + 1]! >= 0xa0 &&
      bytes[start + 1]! <= 0xbf &&
      bytes[start + 2]! >= 0x80 &&
      bytes[start + 2]! <= 0xbf;
    let end = start + 1;
    let reason = length ? "" : "invalid start byte";
    for (let i = 1; i < length; i++) {
      if (start + i === bytes.length) {
        reason = "unexpected end of data";
        break;
      }
      const next = bytes[start + i]!;
      const minimum =
        i === 1 && byte === 0xe0
          ? 0xa0
          : i === 1 && byte === 0xf0
            ? 0x90
            : 0x80;
      const maximum =
        i === 1 && byte === 0xed && !encodedSurrogate
          ? 0x9f
          : i === 1 && byte === 0xf4
            ? 0x8f
            : 0xbf;
      if (next < minimum || next > maximum) {
        reason = "invalid continuation byte";
        break;
      }
      end++;
    }
    if (reason)
      throw new UnicodeDecodeError("utf-8", bytes, start, end, reason);
    if (encodedSurrogate) {
      decoded += bytes.subarray(segment, start).toString("utf8");
      decoded += String.fromCharCode(
        0xd000 | ((bytes[start + 1]! & 0x3f) << 6) | (bytes[start + 2]! & 0x3f),
      );
      segment = start + length;
    }
    start += length;
  }
  return decoded + bytes.subarray(segment).toString("utf8");
}

export function encodeUtf8(text: string): Buffer {
  const surrogate = /[\ud800-\udfff]/u;
  if (surrogate.test(text)) {
    const characters = Array.from(text);
    const start = characters.findIndex((character) =>
      surrogate.test(character),
    );
    let end = start + 1;
    while (end < characters.length && surrogate.test(characters[end]!)) end++;
    const detail =
      end === start + 1
        ? `character '\\u${characters[start]!.charCodeAt(0).toString(16)}' in position ${start}`
        : `characters in position ${start}-${end - 1}`;
    throw new Error(
      `'utf-8' codec can't encode ${detail}: surrogates not allowed`,
    );
  }
  return Buffer.from(text);
}
