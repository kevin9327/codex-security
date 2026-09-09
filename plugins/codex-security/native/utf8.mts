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
