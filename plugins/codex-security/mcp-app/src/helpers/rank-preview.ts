import { closeSync, openSync, readSync } from "node:fs";
import { basename } from "node:path";
import letterRanges from "@unicode/unicode-15.0.0/General_Category/Letter/ranges.js";
import numberRanges from "@unicode/unicode-15.0.0/General_Category/Number/ranges.js";
import { parse, unparse, type ClassDef, type ExprNode } from "py-ast";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";
import { windowsBinding } from "../native";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { object, objectEntries, parseJson } from "./python-json";
import { parsedPath } from "./resolve-security-md";

export const DEFAULT_PREVIEW_BYTES = 1024;
export const TEXT_CODE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cfg",
  ".clj",
  ".cpp",
  ".cs",
  ".css",
  ".cue",
  ".cxx",
  ".dart",
  ".ex",
  ".exs",
  ".go",
  ".graphql",
  ".h",
  ".hpp",
  ".hs",
  ".html",
  ".java",
  ".js",
  ".json",
  ".jsx",
  ".kt",
  ".kts",
  ".lua",
  ".mjs",
  ".mm",
  ".php",
  ".proto",
  ".ps1",
  ".psd1",
  ".psm1",
  ".py",
  ".rb",
  ".rs",
  ".scala",
  ".sh",
  ".sql",
  ".swift",
  ".toml",
  ".ts",
  ".tsx",
  ".vue",
  ".xml",
  ".yaml",
  ".yml",
]);
const JAVASCRIPT = new Set([".js", ".jsx", ".mjs", ".ts", ".tsx", ".vue"]);
const C_LIKE = new Set([".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".mm"]);
const JAVA_LIKE = new Set([...C_LIKE, ".cs", ".java"]);
const BRACE_LANGUAGES = new Set([
  ...JAVASCRIPT,
  ...JAVA_LIKE,
  ".dart",
  ".go",
  ".kt",
  ".kts",
  ".php",
  ".rs",
  ".scala",
  ".swift",
]);
const NESTED_COMMENTS = new Set([".kt", ".kts", ".rs", ".scala", ".swift"]);
const SPACE =
  "\\t-\\r\\x1c-\\x20\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const spaces = new RegExp(`[${SPACE}]+`, "u");
const trailingSpace = new RegExp(`[${SPACE}]+$`, "u");
const leadingSpace = new RegExp(`^[${SPACE}]+`, "u");
const strip = (text: string) =>
  text.replace(leadingSpace, "").replace(trailingSpace, "");
const splitLines = (text: string) => {
  const lines = text.split(/\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/u);
  if (lines.at(-1) === "") lines.pop();
  return lines;
};

// Python 3.12 uses Unicode 15.0 for \w, word boundaries and str.isalpha().
const rangeClass = (ranges: typeof letterRanges) =>
  ranges
    .map(
      ({ begin, end }) =>
        `\\u{${begin.toString(16)}}${end === begin + 1 ? "" : `-\\u{${(end - 1).toString(16)}}`}`,
    )
    .join("");
const LETTER = rangeClass(letterRanges);
const WORD = `${LETTER}${rangeClass(numberRanges)}_`;
const alpha = new RegExp(`^[${LETTER}]$`, "u");
const patterns = new Map<string, RegExp>();
function match(text: string, template: RegExp): RegExpExecArray | null {
  const key = template.toString();
  let pattern = patterns.get(key);
  if (!pattern) {
    let source = template.source;
    // Python's Unicode IGNORECASE additionally matches dotted/dotless I.
    if (template.ignoreCase) source = source.replace(/I/g, "[Iİı]");
    source = source.replace(/\[(?:\\.|[^\]\\])*\]|\\[wsb]/g, (token) => {
      if (token.startsWith("["))
        return token.replace(/\\w/g, WORD).replace(/\\s/g, SPACE);
      if (token === "\\w") return `[${WORD}]`;
      if (token === "\\s") return `[${SPACE}]`;
      return `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`;
    });
    pattern = new RegExp(source, template.ignoreCase ? "iu" : "u");
    patterns.set(key, pattern);
  }
  return pattern.exec(text);
}

function decodeSource(data: Buffer): string {
  const bom = data.subarray(0, 2).toString("hex");
  if (bom !== "fffe" && bom !== "feff")
    return decodePosixBytes(data).replace(/[\udc80-\udcff]/gu, "");
  let text = "";
  const unit = (index: number) =>
    bom === "fffe" ? data.readUInt16LE(index) : data.readUInt16BE(index);
  for (let index = 2; index + 1 < data.length; index += 2) {
    const first = unit(index);
    if (first >= 0xd800 && first <= 0xdbff) {
      if (index + 3 < data.length) {
        const second = unit(index + 2);
        if (second >= 0xdc00 && second <= 0xdfff) {
          text += String.fromCharCode(first, second);
          index += 2;
        }
      }
    } else if (first < 0xdc00 || first > 0xdfff)
      text += String.fromCharCode(first);
  }
  return text;
}

export function isBinarySample(data: Buffer): boolean {
  const bom = data.subarray(0, 2).toString("hex");
  return bom === "fffe" || bom === "feff"
    ? decodeSource(data).includes("\0")
    : data.includes(0);
}
export function compactPreviewLine(line: string): string {
  return line.split(spaces).filter(Boolean).join(" ");
}
function utf8(text: string): Buffer {
  if (/[\ud800-\udfff]/u.test(text))
    throw new Error("UTF-8 cannot encode an unpaired surrogate");
  return Buffer.from(text);
}
export function truncateUtf8(text: string, maximum: number): string {
  if (maximum <= 0) return "";
  const encoded = utf8(text);
  return encoded.length <= maximum
    ? text
    : decodeSource(encoded.subarray(0, maximum));
}
export function selectPreviewLines(lines: string[]): string[] {
  const compact = lines.map(compactPreviewLine).filter(Boolean);
  const head = compact.slice(0, 12),
    remainder = compact.slice(12);
  if (remainder.length <= 10) return [...head, ...remainder];
  return [
    ...head,
    "...",
    ...Array.from(
      { length: 10 },
      (_, index) =>
        remainder[Math.floor((index * (remainder.length - 1)) / 9)]!,
    ),
  ];
}
export function fitPreviewLines(lines: string[], maximum: number): string {
  if (!lines.length || maximum <= 0) return "";
  const full = lines.join("\n");
  if (utf8(full).length <= maximum) return full;
  const content = lines.filter((line) => line !== "...");
  if (!content.length) return truncateUtf8(full, maximum);
  let low = 0,
    high = Math.max(...content.map((line) => utf8(line).length)),
    best = "";
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = lines
      .map((line) =>
        line === "..."
          ? line
          : truncateUtf8(line, middle).replace(trailingSpace, ""),
      )
      .join("\n");
    if (utf8(candidate).length <= maximum) {
      best = candidate;
      low = middle + 1;
    } else high = middle - 1;
  }
  return best || truncateUtf8(full, maximum);
}

type PythonFunction = Extract<
  ReturnType<typeof parse>["body"][number],
  {
    nodeType: "FunctionDef" | "AsyncFunctionDef";
  }
>;
function renderPython(expression: ExprNode): string | undefined {
  try {
    return compactPreviewLine(unparse(expression, { canonical: true }));
  } catch {
    return undefined;
  }
}
function pythonDecorators(node: PythonFunction | ClassDef): string {
  return node.decorator_list
    .map(renderPython)
    .filter(Boolean)
    .map((value) => `@${value}`)
    .join(" ");
}
function pythonArguments(node: PythonFunction): string {
  const args = node.args;
  return [
    ...args.posonlyargs.map((arg) => arg.arg),
    ...args.args.map((arg) => arg.arg),
    ...(args.vararg ? [`*${args.vararg.arg}`] : []),
    ...args.kwonlyargs.map((arg) => arg.arg),
    ...(args.kwarg ? [`**${args.kwarg.arg}`] : []),
  ].join(", ");
}
export function pythonOutline(text: string): string[] {
  let tree: ReturnType<typeof parse>;
  try {
    tree = parse(text, { feature_version: 12 });
  } catch {
    return [];
  }
  const outline: string[] = [];
  for (const node of tree.body) {
    if (
      node.nodeType === "FunctionDef" ||
      node.nodeType === "AsyncFunctionDef"
    ) {
      const kind =
        node.nodeType === "AsyncFunctionDef" ? "async function" : "function";
      outline.push(
        strip(
          `${pythonDecorators(node)} ${kind} ${node.name}(${pythonArguments(node)})`,
        ),
      );
    } else if (node.nodeType === "ClassDef") {
      const bases = node.bases
        .map(renderPython)
        .filter((base) => base !== undefined);
      outline.push(
        strip(
          `${pythonDecorators(node)} class ${node.name}${bases.length ? `(${bases.join(", ")})` : ""}`,
        ),
      );
      for (const member of node.body) {
        if (
          member.nodeType !== "FunctionDef" &&
          member.nodeType !== "AsyncFunctionDef"
        )
          continue;
        const kind =
          member.nodeType === "AsyncFunctionDef" ? "async method" : "method";
        outline.push(
          strip(
            `${pythonDecorators(member)} ${kind} ${node.name}.${member.name}`,
          ),
        );
      }
    }
  }
  return outline;
}

function javascriptRegexEnd(text: string, start: number): number | undefined {
  if (start + 1 >= text.length || ["/", "*"].includes(text[start + 1]!)) return;
  let previous = start - 1;
  while (previous >= 0 && " \t\r".includes(text[previous]!)) previous--;
  if (previous >= 0 && !"=(:,[!&|?{};\n".includes(text[previous]!)) {
    const prefix = Array.from(text.slice(0, previous + 1))
      .slice(-9)
      .join("");
    if (!match(prefix, /\b(?:case|return|throw)$/)) return;
  }
  let index = start + 1,
    inClass = false;
  while (index < text.length) {
    const char = text[index];
    if (char === "\n") return;
    if (char === "\\" && index + 1 < text.length) {
      index += 2;
      continue;
    }
    if (char === "[") inClass = true;
    else if (char === "]") inClass = false;
    else if (char === "/" && !inClass) {
      index++;
      while (index < text.length) {
        const flag = String.fromCodePoint(text.codePointAt(index)!);
        if (!alpha.test(flag)) break;
        index += flag.length;
      }
      return index;
    }
    index++;
  }
  return;
}

function maskCStyleSource(text: string, suffix: string): string {
  const masked: string[] = [];
  let index = 0,
    commentDepth = 0,
    lineComment = false;
  let quote = "",
    rawEnd = "",
    heredocEnd = "";
  const hide = (count: number) => {
    masked.push(" ".repeat(count));
    index += count;
  };
  while (index < text.length) {
    const char = text[index]!,
      next = text[index + 1] ?? "";
    if (char === "\n") {
      masked.push(char);
      lineComment = false;
      if (quote && !["`", '"""', "'''", '@"'].includes(quote)) quote = "";
      index++;
      continue;
    }
    if (lineComment) {
      hide(1);
      continue;
    }
    if (commentDepth) {
      if (char === "/" && next === "*" && NESTED_COMMENTS.has(suffix)) {
        hide(2);
        commentDepth++;
      } else if (char === "*" && next === "/") {
        hide(2);
        commentDepth--;
      } else hide(1);
      continue;
    }
    if (heredocEnd) {
      if (index === 0 || text[index - 1] === "\n") {
        let end = text.indexOf("\n", index);
        if (end < 0) end = text.length;
        if (strip(text.slice(index, end)).replace(/;$/, "") === heredocEnd) {
          hide(end - index);
          heredocEnd = "";
          continue;
        }
      }
      hide(1);
      continue;
    }
    if (rawEnd) {
      if (text.startsWith(rawEnd, index)) {
        hide(rawEnd.length);
        rawEnd = "";
      } else hide(1);
      continue;
    }
    if (quote === '"""' || quote === "'''") {
      if (text.startsWith(quote, index)) {
        hide(quote.length);
        quote = "";
      } else hide(1);
      continue;
    }
    if (quote === '@"') {
      if (char === '"' && next === '"') hide(2);
      else {
        hide(1);
        if (char === '"') quote = "";
      }
      continue;
    }
    if (quote) {
      if (char === "\\" && next) hide(next === "\n" ? 1 : 2);
      else {
        hide(1);
        if (char === quote) quote = "";
      }
      continue;
    }
    if (suffix === ".rs") {
      const raw = /^(?:br|r)(#{0,16})"/.exec(text.slice(index));
      if (raw) {
        hide(raw[0].length);
        rawEnd = `"${raw[1]}`;
        continue;
      }
      if (char === "'") {
        const lifetime = /^'[A-Za-z_][A-Za-z0-9_]*/.exec(text.slice(index));
        if (lifetime && text[index + lifetime[0].length] !== "'") {
          masked.push(lifetime[0]);
          index += lifetime[0].length;
          continue;
        }
      }
    }
    if (suffix === ".cs" && char === "@" && next === '"') {
      hide(2);
      quote = '@"';
      continue;
    }
    const triple = text.slice(index, index + 3);
    if (triple === '"""' || triple === "'''") {
      hide(3);
      quote = triple;
      continue;
    }
    if (suffix === ".php" && text.startsWith("<<<", index)) {
      const heredoc = match(
        text.slice(index),
        /^<<<\s*['"]?([A-Za-z_]\w*)['"]?/,
      );
      if (heredoc) {
        hide(heredoc[0].length);
        heredocEnd = heredoc[1]!;
        continue;
      }
    }
    if (JAVASCRIPT.has(suffix) && char === "/") {
      const end = javascriptRegexEnd(text, index);
      if (end !== undefined) {
        hide(end - index);
        continue;
      }
    }
    if (char === "/" && next === "/") {
      hide(2);
      lineComment = true;
      continue;
    }
    if (char === "/" && next === "*") {
      hide(2);
      commentDepth = 1;
      continue;
    }
    if (char === "#" && suffix === ".php" && next !== "[") {
      hide(1);
      lineComment = true;
      continue;
    }
    if (['"', "'", "`"].includes(char)) {
      quote = char;
      hide(1);
      continue;
    }
    masked.push(char);
    index++;
  }
  return masked.join("");
}

type Declaration = [kind: string, name: string];
function matchType(line: string, suffix: string): Declaration | undefined {
  let found: RegExpExecArray | null = null;
  if (JAVASCRIPT.has(suffix))
    found = match(
      line,
      /^(?:(?:export|default|declare|abstract)\s+)*(class|interface|enum|namespace)\s+([A-Za-z_$][\w$]*)/,
    );
  else if (suffix === ".java")
    found = match(
      line,
      /\b(class|interface|enum|record|@interface)\s+([A-Za-z_$][\w$]*)/,
    );
  else if (suffix === ".cs")
    found = match(
      line,
      /\b(class|interface|struct|enum|record(?:\s+(?:class|struct))?)\s+(@?[A-Za-z_]\w*)/,
    );
  else if (suffix === ".php")
    found = match(
      line,
      /^(?:(?:abstract|final|readonly)\s+)*(class|interface|trait|enum)\s+([A-Za-z_]\w*)/,
    );
  else if (suffix === ".go") {
    found = match(line, /^type\s+([A-Za-z_]\w*)\s+(struct|interface)\b/);
    if (found) return [found[2]!, found[1]!];
  } else if (suffix === ".kt" || suffix === ".kts") {
    const companion = match(line, /\bcompanion\s+object(?:\s+([A-Za-z_]\w*))?/);
    if (companion) return ["object", companion[1] || "Companion"];
    found = match(
      line,
      /\b((?:(?:data|enum|sealed|annotation|value)\s+)?(?:class|interface|object))\s+([A-Za-z_]\w*)/,
    );
  } else if (suffix === ".scala")
    found = match(
      line,
      /^(?:(?:case|sealed|abstract)\s+)*(class|trait|object|enum)\s+([A-Za-z_]\w*)/,
    );
  else if (suffix === ".rs") {
    found = match(line, /\b(struct|enum|trait|union)\s+([A-Za-z_]\w*)/);
    if (!found) {
      const impl = match(
        line,
        /\bimpl(?:\s*<[^>{}]*>)?\s+(?:[\w:<>]+\s+for\s+)?([A-Za-z_]\w*)/,
      );
      if (impl) return ["impl", impl[1]!];
    }
  } else if (suffix === ".swift")
    found = match(
      line,
      /\b(class|struct|enum|protocol|actor|extension)\s+([A-Za-z_]\w*)/,
    );
  else if (suffix === ".dart")
    found = match(line, /\b(class|mixin|enum|extension)\s+([A-Za-z_]\w*)/);
  else if (C_LIKE.has(suffix))
    found = match(
      line,
      /\b(class|struct|union|enum(?:\s+class)?)\s+([A-Za-z_]\w*)/,
    );
  return found ? [found[1]!, found[2]!] : undefined;
}
const CONTROL_NAMES = new Set([
  "assert",
  "catch",
  "for",
  "foreach",
  "if",
  "lock",
  "new",
  "return",
  "sizeof",
  "static_assert",
  "switch",
  "synchronized",
  "throw",
  "typeof",
  "while",
]);
function matchJavaLikeFunction(
  line: string,
  suffix: string,
  typeName?: string,
): Declaration | undefined {
  const paren = line.indexOf("(");
  if (paren < 0) return;
  let before = line.slice(0, paren).replace(trailingSpace, "");
  if (!before || before.includes("=") || before.startsWith("#")) return;
  before = before.replace(/<[^<>]*>$/, "").replace(trailingSpace, "");
  const found = match(
    before,
    /(~?[A-Za-z_$@][\w$@]*(?:(?:::|\.)~?[A-Za-z_$@][\w$@]*)?)$/,
  );
  if (!found) return;
  const qualified = found[1]!,
    name = qualified.split(/::|\./).at(-1)!.replace(/^~+/, "");
  if (CONTROL_NAMES.has(name)) return;
  const prefix = strip(before.slice(0, found.index));
  if (!prefix && name !== (typeName ?? "")) return;
  if (
    C_LIKE.has(suffix) &&
    (prefix.startsWith("typedef") || prefix.startsWith("using"))
  )
    return;
  if (
    C_LIKE.has(suffix) &&
    typeName === undefined &&
    line.endsWith(";") &&
    !match(
      prefix,
      /(?:\b(?:auto|bool|char|consteval|constexpr|double|extern|float|inline|int|long|short|signed|static|unsigned|void)\b|[*&:]|<)/,
    )
  )
    return;
  return [typeName ? "method" : "function", qualified];
}
function matchFunction(
  line: string,
  suffix: string,
  typeName?: string,
): Declaration | undefined {
  if (JAVASCRIPT.has(suffix)) {
    const fn = match(
      line,
      /^(?:(?:export|default|declare)\s+)*(async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^>{}]*>)?\s*\(/,
    );
    if (fn) return [fn[1] ? "async function" : "function", fn[2]!];
    const arrow = match(
      line,
      /^(?:(?:export|declare)\s+)*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)/,
    );
    if (arrow) return ["function", arrow[1]!];
    if (typeName) {
      const field = match(
        line,
        /^(?:(?:public|private|protected|static|abstract|override|readonly|declare|accessor)\s+)*(#?[A-Za-z_$][\w$]*)(?:[?!])?\s*(?::[^=]+)?=\s*(?:async\s+)?(?:\([^)]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)/,
      );
      if (field) return ["method", field[1]!];
      const method = match(
        line,
        /^(?:(?:public|private|protected|static|abstract|async|override|readonly|declare|get|set)\s+)*(#?[A-Za-z_$][\w$]*|constructor)\s*(?:<[^>{}]*>)?\s*\(/,
      );
      if (method && !CONTROL_NAMES.has(method[1]!))
        return ["method", method[1]!];
    }
    return;
  }
  let found: RegExpExecArray | null = null;
  if (suffix === ".php")
    found = match(
      line,
      /^(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*function\s*&?\s*([A-Za-z_]\w*)\s*\(/,
    );
  else if (suffix === ".go") {
    found = match(
      line,
      /^func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]+\]\s*)?\(/,
    );
    if (!found) return;
    if (found[1]) {
      const receiver = match(found[1], /\*?([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*$/);
      return ["method", receiver ? `${receiver[1]}.${found[2]}` : found[2]!];
    }
    return [typeName ? "method" : "function", found[2]!];
  } else if (suffix === ".kt" || suffix === ".kts")
    found = match(
      line,
      /\bfun\s+(?:<[^>{}]*>\s*)?(?:[\w.<>?]+\.)?([A-Za-z_]\w*)\s*\(/,
    );
  else if (suffix === ".scala") found = match(line, /\bdef\s+([A-Za-z_]\w*)\b/);
  else if (suffix === ".rs")
    found = match(
      line,
      /\b(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]+"\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)/,
    );
  else if (suffix === ".swift") {
    found = match(line, /\bfunc\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\(/);
    if (!found && typeName && match(line, /\binit\s*\(/))
      return ["method", "init"];
  } else if (suffix === ".dart" || JAVA_LIKE.has(suffix))
    return matchJavaLikeFunction(line, suffix, typeName);
  return found ? [typeName ? "method" : "function", found[1]!] : undefined;
}

function isAnnotation(line: string): boolean {
  return Boolean(
    match(line, /^@[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\(.*\))?$/) ||
      match(line, /^\[[A-Za-z_][^\]]*\]$/) ||
      match(line, /^#\[[A-Za-z_][^\]]*\]$/),
  );
}
const LEADING_ANNOTATION =
  /^(?:@[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\([^)]*\))?|\[[A-Za-z_][^\]]*\]|#\[[A-Za-z_][^\]]*\])\s*/;
function stripAnnotations(
  original: string,
  masked: string,
): [string, string[]] {
  const annotations: string[] = [];
  if (masked.startsWith("@interface ")) return [masked, annotations];
  let found: RegExpExecArray | null;
  while ((found = match(masked, LEADING_ANNOTATION))) {
    const originalMatch = match(original, LEADING_ANNOTATION);
    if (originalMatch) {
      annotations.push(compactPreviewLine(originalMatch[0]));
      original = original
        .slice(originalMatch[0].length)
        .replace(leadingSpace, "");
    }
    masked = masked.slice(found[0].length).replace(leadingSpace, "");
  }
  return [masked, annotations];
}
function braceLanguageOutline(text: string, suffix: string): string[] {
  const originals = splitLines(text),
    maskedLines = splitLines(maskCStyleSource(text, suffix));
  const outline: string[] = [],
    seen = new Set<string>();
  const types: [string, number][] = [],
    functions: number[] = [],
    blocked: number[] = [];
  let pendingType: string | undefined,
    pendingFunction = false,
    annotations: string[] = [],
    depth = 0;
  const add = (value: string) => {
    const decorated = strip(`${annotations.slice(-2).join(" ")} ${value}`);
    if (!seen.has(decorated)) {
      seen.add(decorated);
      outline.push(decorated);
    }
  };
  const popScopes = () => {
    while (functions.length && depth < functions.at(-1)!) functions.pop();
    while (types.length && depth < types.at(-1)![1]) types.pop();
    while (blocked.length && depth < blocked.at(-1)!) blocked.pop();
  };
  const nextLinesOpenBody = (index: number) => {
    let inspected = 0;
    for (let next = index + 1; next < maskedLines.length; next++) {
      const line = compactPreviewLine(maskedLines[next]!);
      if (!line) continue;
      inspected++;
      if (line.includes("{")) return true;
      if (line.includes("}") || line.endsWith(";") || inspected >= 6)
        return false;
    }
    return false;
  };
  for (
    let index = 0;
    index < Math.min(originals.length, maskedLines.length);
    index++
  ) {
    popScopes();
    const masked = maskedLines[index]!,
      original = compactPreviewLine(originals[index]!);
    let line = compactPreviewLine(masked);
    const opens = masked.split("{").length - 1,
      closes = masked.split("}").length - 1;
    let openedPending = false;
    if (pendingType && masked.includes("{")) {
      types.push([pendingType, depth + 1]);
      pendingType = undefined;
      openedPending = true;
    }
    if (pendingFunction && masked.includes("{")) {
      functions.push(depth + 1);
      pendingFunction = false;
      openedPending = true;
    }
    if (
      line &&
      original &&
      isAnnotation(original) &&
      !functions.length &&
      !blocked.length
    )
      annotations.push(original);
    else if (line && !functions.length && !blocked.length) {
      const [stripped, inline] = stripAnnotations(original, line);
      line = stripped;
      for (const annotation of inline) annotations.push(annotation);
      const currentType = types.at(-1)?.[0],
        directBody = !types.length || depth === types.at(-1)![1];
      const type = directBody ? matchType(line, suffix) : undefined;
      if (type) {
        const kind = type[0];
        let name = type[1];
        if (
          currentType &&
          (suffix === ".kt" || suffix === ".kts") &&
          kind === "object" &&
          name === "Companion"
        )
          name = `${currentType}.${name}`;
        add(`${kind} ${name}`);
        annotations = [];
        if (masked.includes("{")) types.push([name, depth + 1]);
        else if (!line.endsWith(";") && nextLinesOpenBody(index))
          pendingType = name;
      } else if (directBody) {
        const fn = matchFunction(line, suffix, currentType);
        if (fn) {
          const [kind, name] = fn;
          add(
            `${kind} ${currentType && !name.includes(".") && !name.includes("::") ? `${currentType}.${name}` : name}`,
          );
          annotations = [];
          if (masked.includes("{")) functions.push(depth + 1);
          else if (
            !line.endsWith(";") &&
            !line.includes("=>") &&
            !line.includes("=") &&
            nextLinesOpenBody(index)
          )
            pendingFunction = true;
        } else {
          annotations = [];
          const transparent = match(
            line,
            /^(?:(?:export|inline)\s+)?namespace\b|^(?:pub\s+)?mod\b|^(?:declare\s+)?module\b|^(?:unsafe\s+)?extern\b/,
          );
          if (opens && !openedPending && !transparent) blocked.push(depth + 1);
        }
      }
    }
    depth = Math.max(0, depth + opens - closes);
    popScopes();
  }
  return outline;
}

function expandedLength(text: string): number {
  let length = 0,
    column = 0;
  for (const char of text) {
    const size = char === "\t" ? 4 - (column % 4) : 1;
    length += size;
    column = char === "\n" || char === "\r" ? 0 : column + size;
  }
  return length;
}
function rubyOutline(text: string): string[] {
  const outline = new Set<string>(),
    types: [number, string][] = [],
    functions: number[] = [];
  for (const raw of splitLines(text)) {
    const line = strip(raw);
    if (!line || line.startsWith("#")) continue;
    const indent =
      expandedLength(raw) - expandedLength(raw.replace(leadingSpace, ""));
    while (functions.length && indent <= functions.at(-1)!) functions.pop();
    while (types.length && indent <= types.at(-1)![0]) types.pop();
    const type = match(line, /^(class|module)\s+([A-Z]\w*(?:::[A-Z]\w*)*)/);
    if (type && !functions.length) {
      outline.add(`${type[1]} ${type[2]}`);
      types.push([indent, type[2]!]);
      continue;
    }
    const fn = match(line, /^def\s+(?:self\.)?([^\s(]+)/);
    if (fn && !functions.length) {
      outline.add(
        types.length
          ? `method ${types.at(-1)![1]}.${fn[1]}`
          : `function ${fn[1]}`,
      );
      functions.push(indent);
    }
  }
  return [...outline];
}
function simpleLanguageOutline(text: string, suffix: string): string[] {
  const outline = new Set<string>();
  for (const raw of splitLines(text)) {
    const line = compactPreviewLine(raw);
    if (!line) continue;
    let found: RegExpExecArray | null = null;
    if (suffix === ".py") {
      found = match(line, /^(async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
      if (found) {
        outline.add(`${found[1] ? "async function" : "function"} ${found[2]}`);
        continue;
      }
      found = match(line, /^class\s+([A-Za-z_]\w*)/);
      if (found) outline.add(`class ${found[1]}`);
    } else if (suffix === ".rb") {
      found = match(line, /^(class|module)\s+([A-Z]\w*(?:::[A-Z]\w*)*)/);
      if (found) {
        outline.add(`${found[1]} ${found[2]}`);
        continue;
      }
      found = match(line, /^def\s+(?:self\.)?([^\s(]+)/);
      if (found) outline.add(`function ${found[1]}`);
    } else if (suffix === ".ex" || suffix === ".exs") {
      found = match(line, /^defmodule\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)/);
      if (found) {
        outline.add(`module ${found[1]}`);
        continue;
      }
      found = match(line, /^(?:def|defp|defmacro)\s+([A-Za-z_]\w*[!?]?)/);
      if (found) outline.add(`function ${found[1]}`);
    } else if (suffix === ".clj") {
      found = match(
        line,
        /^\((defn|defmacro|defprotocol|defrecord|deftype|defmulti|defmethod)\s+([^\s)]+)/,
      );
      if (found) outline.add(`${found[1]} ${found[2]}`);
    } else if (suffix === ".lua" || suffix === ".sh") {
      found =
        suffix === ".lua"
          ? match(
              line,
              /^(?:local\s+)?function\s+([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)/,
            )
          : match(line, /^(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{?/);
      if (found) outline.add(`function ${found[1]}`);
    } else if (suffix === ".hs") {
      found = match(line, /^(data|newtype|type|class)\s+([A-Z]\w*)/);
      if (found) {
        outline.add(`${found[1]} ${found[2]}`);
        continue;
      }
      found = match(line, /^([a-z_]\w*)\s*::/);
      if (found) outline.add(`function ${found[1]}`);
    } else if (suffix === ".proto") {
      found = match(line, /^(message|service|enum)\s+([A-Za-z_]\w*)/);
      if (found) {
        outline.add(`${found[1]} ${found[2]}`);
        continue;
      }
      found = match(line, /^rpc\s+([A-Za-z_]\w*)\s*\(/);
      if (found) outline.add(`rpc ${found[1]}`);
    } else if (suffix === ".graphql") {
      found =
        match(
          line,
          /^(type|interface|input|enum|union|scalar|directive)\s+([A-Za-z_]\w*)/,
        ) || match(line, /^(query|mutation|subscription)\s+([A-Za-z_]\w*)/);
      if (found) outline.add(`${found[1]} ${found[2]}`);
    } else if (suffix === ".sql") {
      found = match(
        line,
        /^CREATE\s+(?:OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE|TABLE|VIEW|TRIGGER)\s+([^\s(;]+)/i,
      );
      if (found) outline.add(`${found[1]!.toLowerCase()} ${found[2]}`);
    } else if (suffix === ".yaml" || suffix === ".yml") {
      found = match(raw, /^([A-Za-z0-9_.-]+):(?:\s|$)/);
      if (found) outline.add(`key ${found[1]}`);
    } else if (suffix === ".toml" || suffix === ".cfg") {
      found = match(line, /^\[([^\]]+)\]$/);
      if (found) outline.add(`section ${found[1]}`);
    }
  }
  return [...outline];
}
class IntegerLimitError extends Error {}
function previewInteger(source: string): bigint {
  const setting = process.env["PYTHONINTMAXSTRDIGITS"];
  const limit = setting ? Number(setting) : 4300;
  if (
    (setting && !/^[\t-\r ]*[+-]?[0-9]+$/u.test(setting)) ||
    !Number.isInteger(limit) ||
    limit < 0 ||
    limit > 2147483647 ||
    (limit > 0 && limit < 640)
  )
    throw new IntegerLimitError(
      "PYTHONINTMAXSTRDIGITS: invalid limit; must be >= 640 or 0 for unlimited.",
    );
  const digits = source.length - (source.startsWith("-") ? 1 : 0);
  if (limit && digits > limit)
    throw new IntegerLimitError(
      `Exceeds the limit (${limit} digits) for integer string conversion: value has ${digits} digits; use sys.set_int_max_str_digits() to increase the limit`,
    );
  return BigInt(source);
}
function jsonOutline(text: string): string[] {
  let parsed: unknown;
  try {
    parsed = parseJson(text, false, previewInteger);
  } catch (error) {
    if (error instanceof IntegerLimitError) throw error;
    return [];
  }
  if (!object(parsed)) return [];
  return objectEntries(parsed).map(([key, value]) => {
    const children = object(value) ? objectEntries(value) : [];
    return `key ${key}${children.length ? ` [${children.map(([name]) => name).join(", ")}]` : ""}`;
  });
}
export function structuralOutline(path: string, text: string): string[] {
  const name = basename(parsedPath(path)),
    dot = name.lastIndexOf(".");
  const suffix =
    dot > 0 && dot < name.length - 1 ? name.slice(dot).toLowerCase() : "";
  if (suffix === ".py") {
    const outline = pythonOutline(text);
    return outline.length ? outline : simpleLanguageOutline(text, suffix);
  }
  if (suffix === ".rb") return rubyOutline(text);
  if (BRACE_LANGUAGES.has(suffix)) return braceLanguageOutline(text, suffix);
  if (suffix === ".json") return jsonOutline(text);
  return simpleLanguageOutline(text, suffix);
}

export function previewForBytes(
  path: string,
  data: Buffer,
  previewBytes: number,
): [string, boolean] {
  if (isBinarySample(data)) return ["", true];
  const text = decodeSource(data),
    outline = structuralOutline(path, text);
  return [
    fitPreviewLines(
      selectPreviewLines(outline.length ? outline : splitLines(text)),
      previewBytes,
    ),
    false,
  ];
}
export function previewFor(
  path: string,
  previewBytes: number,
  maxReadBytes?: number,
): [string, boolean] {
  path = parsedPath(path);
  let data: Buffer;
  try {
    const source =
      process.platform === "win32"
        ? windowsFileSystem(windowsBinding()).openRead(widePath(path))
        : (() => {
            const descriptor = openSync(encodePosixPath(path), "r");
            return {
              read: (buffer: Buffer) => readSync(descriptor, buffer),
              close: () => closeSync(descriptor),
            };
          })();
    try {
      const read = (size: number) => {
        const bytes = Buffer.alloc(size);
        let length = 0;
        while (length < size) {
          const count = source.read(bytes.subarray(length));
          if (!count) break;
          length += count;
        }
        return bytes.subarray(0, length);
      };
      const sample = read(4096);
      if (isBinarySample(sample)) return ["", true];
      const chunks = [sample];
      let remaining =
        maxReadBytes === undefined
          ? Infinity
          : Math.max(0, maxReadBytes - sample.length);
      while (remaining > 0) {
        const chunk = read(Math.min(64 * 1024, remaining));
        if (!chunk.length) break;
        chunks.push(chunk);
        remaining -= chunk.length;
      }
      data = Buffer.concat(chunks);
    } finally {
      source.close();
    }
  } catch (error) {
    if (!(error instanceof Error) || !("errno" in error || "winerror" in error))
      throw error;
    return ["", true];
  }
  return previewForBytes(path, data, previewBytes);
}
