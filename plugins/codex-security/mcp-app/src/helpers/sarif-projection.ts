import { StringDecoder } from "node:string_decoder";
import { mergedCodeEvidence, primaryFindingLocation } from "./finding-evidence";
import { JsonFloat, object, pythonRepr } from "./python-json";
import { compare } from "./rank-worklists";
import { appendPath } from "./rank-selection";
import { resolvedPath } from "./resolve-path";
import { SymlinkLoopError } from "./posix-path";
import { ContractError } from "./scan-contract-errors";
import {
  openScanLocalFile,
  requireSafeRelativePath,
  type ScanLocalReader,
} from "./scan-local-files";
import { lowercase, uppercase } from "./unicode-case";
import { encodeUtf8 } from "./utf8";

type Table = Record<string, unknown>;
type Numeric = number | bigint | JsonFloat;
type Severity = "critical" | "high" | "medium" | "low" | "informational";
export interface SarifLocation extends Table {
  path: string;
  startLine: Numeric;
  endLine?: Numeric;
  role?: unknown;
}
export interface SarifFinding extends Table {
  occurrenceId: string;
  findingId: string;
  ruleId: string;
  title: string;
  summary: string;
  remediation: string;
  taxonomy: { category: string; cwe: string[] };
  severity: { level: Severity; score?: Numeric };
  confidence: { level: string };
  fingerprints: { primary: string };
  locations: SarifLocation[];
}
export interface SarifManifest {
  schemaVersion: unknown;
  scan: { id: string; producer: { version: string }; target: Table };
}
const levels = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  informational: "note",
};
const scores = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "2.0",
  informational: "0.0",
};
const number = (value: Numeric): number | bigint =>
  value instanceof JsonFloat ? Number(value.source) : value;
const integer = (value: unknown): value is number | bigint =>
  typeof value === "bigint" ||
  (typeof value === "number" && Number.isInteger(value));
const sorted = (values: Iterable<string>) => [...new Set(values)].sort(compare);
const truthy = (value: unknown): boolean =>
  value instanceof JsonFloat
    ? Number(value.source) !== 0
    : object(value)
      ? Object.keys(value).length > 0
      : Array.isArray(value)
        ? value.length > 0
        : Boolean(value);
const string = (value: unknown) =>
  typeof value === "string" ? value : pythonRepr(value);

export function sarifLabel(value: string): string {
  const acronyms = new Set([
    "api",
    "csrf",
    "html",
    "http",
    "id",
    "rce",
    "sql",
    "ssrf",
    "url",
    "xml",
    "xss",
  ]);
  const words = value
    .replace(/[-_./]+/gu, " ")
    .split(/[\p{White_Space}\u001c-\u001f]+/u)
    .filter(Boolean);
  const label = words
    .map((word) => (acronyms.has(lowercase(word)) ? uppercase(word) : word))
    .join(" ");
  const [first = "", ...rest] = Array.from(label);
  return uppercase(first) + rest.join("");
}

function sarifRule(ruleId: string, findings: SarifFinding[]): Table {
  const name = ruleId.split(".").map(sarifLabel).join(": ");
  const categories = sorted(
    findings.map((finding) => finding.taxonomy.category),
  );
  const cwes = sorted(findings.flatMap((finding) => finding.taxonomy.cwe));
  const tags = new Set(["security", ...categories]);
  for (const cwe of cwes) {
    const match = /^CWE-([0-9]+)$(?![\s\S])/iu.exec(cwe);
    if (match) {
      const digits = match[1]!;
      // Retain the isolated Python interpreter's decimal-conversion boundary.
      if (digits.length > 4300)
        throw new Error(
          `Exceeds the limit (4300 digits) for integer string conversion: value has ${digits.length} digits; use sys.set_int_max_str_digits() to increase the limit`,
        );
      const number = BigInt(digits);
      if (number > 0n)
        tags.add(`external/cwe/cwe-${String(number).padStart(3, "0")}`);
    }
  }
  let description = `${name}. Categories: ${categories.map(sarifLabel).join(", ")}.`;
  if (cwes.length) description += ` Weaknesses: ${cwes.join(", ")}.`;
  const remediation = sorted(
    findings.map((finding) => finding.remediation),
  ).join("\n\n");
  const properties: Table = { tags: sorted(tags) };
  const score = findings
    .map(
      (finding) =>
        finding.severity.score ?? new JsonFloat(scores[finding.severity.level]),
    )
    .reduce((left, right) => (number(right) > number(left) ? right : left));
  if (number(score) > 0) properties["security-severity"] = pythonRepr(score);
  return {
    id: ruleId,
    name,
    shortDescription: { text: name },
    fullDescription: { text: description },
    help: {
      text: `${description}\n\nRemediation:\n\n${remediation}`,
      markdown: `${description}\n\n## Remediation\n\n${remediation}`,
    },
    properties,
  };
}

function findingMessage(finding: SarifFinding): string {
  const details = [
    finding.title,
    finding.summary,
    `Severity: ${finding.severity.level}`,
    `Category: ${sarifLabel(finding.taxonomy.category)}`,
  ];
  if (finding.taxonomy.cwe.length)
    details.push(`Weaknesses: ${finding.taxonomy.cwe.join(", ")}`);
  details.push(`Remediation:\n${finding.remediation}`);
  for (const [key, label] of [
    ["remediationTests", "Remediation tests"],
    ["preventiveControls", "Preventive controls"],
  ]) {
    const items = finding[key!];
    if (truthy(items))
      details.push(
        `${label}:\n` +
          (items as unknown[]).map((item) => `- ${string(item)}`).join("\n"),
      );
  }
  return details.join("\n\n");
}

/** Compute GitHub's rolling UTF-16 hashes while reading bounded byte chunks. */
export function githubLineHashes(
  reader: ScanLocalReader,
  requested?: ReadonlySet<bigint>,
): Map<bigint, string> {
  const size = 100,
    mask = (1n << 64n) - 1n,
    firstMod = (37n ** 100n) & mask;
  const window = Array<bigint>(size).fill(0n),
    lines = Array<bigint>(size).fill(-1n);
  const counts = new Map<string, bigint>(),
    hashes = new Map<bigint, string>();
  let raw = 0n,
    index = 0,
    line = 0n,
    lineStart = true,
    previousCR = false;
  function output() {
    const hash = (raw & mask).toString(16),
      count = (counts.get(hash) ?? 0n) + 1n;
    counts.set(hash, count);
    if (requested === undefined || requested.has(lines[index]!))
      hashes.set(lines[index]!, `${hash}:${count}`);
    lines[index] = -1n;
  }
  function update(current: number) {
    const beginning = window[index]!;
    window[index] = BigInt(current);
    raw = (37n * raw + BigInt(current) - firstMod * beginning) & mask;
    index = (index + 1) % size;
  }
  function process(current: number) {
    if (current === 32 || current === 9 || (previousCR && current === 10)) {
      previousCR = false;
      return;
    }
    if (current === 13) {
      current = 10;
      previousCR = true;
    } else previousCR = false;
    if (lines[index] !== -1n) output();
    if (lineStart) {
      lineStart = false;
      line++;
      lines[index] = line;
    }
    if (current === 10) lineStart = true;
    update(current);
  }
  const decoder = new StringDecoder("utf8"),
    buffer = Buffer.alloc(64 * 1024);
  function consume(text: string) {
    for (let i = 0; i < text.length; i++) process(text.charCodeAt(i));
  }
  for (;;) {
    const count = reader.read(buffer);
    if (!count) break;
    consume(decoder.write(buffer.subarray(0, count)));
  }
  consume(decoder.end());
  process(65535);
  for (let i = 0; i < size; i++) {
    if (lines[index] !== -1n) output();
    update(0);
  }
  return hashes;
}

const osError = (error: unknown) =>
  error instanceof Error && ("errno" in error || "winerror" in error);
export function githubLineHashesForSource(
  root: string,
  relative: string,
  requested?: ReadonlySet<bigint>,
): Map<bigint, string> | null {
  let reader: ScanLocalReader;
  try {
    reader = openScanLocalFile(root, relative, `source file ${relative}`);
  } catch (error) {
    if (error instanceof ContractError || osError(error)) return null;
    throw error;
  }
  try {
    try {
      return githubLineHashes(reader, requested);
    } finally {
      reader.close();
    }
  } catch (error) {
    if (osError(error)) return null;
    throw error;
  }
}

function numericKey(value: Numeric): string {
  const numeric = number(value);
  return typeof numeric === "bigint" || Number.isInteger(numeric)
    ? String(BigInt(numeric))
    : String(numeric);
}
function sarifLocations(finding: SarifFinding): SarifLocation[] {
  const primary = primaryFindingLocation(finding);
  const locations = [
    primary,
    ...finding.locations.filter((location) => location !== primary),
  ];
  for (const evidence of mergedCodeEvidence(finding)) {
    const rawPath = evidence["path"],
      start = evidence["startLine"],
      end = evidence["endLine"];
    if (typeof rawPath !== "string" || !integer(start) || start < 1) continue;
    let path: string;
    try {
      path = requireSafeRelativePath(rawPath, "SARIF evidence location");
    } catch (error) {
      if (error instanceof ContractError) continue;
      throw error;
    }
    locations.push({
      path,
      startLine: start,
      endLine: integer(end) && end >= start ? end : start,
      role: `evidence:${evidence["id"]}`,
    });
  }
  const unique = new Map<string, SarifLocation>();
  for (const location of locations) {
    const key = JSON.stringify([
      location.path,
      numericKey(location.startLine),
      numericKey(
        Object.hasOwn(location, "endLine")
          ? location.endLine!
          : location.startLine,
      ),
    ]);
    if (!unique.has(key)) unique.set(key, location);
  }
  return [...unique.values()];
}

type HashCache = Map<string, Map<string, string | null>>;
const pathKey = (root: string, relative: string) => {
  const path = appendPath(root, relative);
  return process.platform === "win32"
    ? lowercase(path.replaceAll("/", "\\"))
    : path;
};
function lineHashCache(
  findings: SarifFinding[],
  sourceRoot: string | undefined,
): HashCache {
  const cache: HashCache = new Map();
  if (sourceRoot === undefined) return cache;
  let root: string;
  try {
    root = resolvedPath(sourceRoot);
  } catch (error) {
    if (osError(error) || error instanceof SymlinkLoopError) return cache;
    throw error;
  }
  const requested = new Map<string, Set<bigint>>();
  for (const finding of findings) {
    const location = primaryFindingLocation(finding);
    const path = requireSafeRelativePath(
      location.path,
      "SARIF source location",
    );
    const lines = requested.get(path) ?? new Set<bigint>();
    lines.add(BigInt(number(location.startLine)));
    requested.set(path, lines);
  }
  for (const [relative, lines] of requested) {
    const hashes = githubLineHashesForSource(root, relative, lines);
    const key = pathKey(root, relative),
      values = cache.get(key) ?? new Map<string, string | null>();
    for (const line of lines)
      values.set(String(line), hashes?.get(line) ?? null);
    cache.set(key, values);
  }
  return cache;
}

function primaryLineHash(
  finding: SarifFinding,
  sourceRoot: string | undefined,
  cache: HashCache,
): string | null {
  if (sourceRoot === undefined) return null;
  let root: string;
  try {
    root = resolvedPath(sourceRoot);
  } catch (error) {
    if (osError(error) || error instanceof SymlinkLoopError) return null;
    throw error;
  }
  const location = primaryFindingLocation(finding);
  const relative = requireSafeRelativePath(
      location.path,
      "SARIF source location",
    ),
    line = BigInt(number(location.startLine));
  const key = pathKey(root, relative),
    values = cache.get(key) ?? new Map<string, string | null>();
  if (values.has(String(line))) return values.get(String(line))!;
  const hash =
    githubLineHashesForSource(root, relative, new Set([line]))?.get(line) ??
    null;
  values.set(String(line), hash);
  cache.set(key, values);
  return hash;
}

function sarifLocation(location: SarifLocation): Table {
  const uri = Array.from(encodeUtf8(location.path), (byte) => {
    const character = String.fromCharCode(byte);
    return /[A-Za-z0-9/_.~-]/u.test(character)
      ? character
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }).join("");
  const value: Table = {
    physicalLocation: {
      artifactLocation: { uri },
      region: {
        startLine: location.startLine,
        endLine: Object.hasOwn(location, "endLine")
          ? location.endLine
          : location.startLine,
      },
    },
  };
  if (truthy(location.role)) value["message"] = { text: location.role };
  return value;
}
function sarifResult(
  finding: SarifFinding,
  ruleIndex: number,
  root: string | undefined,
  cache: HashCache,
): Table {
  const properties: Table = {
    category: finding.taxonomy.category,
    confidence: finding.confidence.level,
    findingId: finding.findingId,
    occurrenceId: finding.occurrenceId,
    severity: finding.severity.level,
  };
  const extensions = finding["extensions"],
    candidate = object(extensions) ? extensions["candidateId"] : null;
  if (typeof candidate === "string" && candidate !== "")
    properties["candidateId"] = candidate;
  const fingerprints: Table = {
    "codexSecurity/v1": finding.fingerprints.primary,
  };
  const hash = primaryLineHash(finding, root, cache);
  if (hash !== null) fingerprints["primaryLocationLineHash"] = hash;
  return {
    ruleId: finding.ruleId,
    ruleIndex,
    level: levels[finding.severity.level],
    message: { text: findingMessage(finding) },
    locations: sarifLocations(finding).map(sarifLocation),
    partialFingerprints: fingerprints,
    properties,
  };
}

export function buildSarif(
  manifest: SarifManifest,
  findings: { findings: SarifFinding[] },
  sourceRoot?: string,
): Table {
  const scan = manifest.scan,
    target = scan.target;
  const ordered = [...findings.findings].sort((left, right) =>
    compare(left.occurrenceId, right.occurrenceId),
  );
  const groups = new Map<string, SarifFinding[]>();
  for (const finding of ordered) {
    const group = groups.get(finding.ruleId) ?? [];
    group.push(finding);
    groups.set(finding.ruleId, group);
  }
  const rules = [...groups.keys()].sort(compare),
    indices = new Map(rules.map((id, index) => [id, index]));
  const cache = lineHashCache(ordered, sourceRoot);
  const run: Table = {
    tool: {
      driver: {
        name: "Codex Security",
        version: scan.producer.version,
        rules: rules.map((id) => sarifRule(id, groups.get(id)!)),
      },
    },
    automationDetails: { id: scan.id },
    results: ordered.map((finding) =>
      sarifResult(finding, indices.get(finding.ruleId)!, sourceRoot, cache),
    ),
    properties: {
      codexSecuritySchemaVersion: manifest.schemaVersion,
      codexSecurityTargetKind: target["kind"],
    },
  };
  if (
    target["kind"] === "git_revision" &&
    truthy(target["remote"]) &&
    truthy(target["revision"])
  )
    run["versionControlProvenance"] = [
      { repositoryUri: target["remote"], revisionId: target["revision"] },
    ];
  return {
    $schema:
      "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [run],
  };
}

export function validateSarif(sarif: Table): void {
  if (sarif["version"] !== "2.1.0")
    throw new ContractError("SARIF: expected version 2.1.0");
  const runs = sarif["runs"];
  if (!Array.isArray(runs) || runs.length !== 1)
    throw new ContractError("SARIF: expected exactly one run");
  const run = runs[0];
  if (!object(run)) throw new ContractError("SARIF: expected a run object");
  const typed = run as {
    tool: { driver: { rules: { id: string }[] } };
    results: { ruleId: string; partialFingerprints?: unknown }[];
  };
  const ids = typed.tool.driver.rules.map((rule) => rule.id);
  for (const result of typed.results) {
    if (!ids.includes(result.ruleId))
      throw new ContractError("SARIF: result references an unknown rule");
    if (!truthy(result.partialFingerprints))
      throw new ContractError("SARIF: result is missing partialFingerprints");
  }
}
