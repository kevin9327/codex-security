import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { hasText } from "./finding-root-cause";
import { JsonFloat, object, objectEntries, pythonRepr } from "./python-json";
import { compare } from "./rank-worklists";
import { ContractError } from "./scan-contract-errors";
import { requireSafeJsonValue } from "./scan-contract-json";
import {
  openScanLocalFile,
  requirePortableRelativePath,
  requireSafeRelativePath,
} from "./scan-local-files";
import { lowercase } from "./unicode-case";
import { encodeUtf8 } from "./utf8";

type Table = Record<string, unknown>;
export const SCHEMA_VERSION = "1.0";
export const FINGERPRINT_ALGORITHM = "codex-security/v1";
const get = (value: Table, key: string, fallback: unknown = null): unknown =>
  Object.hasOwn(value, key) ? value[key] : fallback;
function fail(message: string): never {
  throw new ContractError(message);
}
const slug = /^[a-z0-9][a-z0-9._/-]*$(?![\s\S])/u;
const numeric = (
  value: unknown,
): value is number | bigint | boolean | JsonFloat =>
  typeof value === "number" ||
  typeof value === "bigint" ||
  typeof value === "boolean" ||
  value instanceof JsonFloat;
const number = (
  value: number | bigint | boolean | JsonFloat,
): number | bigint =>
  value instanceof JsonFloat
    ? Number(value.source)
    : typeof value === "boolean"
      ? Number(value)
      : value;
const integer = (value: unknown): value is number | bigint | boolean =>
  typeof value === "bigint" ||
  typeof value === "boolean" ||
  (typeof value === "number" && Number.isInteger(value));
// These semantic checks use ordinary Python equality, including bool == int.
export function contractValuesEqual(left: unknown, right: unknown): boolean {
  if (numeric(left) && numeric(right)) {
    const a = number(left),
      b = number(right);
    return typeof a === typeof b
      ? a === b
      : typeof a === "bigint"
        ? Number.isInteger(b) && a === BigInt(b)
        : Number.isInteger(a) && BigInt(a) === b;
  }
  if (Array.isArray(left))
    return (
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => contractValuesEqual(item, right[index]))
    );
  if (object(left))
    return (
      object(right) &&
      Object.keys(left).length === Object.keys(right).length &&
      objectEntries(left).every(
        ([key, item]) =>
          Object.hasOwn(right, key) && contractValuesEqual(item, right[key]),
      )
    );
  return left === right;
}

export function requireDict(
  payload: Table,
  key: string,
  context: string,
): Table {
  const value = get(payload, key);
  if (!object(value)) fail(`${context}.${key}: expected an object`);
  return value;
}
export function requireList(
  payload: Table,
  key: string,
  context: string,
): unknown[] {
  const value = get(payload, key);
  if (!Array.isArray(value)) fail(`${context}.${key}: expected an array`);
  return value;
}
export function requireString(
  payload: Table,
  key: string,
  context: string,
): string {
  const value = get(payload, key);
  if (!hasText(value)) fail(`${context}.${key}: expected a non-empty string`);
  return value;
}

/** Keep urlsplit's existing acceptance and errors without WHATWG URL rewriting. */
export function validateRemote(remote: string, context: string): void {
  let rest = remote.replace(/^[\x00-\x20]+/u, "").replace(/[\t\r\n]/gu, "");
  const scheme = /^[A-Za-z][A-Za-z0-9+.-]*:/u.exec(rest);
  if (scheme) rest = rest.slice(scheme[0].length);
  let authority = "";
  if (rest.startsWith("//")) {
    const end = rest.slice(2).search(/[/?#]/u);
    authority = end === -1 ? rest.slice(2) : rest.slice(2, end + 2);
    rest = end === -1 ? "" : rest.slice(end + 2);
    if (authority.includes("[") !== authority.includes("]"))
      throw new Error("Invalid IPv6 URL");
    if (authority.includes("[")) {
      const hostInfo = authority.slice(authority.lastIndexOf("@") + 1),
        at = hostInfo.indexOf("[");
      let host: string;
      if (at !== -1) {
        if (at !== 0) throw new Error("Invalid IPv6 URL");
        const close = hostInfo.indexOf("]", 1);
        host = hostInfo.slice(1, close);
        const port = hostInfo.slice(close + 1);
        if (port && !port.startsWith(":")) throw new Error("Invalid IPv6 URL");
      } else host = hostInfo.split(":", 1)[0]!;
      if (host.startsWith("v")) {
        if (!/^v[a-fA-F0-9]+\.[^\n]+$(?![\s\S])/u.test(host))
          throw new Error("IPvFuture address is invalid");
      } else {
        const [address, scope, ...extra] = host.split("%");
        const version = isIP(address!);
        if (
          !version ||
          extra.length ||
          scope === "" ||
          (version === 4 && scope !== undefined)
        )
          throw new Error(
            `${pythonRepr(host)} does not appear to be an IPv4 or IPv6 address`,
          );
        if (version === 4)
          throw new Error("An IPv4 address cannot be in brackets");
      }
    }
  }
  const fragmentAt = rest.indexOf("#"),
    fragment = fragmentAt === -1 ? "" : rest.slice(fragmentAt + 1);
  if (fragmentAt !== -1) rest = rest.slice(0, fragmentAt);
  const queryAt = rest.indexOf("?"),
    query = queryAt === -1 ? "" : rest.slice(queryAt + 1);
  const normalized = authority.replace(/[@:#?]/gu, "").normalize("NFKC");
  if (/[/?#@:]/u.test(normalized))
    throw new Error(
      `netloc '${authority}' contains invalid characters under NFKC normalization`,
    );
  if (!scheme || !authority)
    fail(`${context}: expected a sanitized canonical absolute URL`);
  const at = authority.lastIndexOf("@"),
    userInfo = at === -1 ? "" : authority.slice(0, at);
  const colon = userInfo.indexOf(":"),
    username = colon === -1 ? userInfo : userInfo.slice(0, colon),
    password = colon === -1 ? "" : userInfo.slice(colon + 1);
  if (username || password || query || fragment)
    fail(
      `${context}: remote URL must not contain credentials, query, or fragment`,
    );
}

export function validateTarget(target: Table): void {
  const kind = requireString(target, "kind", "scan.target");
  if (
    ![
      "git_revision",
      "git_worktree",
      "git_diff",
      "directory_snapshot",
    ].includes(kind)
  )
    fail(`scan.target.kind: unsupported target kind: ${kind}`);
  requireString(target, "targetId", "scan.target");
  requireString(target, "displayName", "scan.target");
  const remote = get(target, "remote");
  if (remote !== null) {
    if (typeof remote !== "string")
      fail("scan.target.remote: expected a string");
    validateRemote(remote, "scan.target.remote");
  }
  requireString(
    target,
    kind === "git_revision" ? "revision" : "snapshotDigest",
    "scan.target",
  );
}
export function fingerprint(targetId: string, finding: Table): string {
  const identity = requireDict(finding, "identity", "finding"),
    anchor = requireString(identity, "anchor", "finding.identity");
  if (!slug.test(anchor))
    fail("finding.identity.anchor: expected a stable lowercase semantic slug");
  const instance = get(identity, "instance", "");
  if (typeof instance !== "string")
    fail("finding.identity.instance: expected a string");
  if (instance && !slug.test(instance))
    fail(
      "finding.identity.instance: expected a stable lowercase semantic slug",
    );
  const rule = requireString(finding, "ruleId", "finding");
  if (!slug.test(rule))
    fail("finding.ruleId: expected a stable lowercase rule slug");
  const material = [
    FINGERPRINT_ALGORITHM,
    targetId,
    rule,
    anchor,
    instance,
  ].join("\0");
  return `${FINGERPRINT_ALGORITHM}:sha256:${createHash("sha256").update(encodeUtf8(material)).digest("hex")}`;
}
export function stableId(prefix: string, ...parts: string[]): string {
  return `${prefix}_${createHash("sha256")
    .update(encodeUtf8(parts.join("\0")))
    .digest("hex")
    .slice(0, 24)}`;
}
export function validateLocation(location: Table, context: string): void {
  requireSafeRelativePath(
    requireString(location, "path", context),
    `${context}.path`,
  );
  const start = get(location, "startLine"),
    end = get(location, "endLine", start);
  if (!integer(start) || number(start) < 1)
    fail(`${context}.startLine: expected a positive integer`);
  if (!integer(end) || number(end) < number(start))
    fail(`${context}.endLine: expected an integer >= startLine`);
  const role = get(location, "role");
  if (role !== null && (typeof role !== "string" || !role))
    fail(`${context}.role: expected a non-empty string`);
}

type IdentityRow = [
  context: string,
  finding: Table,
  findingId: string,
  occurrenceId: string,
  fingerprints: { algorithm: string; primary: string },
];
export function derivedFindingIdentityRows(
  manifest: Table,
  findings: Table,
): IdentityRow[] {
  const scan = requireDict(manifest, "scan", "manifest"),
    scanId = requireString(scan, "id", "manifest.scan"),
    targetId = requireString(
      requireDict(scan, "target", "manifest.scan"),
      "targetId",
      "scan.target",
    );
  if (get(findings, "scanId") !== scanId)
    fail("findings.scanId: must match manifest scan id");
  const findingIds = new Set<string>(),
    occurrenceIds = new Set<string>(),
    rows: IdentityRow[] = [];
  for (const [index, value] of requireList(
    findings,
    "findings",
    "findings",
  ).entries()) {
    const context = `findings.findings[${index}]`;
    if (!object(value)) fail(`${context}: expected an object`);
    const finding = value,
      primary = fingerprint(targetId, finding),
      findingId = stableId("csf", primary),
      occurrenceId = stableId("occ", scanId, primary);
    rows.push([
      context,
      finding,
      findingId,
      occurrenceId,
      { algorithm: FINGERPRINT_ALGORITHM, primary },
    ]);
    findingIds.add(findingId);
    if (occurrenceIds.has(occurrenceId))
      fail(
        `${context}: duplicate occurrence identity; use identity.instance to split siblings`,
      );
    occurrenceIds.add(occurrenceId);
  }
  if (findingIds.size !== occurrenceIds.size)
    fail("findings: duplicate logical findings in one scan");
  return rows;
}
export function populateUnsealedFindingIdentities(
  manifest: Table,
  findings: Table,
): void {
  for (const [
    ,
    finding,
    findingId,
    occurrenceId,
    fingerprints,
  ] of derivedFindingIdentityRows(manifest, findings)) {
    finding["findingId"] = findingId;
    finding["occurrenceId"] = occurrenceId;
    finding["fingerprints"] = fingerprints;
  }
}
export function validateDerivedFindingIdentities(
  manifest: Table,
  findings: Table,
): void {
  for (const [
    context,
    finding,
    findingId,
    occurrenceId,
    fingerprints,
  ] of derivedFindingIdentityRows(manifest, findings)) {
    if (get(finding, "findingId") !== findingId)
      fail(`${context}.findingId: does not match derived fingerprint identity`);
    if (get(finding, "occurrenceId") !== occurrenceId)
      fail(`${context}.occurrenceId: does not match scan occurrence identity`);
    if (!contractValuesEqual(get(finding, "fingerprints"), fingerprints))
      fail(`${context}.fingerprints: does not match derived fingerprint`);
  }
}

export function validateFinding(finding: Table, context: string): void {
  for (const key of [
    "findingId",
    "occurrenceId",
    "ruleId",
    "title",
    "summary",
    "remediation",
  ])
    requireString(finding, key, context);
  requireDict(finding, "identity", context);
  const fingerprints = requireDict(finding, "fingerprints", context);
  if (get(fingerprints, "algorithm") !== FINGERPRINT_ALGORITHM)
    fail(`${context}.fingerprints.algorithm: unsupported algorithm`);
  requireString(fingerprints, "primary", `${context}.fingerprints`);
  const severity = requireDict(finding, "severity", context),
    level = requireString(severity, "level", `${context}.severity`);
  if (!["critical", "high", "medium", "low", "informational"].includes(level))
    fail(`${context}.severity.level: unsupported severity: ${level}`);
  const score = get(severity, "score");
  if (score !== null) {
    if (
      !numeric(score) ||
      typeof score === "boolean" ||
      !(number(score) >= 0 && number(score) <= 10)
    )
      fail(`${context}.severity.score: expected a number from 0 through 10`);
    requireString(severity, "scoringSystem", `${context}.severity`);
  }
  const confidence = requireDict(finding, "confidence", context),
    confidenceLevel = requireString(
      confidence,
      "level",
      `${context}.confidence`,
    );
  if (!["low", "medium", "high"].includes(confidenceLevel))
    fail(
      `${context}.confidence.level: unsupported confidence: ${confidenceLevel}`,
    );
  requireString(confidence, "rationale", `${context}.confidence`);
  const taxonomy = requireDict(finding, "taxonomy", context);
  requireString(taxonomy, "category", `${context}.taxonomy`);
  const cwe = get(taxonomy, "cwe", []);
  if (
    !Array.isArray(cwe) ||
    cwe.some((item) => typeof item !== "string" || !item)
  )
    fail(`${context}.taxonomy.cwe: expected an array of strings`);
  const locations = requireList(finding, "locations", context);
  if (!locations.length)
    fail(`${context}.locations: expected at least one location`);
  for (const [index, location] of locations.entries()) {
    if (!object(location))
      fail(`${context}.locations[${index}]: expected an object`);
    validateLocation(location, `${context}.locations[${index}]`);
  }
  const evidenceIds = new Set<string>();
  for (const key of ["codeEvidence", "code_evidence"]) {
    if (!Object.hasOwn(finding, key)) continue;
    const evidence = finding[key];
    if (!Array.isArray(evidence)) fail(`${context}.${key}: expected an array`);
    for (const [index, item] of evidence.entries()) {
      const at = `${context}.${key}[${index}]`;
      if (!object(item)) fail(`${at}: expected an object`);
      const id = requireString(item, "id", at);
      if (evidenceIds.has(id)) fail(`${at}.id: duplicate code-evidence id`);
      evidenceIds.add(id);
      requireString(item, "code", at);
    }
  }
  const sections: [string, unknown][] = [
    "rootCause",
    "root_cause",
    "validation",
    "attackPath",
  ].map((key) => [key, get(finding, key)]);
  const attackPath = get(finding, "attackPath");
  if (object(attackPath))
    for (const key of ["dataFlow", "dataflow", "data_flow", "reachability"])
      sections.push([`attackPath.${key}`, get(attackPath, key)]);
  for (const [name, section] of sections) {
    if (!object(section)) continue;
    for (const key of ["evidenceRefs", "evidence_refs"]) {
      if (!Object.hasOwn(section, key)) continue;
      const refs = section[key];
      if (
        !Array.isArray(refs) ||
        refs.some((ref) => typeof ref !== "string" || !ref)
      )
        fail(`${context}.${name}.${key}: expected strings`);
      const unknown = [
        ...new Set((refs as string[]).filter((ref) => !evidenceIds.has(ref))),
      ].sort(compare);
      if (unknown.length)
        fail(
          `${context}.${name}.${key}: unknown code-evidence ids: ${unknown.join(", ")}`,
        );
    }
  }
  requireString(
    requireDict(finding, "provenance", context),
    "source",
    `${context}.provenance`,
  );
  const extensions = get(finding, "extensions");
  if (extensions !== null && !object(extensions))
    fail(`${context}.extensions: expected an object`);
}

export function requireScanLocalFile(
  scanDir: string,
  relative: string,
  context: string,
): void {
  openScanLocalFile(scanDir, relative, context).close();
}
export function requireDerivedWriteupFiles(
  scanDir: string,
  findings: Table,
): void {
  for (const [index, finding] of (
    get(findings, "findings", []) as unknown[]
  ).entries()) {
    if (!object(finding)) continue;
    const writeup = get(finding, "writeup");
    if (!object(writeup)) continue;
    const path = get(writeup, "reportPath");
    if (typeof path === "string")
      requireScanLocalFile(
        scanDir,
        path,
        `findings[${index}].writeup.reportPath`,
      );
  }
}
export function requireHardeningPortfolioFile(
  scanDir: string,
  scan: Table,
): void {
  const hardening = get(scan, "hardening");
  if (!object(hardening)) return;
  const path = get(hardening, "portfolioPath");
  if (typeof path === "string")
    requireScanLocalFile(
      scanDir,
      path,
      "manifest.scan.hardening.portfolioPath",
    );
}
export function validateCoverage(
  manifest: Table,
  coverage: Table,
  scanDir: string,
): void {
  const scan = requireDict(manifest, "scan", "manifest"),
    scanId = requireString(scan, "id", "manifest.scan");
  if (get(coverage, "scanId") !== scanId)
    fail("coverage.scanId: must match manifest scan id");
  requireString(coverage, "mode", "coverage");
  const completeness = requireString(coverage, "completeness", "coverage");
  requireString(coverage, "inventoryStrategy", "coverage");
  const scope = requireDict(scan, "scope", "manifest.scan");
  if (
    !contractValuesEqual(
      get(coverage, "includePaths"),
      get(scope, "includePaths"),
    )
  )
    fail("coverage.includePaths: must match manifest scope");
  if (
    !contractValuesEqual(
      get(coverage, "excludePaths"),
      get(scope, "excludePaths"),
    )
  )
    fail("coverage.excludePaths: must match manifest scope");
  const ids = new Set<string>();
  let followUp = false;
  for (const [index, value] of requireList(
    coverage,
    "surfaces",
    "coverage",
  ).entries()) {
    const context = `coverage.surfaces[${index}]`;
    if (!object(value)) fail(`${context}: expected an object`);
    const surface = value,
      id = requireString(surface, "id", context);
    if (ids.has(id)) fail(`${context}.id: duplicate surface id`);
    ids.add(id);
    requireString(surface, "label", context);
    const disposition = requireString(surface, "disposition", context);
    if (
      ![
        "reported",
        "no_issue_found",
        "rejected",
        "not_applicable",
        "needs_follow_up",
      ].includes(disposition)
    )
      fail(`${context}.disposition: unsupported disposition: ${disposition}`);
    followUp ||= disposition === "needs_follow_up";
    const refs = get(surface, "receiptRefs", []);
    if (!Array.isArray(refs)) fail(`${context}.receiptRefs: expected an array`);
    for (const [at, ref] of refs.entries()) {
      const label = `${context}.receiptRefs[${at}]`;
      if (typeof ref !== "string") fail(`${label}: expected a string`);
      const normalized = requirePortableRelativePath(ref, label);
      if (!normalized.startsWith("artifacts/"))
        fail(`${label}: expected a file under artifacts/`);
      refs[at] = normalized;
      requireScanLocalFile(scanDir, normalized, label);
    }
  }
  for (const field of ["explicitExclusions", "deferred"])
    if (!Array.isArray(get(coverage, field, [])))
      fail(`coverage.${field}: expected an array`);
  if (
    completeness === "complete" &&
    (followUp || (get(coverage, "deferred", []) as unknown[]).length)
  )
    fail("coverage.completeness: complete coverage cannot have deferred work");
  requireSafeJsonValue(coverage, "coverage.json");
}
export function validateContractRefs(scan: Table): void {
  for (const [field, expected] of [
    ["coverageRef", "coverage.json"],
    ["findingsRef", "findings.json"],
  ] as const) {
    const actual = requireString(scan, field, "manifest.scan");
    if (actual !== expected)
      fail(`manifest.scan.${field}: expected ${pythonRepr(expected)}`);
  }
}
export function validateManifest(manifest: Table): void {
  if (get(manifest, "documentType") !== "codex-security.scan-manifest")
    fail("manifest.documentType: expected codex-security.scan-manifest");
  if (get(manifest, "schemaVersion") !== SCHEMA_VERSION)
    fail(`manifest.schemaVersion: expected ${SCHEMA_VERSION}`);
  const scan = requireDict(manifest, "scan", "manifest");
  for (const key of ["id", "startedAt", "completedAt", "sealedAt"])
    requireString(scan, key, "manifest.scan");
  const status = get(scan, "status");
  if (Array.isArray(status) || object(status))
    throw new TypeError(
      `unhashable type: '${Array.isArray(status) ? "list" : "dict"}'`,
    );
  if (
    !["completed", "failed", "canceled", "interrupted"].includes(
      status as string,
    )
  )
    fail("manifest.scan.status: expected a terminal scan outcome");
  const producer = requireDict(scan, "producer", "manifest.scan");
  requireString(producer, "name", "manifest.scan.producer");
  requireString(producer, "version", "manifest.scan.producer");
  validateTarget(requireDict(scan, "target", "manifest.scan"));
  const scope = requireDict(scan, "scope", "manifest.scan");
  for (const field of ["includePaths", "excludePaths"])
    for (const [index, value] of requireList(
      scope,
      field,
      "manifest.scan.scope",
    ).entries()) {
      const context = `manifest.scan.scope.${field}[${index}]`;
      if (typeof value !== "string") fail(`${context}: expected a string`);
      requireSafeRelativePath(value, context, true);
    }
  validateContractRefs(scan);
  const artifacts = requireList(scan, "artifacts", "manifest.scan");
  if (!artifacts.length)
    fail("manifest.scan.artifacts: expected generated artifact records");
  const paths = new Set<string>(),
    collisionKeys = new Set<string>();
  for (const [index, value] of artifacts.entries()) {
    const context = `manifest.scan.artifacts[${index}]`;
    if (!object(value)) fail(`${context}: expected an object`);
    const artifact = value,
      path = requirePortableRelativePath(
        requireString(artifact, "path", context),
        `${context}.path`,
      ),
      key = lowercase(path);
    if (collisionKeys.has(key))
      fail(`${context}.path: duplicate artifact path`);
    paths.add(path);
    collisionKeys.add(key);
    requireString(artifact, "sha256", context);
    requireString(artifact, "mediaType", context);
  }
  for (const path of ["findings.json", "coverage.json"])
    if (!paths.has(path))
      fail(`manifest.scan.artifacts: missing required artifact: ${path}`);
  requireSafeJsonValue(manifest, "scan-manifest.json");
}
export function validateFindings(manifest: Table, findings: Table): void {
  if (get(findings, "documentType") !== "codex-security.findings")
    fail("findings.documentType: expected codex-security.findings");
  if (get(findings, "schemaVersion") !== SCHEMA_VERSION)
    fail(`findings.schemaVersion: expected ${SCHEMA_VERSION}`);
  const scanId = requireString(
    requireDict(manifest, "scan", "manifest"),
    "id",
    "manifest.scan",
  );
  if (get(findings, "scanId") !== scanId)
    fail("findings.scanId: must match manifest scan id");
  const findingIds = new Set<string>(),
    occurrenceIds = new Set<string>();
  for (const [index, value] of requireList(
    findings,
    "findings",
    "findings",
  ).entries()) {
    const context = `findings.findings[${index}]`;
    if (!object(value)) fail(`${context}: expected an object`);
    const finding = value;
    validateFinding(finding, context);
    const findingId = finding["findingId"] as string,
      occurrenceId = finding["occurrenceId"] as string;
    if (findingIds.has(findingId) || occurrenceIds.has(occurrenceId))
      fail(`${context}: duplicate finding or occurrence id`);
    findingIds.add(findingId);
    occurrenceIds.add(occurrenceId);
  }
  requireSafeJsonValue(findings, "findings.json");
}
