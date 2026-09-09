import type { Row } from "../../native/sqlite.mjs";
import { filesystemErrorMessage } from "./helpers/file-errors";
import { hasText } from "./helpers/finding-root-cause";
import {
  JsonFloat,
  JsonSyntaxError,
  object,
  pythonRepr,
  stringifyJson,
} from "./helpers/python-json";
import { relativePath } from "./helpers/rank-selection";
import { parsedPath } from "./helpers/resolve-security-md";
import { findingCandidateId } from "./helpers/saved-findings-projection";
import { ContractError } from "./helpers/scan-contract-errors";
import { JsonValueError, loadsJson } from "./helpers/scan-contract-json";
import {
  openScanLocalFile,
  readScanLocalBytes,
  writeScanLocalBytes,
} from "./helpers/scan-local-files";
import { decodePythonUtf8, UnicodeDecodeError } from "./helpers/utf8";
import { canonicalDiscoveryArtifacts } from "./workbench-deep-files";
import { artifactPath, readJsonObject } from "./workbench-files";
import { expectedCoverageMode, scanContract } from "./workbench-results";
import { WorkbenchValidationError } from "./workbench-validation";

type Table = Record<string, unknown>;
export interface BudgetCandidate extends Table {
  candidate_id: string;
  summary: string;
  evidence: string;
  locations: (Table & { path: string })[];
}

const osError = (error: unknown) => {
  const value = error as { errno?: number; winerror?: number };
  return value.errno !== undefined || value.winerror !== undefined;
};
function relativeArtifact(path: string, scanDir: string): string {
  const relative = relativePath(path, scanDir);
  if (relative === undefined)
    throw new JsonValueError(
      `${pythonRepr(path)} is not in the subpath of ${pythonRepr(scanDir)} OR one path is relative and the other is absolute.`,
    );
  return relative || ".";
}

// TextIOWrapper reads 8192-byte chunks before yielding universal-newline lines.
// Preserve the ordering of decode and JSON errors, including split UTF-8 bytes.
function* ledgerLines(scanDir: string, relative: string): Generator<string> {
  const file = openScanLocalFile(
    scanDir,
    relative,
    "Canonical Deep Scan candidate ledger",
  );
  const buffer = Buffer.alloc(8192);
  let pending = Buffer.alloc(0),
    text = "";
  try {
    for (;;) {
      const count = file.read(buffer);
      const bytes = Buffer.concat([pending, buffer.subarray(0, count)]);
      pending = Buffer.alloc(0);
      try {
        text += decodePythonUtf8(bytes);
      } catch (error) {
        if (
          count === 0 ||
          !(error instanceof UnicodeDecodeError) ||
          !error.message.endsWith("unexpected end of data")
        )
          throw error;
        let start = bytes.length - 1;
        while ((bytes[start]! & 0xc0) === 0x80) start--;
        pending = bytes.subarray(start);
        text += decodePythonUtf8(bytes.subarray(0, start));
      }
      for (;;) {
        const newline = /[\r\n]/u.exec(text);
        if (!newline) break;
        const offset = newline.index;
        if (text[offset] === "\r" && offset + 1 === text.length && count) break;
        const length = text.slice(offset, offset + 2) === "\r\n" ? 2 : 1;
        const line = text.slice(0, offset) + "\n";
        text = text.slice(offset + length);
        yield line;
      }
      if (count === 0) {
        if (text) yield text;
        return;
      }
    }
  } finally {
    file.close();
  }
}

export function budgetExhaustedCandidates(
  scan: Row,
  scanDir: string,
): BudgetCandidate[] {
  const artifacts = canonicalDiscoveryArtifacts(scan);
  const ledger = parsedPath(artifacts["candidateLedgerPath"]!);
  let inScope: Set<string>, candidates: unknown[];
  try {
    const inventory = parsedPath(artifacts["inScopeFilesPath"]!);
    const lines = decodePythonUtf8(
      readScanLocalBytes(
        scanDir,
        relativeArtifact(inventory, scanDir),
        "Canonical Deep Scan in-scope inventory",
      ),
    ).split(/\r?\n/u);
    inScope = new Set(
      lines.filter(Boolean).map((line) => line.replace(/^(?:\.\/)+/u, "")),
    );
    candidates = [];
    for (const line of ledgerLines(scanDir, relativeArtifact(ledger, scanDir)))
      if (hasText(line)) candidates.push(loadsJson(line));
  } catch (error) {
    if (
      !(error instanceof ContractError) &&
      !osError(error) &&
      !(error instanceof UnicodeDecodeError) &&
      !(error instanceof JsonSyntaxError) &&
      !(error instanceof JsonValueError)
    )
      throw error;
    throw new WorkbenchValidationError(
      `Canonical Deep Scan candidate ledger is invalid: ${filesystemErrorMessage(error)}`,
    );
  }
  const ids = new Set<string>();
  for (const candidate of candidates) {
    if (!object(candidate))
      throw new WorkbenchValidationError(
        "Canonical Deep Scan candidate ledger rows must be objects.",
      );
    const id = candidate["candidate_id"],
      locations = candidate["locations"];
    if (
      !hasText(id) ||
      id === "." ||
      id === ".." ||
      /[/\\]/u.test(id) ||
      ids.has(id) ||
      !hasText(candidate["summary"]) ||
      !hasText(candidate["evidence"]) ||
      !Array.isArray(locations) ||
      !locations.length
    )
      throw new WorkbenchValidationError(
        "Canonical Deep Scan candidate ledger contains an invalid candidate.",
      );
    ids.add(id);
    for (const location of locations) {
      if (!object(location))
        throw new WorkbenchValidationError(
          "Canonical Deep Scan candidate location must be an object.",
        );
      const path = location["path"];
      if (
        typeof path !== "string" ||
        !path ||
        /[\\\0]/u.test(path) ||
        /^[A-Za-z]:/u.test(path) ||
        path.startsWith("/") ||
        path.split("/").some((part) => part === "." || part === ".." || !part)
      )
        throw new WorkbenchValidationError(
          "Canonical Deep Scan candidate location must be repository-relative.",
        );
    }
    if (
      !locations.some((location: Table) =>
        inScope.has(location["path"] as string),
      )
    )
      throw new WorkbenchValidationError(
        "Canonical Deep Scan candidate must include a location in its in-scope inventory.",
      );
  }
  return candidates as BudgetCandidate[];
}

function truth(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (object(value)) return Object.keys(value).length > 0;
  if (value instanceof JsonFloat) return Number(value.source) !== 0;
  return Boolean(value);
}

export function budgetExhaustedDraft(
  scan: Row,
  scanDir: string,
  candidates: BudgetCandidate[],
  warning: string,
): void {
  const documents: Record<string, Table> = {};
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    const path = artifactPath(scanDir, name, false);
    if (path !== null) documents[name] = readJsonObject(path);
  }
  const count = Object.keys(documents).length;
  if (count && count !== 3)
    throw new WorkbenchValidationError(
      "Budget-exhausted scan contains an incomplete canonical scan draft.",
    );
  let manifest: Table, findings: Table, coverage: Table;
  if (count) {
    manifest = documents["scan-manifest.json"]!;
    findings = documents["findings.json"]!;
    coverage = documents["coverage.json"]!;
    if (!object(manifest["scan"]) || !Array.isArray(findings["findings"]))
      throw new WorkbenchValidationError(
        "Budget-exhausted scan contains an invalid canonical scan draft.",
      );
    for (const key of ["surfaces", "explicitExclusions", "deferred"])
      if (!Array.isArray(coverage[key]))
        throw new WorkbenchValidationError(
          "Budget-exhausted scan contains invalid canonical coverage.",
        );
    if (
      (manifest["scan"]["sealedAt"] ?? null) !== null ||
      truth(manifest["scan"]["artifacts"])
    )
      throw new WorkbenchValidationError(
        "Budget-exhausted scan cannot replace an already sealed scan draft.",
      );
  } else {
    const contract = scanContract(scan),
      targetContract = contract["target"] as Table;
    const target: Table = {
      kind: (targetContract["allowedKinds"] as string[])[0],
      targetId: targetContract["targetId"],
      displayName: targetContract["displayName"],
    };
    if (scan.get("target_revision") !== "unversioned")
      target["revision"] = scan.get("target_revision");
    if (Object.hasOwn(targetContract, "requiredSnapshotDigest"))
      target["snapshotDigest"] = targetContract["requiredSnapshotDigest"];
    manifest = {
      scan: {
        target,
        scope: { limitations: [warning], validationMode: "incomplete" },
      },
    };
    findings = { findings: [] };
    coverage = {
      completeness: "partial",
      inventoryStrategy:
        expectedCoverageMode(scan) === "scoped_path"
          ? "scoped_path"
          : "repository",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    };
  }
  const findingIds = new Set(
    (findings["findings"] as unknown[])
      .filter(object)
      .map(findingCandidateId)
      .filter((id) => typeof id === "string"),
  );
  const deferred = coverage["deferred"] as unknown[],
    surfaces = coverage["surfaces"] as unknown[];
  const deferredIds = new Set(
    deferred
      .filter(object)
      .map((item) =>
        Object.hasOwn(item, "candidateId") ? item["candidateId"] : item["id"],
      )
      .filter((id) => typeof id === "string"),
  );
  const surfaceIds = new Set(
    surfaces
      .filter(object)
      .map((item) => item["id"])
      .filter((id) => typeof id === "string"),
  );
  for (const candidate of candidates) {
    const id = candidate.candidate_id;
    if (findingIds.has(id) || deferredIds.has(id)) continue;
    const paths = [
      ...new Set(candidate.locations.map((location) => location.path)),
    ];
    const surfaceId = `candidate-${id}`;
    const validation = object(candidate["validation"])
      ? candidate["validation"]["disposition"]
      : null;
    const attack = object(candidate["attack_path"])
      ? candidate["attack_path"]["decision"]
      : null;
    const disposition =
      validation === "deferred" || attack === "deferred"
        ? "needs_follow_up"
        : validation === "not_applicable"
          ? "not_applicable"
          : validation === "suppressed" || attack === "ignore"
            ? "rejected"
            : "needs_follow_up";
    if (!surfaceIds.has(surfaceId)) {
      surfaces.push({
        id: surfaceId,
        label: candidate.summary,
        disposition,
        notes: candidate.evidence,
        receiptRefs: [],
      });
      surfaceIds.add(surfaceId);
    }
    if (disposition !== "needs_follow_up") continue;
    deferred.push({
      id,
      candidateId: id,
      reason: `Validation was deferred because the scan reached its cost limit: ${candidate.summary}. Evidence: ${candidate.evidence}`,
      paths,
      surfaceIds: [surfaceId],
    });
  }
  if (
    !deferred.some(
      (item) =>
        object(item) &&
        typeof item["reason"] === "string" &&
        (item["reason"] ===
          "Validation was deferred because the scan reached its cost limit." ||
          item["reason"].startsWith(
            "Validation was deferred because the scan reached its cost limit: ",
          )),
    )
  )
    deferred.push({
      id: "scan-cost-limit",
      reason:
        "Validation was deferred because the scan reached its cost limit.",
    });
  coverage["completeness"] = "partial";
  for (const [name, payload] of [
    ["findings.json", findings],
    ["coverage.json", coverage],
    ["scan-manifest.json", manifest],
  ] as const) {
    try {
      writeScanLocalBytes(
        scanDir,
        name,
        Buffer.from(
          stringifyJson(payload, { allowNan: false, sortKeys: true }) + "\n",
        ),
      );
    } catch (error) {
      if (
        !(error instanceof ContractError) &&
        !osError(error) &&
        !(error instanceof TypeError) &&
        !(error instanceof JsonValueError) &&
        !(
          error instanceof Error &&
          error.message.startsWith(
            "Out of range float values are not JSON compliant:",
          )
        )
      )
        throw error;
      throw new WorkbenchValidationError(
        `Budget-exhausted scan draft could not be saved: ${filesystemErrorMessage(error)}`,
      );
    }
  }
}
