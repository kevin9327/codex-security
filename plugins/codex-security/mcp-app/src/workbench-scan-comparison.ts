import { WorkbenchValidationError } from "./workbench-validation";
import { requireScan as requireScanRecord } from "./workbench-records";
export { resolveScanId } from "./workbench-records";
import type { Connection, Parameter } from "../../native/sqlite.mjs";
import { hasText } from "./helpers/finding-root-cause";
import {
  confirmedFindingAliases,
  knownFindingGroups,
  savedFindingLinks,
  separateFindingPairs,
  type FindingLink,
  type FindingPair,
} from "./workbench-finding-links";
export { findingMatches } from "./workbench-finding-links";
import { environment } from "./helpers/environment";
import {
  JsonFloat,
  object,
  objectEntries,
  objectFromEntries,
  parseJson,
  pythonRepr,
  stringifyJson,
} from "./helpers/python-json";
import { compare } from "./helpers/rank-worklists";
import { expandHome, parsedPath } from "./helpers/resolve-security-md";
import { resolvedPath } from "./helpers/resolve-path";
import {
  sameRepository,
  type RepositoryTarget,
} from "./workbench-scan-history";

type Table = Record<string, unknown>;
export interface ComparisonScan extends RepositoryTarget {
  id: string;
  status: string;
  started_at: string;
  [key: string]: unknown;
}
interface Finding extends Table {
  id: string;
  finding_id: string;
  title: string;
  summary: string;
  severity: string;
  remediation: string;
  details_json: string;
  triage_status: string;
  close_reason: string | null;
  relative_path: string | null;
}
export interface PairArgs {
  beforeScanId: string;
  afterScanId: string;
}
export interface ComparisonCallbacks {
  requireScan: (connection: Connection, id: string) => ComparisonScan;
  readCoverage: (scan: ComparisonScan) => Table;
  backfillFindingDetails?: (
    connection: Connection,
    scan: ComparisonScan,
  ) => void;
}
/** The Python command's SystemExit boundary, including unavailable sealed scans. */
export class ScanComparisonError extends WorkbenchValidationError {}
export function requireScan(
  connection: Connection,
  value: string,
): ComparisonScan {
  return requireScanRecord(connection, value).toObject() as ComparisonScan;
}
function pair(
  connection: Connection,
  args: PairArgs,
  getScan: ComparisonCallbacks["requireScan"],
): [ComparisonScan, ComparisonScan] {
  const before = getScan(connection, args.beforeScanId),
    after = getScan(connection, args.afterScanId);
  if (before.id === after.id)
    throw new ScanComparisonError("Select two different scans to compare.");
  if (before.status !== "complete" || after.status !== "complete")
    throw new ScanComparisonError("Only completed scans can be compared.");
  if (!sameRepository(before, after))
    throw new ScanComparisonError(
      "Semantic scan comparisons require the same repository target.",
    );
  return [before, after];
}
function scanFindings(
  connection: Connection,
  scanId: string,
): Map<string, Finding> {
  const rows = connection
    .prepare(
      `
    SELECT occurrences.*, COALESCE(triage.status, 'open') AS triage_status, triage.close_reason,
      (SELECT locations.relative_path FROM finding_locations AS locations
       WHERE locations.occurrence_id = occurrences.id
       ORDER BY CASE WHEN locations.role = 'root_control' THEN 0 ELSE 1 END, locations.sort_order LIMIT 1) AS relative_path
    FROM finding_occurrences AS occurrences LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
    WHERE occurrences.scan_id = ?`,
    )
    .all([scanId]);
  return new Map(
    rows.map((row) => {
      const finding = row.toObject() as Finding;
      return [finding.finding_id, finding];
    }),
  );
}
function pythonKind(value: unknown): string {
  return value === null
    ? "NoneType"
    : Array.isArray(value)
      ? "list"
      : value instanceof JsonFloat
        ? "float"
        : typeof value === "bigint"
          ? "int"
          : typeof value === "boolean"
            ? "bool"
            : "str";
}
function mapping(value: unknown): Table {
  if (object(value)) return value;
  throw new TypeError(`'${pythonKind(value)}' object is not a mapping`);
}
function matchingInput(row: Finding): Table {
  const finding = mapping(parseJson(row.details_json));
  const severity = Object.hasOwn(finding, "severity")
    ? mapping(finding["severity"])
    : {};
  return objectFromEntries([
    ...objectEntries(finding),
    ["findingId", row.finding_id],
    ["occurrenceId", row.id],
    ["remediation", row.remediation],
    [
      "severity",
      objectFromEntries([["level", row.severity], ...objectEntries(severity)]),
    ],
    ["summary", row.summary],
    ["title", row.title],
  ]);
}
interface Match {
  beforeOccurrenceIds: string[];
  afterOccurrenceIds: string[];
  reason: string;
  confidence: "high";
}
interface Matches {
  matches: Match[];
  uncertain?: FindingPair[];
  related?: FindingPair[];
}
function matchReason(match: Match | FindingPair): string {
  if (!Object.hasOwn(match, "reason")) throw new Error("'reason'");
  return match.reason;
}
function joinedReasons(reasons: readonly string[]): string {
  for (const value of reasons)
    if (object(value) || Array.isArray(value))
      throw new TypeError(
        `unhashable type: '${Array.isArray(value) ? "list" : "dict"}'`,
      );
  const unique = [...new Set(reasons)];
  for (const [index, value] of unique.entries())
    if (typeof value !== "string")
      throw new TypeError(
        `sequence item ${index}: expected str instance, ${pythonKind(value)} found`,
      );
  return unique.join(" ");
}
type Group = [Finding[], Finding[], string | null];
function findingGroups(
  before: Map<string, Finding>,
  after: Map<string, Finding>,
  matches: Match[],
  aliases: ReadonlyMap<string, string>,
): Group[] {
  const rows = {
    before: new Map([...before.values()].map((row) => [row.id, row])),
    after: new Map([...after.values()].map((row) => [row.id, row])),
  };
  const groups = new Map<string, [Finding[], Finding[], string[]]>();
  const group = (row: Finding) => {
    const identity = aliases.get(row.finding_id) ?? row.finding_id;
    if (!groups.has(identity)) groups.set(identity, [[], [], []]);
    return groups.get(identity)!;
  };
  for (const match of matches)
    group(rows.before.get(match.beforeOccurrenceIds[0]!)!)[2].push(
      matchReason(match),
    );
  for (const [index, side] of (["before", "after"] as const).entries()) {
    const ids = new Set([
      ...matches.flatMap((match) => match[`${side}OccurrenceIds`]),
      ...rows[side].keys(),
    ]);
    for (const id of ids) {
      const row = rows[side].get(id)!;
      group(row)[index as 0 | 1].push(row);
    }
  }
  const result: Group[] = [...groups.values()].map(
    ([previous, current, reasons]) => [
      previous,
      current,
      previous.length && current.length
        ? reasons.length
          ? joinedReasons(reasons)
          : "The findings share a stable identity or a previously confirmed link."
        : null,
    ],
  );
  return result.sort(([a, b], [c, d]) => {
    const left = (b.length ? b : a)[0]!,
      right = (d.length ? d : c)[0]!;
    return (
      compare(left.finding_id, right.finding_id) || compare(left.id, right.id)
    );
  });
}
export function compareScans(
  connection: Connection,
  args: PairArgs & {
    includeMatchingInputs?: boolean;
    requireMatches?: boolean;
  },
  callbacks: ComparisonCallbacks,
) {
  const [before, after] = pair(connection, args, callbacks.requireScan);
  const cached = connection
    .prepare(
      "SELECT result_json FROM scan_comparisons WHERE before_scan_id = ? AND after_scan_id = ?",
    )
    .get([before.id, after.id]);
  if (cached === undefined && args.requireMatches) {
    if (
      connection
        .prepare(
          "SELECT 1 FROM scan_comparisons WHERE before_scan_id = ? AND after_scan_id = ?",
        )
        .get([after.id, before.id]) !== undefined
    )
      throw new ScanComparisonError(
        `These scans are in the wrong order. Run 'codex-security scans compare ${after.id} ${before.id}'.`,
      );
    throw new ScanComparisonError(
      "No saved matches for these scans. Run 'codex-security scans match BEFORE AFTER' first.",
    );
  }
  if (
    args.includeMatchingInputs &&
    callbacks.backfillFindingDetails !== undefined
  ) {
    callbacks.backfillFindingDetails(connection, before);
    callbacks.backfillFindingDetails(connection, after);
  }
  const coverage = callbacks.readCoverage(after),
    comparable = coverage["completeness"] === "complete";
  const beforeFindings = scanFindings(connection, before.id),
    afterFindings = scanFindings(connection, after.id);
  const matches =
    cached === undefined
      ? null
      : (parseJson(cached.get("result_json") as string) as Matches);
  const occurrences = new Map(
    [...beforeFindings.values(), ...afterFindings.values()].map((row) => [
      row.id,
      row,
    ]),
  );
  const aliases = confirmedFindingAliases(connection, occurrences.keys());
  const groups = findingGroups(
    beforeFindings,
    afterFindings,
    matches === null ? [] : matches.matches,
    aliases,
  );
  const uncertain = {
    before: new Map<string, string>(),
    after: new Map<string, string>(),
  };
  for (const match of matches === null
    ? []
    : Object.hasOwn(matches, "uncertain")
      ? matches.uncertain!
      : []) {
    uncertain.before.set(match.beforeOccurrenceId, matchReason(match));
    uncertain.after.set(match.afterOccurrenceId, matchReason(match));
  }
  const findings: Table[] = [],
    summary = { new: 0, persisting: 0, resolved: 0, reopened: 0, unknown: 0 };
  const levels = ["critical", "high", "medium", "low", "informational"];
  const severity = (row: Finding) => {
    const index = levels.indexOf(row.severity);
    if (index === -1) throw new Error(pythonRepr(row.severity));
    return index;
  };
  const strongest = (rows: Finding[]) =>
    rows
      .map((row) => [severity(row), row] as const)
      .reduce<
        readonly [number, Finding] | undefined
      >((best, entry) => (best === undefined || entry[0] < best[0] ? entry : best), undefined)?.[1];
  for (const [previousRows, currentRows, matchReason] of groups) {
    const previous = strongest(previousRows),
      current = strongest(currentRows),
      selected = (current ?? previous)!;
    const item: Table = {
      findingId: selected.finding_id,
      path: selected.relative_path,
      severity: selected.severity,
      title: selected.title,
    };
    const side = currentRows.length ? "after" : "before";
    const uncertainRow = (currentRows.length ? currentRows : previousRows).find(
      (row) => uncertain[side].has(row.id),
    );
    const uncertainReason =
      uncertainRow === undefined ? null : uncertain[side].get(uncertainRow.id);
    let status: keyof typeof summary;
    if (previous === undefined) {
      status = uncertainReason == null ? "new" : "unknown";
      if (uncertainReason != null) item["reason"] = uncertainReason;
    } else if (current !== undefined) {
      status =
        previousRows.some(
          (row) =>
            row.triage_status === "closed" &&
            row.close_reason === "already_fixed",
        ) && currentRows.some((row) => row.triage_status === "open")
          ? "reopened"
          : "persisting";
      if (matchReason !== null) item["matchReason"] = matchReason;
    } else if (uncertainReason != null) {
      status = "unknown";
      item["reason"] = uncertainReason;
    } else if (!comparable) {
      status = "unknown";
      item["reason"] = "The later scan has incomplete coverage.";
    } else if (
      !previousRows.every((row) =>
        scanCoversPath(after, after.target_id, row.relative_path, coverage),
      )
    ) {
      status = "unknown";
      item["reason"] =
        "The affected path was excluded or outside the later scope.";
    } else status = "resolved";
    if (previousRows.length === 1) item["beforeOccurrenceId"] = previous!.id;
    else if (previousRows.length)
      item["beforeOccurrenceIds"] = previousRows.map((row) => row.id);
    if (currentRows.length === 1) item["afterOccurrenceId"] = current!.id;
    else if (currentRows.length)
      item["afterOccurrenceIds"] = currentRows.map((row) => row.id);
    if (current !== undefined)
      item["triage"] = {
        closeReason: current.close_reason,
        status: current.triage_status,
      };
    item["status"] = status;
    findings.push(item);
    summary[status]++;
  }
  const related = matches?.related
    ? separateFindingPairs(matches.related, occurrences, aliases).map(
        (pair) => ({
          ...pair,
          beforeTitle: occurrences.get(pair.beforeOccurrenceId)!.title,
          afterTitle: occurrences.get(pair.afterOccurrenceId)!.title,
        }),
      )
    : [];
  let matching: {
    matchingCached?: boolean;
    matchingInputs?: {
      before: Table[];
      after: Table[];
      knownFindingGroups?: string[][];
    };
  } = {};
  if (args.includeMatchingInputs) {
    const knownScanIds = new Set(
      connection
        .prepare(
          "SELECT * FROM scans WHERE status = 'complete' AND (started_at < ? OR (started_at = ? AND id <= ?))",
        )
        .all([after.started_at, after.started_at, after.id])
        .map((row) => row.toObject() as ComparisonScan)
        .filter((scan) => sameRepository(scan, after))
        .map((scan) => scan.id),
    );
    const knownGroups = knownFindingGroups(
      savedFindingLinks(connection, knownScanIds).filter(
        (link) =>
          !(
            link.before_scan_id === before.id && link.after_scan_id === after.id
          ) &&
          !(
            link.before_scan_id === after.id && link.after_scan_id === before.id
          ),
      ),
      knownScanIds,
    );
    matching = {
      matchingCached: cached !== undefined,
      matchingInputs: {
        before: [...beforeFindings.values()].map(matchingInput),
        after: [...afterFindings.values()].map(matchingInput),
        ...(knownGroups.length ? { knownFindingGroups: knownGroups } : {}),
      },
    };
  }
  return {
    afterScanId: after.id,
    beforeScanId: before.id,
    comparable,
    coverage: { afterCompleteness: coverage["completeness"] ?? null },
    findings,
    repository: before.target_path,
    summary,
    ...(related.length ? { related } : {}),
    ...matching,
  };
}
export function listUnmatchedScanPairs(
  connection: Connection,
  args: { repository: string; force?: boolean },
  callbacks: Pick<ComparisonCallbacks, "readCoverage"> &
    Required<Pick<ComparisonCallbacks, "backfillFindingDetails">>,
) {
  const repository = resolvedPath(
    expandHome(parsedPath(args.repository), environment("HOME")),
    false,
  );
  const requested: RepositoryTarget = {
    target_path: repository,
    target_id: connection
      .prepare(
        "SELECT COALESCE((SELECT id FROM security_targets WHERE current_path = ?), '') AS target_id",
      )
      .get([repository])!
      .get("target_id") as string,
  };
  const selected = connection
    .prepare(
      "SELECT * FROM scans WHERE status = 'complete' ORDER BY started_at, id",
    )
    .all()
    .map((row) => row.toObject() as ComparisonScan)
    .filter((scan) => sameRepository(scan, requested));
  const available = selected.filter((scan) => {
    try {
      callbacks.readCoverage(scan);
      return true;
    } catch (error) {
      if (error instanceof WorkbenchValidationError) return false;
      throw error;
    }
  });
  const saved = new Map<string, Set<string>>();
  for (const row of connection
    .prepare("SELECT before_scan_id, after_scan_id FROM scan_comparisons")
    .all()) {
    const before = row.get("before_scan_id") as string,
      after = row.get("after_scan_id") as string;
    if (!saved.has(before)) saved.set(before, new Set());
    saved.get(before)!.add(after);
  }
  const batches: {
      afterFindings: Table[];
      afterScanId: string;
      beforeScans: { findings: Table[]; scanId: string }[];
      knownFindingGroups?: string[][];
    }[] = [],
    matching = new Map<string, Table[]>();
  let skipped = 0;
  let knownLinks: FindingLink[] | undefined;
  for (const [index, after] of available.entries()) {
    const previous = available
      .slice(0, index)
      .filter((before) => args.force || !saved.get(before.id)?.has(after.id));
    skipped += index - previous.length;
    if (!previous.length) continue;
    knownLinks ??= args.force
      ? []
      : savedFindingLinks(connection, new Set(selected.map((scan) => scan.id)));
    for (const scan of [...previous, after])
      if (!matching.has(scan.id)) {
        callbacks.backfillFindingDetails(connection, scan);
        matching.set(
          scan.id,
          [...scanFindings(connection, scan.id).values()].map(matchingInput),
        );
      }
    const knownGroups = knownFindingGroups(
      knownLinks,
      new Set(
        selected
          .filter(
            (scan) =>
              compare(scan.started_at, after.started_at) < 0 ||
              (scan.started_at === after.started_at &&
                compare(scan.id, after.id) <= 0),
          )
          .map((scan) => scan.id),
      ),
    );
    batches.push({
      afterFindings: matching.get(after.id)!,
      afterScanId: after.id,
      beforeScans: previous.map((scan) => ({
        findings: matching.get(scan.id)!,
        scanId: scan.id,
      })),
      ...(knownGroups.length ? { knownFindingGroups: knownGroups } : {}),
    });
  }
  return {
    batches,
    repository,
    scanCount: selected.length,
    skippedPairs: skipped,
    unavailableScans: selected.length - available.length,
  };
}
export function saveScanComparison(
  connection: Connection,
  args: PairArgs,
  callbacks: Omit<ComparisonCallbacks, "backfillFindingDetails"> & {
    now: () => string;
    readMatches: () => string | undefined;
  },
) {
  const [before, after] = pair(connection, args, callbacks.requireScan);
  callbacks.readCoverage(after);
  const beforeFindings = scanFindings(connection, before.id),
    afterFindings = scanFindings(connection, after.id);
  const source = callbacks.readMatches();
  let payload: Matches;
  try {
    payload = parseJson(source as string, false, (value) => {
      if (value.replace(/^-/, "").length > 4300)
        throw new Error("integer string conversion limit");
      return BigInt(value);
    }) as Matches;
  } catch {
    throw new ScanComparisonError(
      "Scan comparison matches must be a valid JSON object.",
    );
  }
  if (
    !object(payload) ||
    !Object.hasOwn(payload, "matches") ||
    !Object.hasOwn(payload, "uncertain") ||
    Object.keys(payload).some(
      (key) => !["matches", "uncertain", "related"].includes(key),
    ) ||
    !Array.isArray(payload.matches) ||
    !Array.isArray(payload.uncertain) ||
    (Object.hasOwn(payload, "related") && !Array.isArray(payload.related))
  )
    throw new ScanComparisonError(
      "Scan comparison matches must contain matches and uncertain arrays.",
    );
  const allowed = {
    before: new Set([...beforeFindings.values()].map((row) => row.id)),
    after: new Set([...afterFindings.values()].map((row) => row.id)),
  };
  const consumed = {
    before: new Map<string, number>(),
    after: new Map<string, number>(),
  };
  for (const [index, match] of payload.matches.entries()) {
    if (!object(match) || match.confidence !== "high" || !hasText(match.reason))
      throw new ScanComparisonError(
        "Scan comparison matches must have high confidence and a reason.",
      );
    for (const side of ["before", "after"] as const) {
      const occurrences = match[`${side}OccurrenceIds`];
      if (
        !Array.isArray(occurrences) ||
        occurrences.some((id) => typeof id !== "string")
      )
        throw new ScanComparisonError(
          "Scan comparison matches must identify distinct scan findings.",
        );
      const unique = new Set(occurrences);
      if (
        !occurrences.length ||
        unique.size !== occurrences.length ||
        [...unique].some(
          (id) => !allowed[side].has(id) || consumed[side].has(id),
        )
      )
        throw new ScanComparisonError(
          "Scan comparison matches must identify distinct scan findings.",
        );
      for (const id of unique) consumed[side].set(id, index);
    }
  }
  const uncertain = new Map<string, Set<string>>();
  for (const match of payload.uncertain) {
    if (!validFindingPair(match))
      throw new ScanComparisonError(
        "Uncertain scan comparison matches must identify distinct findings.",
      );
    const a = match.beforeOccurrenceId,
      b = match.afterOccurrenceId;
    if (
      !allowed.before.has(a) ||
      consumed.before.has(a) ||
      !allowed.after.has(b) ||
      consumed.after.has(b) ||
      uncertain.get(a)?.has(b)
    )
      throw new ScanComparisonError(
        "Uncertain scan comparison matches must identify distinct findings.",
      );
    if (!uncertain.has(a)) uncertain.set(a, new Set());
    uncertain.get(a)!.add(b);
  }
  const related = new Map<string, Set<string>>();
  for (const match of payload.related ?? []) {
    if (!validFindingPair(match))
      throw new ScanComparisonError(
        "Related scan comparison findings must identify distinct findings.",
      );
    const a = match.beforeOccurrenceId,
      b = match.afterOccurrenceId,
      group = consumed.before.get(a);
    if (
      !allowed.before.has(a) ||
      !allowed.after.has(b) ||
      (group !== undefined && group === consumed.after.get(b)) ||
      uncertain.get(a)?.has(b) ||
      related.get(a)?.has(b)
    )
      throw new ScanComparisonError(
        "Related scan comparison findings must identify distinct findings.",
      );
    if (!related.has(a)) related.set(a, new Set());
    related.get(a)!.add(b);
  }
  const timestamp = callbacks.now();
  connection.transaction(() => {
    connection.exec("BEGIN IMMEDIATE");
    connection
      .prepare(
        "DELETE FROM scan_comparisons WHERE before_scan_id = ? AND after_scan_id = ?",
      )
      .run([before.id, after.id]);
    const json = stringifyJson(payload, {
      allowNan: false,
      sortKeys: true,
      compact: true,
    });
    connection
      .prepare(
        "INSERT INTO scan_comparisons (before_scan_id, after_scan_id, result_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run([before.id, after.id, json, timestamp, timestamp]);
    for (const match of payload.matches)
      for (const previous of match.beforeOccurrenceIds)
        for (const current of match.afterOccurrenceIds) {
          const reason: unknown = matchReason(match);
          connection
            .prepare(
              "INSERT INTO scan_comparison_matches (before_scan_id, after_scan_id, before_occurrence_id, after_occurrence_id, reason) VALUES (?, ?, ?, ?, ?)",
            )
            .run([
              before.id,
              after.id,
              previous,
              current,
              (reason instanceof JsonFloat
                ? Number(reason.source)
                : reason) as Parameter,
            ]);
        }
  });
  return compareScans(
    connection,
    { beforeScanId: args.beforeScanId, afterScanId: args.afterScanId },
    callbacks,
  );
}
function validFindingPair(value: unknown): value is FindingPair {
  return (
    object(value) &&
    Object.keys(value).length === 3 &&
    ["beforeOccurrenceId", "afterOccurrenceId", "reason"].every((key) =>
      Object.hasOwn(value, key),
    ) &&
    Object.values(value).every(hasText)
  );
}
function pathWithin(path: string, scope: string): boolean {
  const parts = (value: string): [string, string[]] => [
    value.startsWith("//") && !value.startsWith("///")
      ? "//"
      : value.startsWith("/")
        ? "/"
        : "",
    value.split("/").filter((part) => part && part !== "."),
  ];
  const [anchor, candidate] = parts(path),
    [root, parent] = parts(scope);
  return (
    (!root && !parent.length) ||
    (anchor === root &&
      parent.every((part, index) => candidate[index] === part))
  );
}
// fnmatchcase treats slash as an ordinary character and removes reversed ranges.
function matchesPattern(value: string, pattern: string): boolean {
  const chars = Array.from(pattern),
    tokens: (string | RegExp | null)[] = [];
  for (let i = 0; i < chars.length; i++) {
    const char = chars[i]!;
    if (char === "*") {
      if (tokens.at(-1) !== null) tokens.push(null);
    } else if (char === "?") tokens.push(/./su);
    else if (char !== "[") tokens.push(char);
    else {
      let j = i + 1;
      if (chars[j] === "!") j++;
      if (chars[j] === "]") j++;
      while (j < chars.length && chars[j] !== "]") j++;
      if (j === chars.length) {
        tokens.push("[");
        continue;
      }
      const content = chars.slice(i + 1, j),
        negated = content[0] === "!";
      let text = content.join("");
      if (text.includes("-")) {
        const chunks: string[][] = [];
        let start = 0,
          k = negated ? 2 : 1;
        while ((k = content.indexOf("-", k)) !== -1) {
          chunks.push(content.slice(start, k));
          start = k + 1;
          k += 3;
        }
        const last = content.slice(start);
        if (last.length) chunks.push(last);
        else chunks.at(-1)!.push("-");
        for (let k = chunks.length - 1; k > 0; k--)
          if (compare(chunks[k - 1]!.at(-1)!, chunks[k]![0]!) > 0) {
            chunks[k - 1] = [
              ...chunks[k - 1]!.slice(0, -1),
              ...chunks[k]!.slice(1),
            ];
            chunks.splice(k, 1);
          }
        text = chunks
          .map((chunk) =>
            chunk.join("").replaceAll("\\", "\\\\").replaceAll("-", "\\-"),
          )
          .join("-");
      } else text = text.replaceAll("\\", "\\\\");
      if (!text) tokens.push(/(?!)/u);
      else if (text === "!") tokens.push(/./su);
      else {
        if (text.startsWith("!")) text = "^" + text.slice(1);
        else if (text.startsWith("^") || text.startsWith("["))
          text = "\\" + text;
        // A leading closing bracket is literal in Python character classes.
        text = text.replace(/^(\^?)\]/u, "$1\\]");
        tokens.push(new RegExp(`[${text}]`, "su"));
      }
      i = j;
    }
  }
  const source = Array.from(value);
  let i = 0,
    j = 0,
    star = -1,
    retry = 0;
  while (i < source.length) {
    const token = tokens[j];
    if (token === null) {
      star = j++;
      retry = i;
    } else if (
      token !== undefined &&
      (typeof token === "string" ? token === source[i] : token.test(source[i]!))
    ) {
      i++;
      j++;
    } else if (star !== -1) {
      j = star + 1;
      i = ++retry;
    } else return false;
  }
  while (tokens[j] === null) j++;
  return j === tokens.length;
}
export function scanCoversPath(
  scan: Pick<ComparisonScan, "status" | "target_id">,
  targetId: string | null,
  path: string | null,
  coverage: Table,
): boolean {
  if (
    scan.status !== "complete" ||
    scan.target_id !== targetId ||
    coverage["completeness"] !== "complete" ||
    typeof path !== "string" ||
    !path
  )
    return false;
  const included = coverage["includePaths"],
    excluded = coverage["excludePaths"],
    exclusions = coverage["explicitExclusions"];
  return (
    Array.isArray(included) &&
    included.some(
      (scope) => typeof scope === "string" && pathWithin(path, scope),
    ) &&
    Array.isArray(excluded) &&
    !excluded.some(
      (scope) =>
        typeof scope === "string" &&
        (pathWithin(path, scope) || matchesPattern(path, scope)),
    ) &&
    Array.isArray(exclusions) &&
    !exclusions.some(
      (item) =>
        object(item) &&
        typeof item["pattern"] === "string" &&
        (pathWithin(path, item["pattern"]) ||
          matchesPattern(path, item["pattern"])),
    )
  );
}
