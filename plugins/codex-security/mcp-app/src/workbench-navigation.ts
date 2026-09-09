import type { Connection } from "../../native/sqlite.mjs";
import { fileInfo } from "./helpers/helper-files";
import { pythonRepr } from "./helpers/python-json";
import { listScans } from "./workbench-scan-history";
import { compare } from "./helpers/rank-worklists";
import { casefold } from "./workbench-dashboard";

export interface NavigationQuery {
  query?: string;
  targetId?: string;
  severity?: string;
  status?: string;
  offset: bigint;
  limit?: bigint;
}
interface Occurrence {
  occurrence_id: string;
  finding_id: string;
  severity: string;
  created_at: string;
  scan_id: string;
  scan_started_at: string;
  target_id: string;
  target_path: string;
  scope: string;
  updated_at: string;
  decision_status: string | null;
  close_reason: string | null;
  decision_updated_at: string | null;
  title: string;
  summary: string;
  location_path: string | null;
}
const severityOrder = ["critical", "high", "medium", "low", "informational"];
const severity = (value: string) => {
  const index = severityOrder.indexOf(value);
  return index === -1 ? 5 : index;
};
const queryText = (value = "") =>
  casefold(
    value.replace(
      /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
      "",
    ),
  );
const latest = (left: string, right: string) =>
  compare(left, right) < 0 ? right : left;

function boundedText(value: string, maximum: number): string {
  const text = typeof value === "string" ? value : pythonRepr(value);
  if (/[\ud800-\udfff]/u.test(text))
    throw new Error(
      "'utf-8' codec can't encode a surrogate: surrogates not allowed",
    );
  const bytes = Buffer.from(text).subarray(0, maximum);
  let end = bytes.length;
  while (end && (bytes[end - 1]! & 0xc0) === 0x80) end--;
  if (end && bytes[end - 1]! >= 0xc0) {
    const first = bytes[end - 1]!;
    const width = first < 0xe0 ? 2 : first < 0xf0 ? 3 : 4;
    if (bytes.length - end + 1 < width)
      return bytes.subarray(0, end - 1).toString("utf8");
  }
  return bytes.toString("utf8");
}

function indexedFindings(connection: Connection) {
  const parents = new Map<string, string>();
  const identity = (target: string, finding: string) =>
    `${target.length}:${target}${finding}`;
  const group = (value: string) => {
    while (parents.has(value)) value = parents.get(value)!;
    return value;
  };
  for (const row of connection
    .prepare(
      `
    SELECT before_scans.target_id, before.finding_id AS before_finding_id,
        after.finding_id AS after_finding_id
    FROM scan_comparison_matches AS matches
    JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
    JOIN scans AS before_scans ON before_scans.id = before.scan_id
    JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
    JOIN scans AS after_scans ON after_scans.id = after.scan_id
    WHERE before_scans.target_id = after_scans.target_id
  `,
    )
    .iterate()) {
    const target = row.get("target_id") as string;
    const before = group(
      identity(target, row.get("before_finding_id") as string),
    );
    const after = group(
      identity(target, row.get("after_finding_id") as string),
    );
    if (before !== after) parents.set(after, before);
  }
  const latestScan = new Map<string, string>();
  for (const row of connection
    .prepare(
      "SELECT target_id, id FROM scans WHERE status = 'complete' ORDER BY started_at, id",
    )
    .iterate())
    latestScan.set(row.get("target_id") as string, row.get("id") as string);
  const grouped = new Map<string, Occurrence[]>();
  for (const row of connection
    .prepare(
      `
    SELECT occurrences.id AS occurrence_id, occurrences.finding_id,
        occurrences.severity, occurrences.created_at, scans.id AS scan_id,
        scans.started_at AS scan_started_at, scans.target_id,
        targets.current_path AS target_path, scans.scope,
        MAX(scans.updated_at, COALESCE(triage.updated_at, '')) AS updated_at,
        triage.status AS decision_status, triage.close_reason,
        triage.updated_at AS decision_updated_at, occurrences.title, occurrences.summary,
        (SELECT locations.relative_path FROM finding_locations AS locations
         WHERE locations.occurrence_id = occurrences.id
         ORDER BY CASE WHEN locations.role = 'root_control' THEN 0 ELSE 1 END,
             locations.sort_order LIMIT 1) AS location_path
    FROM finding_occurrences AS occurrences
    JOIN scans ON scans.id = occurrences.scan_id
    JOIN security_targets AS targets ON targets.id = scans.target_id
    LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
  `,
    )
    .iterate()) {
    const occurrence = row.toObject() as unknown as Occurrence;
    const key = group(identity(occurrence.target_id, occurrence.finding_id));
    const values = grouped.get(key) ?? [];
    values.push(occurrence);
    grouped.set(key, values);
  }
  const findings = [...grouped.values()].map((occurrences) => {
    const newest = occurrences.reduce((left, right) =>
      (compare(left.created_at, right.created_at) ||
        compare(left.occurrence_id, right.occurrence_id)) < 0
        ? right
        : left,
    );
    const decision = occurrences
      .filter((row) => row.decision_status !== null)
      .reduce<
        Occurrence | undefined
      >((left, right) => (left === undefined || (compare(left.decision_updated_at!, right.decision_updated_at!) || compare(left.occurrence_id, right.occurrence_id)) < 0 ? right : left), undefined);
    let status = decision?.decision_status ?? "open";
    if (
      status === "closed" &&
      decision?.close_reason === "already_fixed" &&
      compare(newest.created_at, decision.decision_updated_at!) > 0
    )
      status = "open";
    const scans = [
      ...new Map(
        occurrences.map((row) => [row.scan_id, row.scan_started_at]),
      ).entries(),
    ].sort(([a, timeA], [b, timeB]) => compare(timeA, timeB) || compare(a, b));
    return {
      ...newest,
      confirmed_in_latest_scan:
        latestScan.get(newest.target_id) === newest.scan_id,
      known_since: scans[0]![1],
      known_scan_ids: scans.map(([id]) => id),
      matched_finding_ids: [
        ...new Set(occurrences.map((row) => row.finding_id)),
      ].sort(compare),
      occurrence_count: occurrences.length,
      status,
      updated_at: latest(
        newest.updated_at,
        decision?.decision_updated_at ?? "",
      ),
    };
  });
  return findings.sort(
    (a, b) =>
      Number(b.status === "open") - Number(a.status === "open") ||
      severity(a.severity) - severity(b.severity) ||
      compare(b.created_at, a.created_at) ||
      compare(a.occurrence_id, b.occurrence_id),
  );
}

export function listGlobalFindings(
  connection: Connection,
  args: NavigationQuery,
) {
  const limit = args.limit === undefined || args.limit > 20n ? 20n : args.limit;
  const query = queryText(args.query);
  // itertools.islice checks its stop index against Py_ssize_t before iteration.
  if (args.offset + limit + 1n > 9223372036854775807n)
    throw new Error(
      "Stop argument for islice() must be None or an integer: 0 <= x <= sys.maxsize.",
    );
  const rows: ReturnType<typeof indexedFindings> = [];
  let matched = 0n;
  for (const row of indexedFindings(connection)) {
    if (
      (args.targetId === undefined || row.target_id === args.targetId) &&
      (args.severity === undefined || row.severity === args.severity) &&
      (args.status === undefined || row.status === args.status) &&
      (!query ||
        [row.title, row.summary, row.target_path, row.location_path].some(
          (value) => value !== null && casefold(value).includes(query),
        ))
    ) {
      if (matched++ >= args.offset) rows.push(row);
      if (rows.length > limit) break;
    }
  }
  return {
    findings: rows.slice(0, Number(limit)).map((row) => ({
      confirmedInLatestScan: row.confirmed_in_latest_scan,
      createdAt: row.created_at,
      findingId: row.finding_id,
      knownSince: row.known_since,
      knownScanIds: row.known_scan_ids,
      locationPath: row.location_path,
      matchedFindingIds: row.matched_finding_ids,
      occurrenceCount: row.occurrence_count,
      occurrenceId: row.occurrence_id,
      scanId: row.scan_id,
      scope: row.scope,
      severity: { level: row.severity },
      status: row.status,
      summary: boundedText(row.summary, 2000),
      targetId: row.target_id,
      targetPath: row.target_path,
      title: boundedText(row.title, 512),
      updatedAt: row.updated_at,
    })),
    limit,
    nextOffset: rows.length > limit ? args.offset + limit : null,
    offset: args.offset,
  };
}

export function listRepositories(
  connection: Connection,
  args?: NavigationQuery,
) {
  const scans = listScans(connection).scans;
  const scansById = new Map(scans.map((scan) => [scan.scanId, scan]));
  const counts = new Map<string, number>();
  for (const scan of scans)
    counts.set(scan.targetId, (counts.get(scan.targetId) ?? 0) + 1);
  const latestByTarget = new Map<string, (typeof scans)[number]>();
  for (const row of connection
    .prepare(
      "SELECT id, target_id FROM scans ORDER BY started_at DESC, id DESC",
    )
    .iterate()) {
    const id = row.get("id") as string,
      target = row.get("target_id") as string;
    if (!scansById.has(id)) throw new Error(pythonRepr(id));
    if (!latestByTarget.has(target))
      latestByTarget.set(target, scansById.get(id)!);
  }
  const open = new Map<string, number>();
  for (const row of indexedFindings(connection))
    if (row.status === "open")
      open.set(row.target_id, (open.get(row.target_id) ?? 0) + 1);
  const targets = new Map(
    connection
      .prepare("SELECT * FROM security_targets")
      .all()
      .map((row) => [row.get("id") as string, row]),
  );
  let repositories = [...latestByTarget].flatMap(([targetId, scan]) => {
    const target = targets.get(targetId);
    return target === undefined
      ? []
      : [
          {
            checkoutAvailable:
              fileInfo(target.get("current_path") as string)?.isDirectory() ??
              false,
            displayName: target.get("display_name") as string,
            latestScan: scan,
            openFindingsCount: open.get(targetId) ?? 0,
            scanCount: counts.get(targetId)!,
            targetId,
            targetPath: target.get("current_path") as string,
          },
        ];
  });
  if (args === undefined) return { repositories };
  const query = queryText(args.query);
  repositories = repositories.filter(
    (row) =>
      (args.targetId === undefined || row.targetId === args.targetId) &&
      args.status !== "not_scanned" &&
      (args.status !== "open_findings" || row.openFindingsCount > 0) &&
      (!query ||
        casefold(row.displayName).includes(query) ||
        casefold(row.targetPath).includes(query)),
  );
  if (args.limit === undefined && args.offset === 0n) return { repositories };
  const limit = args.limit === undefined || args.limit > 20n ? 20n : args.limit;
  const page = repositories.slice(
    Number(args.offset),
    Number(args.offset + limit),
  );
  const next = args.offset + BigInt(page.length);
  return {
    repositories: page,
    limit,
    nextOffset: next < repositories.length ? next : null,
    offset: args.offset,
  };
}
