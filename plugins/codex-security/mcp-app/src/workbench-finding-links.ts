import type { Connection, Row } from "../../native/sqlite.mjs";
import { objectFromEntries, parseJson } from "./helpers/python-json";
import { compare } from "./helpers/rank-worklists";

export interface FindingLink {
  before_scan_id: string;
  before_finding_id: string;
  after_scan_id: string;
  after_finding_id: string;
}
export interface FindingPair {
  beforeOccurrenceId: string;
  afterOccurrenceId: string;
  reason: string;
}
interface Occurrence {
  id: string;
  finding_id: string;
  scan_id: string;
  title: string;
}

export function* rowsForIds(
  connection: Connection,
  query: string,
  ids: Iterable<string>,
): Generator<Row> {
  const values = [...new Set(ids)],
    limit = connection.variableLimit;
  if (limit === 0) throw new RangeError("range() arg 3 must not be zero");
  for (let start = 0; start < values.length; start += limit) {
    const batch = values.slice(start, start + limit);
    yield* connection
      .prepare(
        query.replaceAll("{placeholders}", batch.map(() => "?").join(", ")),
      )
      .iterate(batch);
  }
}

export function savedFindingLinks(
  connection: Connection,
  scanIds: ReadonlySet<string>,
): FindingLink[] {
  return [
    ...rowsForIds(
      connection,
      `
    SELECT before.scan_id AS before_scan_id, before.finding_id AS before_finding_id,
      after.scan_id AS after_scan_id, after.finding_id AS after_finding_id
    FROM scan_comparison_matches AS matches
    JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
    JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
    WHERE matches.before_scan_id IN ({placeholders})
    ORDER BY matches.before_scan_id, after.scan_id, before.finding_id, after.finding_id
  `,
      [...scanIds].sort(compare),
    ),
  ]
    .map((row) => row.toObject() as unknown as FindingLink)
    .filter(
      (row) =>
        scanIds.has(row.before_scan_id) && scanIds.has(row.after_scan_id),
    );
}

export function findingAliases(
  links: Iterable<readonly [string, string]>,
): Map<string, string> {
  const parents = new Map<string, string>();
  const root = (value: string): string => {
    if (!parents.has(value)) parents.set(value, value);
    while (parents.get(value) !== value) {
      parents.set(value, parents.get(parents.get(value)!)!);
      value = parents.get(value)!;
    }
    return value;
  };
  for (const [before, after] of links) {
    // Python evaluates the assigned value before the subscript expression.
    const parent = root(before);
    parents.set(root(after), parent);
  }
  return new Map([...parents.keys()].map((id) => [id, root(id)]));
}

export function knownFindingGroups(
  links: readonly FindingLink[],
  scanIds: ReadonlySet<string>,
): string[][] {
  const aliases = findingAliases(
    links
      .filter(
        (link) =>
          scanIds.has(link.before_scan_id) && scanIds.has(link.after_scan_id),
      )
      .map((link) => [link.before_finding_id, link.after_finding_id]),
  );
  const groups = new Map<string, string[]>();
  for (const [id, identity] of aliases) {
    if (!groups.has(identity)) groups.set(identity, []);
    groups.get(identity)!.push(id);
  }
  return [...groups.values()]
    .filter((group) => group.length > 1)
    .map((group) => group.sort(compare))
    .sort((left, right) => {
      for (let i = 0; i < Math.min(left.length, right.length); i++) {
        const order = compare(left[i]!, right[i]!);
        if (order) return order;
      }
      return left.length - right.length;
    });
}

// Stable finding IDs include target identity. Walk indexed occurrences of only
// the selected components, including recurring IDs, as the original owner does.
const findingNeighborsSql = `
    FROM linked
    CROSS JOIN finding_occurrences AS source ON source.finding_id = linked.finding_id
    CROSS JOIN scan_comparison_matches AS matches
      ON matches.before_occurrence_id = source.id OR matches.after_occurrence_id = source.id
    CROSS JOIN finding_occurrences AS neighbor ON neighbor.id = CASE
      WHEN matches.before_occurrence_id = source.id THEN matches.after_occurrence_id
      ELSE matches.before_occurrence_id END
`;
const linkedFindingsSql = `
    WITH RECURSIVE linked(finding_id) AS (
      SELECT occurrences.finding_id FROM finding_occurrences AS occurrences
      WHERE occurrences.id IN ({placeholders})
      UNION SELECT neighbor.finding_id ${findingNeighborsSql}
    )
`;

export function confirmedFindingAliases(
  connection: Connection,
  occurrenceIds: Iterable<string>,
): Map<string, string> {
  return findingAliases(
    [
      ...rowsForIds(
        connection,
        `
    ${linkedFindingsSql}
    SELECT DISTINCT linked.finding_id AS before_finding_id, neighbor.finding_id AS after_finding_id
    ${findingNeighborsSql}
  `,
        occurrenceIds,
      ),
    ].map((row) => [
      row.get("before_finding_id") as string,
      row.get("after_finding_id") as string,
    ]),
  );
}

export function separateFindingPairs<T extends FindingPair>(
  pairs: readonly T[],
  occurrences: ReadonlyMap<string, Pick<Occurrence, "finding_id">>,
  aliases: ReadonlyMap<string, string>,
): T[] {
  const identity = (occurrenceId: string) => {
    const id = occurrences.get(occurrenceId)!.finding_id;
    return aliases.get(id) ?? id;
  };
  return pairs.filter(
    (pair) =>
      identity(pair.beforeOccurrenceId) !== identity(pair.afterOccurrenceId),
  );
}

export function findingRelations(
  connection: Connection,
  scanId: string,
  occurrenceIds: Iterable<string>,
) {
  const selected = new Set(occurrenceIds);
  if (!selected.size) return {};
  let pairs: (FindingPair & { afterScanId: string })[] = [];
  for (const comparison of connection
    .prepare(
      "SELECT before_scan_id, after_scan_id, result_json FROM scan_comparisons " +
        "WHERE before_scan_id = ? OR after_scan_id = ? ORDER BY before_scan_id, after_scan_id",
    )
    .iterate([scanId, scanId])) {
    const side =
        comparison.get("before_scan_id") === scanId ? "before" : "after",
      other = side === "before" ? "after" : "before";
    const payload = parseJson(comparison.get("result_json") as string) as {
      related?: FindingPair[];
    };
    for (const pair of Object.hasOwn(payload, "related")
      ? payload.related!
      : []) {
      if (selected.has(pair[`${side}OccurrenceId`]))
        pairs.push({
          beforeOccurrenceId: pair[`${side}OccurrenceId`],
          afterOccurrenceId: pair[`${other}OccurrenceId`],
          afterScanId: comparison.get(`${other}_scan_id`) as string,
          reason: pair.reason,
        });
    }
  }
  const occurrences = new Map(
    [
      ...rowsForIds(
        connection,
        "SELECT id, finding_id, scan_id, title FROM finding_occurrences WHERE id IN ({placeholders})",
        pairs.flatMap((pair) => [
          pair.beforeOccurrenceId,
          pair.afterOccurrenceId,
        ]),
      ),
    ].map((row) => [
      row.get("id") as string,
      row.toObject() as unknown as Occurrence,
    ]),
  );
  pairs = pairs.filter(
    (pair) =>
      occurrences.get(pair.beforeOccurrenceId)?.scan_id === scanId &&
      occurrences.get(pair.afterOccurrenceId)?.scan_id === pair.afterScanId,
  );
  const aliases = confirmedFindingAliases(
    connection,
    pairs.map((pair) => pair.beforeOccurrenceId),
  );
  const result = new Map<string, Record<string, unknown>[]>();
  for (const pair of separateFindingPairs(pairs, occurrences, aliases)) {
    const finding = occurrences.get(pair.afterOccurrenceId)!;
    if (!result.has(pair.beforeOccurrenceId))
      result.set(pair.beforeOccurrenceId, []);
    result.get(pair.beforeOccurrenceId)!.push({
      findingId: finding.finding_id,
      occurrenceId: finding.id,
      reason: pair.reason,
      scanId: pair.afterScanId,
      title: finding.title,
    });
  }
  return objectFromEntries(result);
}

export function findingMatches(
  connection: Connection,
  occurrenceId: string,
  scanId: string,
  startedAt: string,
): [Record<string, unknown>[], string, string[]] {
  const rows = connection
    .prepare(
      `
    SELECT matches.after_scan_id AS scan_id, occurrences.id AS occurrence_id, occurrences.finding_id, occurrences.title, matches.reason
    FROM scan_comparison_matches AS matches JOIN finding_occurrences AS occurrences ON occurrences.id = matches.after_occurrence_id WHERE matches.before_occurrence_id = ?
    UNION
    SELECT matches.before_scan_id AS scan_id, occurrences.id AS occurrence_id, occurrences.finding_id, occurrences.title, matches.reason
    FROM scan_comparison_matches AS matches JOIN finding_occurrences AS occurrences ON occurrences.id = matches.before_occurrence_id WHERE matches.after_occurrence_id = ?
    ORDER BY scan_id, occurrence_id
  `,
    )
    .all([occurrenceId, occurrenceId])
    .map((row) => row.toObject());
  const linked = [
    ...rowsForIds(
      connection,
      `
    ${linkedFindingsSql}
    SELECT occurrences.id AS occurrence_id, occurrences.finding_id, occurrences.title, scans.started_at, scans.id AS scan_id
    FROM linked CROSS JOIN finding_occurrences AS occurrences ON occurrences.finding_id = linked.finding_id
    CROSS JOIN scans ON scans.id = occurrences.scan_id
  `,
      [occurrenceId],
    ),
  ].map((row) => row.toObject());
  const scans = new Map<string, [string, string]>();
  for (const entry of [
    [startedAt, scanId] as [string, string],
    ...linked.map(
      (row) => [row["started_at"], row["scan_id"]] as [string, string],
    ),
  ])
    scans.set(JSON.stringify(entry), entry);
  const known = [...scans.values()].sort(
    ([a, b], [c, d]) => compare(a, c) || compare(b, d),
  );
  const included = new Set([
    occurrenceId,
    ...rows.map((row) => row["occurrence_id"]),
  ]);
  rows.push(
    ...linked
      .filter((row) => !included.has(row["occurrence_id"]))
      .map((row) => ({
        ...row,
        reason:
          "The findings share a stable identity or a previously confirmed link.",
      })),
  );
  rows.sort(
    (a, b) =>
      compare(a["scan_id"] as string, b["scan_id"] as string) ||
      compare(a["occurrence_id"] as string, b["occurrence_id"] as string),
  );
  const bounds = [known[0]![1]];
  if (known.length > 1) bounds.push(known.at(-1)![1]);
  return [
    rows.map((row) => ({
      findingId: row["finding_id"],
      occurrenceId: row["occurrence_id"],
      reason: row["reason"],
      scanId: row["scan_id"],
      title: row["title"],
    })),
    known[0]![0],
    bounds,
  ];
}
