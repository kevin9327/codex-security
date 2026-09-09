import commonFolds from "@unicode/unicode-15.0.0/Case_Folding/C/symbols.js";
import fullFolds from "@unicode/unicode-15.0.0/Case_Folding/F/symbols.js";
import type { Connection, Parameter, Row } from "../../native/sqlite.mjs";
import { JsonFloat, parseJson } from "./helpers/python-json";

type PaginationValue = bigint | JsonFloat | boolean;
function numeric(value: PaginationValue): bigint | number {
  return value instanceof JsonFloat
    ? Number(value.source)
    : typeof value === "boolean"
      ? BigInt(value)
      : value;
}

export interface DashboardQuery {
  view: "findings" | "groups";
  query?: string;
  repository?: string;
  sort: "newest" | "activity";
  limit: PaginationValue;
  offset: PaginationValue;
  id?: string;
}

export function casefold(value: string): string {
  return Array.from(
    value,
    (character) =>
      fullFolds.get(character) ?? commonFolds.get(character) ?? character,
  ).join("");
}

const RECORDS = {
  findings: `
SELECT findings.id, json_extract(details_json, '$.title') AS title,
    COALESCE(repositories.ids, '[]') AS repositoryIds,
    json_extract(details_json, '$.severity.level') AS severity,
    findings.created_at AS createdAt, findings.updated_at AS updatedAt
FROM findings LEFT JOIN (
    SELECT finding_id, json_group_array(repository_id) AS ids
    FROM finding_repositories GROUP BY finding_id
) AS repositories ON repositories.finding_id = findings.id
WHERE details_json IS NOT NULL`,
  groups: `
SELECT groups.id, groups.id AS title,
    (SELECT json_group_array(DISTINCT repository_id)
     FROM finding_dedupe_group_members AS members
     JOIN finding_repositories ON finding_repositories.finding_id = members.finding_id
     WHERE members.group_id = groups.id) AS repositoryIds,
    groups.created_at AS createdAt, groups.created_at AS updatedAt,
    (SELECT COUNT(*) FROM finding_dedupe_group_members WHERE group_id = groups.id) AS memberCount
FROM finding_dedupe_groups AS groups`,
};

export function listDedupeGroups(connection: Connection, findingId: string) {
  const groups = new Map<
    string,
    { groupId: string; findingIds: string[]; createdAt: string }
  >();
  for (const row of connection
    .prepare(
      `
        SELECT groups.id, groups.created_at, members.finding_id
        FROM finding_dedupe_group_members AS matched
        JOIN finding_dedupe_groups AS groups ON groups.id = matched.group_id
        JOIN finding_dedupe_group_members AS members ON members.group_id = groups.id
        WHERE matched.finding_id = ?
        ORDER BY groups.created_at, groups.id, members.finding_id
        `,
    )
    .iterate([findingId])) {
    const id = row.get("id") as string;
    let group = groups.get(id);
    if (group === undefined) {
      group = {
        groupId: id,
        findingIds: [],
        createdAt: row.get("created_at") as string,
      };
      groups.set(id, group);
    }
    group.findingIds.push(row.get("finding_id") as string);
  }
  return { groups: [...groups.values()] };
}

function item(row: Row) {
  return {
    ...row.toObject(),
    repositoryIds: parseJson(row.get("repositoryIds") as string),
  };
}

function detail(
  connection: Connection,
  view: DashboardQuery["view"],
  selected: Row,
) {
  const selectedId = selected.get("id") as string;
  const result = { item: item(selected) };
  return view === "findings"
    ? {
        ...result,
        finding: parseJson(
          connection
            .prepare("SELECT details_json FROM findings WHERE id = ?")
            .get([selectedId])!
            .get(0) as string,
        ),
        groups: listDedupeGroups(connection, selectedId).groups,
      }
    : {
        ...result,
        group: {
          groupId: selectedId,
          createdAt: selected.get("createdAt"),
          findingIds: connection
            .prepare(
              "SELECT finding_id FROM finding_dedupe_group_members WHERE group_id = ? ORDER BY finding_id",
            )
            .all([selectedId])
            .map((row) => row.get(0)),
        },
      };
}

/** One read snapshot over the four findings and dedupe tables. */
export function dashboard(connection: Connection, query: DashboardQuery) {
  const records = RECORDS[query.view];
  const clauses: string[] = [],
    values: Parameter[] = [];
  if (query.query) {
    connection.function("casefold", 1, true, (value) => {
      if (typeof value !== "string")
        throw new TypeError("casefold requires a string");
      return casefold(value);
    });
    const columns = ["id", "title", "repositoryIds"];
    clauses.push(
      `(${columns.map((column) => `instr(casefold(COALESCE(${column}, '')), casefold(?)) > 0`).join(" OR ")})`,
    );
    values.push(...columns.map(() => query.query!));
  }
  if (query.repository) {
    clauses.push(
      "EXISTS (SELECT 1 FROM json_each(repositoryIds) WHERE value = ?)",
    );
    values.push(query.repository);
  }
  const where = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
  const order =
    query.sort === "newest" ? "createdAt DESC, id" : "updatedAt DESC, id";
  connection.exec("BEGIN");
  return connection.transaction(() => {
    const repositories = connection
      .prepare(
        `
            SELECT DISTINCT repository_id AS id, repository_id AS label
            FROM finding_repositories ORDER BY repository_id
        `,
      )
      .all();
    const total = connection
      .prepare(`SELECT COUNT(*) FROM (${records}) ${where}`)
      .get(values)!
      .get(0) as bigint;
    const rows = connection
      .prepare(
        `SELECT * FROM (${records}) ${where} ORDER BY ${order} LIMIT ? OFFSET ?`,
      )
      .all([...values, numeric(query.limit), numeric(query.offset)]);
    const selected = query.id
      ? connection
          .prepare(`SELECT * FROM (${records}) WHERE id = ?`)
          .get([query.id])
      : undefined;
    const offset = numeric(query.offset);
    if (typeof offset === "string")
      throw new TypeError('can only concatenate str (not "int") to str');
    const nextOffset =
      typeof offset === "number"
        ? offset + rows.length
        : offset + BigInt(rows.length);
    return {
      overview: {
        findings: connection
          .prepare(
            "SELECT COUNT(*) FROM findings WHERE details_json IS NOT NULL",
          )
          .get()!
          .get(0),
        groups: connection
          .prepare("SELECT COUNT(*) FROM finding_dedupe_groups")
          .get()!
          .get(0),
      },
      repositories: repositories.map((row) => row.toObject()),
      items: rows.map(item),
      total,
      limit: query.limit,
      offset: query.offset,
      nextOffset:
        nextOffset < total
          ? typeof nextOffset === "number"
            ? new JsonFloat(String(nextOffset))
            : nextOffset
          : null,
      detail:
        selected === undefined
          ? null
          : detail(connection, query.view, selected),
    };
  });
}
