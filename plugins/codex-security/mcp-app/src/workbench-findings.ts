import { createHash } from "node:crypto";
import type { Connection, Parameter } from "../../native/sqlite.mjs";
import {
  InvalidEmbeddingError,
  normalizedVector,
  similarity,
} from "./finding-similarity";
import {
  JsonFloat,
  JsonSyntaxError,
  jsonGet,
  jsonItem,
  object,
  objectEntries,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { compare } from "./helpers/rank-worklists";

export interface ImportedFinding {
  findingId: string;
  fingerprints: { primary: string };
  ruleId: string;
  identity: { anchor: string; instance?: string | null };
  [key: string]: unknown;
}
export interface ImportedEntry {
  finding: ImportedFinding;
  embedding: { model: string; vector: unknown[] };
}
const conflict = { error: "finding_conflict" };
const constraint = (error: unknown) =>
  (error as { sqliteErrorCode?: number }).sqliteErrorCode === 19;

// The caller owns the transaction.
export function upsertFinding(
  connection: Connection,
  finding: ImportedFinding,
  timestamp: string,
  repositoryId: string | null = null,
): void {
  connection
    .prepare(
      `
    INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, identity_instance,
      details_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint, rule_id=excluded.rule_id,
      identity_anchor=excluded.identity_anchor, identity_instance=excluded.identity_instance,
      details_json=excluded.details_json, updated_at=excluded.updated_at
  `,
    )
    .run(
      [
        jsonItem(finding, "findingId"),
        jsonItem(jsonItem(finding, "fingerprints"), "primary"),
        jsonItem(finding, "ruleId"),
        jsonItem(jsonItem(finding, "identity"), "anchor"),
        jsonGet(jsonItem(finding, "identity"), "instance"),
        stringifyJson(finding, {
          compact: true,
          allowNan: false,
          sortKeys: true,
        }),
        timestamp,
        timestamp,
      ].map((value) =>
        value instanceof JsonFloat ? Number(value.source) : value,
      ) as Parameter[],
    );
  if (repositoryId !== null)
    connection
      .prepare(
        "INSERT OR IGNORE INTO finding_repositories (repository_id, finding_id) VALUES (?, ?)",
      )
      .run(
        [repositoryId, jsonItem(finding, "findingId")].map((value) =>
          value instanceof JsonFloat ? Number(value.source) : value,
        ) as Parameter[],
      );
}

export function storeFindings(
  connection: Connection,
  entries: ImportedEntry[],
  timestamp: string,
  repositoryId: string | null = null,
) {
  try {
    connection.transaction(() => {
      connection.exec("BEGIN IMMEDIATE");
      for (const { finding, embedding } of entries) {
        const identity = [
          finding.fingerprints.primary,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance ?? null,
        ];
        const current = connection
          .prepare(
            "SELECT fingerprint, rule_id, identity_anchor, identity_instance FROM findings WHERE id = ?",
          )
          .get([finding.findingId]);
        if (
          current !== undefined &&
          current.values.some((value, index) => value !== identity[index])
        )
          throw Object.assign(
            new Error("The stored finding identity cannot be replaced."),
            { sqliteErrorCode: 19 },
          );
        upsertFinding(connection, finding, timestamp, repositoryId);
        connection
          .prepare(
            `
          INSERT INTO finding_embeddings (finding_id, model, vector_json) VALUES (?, ?, ?)
          ON CONFLICT(finding_id) DO UPDATE SET model=excluded.model, vector_json=excluded.vector_json
        `,
          )
          .run([
            finding.findingId,
            embedding.model,
            stringifyJson(embedding.vector, { compact: true, allowNan: false }),
          ]);
      }
    });
  } catch (error) {
    if (constraint(error)) return conflict;
    throw error;
  }
  return { findingIds: entries.map(({ finding }) => finding.findingId) };
}

export function listStoredFindings(
  connection: Connection,
  limit: bigint,
  offset: bigint,
) {
  connection.exec("BEGIN");
  const { total, rows } = connection.transaction(() => ({
    total: connection
      .prepare("SELECT COUNT(*) FROM findings WHERE details_json IS NOT NULL")
      .get()!
      .get(0) as bigint,
    rows: connection
      .prepare(
        "SELECT details_json FROM findings WHERE details_json IS NOT NULL ORDER BY created_at, id LIMIT ? OFFSET ?",
      )
      .all([limit, offset]),
  }));
  const nextOffset = offset + BigInt(rows.length);
  return {
    findings: rows.map((row) => parseJson(row.get("details_json") as string)),
    limit,
    offset,
    total,
    nextOffset: nextOffset < total ? nextOffset : null,
  };
}

function length(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (typeof value === "string") return Array.from(value).length;
  if (object(value)) return objectEntries(value).length;
  throw new TypeError("Stored vector has no len()");
}

export function findPotentialDuplicates(
  connection: Connection,
  findingId: string,
  repositoryId: string | null,
) {
  connection.exec("BEGIN");
  return connection.transaction(() => {
    const source =
      repositoryId === null
        ? "finding_embeddings AS embeddings"
        : "finding_repositories AS repositories JOIN finding_embeddings AS embeddings ON embeddings.finding_id = repositories.finding_id";
    const predicate =
      repositoryId === null ? "" : "repositories.repository_id = ? AND ";
    const scope: Parameter[] = repositoryId === null ? [] : [repositoryId];
    const anchor = connection
      .prepare(
        `SELECT embeddings.model, embeddings.vector_json FROM ${source} WHERE ${predicate}embeddings.finding_id = ?`,
      )
      .get([...scope, findingId]);
    if (anchor === undefined) return { error: "finding_not_indexed" };
    const rows = connection
      .prepare(
        `SELECT embeddings.finding_id, embeddings.vector_json FROM ${source} JOIN findings ON findings.id = embeddings.finding_id WHERE ${predicate}embeddings.model = ? AND embeddings.finding_id != ? ORDER BY findings.created_at, findings.id`,
      )
      .iterate([...scope, anchor.get("model"), findingId]);
    let current = rows.next();
    const ranked: { id: string; score: number }[] = [];
    try {
      const vector = normalizedVector(
        parseJson(anchor.get("vector_json") as string),
      );
      for (; !current.done; current = rows.next()) {
        const row = current.value;
        const candidate = parseJson(row.get("vector_json") as string);
        if (length(candidate) !== vector.length) continue;
        const score = similarity(vector, normalizedVector(candidate));
        if (score >= 0.55)
          ranked.push({ id: row.get("finding_id") as string, score });
      }
    } catch (error) {
      if (
        error instanceof InvalidEmbeddingError ||
        error instanceof JsonSyntaxError
      )
        return { error: "embedding_failed" };
      throw error;
    } finally {
      rows.return(undefined);
    }
    ranked.sort((left, right) => right.score - left.score);
    const ids = [findingId, ...ranked.slice(0, 50).map(({ id }) => id)];
    const documents = new Map(
      connection
        .prepare(
          `SELECT id, details_json FROM findings WHERE id IN (${ids.map(() => "?").join(",")})`,
        )
        .all(ids)
        .map((row) => [
          row.get("id"),
          parseJson(row.get("details_json") as string),
        ]),
    );
    return {
      finding: documents.get(findingId),
      potentialDuplicates: ids.slice(1).map((id) => documents.get(id)),
    };
  });
}

export function storeDedupeGroups(
  connection: Connection,
  groups: string[][],
  timestamp: string,
) {
  const stored = new Map<
    string,
    { groupId: string; findingIds: string[]; createdAt: string }
  >();
  try {
    connection.transaction(() => {
      connection.exec("BEGIN IMMEDIATE");
      for (const group of groups) {
        const members = [...new Set(group)].sort(compare);
        const json = `[${members.map((member) => stringifyJson(member)).join(",")}]`;
        const groupId = `fdg_${createHash("sha256").update(json).digest("hex")}`;
        connection
          .prepare(
            "INSERT INTO finding_dedupe_groups (id, created_at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
          )
          .run([groupId, timestamp]);
        for (const member of members)
          connection
            .prepare(
              "INSERT INTO finding_dedupe_group_members (group_id, finding_id) VALUES (?, ?) ON CONFLICT(group_id, finding_id) DO NOTHING",
            )
            .run([groupId, member]);
        const createdAt = connection
          .prepare("SELECT created_at FROM finding_dedupe_groups WHERE id = ?")
          .get([groupId])!
          .get(0) as string;
        stored.set(groupId, { groupId, findingIds: members, createdAt });
      }
    });
  } catch (error) {
    if (constraint(error)) return conflict;
    throw error;
  }
  return { groups: [...stored.values()] };
}

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
    WHERE matched.finding_id = ? ORDER BY groups.created_at, groups.id, members.finding_id
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
