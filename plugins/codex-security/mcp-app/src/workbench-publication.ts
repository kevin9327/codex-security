import { Connection, type Row } from "../../native/sqlite.mjs";
import { sqliteBinding } from "./native";
import { object } from "./helpers/python-json";
import { scanPathNormcase } from "./helpers/scan-local-files";
import { encodeUtf8 } from "./helpers/utf8";
import { requireRecordedManifestDigest } from "./workbench-binding";
import {
  readJsonObject,
  requireCanonicalScanDirectory,
} from "./workbench-files";
import { requireScan } from "./workbench-records";
import { WorkbenchValidationError } from "./workbench-validation";

export interface LinearDestination {
  type: "linear";
  teamId: string;
  projectId?: string;
}
export interface PublicationFinding {
  findingId: string;
  occurrenceId: string;
}
export interface LinearPublication extends PublicationFinding {
  issueIdentifier: string;
  url?: string;
}
export interface LinearPublicationInput {
  scanId: string;
  scanDirectory: string;
  destination: LinearDestination;
  findings: PublicationFinding[];
  publications?: unknown;
}
export interface PublicationArguments {
  inputFile: string;
}
export interface WorkbenchPublicationContext {
  databasePath(): string;
  now(): string;
}
const exactKeys = (value: Record<string, unknown>, keys: string[]) =>
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const nonempty = (value: unknown): value is string =>
  typeof value === "string" && /[^\p{White_Space}\u001c-\u001f]/u.test(value);

export function linearPublicationInput(
  args: PublicationArguments,
  recording: boolean,
): [LinearPublicationInput, LinearDestination, PublicationFinding[]] {
  const payload = readJsonObject(args.inputFile);
  const required = ["scanId", "scanDirectory", "destination", "findings"];
  if (recording) required.push("publications");
  if (!exactKeys(payload, required))
    throw new WorkbenchValidationError(
      "Linear publication input contains unexpected or missing fields.",
    );
  const { scanId, scanDirectory, destination, findings } = payload;
  if (typeof scanId !== "string" || typeof scanDirectory !== "string")
    throw new WorkbenchValidationError(
      "Linear publication input must identify the exact completed scan.",
    );
  if (
    !object(destination) ||
    !Object.hasOwn(destination, "type") ||
    !Object.hasOwn(destination, "teamId") ||
    Object.keys(destination).some(
      (key) => !["type", "teamId", "projectId"].includes(key),
    ) ||
    destination["type"] !== "linear" ||
    !nonempty(destination["teamId"]) ||
    (Object.hasOwn(destination, "projectId") &&
      !nonempty(destination["projectId"]))
  )
    throw new WorkbenchValidationError(
      "Linear publication input must identify the exact team and optional project.",
    );
  if (!Array.isArray(findings))
    throw new WorkbenchValidationError(
      "Linear publication input must include the planned scan findings.",
    );
  const findingIds = new Set<string>(),
    occurrenceIds = new Set<string>();
  for (const finding of findings) {
    if (
      !object(finding) ||
      !exactKeys(finding, ["findingId", "occurrenceId"]) ||
      !nonempty(finding["findingId"]) ||
      !nonempty(finding["occurrenceId"])
    )
      throw new WorkbenchValidationError(
        "Linear publication input contains an invalid finding identity.",
      );
    if (
      findingIds.has(finding["findingId"]) ||
      occurrenceIds.has(finding["occurrenceId"])
    )
      throw new WorkbenchValidationError(
        "Linear publication input repeats a finding or occurrence.",
      );
    findingIds.add(finding["findingId"]);
    occurrenceIds.add(finding["occurrenceId"]);
  }
  return [
    payload as unknown as LinearPublicationInput,
    destination as unknown as LinearDestination,
    findings as PublicationFinding[],
  ];
}

export function verifyLinearPublicationScan(
  connection: Connection,
  payload: LinearPublicationInput,
  findings: PublicationFinding[],
): Row {
  let scan: Row;
  try {
    scan = requireScan(connection, payload.scanId);
  } catch (error) {
    if (!(error instanceof WorkbenchValidationError)) throw error;
    throw new WorkbenchValidationError(
      "The completed scan is not present in the local Codex Security scan-history database. " +
        "Use the state directory where the scan was completed.",
    );
  }
  if (scan.get("id") !== payload.scanId)
    throw new WorkbenchValidationError(
      "Linear publication must use the exact completed scan identifier.",
    );
  if (scan.get("status") !== "complete")
    throw new WorkbenchValidationError(
      "Only completed scans can publish findings to Linear.",
    );
  const requested = requireCanonicalScanDirectory(payload.scanDirectory),
    recorded = requireCanonicalScanDirectory(scan.get("scan_dir") as string);
  if (scanPathNormcase(requested) !== scanPathNormcase(recorded))
    throw new WorkbenchValidationError(
      "The selected scan directory does not match its local Codex Security scan history.",
    );
  if (scan.columns.includes("seal_manifest_digest"))
    requireRecordedManifestDigest(scan, recorded);
  const stored = new Map(
    connection
      .prepare(
        "SELECT id, finding_id FROM finding_occurrences WHERE scan_id = ?",
      )
      .all([scan.get("id")])
      .map((row) => [row.get("id"), row.get("finding_id")]),
  );
  for (const finding of findings)
    if (stored.get(finding.occurrenceId) !== finding.findingId)
      throw new WorkbenchValidationError(
        "A selected finding or occurrence does not belong to the completed scan " +
          "in local Codex Security scan history.",
      );
  if (stored.size !== findings.length)
    throw new WorkbenchValidationError(
      "The completed scan findings do not exactly match local Codex Security scan history.",
    );
  return scan;
}

function recordedPublication(row: Row): LinearPublication {
  const result: LinearPublication = {
    findingId: row.get("finding_id") as string,
    occurrenceId: row.get("occurrence_id") as string,
    issueIdentifier: row.get("external_id") as string,
  };
  if (row.get("external_url") !== null)
    result.url = row.get("external_url") as string;
  return result;
}

export function inspectLinearPublication(
  db: Pick<WorkbenchPublicationContext, "databasePath">,
  args: PublicationArguments,
): {
  scanId: string;
  destination: LinearDestination;
  findingCount: bigint;
  recorded: LinearPublication[];
} {
  const [payload, destination, findings] = linearPublicationInput(args, false);
  const path = Array.from(encodeUtf8(db.databasePath()), (byte) =>
    /[A-Za-z0-9_.~-]/u.test(String.fromCharCode(byte))
      ? String.fromCharCode(byte)
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`,
  ).join("");
  const connection = new Connection(sqliteBinding(), `file:${path}?mode=ro`, {
    uri: true,
  });
  try {
    connection.prepare("BEGIN").run();
    const scan = verifyLinearPublicationScan(connection, payload, findings),
      recorded = new Map<string, LinearPublication>();
    if (
      connection
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'finding_publications'",
        )
        .get()
    )
      for (const row of connection
        .prepare(
          `
        SELECT finding_id, occurrence_id, external_id, external_url
        FROM finding_publications
        WHERE scan_id = ? AND destination_type = ? AND team_id = ? AND project_id IS ?
        ORDER BY created_at, external_id
      `,
        )
        .iterate([
          scan.get("id"),
          destination.type,
          destination.teamId,
          destination.projectId ?? null,
        ])) {
        const publication = recordedPublication(row);
        if (!recorded.has(publication.occurrenceId))
          recorded.set(publication.occurrenceId, publication);
      }
    return {
      scanId: scan.get("id") as string,
      destination,
      findingCount: BigInt(findings.length),
      recorded: findings
        .filter((finding) => recorded.has(finding.occurrenceId))
        .map((finding) => recorded.get(finding.occurrenceId)!),
    };
  } finally {
    connection.close();
  }
}

export function prepareLinearPublication(
  connection: Connection,
  args: PublicationArguments,
): { scanId: string; destination: LinearDestination; findingCount: bigint } {
  const [payload, destination, findings] = linearPublicationInput(args, false);
  connection.prepare("BEGIN IMMEDIATE").run();
  return connection.transaction(() => {
    const scan = verifyLinearPublicationScan(connection, payload, findings);
    return {
      scanId: scan.get("id") as string,
      destination,
      findingCount: BigInt(findings.length),
    };
  });
}

export function recordLinearPublications(
  db: Pick<WorkbenchPublicationContext, "now">,
  connection: Connection,
  args: PublicationArguments,
): {
  scanId: string;
  destination: LinearDestination;
  created: LinearPublication[];
} {
  const [payload, destination, findings] = linearPublicationInput(args, true),
    publications = payload.publications;
  if (!Array.isArray(publications))
    throw new WorkbenchValidationError(
      "Linear publication results must be an array.",
    );
  const planned = new Map(
      findings.map((finding) => [finding.findingId, finding.occurrenceId]),
    ),
    current = new Map<string, LinearPublication>(),
    externalIds = new Set<string>();
  for (const publication of publications) {
    if (
      !object(publication) ||
      !["findingId", "occurrenceId", "issueIdentifier"].every((key) =>
        Object.hasOwn(publication, key),
      ) ||
      Object.keys(publication).some(
        (key) =>
          !["findingId", "occurrenceId", "issueIdentifier", "url"].includes(
            key,
          ),
      ) ||
      typeof publication["findingId"] !== "string" ||
      typeof publication["occurrenceId"] !== "string" ||
      !nonempty(publication["issueIdentifier"]) ||
      (Object.hasOwn(publication, "url") && !nonempty(publication["url"]))
    )
      throw new WorkbenchValidationError(
        "Linear publication results contain an invalid issue association.",
      );
    const findingId = publication["findingId"],
      issue = publication["issueIdentifier"];
    if (planned.get(findingId) !== publication["occurrenceId"])
      throw new WorkbenchValidationError(
        "A created Linear issue does not match its planned finding and occurrence.",
      );
    if (current.has(findingId) || externalIds.has(issue))
      throw new WorkbenchValidationError(
        "Linear publication results repeat a finding or issue identifier.",
      );
    current.set(findingId, publication as unknown as LinearPublication);
    externalIds.add(issue);
  }
  connection.prepare("BEGIN IMMEDIATE").run();
  return connection.transaction(() => {
    const scan = verifyLinearPublicationScan(connection, payload, findings),
      timestamp = db.now();
    for (const publication of publications as LinearPublication[]) {
      const conflicting = connection
        .prepare(
          `
        SELECT occurrence_id, external_url
        FROM finding_publications
        WHERE destination_type = ? AND team_id = ? AND project_id IS ?
            AND external_id = ?
      `,
        )
        .get([
          destination.type,
          destination.teamId,
          destination.projectId ?? null,
          publication.issueIdentifier,
        ]);
      if (
        conflicting &&
        conflicting.get("occurrence_id") !== publication.occurrenceId
      )
        throw new WorkbenchValidationError(
          "This Linear issue is already associated with a different finding.",
        );
      if (
        conflicting &&
        Object.hasOwn(publication, "url") &&
        conflicting.get("external_url") !== publication.url
      )
        throw new WorkbenchValidationError(
          "This Linear issue is already associated with a different URL.",
        );
      connection
        .prepare(
          `
        INSERT INTO finding_publications (
            scan_id, finding_id, occurrence_id, destination_type,
            team_id, project_id, external_id, external_url, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
      `,
        )
        .run([
          scan.get("id"),
          publication.findingId,
          publication.occurrenceId,
          destination.type,
          destination.teamId,
          destination.projectId ?? null,
          publication.issueIdentifier,
          publication.url ?? null,
          timestamp,
        ]);
    }
    const created: LinearPublication[] = [];
    for (const finding of findings) {
      const publication = current.get(finding.findingId);
      if (publication === undefined) continue;
      const row = connection
        .prepare(
          `
        SELECT finding_id, occurrence_id, external_id, external_url
        FROM finding_publications
        WHERE scan_id = ? AND occurrence_id = ? AND destination_type = ?
            AND team_id = ? AND project_id IS ? AND external_id = ?
      `,
        )
        .get([
          scan.get("id"),
          publication.occurrenceId,
          destination.type,
          destination.teamId,
          destination.projectId ?? null,
          publication.issueIdentifier,
        ]);
      if (row === undefined)
        throw new WorkbenchValidationError(
          "A created Linear issue could not be read from scan history.",
        );
      created.push(recordedPublication(row));
    }
    return { scanId: scan.get("id") as string, destination, created };
  });
}
