import type { Connection, Parameter, Row } from "../../native/sqlite.mjs";
import {
  JsonSyntaxError,
  object,
  parseJson,
  stringifyJson,
} from "./helpers/python-json";
import { requireCurrentCoordinator } from "./workbench-deep-lease";
import { requireCurrentContinuation } from "./workbench-handoff";
import {
  optionalText,
  requireUuid,
  userContextArgument,
  WorkbenchValidationError,
} from "./workbench-validation";

export const PHASES = [
  "preflight",
  "threat_model",
  "discovery",
  "validation",
  "attack_path",
  "reporting",
] as const;
export const MAX_PREFLIGHT_ISSUES = 32;

export function javascriptStringLength(value: string): number {
  return value.length;
}

export function preflightIssueText(
  value: unknown,
  maximum: number,
  label: string,
): string {
  if (typeof value !== "string")
    throw new WorkbenchValidationError(
      `Preflight issue ${label} must be text.`,
    );
  const normalized = optionalText(value) ?? "";
  if (!normalized || javascriptStringLength(normalized) > maximum)
    throw new WorkbenchValidationError(
      `Preflight issue ${label} must contain 1 to ${maximum} characters.`,
    );
  return normalized;
}

function includes(values: readonly unknown[], value: unknown): boolean {
  if (Array.isArray(value) || object(value))
    throw new TypeError(
      `unhashable type: '${Array.isArray(value) ? "list" : "dict"}'`,
    );
  return values.includes(value);
}

export function preflightIssuesJson(value: string | null): string | null {
  if (value === null) return null;
  let payload: unknown;
  try {
    payload = parseJson(value, false, (source) => {
      const digits = source.replace(/^-/, "").length;
      if (digits > 4300)
        throw new Error(
          `Exceeds the limit (4300 digits) for integer string conversion: value has ${digits} digits; use sys.set_int_max_str_digits() to increase the limit`,
        );
      return BigInt(source);
    });
  } catch (error) {
    if (!(error instanceof JsonSyntaxError)) throw error;
    throw new WorkbenchValidationError("Preflight issues must be valid JSON.");
  }
  if (!Array.isArray(payload) || payload.length > MAX_PREFLIGHT_ISSUES)
    throw new WorkbenchValidationError(
      `Preflight issues must be an array of at most ${MAX_PREFLIGHT_ISSUES} objects.`,
    );
  const expectedKeys = ["capability", "reason", "severity", "status"];
  const normalized = payload.map((issue, index) => {
    const label = String(index + 1);
    if (
      !object(issue) ||
      Object.keys(issue).length !== expectedKeys.length ||
      Object.keys(issue).some((key) => !expectedKeys.includes(key))
    )
      throw new WorkbenchValidationError(
        `Preflight issue ${label} must contain capability, reason, severity, and status.`,
      );
    const severity = issue["severity"],
      status = issue["status"];
    if (
      !includes(["block", "warn"], severity) ||
      !includes(["fail", "unknown"], status)
    )
      throw new WorkbenchValidationError(
        `Preflight issue ${label} has an invalid severity or status.`,
      );
    return {
      capability: preflightIssueText(
        issue["capability"],
        128,
        `${label} capability`,
      ),
      reason: preflightIssueText(issue["reason"], 1200, `${label} reason`),
      severity,
      status,
    };
  });
  return stringifyJson(normalized, {
    compact: true,
    separators: [",", ":"],
    sortKeys: true,
  });
}

export function reportableCount(
  currentPhase: string,
  requestedPhase: string | null,
  count: bigint | null,
): bigint | null {
  if (
    count === null &&
    PHASES.slice(3).includes(requestedPhase as (typeof PHASES)[number]) &&
    PHASES.slice(0, 3).includes(currentPhase as (typeof PHASES)[number])
  )
    return 0n;
  return count;
}

export interface ContextArguments {
  scanId: string;
  workspaceId: string | null;
  threadId: string | null;
  claimToken: string | null;
  userContext: string | null;
  userContextStdin: boolean;
}
export interface ProgressArguments {
  scanId: string;
  model: string | null;
  reasoningEffort: string | null;
  preflightIssuesJson: string | null;
  preflightIssuesJsonStdin: boolean;
  coordinatorGeneration: bigint | null;
  claimToken: string | null;
  deepReviewPass: bigint | null;
  phase: string | null;
  phaseItemsTotal: bigint | null;
  phaseItemsCompleted: bigint | null;
  phaseProgressUnit: string | null;
  reviewItemsTotal: bigint | null;
  reviewItemsCompleted: bigint | null;
  reportableFindingsCount: bigint | null;
}
export interface ProgressCallbacks {
  now(): string;
  readStdin(): string;
  requireScan(connection: Connection, scanId: string): Row;
  scanContext(connection: Connection, scanId: string): Record<string, unknown>;
}
export interface ContextCallbacks extends ProgressCallbacks {
  requireWorkspace(connection: Connection, workspaceId: string): Row;
}

export function updateContext(
  connection: Connection,
  args: ContextArguments,
  callbacks: ContextCallbacks,
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id");
  const context = userContextArgument(args, () => callbacks.readStdin());
  connection.exec("BEGIN IMMEDIATE");
  try {
    const scan = callbacks.requireScan(connection, scanId);
    if (scan.get("status") !== "running" || scan.get("canceled_at") !== null)
      throw new WorkbenchValidationError(
        "Only a running scan can update context.",
      );
    const workspace = callbacks.requireWorkspace(
      connection,
      scan.get("workspace_id") as string,
    );
    if (args.workspaceId !== null) {
      if (args.claimToken !== null)
        throw new WorkbenchValidationError(
          "claim-token is only valid with thread-id.",
        );
      if (requireUuid(args.workspaceId, "workspace-id") !== workspace.get("id"))
        throw new WorkbenchValidationError(
          "This scan does not belong to the selected workspace.",
        );
    } else {
      const threadId = optionalText(args.threadId, 512);
      const owningThreadId =
        scan.get("continuation_thread_id") || workspace.get("thread_id");
      if (threadId === null || threadId !== owningThreadId)
        throw new WorkbenchValidationError(
          "This scan does not belong to the current Codex thread.",
        );
      requireCurrentContinuation(scan, args.claimToken, {
        errorMessage: "Scan context updates are owned by another continuation.",
      });
    }
    const timestamp = callbacks.now();
    connection
      .prepare("UPDATE scans SET user_context = ?, updated_at = ? WHERE id = ?")
      .run([context, timestamp, scan.get("id")]);
    if (args.workspaceId !== null)
      connection
        .prepare(
          "UPDATE workspaces SET user_context = ?, updated_at = ? WHERE id = ?",
        )
        .run([context, timestamp, workspace.get("id")]);
    else
      connection
        .prepare("UPDATE workspaces SET updated_at = ? WHERE id = ?")
        .run([timestamp, workspace.get("id")]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return callbacks.scanContext(connection, scanId);
}

export function update(
  connection: Connection,
  args: ContextArguments & ProgressArguments & { command: string },
  callbacks: ContextCallbacks,
): Record<string, unknown> {
  return args.command === "update-scan-context"
    ? updateContext(connection, args, callbacks)
    : updateProgress(connection, args, callbacks);
}

function phaseIndex(phase: string): number {
  const index = PHASES.indexOf(phase as (typeof PHASES)[number]);
  if (index < 0) throw new Error("tuple.index(x): x not in tuple");
  return index;
}

export function updateProgress(
  connection: Connection,
  args: ProgressArguments,
  callbacks: ProgressCallbacks,
): Record<string, unknown> {
  const scanId = requireUuid(args.scanId, "scan-id");
  const model = optionalText(args.model, 200);
  const reasoningEffort = optionalText(args.reasoningEffort, 32);
  const preflightIssues = args.preflightIssuesJsonStdin
    ? callbacks.readStdin()
    : args.preflightIssuesJson;
  const serializedPreflightIssues = preflightIssuesJson(preflightIssues);
  connection.exec("BEGIN IMMEDIATE");
  let scan: Row;
  try {
    const timestamp = callbacks.now();
    scan = callbacks.requireScan(connection, scanId);
    if (scan.get("status") !== "running")
      throw new WorkbenchValidationError(
        "Only a running scan can update progress.",
      );
    if (scan.get("mode") === "deep") {
      const coordinator = connection
        .prepare("SELECT * FROM deep_scan_runs WHERE scan_id = ?")
        .get([scanId]);
      if (
        coordinator !== undefined &&
        (coordinator.get("status") === "running" ||
          args.coordinatorGeneration !== null)
      )
        requireCurrentCoordinator(coordinator, args);
    } else if (args.coordinatorGeneration !== null)
      throw new WorkbenchValidationError(
        "Coordinator leases apply only to Deep Scan progress.",
      );
    requireCurrentContinuation(scan, args.claimToken, {
      errorMessage: "Scan updates are owned by another continuation.",
    });
    if (args.deepReviewPass !== null && scan.get("mode") !== "deep")
      throw new WorkbenchValidationError(
        "Only Deep Scan can record a deep review pass.",
      );
    if (serializedPreflightIssues !== null) {
      if (scan.get("mode") === "deep")
        throw new WorkbenchValidationError(
          "Deep Scan preflight progress is owned by its coordinator.",
        );
      if (
        scan.get("phase") !== "preflight" ||
        ![null, "preflight"].includes(args.phase)
      )
        throw new WorkbenchValidationError(
          "Preflight issues can only be updated during preflight.",
        );
    }
    const progress = connection
      .prepare("SELECT * FROM scan_progress WHERE scan_id = ?")
      .get([scan.get("id")]);
    const progressValue = (column: string) => {
      if (progress === undefined)
        throw new TypeError("'NoneType' object is not subscriptable");
      return progress.get(column);
    };
    const currentPhase = scan.get("phase") as string;
    if (
      args.phase !== null &&
      phaseIndex(args.phase) < phaseIndex(currentPhase)
    )
      throw new WorkbenchValidationError(
        "Scan progress cannot move to an earlier phase.",
      );
    const nextPhase = args.phase || currentPhase;
    const phaseChanged = nextPhase !== currentPhase;
    let phaseTotal = phaseChanged
      ? 0n
      : (progressValue("phase_items_total") as bigint);
    let phaseCompleted = phaseChanged
      ? 0n
      : (progressValue("phase_items_completed") as bigint);
    let phaseUnit = phaseChanged
      ? null
      : (progressValue("phase_progress_unit") as string | null);
    if (args.phaseItemsTotal !== null) phaseTotal = args.phaseItemsTotal;
    if (args.phaseItemsCompleted !== null)
      phaseCompleted = args.phaseItemsCompleted;
    if (args.phaseProgressUnit !== null) phaseUnit = args.phaseProgressUnit;
    if (phaseCompleted > phaseTotal)
      throw new WorkbenchValidationError(
        "Completed phase items cannot exceed total phase items.",
      );
    if (phaseTotal > 0n && phaseUnit === null)
      throw new WorkbenchValidationError(
        "Phase progress with a nonzero total requires a progress unit.",
      );
    if (!phaseChanged) {
      if (
        args.phaseItemsTotal !== null &&
        args.phaseItemsTotal < (progressValue("phase_items_total") as bigint)
      )
        throw new WorkbenchValidationError(
          "Phase item total cannot decrease within a phase.",
        );
      if (
        args.phaseItemsCompleted !== null &&
        args.phaseItemsCompleted <
          (progressValue("phase_items_completed") as bigint)
      )
        throw new WorkbenchValidationError(
          "Completed phase items cannot decrease within a phase.",
        );
      if (
        args.phaseProgressUnit !== null &&
        progressValue("phase_progress_unit") !== null &&
        args.phaseProgressUnit !== progressValue("phase_progress_unit")
      )
        throw new WorkbenchValidationError(
          "Phase progress unit cannot change within a phase.",
        );
    }
    const updates: string[] = [],
      values: Parameter[] = [];
    if (nextPhase === "preflight" && scan.get("mode") !== "deep") {
      updates.push(
        "preflight_checks_total = ?",
        "preflight_checks_completed = ?",
      );
      values.push(phaseTotal, phaseCompleted);
    }
    for (const [column, value] of [
      ["preflight_issues_json", serializedPreflightIssues],
      ["review_items_total", args.reviewItemsTotal],
      ["review_items_completed", args.reviewItemsCompleted],
      [
        "reportable_findings_count",
        reportableCount(currentPhase, args.phase, args.reportableFindingsCount),
      ],
      ["deep_review_pass", args.deepReviewPass],
    ] as const) {
      if (value !== null) {
        updates.push(`${column} = ?`);
        values.push(value);
      }
    }
    const currentPass =
      (progressValue("deep_review_pass") as bigint | null) || 0n;
    const requestedPass = args.deepReviewPass || currentPass;
    if (requestedPass < currentPass)
      throw new WorkbenchValidationError(
        "Deep Scan progress cannot move to an earlier review pass.",
      );
    const advancingPass = requestedPass > currentPass;
    if (advancingPass && args.reviewItemsCompleted !== 0n)
      throw new WorkbenchValidationError(
        "A new Deep Scan review pass must start with zero completed items.",
      );
    if (!advancingPass) {
      if (
        args.reviewItemsTotal !== null &&
        args.reviewItemsTotal < (progressValue("review_items_total") as bigint)
      )
        throw new WorkbenchValidationError(
          "Review item total cannot decrease within a review pass.",
        );
      if (
        args.reviewItemsCompleted !== null &&
        args.reviewItemsCompleted <
          (progressValue("review_items_completed") as bigint)
      )
        throw new WorkbenchValidationError(
          "Completed review items cannot decrease within a review pass.",
        );
    }
    const total =
      args.reviewItemsTotal ?? (progressValue("review_items_total") as bigint);
    const completed =
      args.reviewItemsCompleted ??
      (progressValue("review_items_completed") as bigint);
    if (completed > total)
      throw new WorkbenchValidationError(
        "Completed review items cannot exceed total review items.",
      );
    const updated = connection
      .prepare(
        `
      UPDATE scans
      SET phase = COALESCE(?, phase), model = COALESCE(?, model),
          reasoning_effort = COALESCE(?, reasoning_effort), updated_at = ?
      WHERE id = ? AND status = 'running'
    `,
      )
      .run([args.phase, model, reasoningEffort, timestamp, scan.get("id")]);
    if (updated.rowcount !== 1n)
      throw new WorkbenchValidationError(
        "Only a running scan can update progress.",
      );
    if (updates.length)
      connection
        .prepare(
          `UPDATE scan_progress SET ${updates.join(", ")}, updated_at = ? WHERE scan_id = ?`,
        )
        .run([...values, timestamp, scan.get("id")]);
    else
      connection
        .prepare("UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?")
        .run([timestamp, scan.get("id")]);
    connection
      .prepare(
        `
      UPDATE scan_progress
      SET phase_items_total = ?, phase_items_completed = ?,
          phase_progress_unit = ?, updated_at = ?
      WHERE scan_id = ?
    `,
      )
      .run([phaseTotal, phaseCompleted, phaseUnit, timestamp, scan.get("id")]);
    connection.commit();
  } catch (error) {
    connection.rollback();
    throw error;
  }
  return callbacks.scanContext(connection, scan.get("id") as string);
}
