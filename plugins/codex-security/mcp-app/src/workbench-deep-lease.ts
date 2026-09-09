import type { Row } from "../../native/sqlite.mjs";
import { WorkbenchValidationError } from "./workbench-validation";

export function requireCurrentCoordinator(
  run: Row,
  args: { coordinatorGeneration?: bigint | null },
): void {
  const generation = args.coordinatorGeneration ?? null;
  if (run.get("coordinator_generation") === 1n) {
    if (generation !== null)
      throw new WorkbenchValidationError(
        "Deep Scan coordinator lease has not been claimed.",
      );
    return;
  }
  if (generation === null)
    throw new WorkbenchValidationError(
      "Deep Scan mutation requires the current coordinator lease.",
    );
  if (generation !== run.get("coordinator_generation"))
    throw new WorkbenchValidationError(
      "Deep Scan coordinator lease belongs to a newer generation.",
    );
}
