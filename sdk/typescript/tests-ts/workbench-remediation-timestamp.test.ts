import { describe, expect, test } from "bun:test";
import { Row } from "../../../plugins/codex-security/native/sqlite.mjs";
import { remediationClaimIsActive } from "../../../plugins/codex-security/mcp-app/src/workbench-remediation";

interface RemediationClaim {
  token: string | null;
  claimedAt?: string;
  deliveredAt?: string;
}
function isClaimActive(claim: RemediationClaim): boolean {
  return remediationClaimIsActive(
    new Row(
      [
        "pending_action_claim_token",
        "pending_action_delivered_at",
        "pending_action_claimed_at",
      ],
      [claim.token, claim.deliveredAt ?? null, claim.claimedAt ?? null],
    ),
    () => BigInt(Date.parse("2026-08-15T12:00:00Z")) * 1000n,
  );
}

describe("workbench remediation timestamp compatibility", () => {
  test.each([
    [
      "expires at the claim deadline",
      { claimedAt: "2026-08-15T11:58:00Z" },
      false,
    ],
    ["accepts lowercase UTC", { claimedAt: "2026-08-15T11:58:00z" }, false],
    [
      "preserves explicit offsets",
      { claimedAt: "2026-08-15T13:58:00+02:00" },
      false,
    ],
    ["keeps a fresh claim", { claimedAt: "2026-08-15T11:58:01Z" }, true],
    [
      "expires at the delivery deadline",
      {
        claimedAt: "2026-08-15T11:30:00Z",
        deliveredAt: "2026-08-15T11:45:00Z",
      },
      false,
    ],
    [
      "keeps a fresh delivery after an older claim",
      {
        claimedAt: "2026-08-15T11:30:00Z",
        deliveredAt: "2026-08-15T11:45:01Z",
      },
      true,
    ],
    ["has no claim without a token", { token: null }, false],
    ["preserves an invalid timestamp", { claimedAt: "not-a-timestamp" }, true],
    ["preserves a naive timestamp", { claimedAt: "2026-08-15T11:00:00" }, true],
  ] as const)("%s", (_label, fields, active) => {
    expect(isClaimActive({ token: "claim", ...fields })).toBe(active);
  });
});
