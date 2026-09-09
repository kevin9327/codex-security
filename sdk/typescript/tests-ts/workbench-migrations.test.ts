import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { MIGRATIONS } from "../../../plugins/codex-security/mcp-app/src/workbench-migrations";
import { PLUGIN_ROOT } from "./plugin-root.js";

describe("workbench migration records", () => {
  test("preserves the first 41 historical versions, names, and SQL bytes", () => {
    // New migrations append after this historical prefix.
    const digest = createHash("sha256")
      .update(JSON.stringify(MIGRATIONS.slice(0, 41)))
      .digest("hex");
    expect(digest).toBe(
      "2a8769ab80db82109d111ccc38c3a750112ceee6d96fdc09b47ead69f87c91e2",
    );
  });

  test("ships the same canonical data used by the Python schema module", () => {
    expect(
      readFileSync(join(PLUGIN_ROOT, "data", "workbench-migrations.json")),
    ).toEqual(
      readFileSync(
        new URL(
          "../../../plugins/codex-security/data/workbench-migrations.json",
          import.meta.url,
        ),
      ),
    );
  });

  test("reconstructs executable SQL through the typed records", () => {
    const db = new Database(":memory:");
    try {
      for (const [, , sql] of MIGRATIONS) db.exec(sql);
      const columns = db
        .query<{ name: string }, []>(
          "PRAGMA table_info(finding_workflow_reviews)",
        )
        .all()
        .map(({ name }) => name);
      expect(columns).toContain("review_contract_version");
      expect(columns).toContain("contract_digest");
      expect(
        db
          .query("SELECT name FROM sqlite_master WHERE name='security_targets'")
          .get(),
      ).toEqual({ name: "security_targets" });
    } finally {
      db.close();
    }
  });
});
