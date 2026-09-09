import { clearImmediate, setImmediate } from "node:timers";
import { describe, expect, test } from "bun:test";
import { unifiedPolicyDiff } from "../src/security-policy-diff.js";

// Expected output captured from the former difflib.unified_diff implementation.
const cases = [
  {
    name: "empty inputs",
    before: "",
    after: "",
    expected: "",
  },
  {
    name: "creation",
    before: "",
    after: "# Policy\n",
    expected:
      "--- a/SECURITY.md\n+++ b/SECURITY.md\n@@ -0,0 +1 @@\n+# Policy\n",
  },
  {
    name: "deletion",
    before: "# Policy\n",
    after: "",
    expected:
      "--- a/SECURITY.md\n+++ b/SECURITY.md\n@@ -1 +0,0 @@\n-# Policy\n",
  },
  {
    name: "longest match tie breaking",
    before: "a\nb\n",
    after: "a\nc\na\nb\n",
    expected:
      "--- a/SECURITY.md\n+++ b/SECURITY.md\n@@ -1,2 +1,4 @@\n+a\n+c\n a\n b\n",
  },
  {
    name: "separate hunks",
    before:
      "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n21\n22\n23\n24\n",
    after:
      "1\n2 updated\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20 updated\n21\n22\n23\n24\n",
    expected:
      "--- a/SECURITY.md\n+++ b/SECURITY.md\n@@ -1,5 +1,5 @@\n 1\n-2\n+2 updated\n 3\n 4\n 5\n@@ -17,7 +17,7 @@\n 17\n 18\n 19\n-20\n+20 updated\n 21\n 22\n 23\n",
  },
];

describe("policy unified diffs", () => {
  for (const { name, before, after, expected } of cases) {
    test(name, async () => {
      expect(
        await unifiedPolicyDiff(
          before,
          after,
          "a/SECURITY.md",
          "b/SECURITY.md",
        ),
      ).toBe(expected);
    });
  }
  test("preserves popular-line matching for long repetitive policies", async () => {
    const before = "old\n" + "repeat\n".repeat(210);
    const after = "new\n" + "repeat\n".repeat(210);
    expect(
      await unifiedPolicyDiff(before, after, "a/SECURITY.md", "b/SECURITY.md"),
    ).toBe(
      "--- a/SECURITY.md\n+++ b/SECURITY.md\n@@ -1,211 +1,211 @@\n-old\n" +
        "-repeat\n".repeat(210) +
        "+new\n" +
        "+repeat\n".repeat(210),
    );
  });
  test("honors cancellation before and during matching", async () => {
    const cancelled = AbortSignal.abort(new Error("cancelled preview"));
    await expect(
      unifiedPolicyDiff("a", "b", "a", "b", cancelled),
    ).rejects.toThrow("cancelled preview");
    const controller = new AbortController();
    const before = Array.from(
      { length: 40_000 },
      (_, index) => `${index}\n`,
    ).join("");
    const abort = setImmediate(() => controller.abort());
    try {
      await expect(
        unifiedPolicyDiff(
          before,
          `new\n${before}`,
          "a",
          "b",
          controller.signal,
        ),
      ).rejects.toMatchObject({ name: "AbortError" });
    } finally {
      clearImmediate(abort);
    }
  });
});
