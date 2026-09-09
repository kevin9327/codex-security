import { describe, expect, test } from "bun:test";
import { boundedFindingDetails } from "../../../plugins/codex-security/mcp-app/src/helpers/finding-preview";
import {
  contractJsonBytes,
  requireSafeJsonValue,
} from "../../../plugins/codex-security/mcp-app/src/helpers/scan-contract-json";
import { validateAgainstSchema } from "../../../plugins/codex-security/mcp-app/src/helpers/contract-schema";
import {
  parseJson,
  stringifyJson,
} from "../../../plugins/codex-security/mcp-app/src/helpers/python-json";

describe("bundled scan report limits", () => {
  test("accepts large reports, schemas, and deeply nested JSON", () => {
    const document = contractJsonBytes("scan-manifest.json", {
      metadata: "x".repeat(16 * 1024 * 1024),
    });
    let nested: unknown = 0n;
    for (let index = 0; index < 258; index++) nested = [nested];
    requireSafeJsonValue(nested, "nested");
    validateAgainstSchema(
      { safe: true },
      {
        type: "object",
        description: "x".repeat(4 * 1024 * 1024),
        allOf: Array.from({ length: 129 }, () => ({ type: "object" })),
      },
      "large.schema.json",
    );
    expect(document.length).toBeGreaterThan(16 * 1024 * 1024);
  });

  test("preserves bounded remediation tests and preventive controls", () => {
    const diagnostics = {
      rootCause: { summary: "Missing authorization check." },
      validation: {
        summary: "An untrusted request reaches the protected resource.",
      },
      attackPath: {
        narrative: "The request bypasses the authorization boundary.",
      },
      codeEvidence: [
        {
          id: "evidence",
          label: "Missing check",
          path: "example.py",
          startLine: 1,
          code: "return resource",
          explanation: "No authorization check runs.",
        },
      ],
      evidence: "The protected resource was exposed.",
      evidenceExcerpt: "return resource",
    };
    const inputs = {
      details: {
        remediationTests: Array.from(
          { length: 40 },
          (_, index) => `test-${index}`,
        ),
        preventiveControls: Array.from(
          { length: 40 },
          (_, index) => `control-${index}`,
        ),
      },
      large: {
        ...diagnostics,
        preventiveControls: Array.from({ length: 20 }, () => "x".repeat(900)),
        remediationTests: ["Verify authorization."],
        writeup: { reportPath: "findings/example/example.md" },
        provenance: { source: "scan" },
        severity: { level: "high", rationale: "Verified impact" },
        status: "open",
        taxonomy: { category: "injection", cwe: ["CWE-79"] },
      },
      rich: {
        rootCause: { summary: "r".repeat(2000) },
        validation: { summary: "v".repeat(3000) },
        attackPath: { narrative: "a".repeat(4000) },
        codeEvidence: Array.from({ length: 4 }, (_, index) => ({
          id: `evidence-${index}`,
          label: "example",
          path: "example.py",
          startLine: 1,
          code: "c".repeat(1500),
          explanation: "e".repeat(1500),
        })),
        evidenceExcerpt: "e".repeat(8000),
        identity: { anchor: "finding" },
        preventiveControls: ["Centralize authorization."],
        remediationTests: ["Verify authorization."],
      },
      boundary: {
        ...diagnostics,
        remediationTests: Array<string>(4000).fill("x"),
        preventiveControls: ["Keep authorization centralized."],
      },
      unicodeBoundary: {
        ...diagnostics,
        remediationTests: Array<string>(2000).fill("😀"),
        preventiveControls: Array<string>(2000).fill("🛡"),
      },
      emptyControls: {
        ...diagnostics,
        remediationTests: Array<string>(4000).fill("x"),
        preventiveControls: [],
      },
      emptyTests: {
        ...diagnostics,
        remediationTests: [],
        preventiveControls: Array<string>(4000).fill("control"),
      },
      oversizedMetadata: {
        ...diagnostics,
        confidence: { level: "high", rationale: "x".repeat(17000) },
        remediationTests: ["Verify authorization."],
        preventiveControls: ["Centralize authorization."],
      },
      oversizedGuidance: {
        rootCause: { summary: "root" },
        validation: { summary: "validation" },
        attackPath: { narrative: "attack" },
        codeEvidence: [
          {
            id: "evidence",
            label: "evidence",
            path: "example.py",
            startLine: 1,
            code: "x",
            explanation: "evidence",
          },
        ],
        evidence: "legacy",
        evidenceExcerpt: "excerpt",
        remediationTests: ["x".repeat(7800)],
        preventiveControls: ["y".repeat(7930)],
      },
      nestedBoundary: {
        remediationTests: Array<string>(3937).fill("x"),
        rootCause: { summary: "r".repeat(178), detail: { x: { y: "z" } } },
      },
    };
    const bounded = Object.fromEntries(
      Object.entries(inputs).map(([key, value]) => [
        key,
        boundedFindingDetails(parseJson(JSON.stringify(value))),
      ]),
    );
    const { projections, bytes } = JSON.parse(
      stringifyJson({
        projections: bounded,
        bytes: Object.fromEntries(
          Object.entries(bounded).map(([key, value]) => [
            key,
            Buffer.byteLength(
              stringifyJson(value, { compact: true, separators: [",", ":"] }),
            ),
          ]),
        ),
      }),
    ) as {
      projections: {
        details: Record<string, unknown>;
        large: Record<string, unknown>;
        rich: Record<string, unknown>;
        boundary: { remediationTests: string[]; preventiveControls: string[] };
        unicodeBoundary: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        emptyControls: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        emptyTests: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        oversizedMetadata: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        oversizedGuidance: {
          remediationTests: string[];
          preventiveControls: string[];
        };
        nestedBoundary: {
          remediationTests: string[];
          rootCause: { summary: string };
        };
      };
      bytes: Record<string, number>;
    };
    expect(projections.details).toEqual({
      preventiveControls: Array.from(
        { length: 40 },
        (_, index) => `control-${index}`,
      ),
      remediationTests: Array.from(
        { length: 40 },
        (_, index) => `test-${index}`,
      ),
    });
    expect(projections.large).toMatchObject({
      writeup: { reportPath: "findings/example/example.md" },
      provenance: { source: "scan" },
      remediationTests: ["Verify authorization."],
      severity: { level: "high", rationale: "Verified impact" },
      status: "open",
      taxonomy: { category: "injection", cwe: ["CWE-79"] },
    });
    expect(projections.rich).toMatchObject({
      identity: { anchor: "finding" },
      preventiveControls: ["Centralize authorization."],
      remediationTests: ["Verify authorization."],
    });
    for (const finding of [
      projections.large,
      projections.rich,
      projections.boundary,
      projections.unicodeBoundary,
      projections.emptyControls,
      projections.emptyTests,
      projections.oversizedMetadata,
      projections.oversizedGuidance,
    ]) {
      expect(finding).toMatchObject({
        rootCause: { summary: expect.any(String) },
        validation: { summary: expect.any(String) },
        attackPath: { narrative: expect.any(String) },
        codeEvidence: expect.arrayContaining([
          expect.objectContaining({
            id: expect.any(String),
            path: "example.py",
          }),
        ]),
      });
    }
    for (const finding of [
      projections.large,
      projections.boundary,
      projections.unicodeBoundary,
      projections.emptyControls,
      projections.emptyTests,
    ]) {
      expect(finding).toMatchObject({
        evidence: "The protected resource was exposed.",
        evidenceExcerpt: "return resource",
      });
    }
    expect(projections.rich).toHaveProperty("evidenceExcerpt");
    expect(projections.oversizedGuidance).toMatchObject({
      evidence: "legacy",
      evidenceExcerpt: "excerpt",
    });
    expect(
      projections.boundary.remediationTests.every((value) => value !== ""),
    ).toBe(true);
    expect(projections.boundary.preventiveControls).toEqual([
      "Keep authorization centralized.",
    ]);
    expect(projections.unicodeBoundary.remediationTests.length).toBeGreaterThan(
      0,
    );
    expect(
      projections.unicodeBoundary.preventiveControls.every(
        (value) => value === "🛡",
      ),
    ).toBe(true);
    expect(
      projections.unicodeBoundary.preventiveControls.length,
    ).toBeGreaterThan(0);
    expect(projections.emptyControls.preventiveControls).toEqual([]);
    expect(projections.emptyControls.remediationTests.length).toBeGreaterThan(
      20,
    );
    expect(projections.emptyTests.remediationTests).toEqual([]);
    expect(projections.emptyTests.preventiveControls.length).toBeGreaterThan(
      20,
    );
    expect(projections.nestedBoundary.rootCause.summary).toContain("r");
    expect(Object.values(bytes).every((value) => value <= 16_000)).toBe(true);
  });
});
