import { describe, expect, it } from "vitest";
import { computeFingerprint, deduplicateFindings } from "../../lib/dedup";
import type { RawFinding } from "../../lib/types";

function raw(overrides: Partial<RawFinding>): RawFinding {
  return {
    ruleId: "MISSING_CSP",
    title: "Content-Security-Policy header missing",
    severity: "MEDIUM",
    confidence: "CONFIRMED",
    exposure: "CONFIG_WEAKNESS",
    affectedUrl: "https://example.com/",
    description: "desc",
    remediation: "add CSP",
    source: "Custom Header Scanner",
    ...overrides,
  };
}

describe("deduplicateFindings", () => {
  it("merges the same issue found by two scanners into a single finding", () => {
    const findings = [
      raw({ source: "Custom Header Scanner" }),
      raw({ source: "OWASP ZAP" }),
    ];
    const result = deduplicateFindings(findings);
    expect(result).toHaveLength(1);
    expect(result[0]!.sources.sort()).toEqual(["Custom Header Scanner", "OWASP ZAP"].sort());
    expect(result[0]!.occurrences).toBe(2);
  });

  it("does not merge different rules on the same URL", () => {
    const findings = [
      raw({ ruleId: "MISSING_CSP" }),
      raw({ ruleId: "MISSING_HSTS" }),
    ];
    expect(deduplicateFindings(findings)).toHaveLength(2);
  });

  it("does not merge the same rule on different URL paths", () => {
    const findings = [
      raw({ affectedUrl: "https://example.com/a" }),
      raw({ affectedUrl: "https://example.com/b" }),
    ];
    expect(deduplicateFindings(findings)).toHaveLength(2);
  });

  it("merges the same rule+path regardless of query string", () => {
    const findings = [
      raw({ affectedUrl: "https://example.com/page?x=1" }),
      raw({ affectedUrl: "https://example.com/page?x=2" }),
    ];
    expect(deduplicateFindings(findings)).toHaveLength(1);
  });

  it("fingerprint is stable for identical input", () => {
    const f = raw({});
    expect(computeFingerprint(f)).toBe(computeFingerprint(f));
  });

  it("detailKey distinguishes findings sharing a ruleId and URL (e.g. different headers)", () => {
    const findings = [
      raw({ ruleId: "WEAK_HEADER", detailKey: "X-Frame-Options" }),
      raw({ ruleId: "WEAK_HEADER", detailKey: "X-Content-Type-Options" }),
    ];
    expect(deduplicateFindings(findings)).toHaveLength(2);
  });
});
