import { describe, expect, it } from "vitest";
import { calculateSecurityScore } from "../../lib/scoring";
import type { DedupedFinding } from "../../lib/types";

function finding(overrides: Partial<DedupedFinding>): DedupedFinding {
  return {
    ruleId: "RULE",
    title: "Test finding",
    severity: "HIGH",
    confidence: "CONFIRMED",
    exposure: "DIRECT_PROVEN",
    affectedUrl: "https://example.com/",
    description: "desc",
    remediation: "fix it",
    source: "Custom Header Scanner",
    fingerprint: "fp-1",
    sources: ["Custom Header Scanner"],
    occurrences: 1,
    ...overrides,
  };
}

describe("calculateSecurityScore — fixed fixtures from spec", () => {
  it("no findings → 100", () => {
    expect(calculateSecurityScore([]).displayedScore).toBe(100);
  });

  it("one confirmed High with full exposure → 85", () => {
    const result = calculateSecurityScore([finding({ fingerprint: "h1" })]);
    expect(result.displayedScore).toBe(85);
    expect(result.exactScore).toBe(85);
  });

  it("one confirmed Medium with full exposure → 93", () => {
    const result = calculateSecurityScore([
      finding({ fingerprint: "m1", severity: "MEDIUM" }),
    ]);
    expect(result.displayedScore).toBe(93);
  });

  it("one confirmed Low with full exposure → 98", () => {
    const result = calculateSecurityScore([finding({ fingerprint: "l1", severity: "LOW" })]);
    expect(result.displayedScore).toBe(98);
  });

  it("one informational finding → 100", () => {
    const result = calculateSecurityScore([
      finding({ fingerprint: "i1", severity: "INFORMATIONAL", confidence: "LOW", exposure: "INFORMATIONAL_ONLY" }),
    ]);
    expect(result.displayedScore).toBe(100);
  });
});

describe("calculateSecurityScore — invariants", () => {
  it("is order-independent (commutative penalty sum)", () => {
    const a = finding({ fingerprint: "a", severity: "HIGH" });
    const b = finding({ fingerprint: "b", severity: "MEDIUM" });
    const c = finding({ fingerprint: "c", severity: "LOW" });
    const r1 = calculateSecurityScore([a, b, c]);
    const r2 = calculateSecurityScore([c, a, b]);
    expect(r1.exactScore).toBe(r2.exactScore);
    expect(r1.displayedScore).toBe(r2.displayedScore);
  });

  it("gives the same score for the same findings every time (deterministic)", () => {
    const findings = [finding({ fingerprint: "x", severity: "CRITICAL" })];
    const r1 = calculateSecurityScore(findings);
    const r2 = calculateSecurityScore(findings);
    expect(r1).toEqual(r2);
  });

  it("informational findings never deduct points regardless of confidence/exposure", () => {
    const result = calculateSecurityScore([
      finding({
        fingerprint: "i",
        severity: "INFORMATIONAL",
        confidence: "CONFIRMED",
        exposure: "DIRECT_PROVEN",
      }),
    ]);
    expect(result.totalPenalty).toBe(0);
    expect(result.displayedScore).toBe(100);
  });

  it("critical findings deduct more than high findings, all else equal", () => {
    const critical = calculateSecurityScore([finding({ fingerprint: "c", severity: "CRITICAL" })]);
    const high = calculateSecurityScore([finding({ fingerprint: "h", severity: "HIGH" })]);
    expect(critical.totalPenalty).toBeGreaterThan(high.totalPenalty);
  });

  it("low-confidence findings deduct less than confirmed findings, all else equal", () => {
    const confirmed = calculateSecurityScore([finding({ fingerprint: "a", confidence: "CONFIRMED" })]);
    const low = calculateSecurityScore([finding({ fingerprint: "b", confidence: "LOW" })]);
    expect(low.totalPenalty).toBeLessThan(confirmed.totalPenalty);
  });

  it("never drops below 0 even with many critical findings", () => {
    const many = Array.from({ length: 20 }, (_, i) =>
      finding({ fingerprint: `crit-${i}`, severity: "CRITICAL" }),
    );
    const result = calculateSecurityScore(many);
    expect(result.exactScore).toBeGreaterThanOrEqual(0);
    expect(result.displayedScore).toBeGreaterThanOrEqual(0);
  });

  it("never exceeds 100", () => {
    const result = calculateSecurityScore([]);
    expect(result.exactScore).toBeLessThanOrEqual(100);
  });

  it("caps the repeated-issue penalty instead of multiplying it linearly", () => {
    const singleOccurrence = calculateSecurityScore([
      finding({ fingerprint: "rep", severity: "MEDIUM", occurrences: 1 }),
    ]);
    const widespread = calculateSecurityScore([
      finding({ fingerprint: "rep", severity: "MEDIUM", occurrences: 20 }),
    ]);
    // 20x the naive penalty would be 140 points; the capped repetition
    // multiplier (max 1.25x) must keep it far below that.
    expect(widespread.totalPenalty).toBeLessThan(singleOccurrence.totalPenalty * 1.26);
    expect(widespread.totalPenalty).toBeGreaterThan(singleOccurrence.totalPenalty);
  });
});
