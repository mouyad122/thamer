import { describe, expect, it } from "vitest";
import { buildReportHtml, type ReportScanData } from "../../lib/report";
import { calculateSecurityScore, computePenalty } from "../../lib/scoring";
import type { ScoredFinding, ZapExecutionResult } from "../../lib/types";

const NOT_TESTED_ZAP: ZapExecutionResult = {
  status: "NOT_TESTED",
  reasonCode: "ZAP_WORKER_NOT_CONFIGURED",
  reasonMessage: "SCANNER_WORKER_URL and/or SCANNER_WORKER_SECRET are not configured.",
  startedAt: null,
  completedAt: null,
  durationMs: null,
};

const COMPLETED_ZAP: ZapExecutionResult = {
  status: "COMPLETED",
  reasonCode: null,
  reasonMessage: "OWASP ZAP Baseline (passive) scan completed successfully.",
  startedAt: "2026-01-01T10:00:00.000Z",
  completedAt: "2026-01-01T10:00:20.000Z",
  durationMs: 20000,
};

function scan(overrides: Partial<ReportScanData> = {}): ReportScanData {
  return {
    id: "scan-123",
    targetUrl: "https://example.com",
    status: "PARTIAL",
    startedAt: new Date("2026-01-01T10:00:00Z"),
    completedAt: new Date("2026-01-01T10:00:30Z"),
    durationMs: 30000,
    errorMessage: null,
    completedChecks: ["URL_VALIDATION", "SECURITY_HEADERS"],
    failedChecks: [],
    skippedChecks: ["ZAP_BASELINE"],
    zapExecution: NOT_TESTED_ZAP,
    ...overrides,
  };
}

function finding(overrides: Partial<ScoredFinding> = {}): ScoredFinding {
  return {
    id: "f1",
    ruleId: "CSP_MISSING",
    title: "Content-Security-Policy header is missing",
    severity: "MEDIUM",
    confidence: "CONFIRMED",
    exposure: "BEST_PRACTICE",
    affectedUrl: "https://example.com/",
    description: "desc",
    remediation: "add CSP",
    source: "Custom Header Scanner",
    fingerprint: "fp1",
    sources: ["Custom Header Scanner"],
    occurrences: 1,
    penalty: 2.1,
    severityPoints: 7,
    confidenceMultiplier: 1,
    exposureMultiplier: 0.3,
    ...overrides,
  };
}

describe("buildReportHtml — real data only, no fabrication", () => {
  it("includes the actual target URL, score, and rating from the scan's own data", () => {
    const findings = [finding()];
    const score = calculateSecurityScore(findings);
    const html = buildReportHtml(scan(), findings, score);
    expect(html).toContain("https://example.com");
    expect(html).toContain(`${score.displayedScore}%`);
    expect(html).toContain(score.rating);
  });

  it("lists every finding that was passed in, and no others", () => {
    const findings = [finding({ id: "a", title: "Finding A" }), finding({ id: "b", title: "Finding B", fingerprint: "fp2" })];
    const score = calculateSecurityScore(findings);
    const html = buildReportHtml(scan(), findings, score);
    expect(html).toContain("Finding A");
    expect(html).toContain("Finding B");
    expect(html).toContain("Detailed Findings (2)");
  });

  it("shows a clear 'no findings' message rather than fabricating one", () => {
    const score = calculateSecurityScore([]);
    const html = buildReportHtml(scan(), [], score);
    expect(html).toContain("No findings were recorded");
    expect(html).toContain("100%");
  });

  it("marks skipped checks as Not Tested, never as passed/completed", () => {
    const html = buildReportHtml(scan(), [], calculateSecurityScore([]));
    expect(html).toContain("Not Tested");
  });

  it("shows the real error message for a FAILED scan instead of a score", () => {
    const failedScan = scan({ status: "FAILED", errorMessage: "DNS resolution failed", completedChecks: [] });
    const html = buildReportHtml(failedScan, [], calculateSecurityScore([]));
    expect(html).toContain("DNS resolution failed");
  });

  it("redacts sensitive-looking evidence text before embedding it", () => {
    const withSecret = finding({
      evidence: 'Authorization: Bearer abcdef123456\nSet-Cookie: sessionid=verysecretvalue; Path=/',
    });
    const html = buildReportHtml(scan(), [withSecret], calculateSecurityScore([withSecret]));
    expect(html).not.toContain("abcdef123456");
    expect(html).not.toContain("verysecretvalue");
    expect(html).toContain("[REDACTED]");
  });

  it("includes the disclaimer and limitations section", () => {
    const html = buildReportHtml(scan(), [], calculateSecurityScore([]));
    expect(html).toContain("Disclaimer");
    expect(html).toContain("Limitations of This Scan");
  });
});

describe("buildReportHtml — Partial Scan / Provisional Score (mandated)", () => {
  it("labels the score as Provisional and shows the partial-scan banner when status is PARTIAL", () => {
    const html = buildReportHtml(scan({ status: "PARTIAL" }), [], calculateSecurityScore([]));
    expect(html).toContain("Provisional Automated Security Score");
    expect(html).toContain("This was a partial scan. The score only reflects checks that completed successfully.");
    expect(html).toContain("Based only on completed checks.");
  });

  it("explicitly states ZAP Passive Scan was not executed when it wasn't", () => {
    const html = buildReportHtml(scan({ status: "PARTIAL", zapExecution: NOT_TESTED_ZAP }), [], calculateSecurityScore([]));
    expect(html).toContain("OWASP ZAP Passive Scan was not executed.");
  });

  it("does NOT show the provisional banner for a fully COMPLETED scan", () => {
    const html = buildReportHtml(
      scan({ status: "COMPLETED", skippedChecks: [], zapExecution: COMPLETED_ZAP }),
      [],
      calculateSecurityScore([]),
    );
    expect(html).not.toContain("Provisional Automated Security Score");
    expect(html).not.toContain("This was a partial scan");
  });

  it("shows the real ZAP failure reason code and message, not just 'Not Tested'", () => {
    const html = buildReportHtml(
      scan({
        zapExecution: {
          status: "TIMED_OUT",
          reasonCode: "ZAP_TIMEOUT",
          reasonMessage: "The scanner worker did not respond within 120000ms and the request was aborted.",
          startedAt: "2026-01-01T10:00:00.000Z",
          completedAt: "2026-01-01T10:02:00.000Z",
          durationMs: 120000,
        },
      }),
      [],
      calculateSecurityScore([]),
    );
    expect(html).toContain("ZAP_TIMEOUT");
    expect(html).toContain("did not respond within 120000ms");
  });

  it("Scan Coverage is computed from completed checks, not from finding count, and is shown separately from the score", () => {
    const manyFindings = [finding({ id: "a" }), finding({ id: "b", fingerprint: "fp2" }), finding({ id: "c", fingerprint: "fp3" })];
    const score = calculateSecurityScore(manyFindings);
    const html = buildReportHtml(
      scan({ completedChecks: ["URL_VALIDATION", "SECURITY_HEADERS", "HTTPS_CHECK"], failedChecks: [], skippedChecks: ["ZAP_BASELINE"] }),
      manyFindings,
      score,
    );
    // 3 completed out of 10 configured checks = 30% coverage, independent of having 3 findings.
    expect(html).toContain("3 completed checks out of 10 configured checks = 30% coverage");
    expect(html).toContain("Scan Coverage");
    expect(html).toContain("must not be confused with, the Automated Security Score");
  });
});

describe("buildReportHtml — How this score was calculated (mandated)", () => {
  it("lists only findings that actually reduced the score, with base/confidence/exposure/applied penalty columns", () => {
    const scoring = finding({ title: "CSP allows inline styles", severity: "LOW", severityPoints: 2, confidenceMultiplier: 1, exposureMultiplier: 0.3, penalty: 0.6 });
    const informational = finding({
      id: "info1",
      fingerprint: "fp-info",
      title: "robots.txt is missing",
      severity: "INFORMATIONAL",
      exposure: "INFORMATIONAL_ONLY",
      severityPoints: 0,
      penalty: 0,
    });
    const findings = [scoring, informational];
    const score = calculateSecurityScore(findings);
    const html = buildReportHtml(scan(), findings, score);

    expect(html).toContain("How this score was calculated");
    expect(html).toContain("CSP allows inline styles");
    expect(html).not.toContain("<td>robots.txt is missing</td>");
  });

  it("shows no-deduction message when every finding is informational", () => {
    const informational = finding({ severity: "INFORMATIONAL", exposure: "INFORMATIONAL_ONLY", severityPoints: 0, penalty: 0 });
    const html = buildReportHtml(scan(), [informational], calculateSecurityScore([informational]));
    expect(html).toContain("No findings reduced the score");
  });

  it("PDF breakdown values match the same formula used by the scoring engine (no drift between UI and PDF)", () => {
    const f = finding({ severity: "MEDIUM", confidence: "CONFIRMED", exposure: "CONFIG_WEAKNESS", occurrences: 1 });
    const expected = computePenalty(f);
    const score = calculateSecurityScore([f]);
    const html = buildReportHtml(scan(), [f], score);
    expect(html).toContain(expected.finalPenalty.toFixed(2));
  });
});

describe("buildReportHtml — OWASP/CWE 'Not mapped' display (mandated)", () => {
  it("shows 'Not mapped' when owaspCategory/cweId are absent, instead of hiding the line or guessing", () => {
    const f = finding({ owaspCategory: undefined, cweId: undefined });
    const html = buildReportHtml(scan(), [f], calculateSecurityScore([f]));
    expect(html).toMatch(/OWASP Mapping:<\/strong>\s*Not mapped/);
    expect(html).toMatch(/CWE:<\/strong>\s*Not mapped/);
  });

  it("never renders a 2021-dated OWASP category label", () => {
    const f = finding({ owaspCategory: "A02:2025 - Security Misconfiguration" });
    const html = buildReportHtml(scan(), [f], calculateSecurityScore([f]));
    expect(html).not.toMatch(/A0\d:2021/);
    expect(html).toContain("A02:2025 - Security Misconfiguration");
  });
});
