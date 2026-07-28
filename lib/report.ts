import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { CheckName, ScoredFinding, ScoreResult, Severity, ZapExecutionResult } from "./types";
import { STEP_LABELS } from "./step-labels";
import { redact } from "./redact";
import { computeScanCoverage } from "./run-scan";
import { OWASP_NOT_MAPPED_LABEL } from "./owasp";

export interface ReportScanData {
  id: string;
  targetUrl: string;
  status: string;
  startedAt: Date | null;
  completedAt: Date | null;
  durationMs: number | null;
  errorMessage: string | null;
  completedChecks: CheckName[];
  failedChecks: CheckName[];
  skippedChecks: CheckName[];
  zapExecution: ZapExecutionResult;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

function severityCounts(findings: ScoredFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFORMATIONAL: 0,
  };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDate(date: Date | null): string {
  if (!date) return "N/A";
  return date.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function severityBadgeClass(severity: Severity): string {
  return `badge sev-${severity.toLowerCase()}`;
}

/**
 * Builds the report HTML from the scan's own persisted results only — no
 * finding is added here that wasn't already computed by the scan/scoring
 * engine, and nothing sensitive (cookie values, tokens, auth headers) is
 * rendered even if a check's evidence text somehow contained it.
 */
export function buildReportHtml(scan: ReportScanData, findings: ScoredFinding[], score: ScoreResult): string {
  const counts = severityCounts(findings);
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  const allChecks: CheckName[] = [
    ...scan.completedChecks,
    ...scan.failedChecks,
    ...scan.skippedChecks,
  ];
  const uniqueChecks = [...new Set(allChecks)];
  const coverage = computeScanCoverage({
    completed: scan.completedChecks,
    failed: scan.failedChecks,
    skipped: scan.skippedChecks,
  });
  const isPartial = scan.status === "PARTIAL";
  const zapNotExecuted = scan.zapExecution.status !== "COMPLETED";

  // Only findings that actually reduced the score belong in "how this score
  // was calculated" — informational findings (zero severity points) never
  // affected it and are shown separately in the full findings list only.
  const scoreAffecting = [...score.breakdown].filter((entry) => entry.finalPenalty > 0);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Scan Report — ${escapeHtml(scan.targetUrl)}</title>
<style>
  @page { margin: 20mm 15mm; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; color: #1a1f26; font-size: 12px; line-height: 1.5; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  h2 { font-size: 16px; margin-top: 28px; border-bottom: 2px solid #1f2937; padding-bottom: 4px; }
  .subtitle { color: #555; margin-top: 0; }
  .cover-meta { margin: 16px 0; border: 1px solid #ddd; border-radius: 6px; padding: 12px 16px; }
  .cover-meta div { margin: 3px 0; }
  .score-box { display: flex; align-items: center; gap: 24px; margin: 16px 0; padding: 16px; border-radius: 8px; background: #f3f4f6; }
  .score-number { font-size: 48px; font-weight: 700; }
  .rating { font-size: 16px; font-weight: 600; }
  .provisional-banner { background: #fff7ed; border: 1px solid #fdba74; border-radius: 6px; padding: 10px 14px; margin: 12px 0; font-weight: 600; }
  .coverage-box { margin: 8px 0 16px; padding: 10px 14px; border: 1px solid #ddd; border-radius: 6px; background: #fafafa; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; }
  th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #f3f4f6; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 600; color: white; font-size: 11px; }
  .sev-critical { background: #b91c1c; }
  .sev-high { background: #d9590f; }
  .sev-medium { background: #b4820a; }
  .sev-low { background: #477a27; }
  .sev-informational { background: #475569; }
  .finding { border: 1px solid #ddd; border-radius: 6px; padding: 12px 14px; margin: 10px 0; page-break-inside: avoid; }
  .finding h3 { margin: 0 0 6px 0; font-size: 13px; }
  .finding .meta { color: #555; margin-bottom: 8px; }
  .evidence { background: #f3f4f6; padding: 8px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; word-break: break-all; }
  .raw-evidence summary { cursor: pointer; font-weight: 600; color: #374151; margin-top: 6px; }
  .raw-evidence pre { background: #f3f4f6; padding: 8px; border-radius: 4px; white-space: pre-wrap; word-break: break-all; margin-top: 4px; }
  .disclaimer { background: #fff7ed; border: 1px solid #fdba74; border-radius: 6px; padding: 12px; margin-top: 20px; }
  .footer { margin-top: 24px; font-size: 10px; color: #888; }
  .checks-list { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { border: 1px solid #ccc; border-radius: 12px; padding: 2px 10px; font-size: 11px; }
  .chip.completed { background: #ecfdf5; border-color: #34d399; }
  .chip.failed { background: #fef2f2; border-color: #f87171; }
  .chip.skipped { background: #f9fafb; border-color: #d1d5db; }
  .breakdown-row { display: flex; justify-content: space-between; border-bottom: 1px solid #eee; padding: 6px 0; }
  .breakdown-row:last-child { border-bottom: none; }
</style>
</head>
<body>
  <h1>Web Security Scanner — Automated Security Scan Report</h1>
  <p class="subtitle">This report was generated automatically from a real scan of the target below. It is not an official OWASP certification.</p>

  ${
    isPartial
      ? `<div class="provisional-banner">This was a partial scan. The score only reflects checks that completed successfully.${zapNotExecuted ? " OWASP ZAP Passive Scan was not executed." : ""}</div>`
      : ""
  }

  <div class="cover-meta">
    <div><strong>Target URL:</strong> ${escapeHtml(scan.targetUrl)}</div>
    <div><strong>Scan ID:</strong> ${escapeHtml(scan.id)}</div>
    <div><strong>Started:</strong> ${formatDate(scan.startedAt)}</div>
    <div><strong>Completed:</strong> ${formatDate(scan.completedAt)}</div>
    <div><strong>Duration:</strong> ${scan.durationMs !== null ? `${(scan.durationMs / 1000).toFixed(1)}s` : "N/A"}</div>
    <div><strong>Scan Status:</strong> ${escapeHtml(scan.status)}</div>
    ${scan.errorMessage ? `<div><strong>Error:</strong> ${escapeHtml(scan.errorMessage)}</div>` : ""}
  </div>

  <h2>${isPartial ? "Provisional Automated Security Score" : "Automated Security Score"}</h2>
  <div class="score-box">
    <div class="score-number">${score.displayedScore}%</div>
    <div>
      <div class="rating">${escapeHtml(score.rating)}</div>
      <div>Exact score: ${score.exactScore} / 100 &middot; Total penalty: ${score.totalPenalty}</div>
      ${isPartial ? `<div>Based only on completed checks.</div>` : ""}
    </div>
  </div>
  <p>This score is an <strong>Automated Security Score</strong> designed and computed by this project from the findings below.
  It is deterministic (the same findings always produce the same score), starts at 100, and subtracts a penalty per finding
  based on severity &times; confidence &times; exposure, capped so a single repeated issue cannot be double-counted across pages.
  It reflects only the automated checks performed in this scan and is not a guarantee of overall security.</p>

  <div class="coverage-box">
    <strong>Scan Coverage:</strong> ${coverage.completedChecks} completed checks out of ${coverage.totalChecks} configured checks = ${coverage.coveragePercent}% coverage.
    <br>Coverage measures how many checks actually ran — it is separate from, and must not be confused with, the Automated Security Score above.
  </div>

  <h2>How this score was calculated</h2>
  ${
    scoreAffecting.length === 0
      ? "<p>No findings reduced the score — every completed check either passed or only produced informational-only observations.</p>"
      : `<table>
    <tr><th>Finding</th><th>Base penalty</th><th>Confidence &times;</th><th>Exposure &times;</th><th>Applied penalty</th></tr>
    ${scoreAffecting
      .map(
        (entry) => `<tr>
      <td>${escapeHtml(entry.title)}</td>
      <td>${entry.severityPoints}</td>
      <td>${entry.confidenceMultiplier.toFixed(2)}</td>
      <td>${entry.exposureMultiplier.toFixed(2)}</td>
      <td>${entry.finalPenalty.toFixed(2)}</td>
    </tr>`,
      )
      .join("")}
  </table>`
  }

  <h2>Findings by Severity</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    ${SEVERITY_ORDER.map((s) => `<tr><td><span class="${severityBadgeClass(s)}">${s}</span></td><td>${counts[s]}</td></tr>`).join("")}
  </table>

  <h2>Checks Performed</h2>
  <div class="checks-list">
    ${uniqueChecks
      .map((c) => {
        const cls = scan.completedChecks.includes(c) ? "completed" : scan.failedChecks.includes(c) ? "failed" : "skipped";
        const label = scan.failedChecks.includes(c) ? "Failed" : scan.skippedChecks.includes(c) ? "Not Tested" : "Completed";
        return `<span class="chip ${cls}">${escapeHtml(STEP_LABELS[c])} — ${label}</span>`;
      })
      .join("")}
  </div>

  <h2>OWASP ZAP Baseline Scan</h2>
  <p>
    <strong>Status:</strong> ${escapeHtml(scan.zapExecution.status)}
    ${scan.zapExecution.reasonCode ? ` (${escapeHtml(scan.zapExecution.reasonCode)})` : ""}<br>
    ${escapeHtml(scan.zapExecution.reasonMessage)}
    ${scan.zapExecution.durationMs !== null ? `<br><strong>Duration:</strong> ${(scan.zapExecution.durationMs / 1000).toFixed(1)}s` : ""}
  </p>

  <h2>Detailed Findings (${findings.length})</h2>
  ${
    sorted.length === 0
      ? "<p>No findings were recorded for the checks that completed.</p>"
      : sorted
          .map(
            (f) => `
    <div class="finding">
      <h3>${escapeHtml(f.title)} <span class="${severityBadgeClass(f.severity)}">${f.severity}</span></h3>
      <div class="meta">
        Confidence: <strong>${f.confidence}</strong> &middot;
        Rule: <code>${escapeHtml(f.ruleId)}</code> &middot;
        Affected URL: ${escapeHtml(f.affectedUrl)} &middot;
        Sources: ${f.sources.map(escapeHtml).join(", ")}
        ${f.occurrences > 1 ? ` &middot; Observed ${f.occurrences} times` : ""}
        ${f.reviewStatus ? ` &middot; <strong>${escapeHtml(f.reviewStatus)}</strong>` : ""}
      </div>
      <p>${escapeHtml(redact(f.description))}</p>
      ${f.evidence ? `<div class="evidence">${escapeHtml(redact(f.evidence))}</div>` : ""}
      ${
        f.rawEvidence
          ? `<details class="raw-evidence"><summary>Raw Evidence</summary><pre>${escapeHtml(redact(f.rawEvidence))}</pre></details>`
          : ""
      }
      <p><strong>Remediation:</strong> ${escapeHtml(redact(f.remediation))}</p>
      <p><strong>OWASP Mapping:</strong> ${f.owaspCategory ? escapeHtml(f.owaspCategory) : OWASP_NOT_MAPPED_LABEL}</p>
      <p><strong>CWE:</strong> ${f.cweId ? escapeHtml(f.cweId) : "Not mapped"}</p>
    </div>`,
          )
          .join("")
  }

  <h2>Limitations of This Scan</h2>
  <p>This is an automated, non-intrusive scan. It does not cover business logic flaws, secure design review, server-side
  source code review, authenticated/logged-in application areas, or the full breadth of manual penetration testing.
  A "not tested" check is never treated as a passing check — see the checks list above for anything skipped or failed.</p>

  <div class="disclaimer">
    <strong>Disclaimer:</strong> This report reflects automated findings only, generated by this student project's own
    scanning engine. It is not an official certification from OWASP or any standards body, and does not guarantee the
    target is free of vulnerabilities beyond what was actually tested above.
  </div>

  <div class="footer">Generated by Web Security Scanner (university graduation project).</div>
</body>
</html>`;
}

export interface GeneratedReport {
  filePath: string;
  sha256: string;
}

/**
 * Renders the report HTML to a real PDF using Playwright/Chromium and writes
 * it to REPORTS_DIR, returning the file path and a SHA-256 integrity hash of
 * the PDF bytes (stored alongside the Report record).
 */
export async function generateReportPdf(
  scan: ReportScanData,
  findings: ScoredFinding[],
  score: ScoreResult,
): Promise<GeneratedReport> {
  const html = buildReportHtml(scan, findings, score);

  // Lazy import so environments without Playwright installed (e.g. a pure
  // API-only deployment) don't fail at module load time, only when a report
  // is actually requested.
  const { chromium } = await import("playwright");
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle" });
    const pdfBuffer = await page.pdf({
      format: "A4",
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: "<span></span>",
      footerTemplate:
        '<div style="font-size:9px;width:100%;text-align:center;color:#888;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
      margin: { top: "20mm", bottom: "16mm", left: "15mm", right: "15mm" },
    });

    const reportsDir = path.resolve(process.env.REPORTS_DIR ?? "./reports");
    await mkdir(reportsDir, { recursive: true });
    const fileName = `${scan.id}.pdf`;
    const filePath = path.join(reportsDir, fileName);
    await writeFile(filePath, pdfBuffer);

    const sha256 = createHash("sha256").update(pdfBuffer).digest("hex");
    return { filePath, sha256 };
  } finally {
    await browser.close();
  }
}
