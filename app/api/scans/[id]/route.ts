import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { deserializeChecklistPart, scanFieldsToZapExecution } from "@/lib/persist";
import { computeScanCoverage } from "@/lib/run-scan";
import { computeScoreAffectingBreakdown } from "@/lib/scoring";
import type { Confidence, Exposure, Severity } from "@/lib/types";

export const runtime = "nodejs";

/** Full scan result: metadata, score, coverage, ZAP outcome, breakdown, and every finding — used by the results page. */
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const scan = await prisma.scan.findUnique({
    where: { id },
    include: { findings: true, report: true },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }

  const completedChecks = deserializeChecklistPart(scan.completedChecks);
  const failedChecks = deserializeChecklistPart(scan.failedChecks);
  const skippedChecks = deserializeChecklistPart(scan.skippedChecks);

  const findings = scan.findings.map((f) => ({
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    exposure: f.exposure,
    affectedUrl: f.affectedUrl,
    description: f.description,
    evidence: f.evidence,
    rawEvidence: f.rawEvidence,
    remediation: f.remediation,
    owaspCategory: f.owaspCategory,
    cweId: f.cweId,
    sources: JSON.parse(f.source) as string[],
    occurrences: f.occurrences,
    penalty: f.penalty,
    exploitability: f.exploitability,
    reviewStatus: f.reviewStatus,
  }));

  // Recomputed from the same persisted severity/confidence/exposure fields
  // used at scan time — guaranteed to match the PDF's "How this score was
  // calculated" section, and to exclude informational (zero-penalty) findings.
  const scoreBreakdown = computeScoreAffectingBreakdown(
    scan.findings.map((f) => ({
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity as Severity,
      confidence: f.confidence as Confidence,
      exposure: f.exposure as Exposure,
      occurrences: f.occurrences,
    })),
  );

  return NextResponse.json({
    id: scan.id,
    targetUrl: scan.targetUrl,
    normalizedUrl: scan.normalizedUrl,
    status: scan.status,
    isPartial: scan.status === "PARTIAL",
    exactScore: scan.exactScore,
    displayedScore: scan.displayedScore,
    rating: scan.rating,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    durationMs: scan.durationMs,
    errorMessage: scan.errorMessage,
    completedChecks,
    failedChecks,
    skippedChecks,
    coverage: computeScanCoverage({ completed: completedChecks, failed: failedChecks, skipped: skippedChecks }),
    zapExecution: scanFieldsToZapExecution(scan),
    scoreBreakdown,
    hasReport: Boolean(scan.report),
    findings: findings.sort((a, b) => b.penalty - a.penalty),
  });
}
