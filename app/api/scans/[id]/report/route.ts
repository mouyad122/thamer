import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { buildReportHtml } from "@/lib/report";
import { deserializeChecklistPart, scanFieldsToZapExecution } from "@/lib/persist";
import type { CheckName, ScoredFinding } from "@/lib/types";
import { calculateSecurityScore } from "@/lib/scoring";

export const runtime = "nodejs";

/** Generates and returns the HTML report that auto-prints as PDF. */
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const scan = await prisma.scan.findUnique({
    where: { id },
    include: { findings: true },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }

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
  })) as unknown as ScoredFinding[];

  const score = calculateSecurityScore(findings); // re-calc for breakdown

  const reportScanData = {
    id: scan.id,
    targetUrl: scan.targetUrl,
    status: scan.status,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    durationMs: scan.durationMs,
    errorMessage: scan.errorMessage,
    completedChecks: deserializeChecklistPart(scan.completedChecks) as CheckName[],
    failedChecks: deserializeChecklistPart(scan.failedChecks) as CheckName[],
    skippedChecks: deserializeChecklistPart(scan.skippedChecks) as CheckName[],
    zapExecution: scanFieldsToZapExecution(scan),
  };

  const html = buildReportHtml(reportScanData, findings, score);

  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html",
    },
  });
}
