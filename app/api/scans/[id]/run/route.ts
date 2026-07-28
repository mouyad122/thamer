import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { runScan } from "@/lib/run-scan";
import { deduplicateFindings } from "@/lib/dedup";
import { attachPenalties, calculateSecurityScore } from "@/lib/scoring";
import { checklistToJson, findingToCreateData, zapExecutionToScanFields, scanFieldsToZapExecution } from "@/lib/persist";
import { generateReportPdf } from "@/lib/report";
import type { CheckName } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 300;

/**
 * Executes the scan for an existing PENDING Scan record. This is a single,
 * long-lived request (no background queue) — the client polls
 * GET /api/scans/:id/status concurrently to see live progress, since the
 * database is updated after every check completes, not just at the end.
 */
export async function POST(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const scan = await prisma.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }
  if (scan.status !== "PENDING") {
    return NextResponse.json({ id: scan.id, status: scan.status });
  }

  const startedAt = new Date();
  await prisma.scan.update({
    where: { id },
    data: { status: "SCANNING", startedAt, currentStep: "Validating URL" },
  });

  const result = await runScan(scan.targetUrl, {
    onStep: async (step, checklist) => {
      await prisma.scan.update({
        where: { id },
        data: {
          currentStep: step,
          ...checklistToJson(checklist),
        },
      });
    },
  });

  const completedAt = new Date();
  const durationMs = completedAt.getTime() - startedAt.getTime();

  if (result.status === "FAILED") {
    await prisma.scan.update({
      where: { id },
      data: {
        status: "FAILED",
        errorMessage: result.errorMessage,
        completedAt,
        durationMs,
        currentStep: "Scan Failed",
        ...checklistToJson(result.checklist),
        ...zapExecutionToScanFields(result.zapExecution),
      },
    });
    return NextResponse.json({ id: scan.id, status: "FAILED", errorMessage: result.errorMessage });
  }

  const deduped = deduplicateFindings(result.findings);
  const score = calculateSecurityScore(deduped);
  const scored = attachPenalties(deduped, score.breakdown);

  await prisma.$transaction([
    prisma.finding.deleteMany({ where: { scanId: id } }),
    ...scored.map((finding) => prisma.finding.create({ data: findingToCreateData(finding, id) })),
    prisma.scan.update({
      where: { id },
      data: {
        status: result.status,
        normalizedUrl: result.finalUrl ?? scan.normalizedUrl,
        exactScore: score.exactScore,
        displayedScore: score.displayedScore,
        rating: score.rating,
        completedAt,
        durationMs,
        currentStep: "Scan Complete",
        ...checklistToJson(result.checklist),
        ...zapExecutionToScanFields(result.zapExecution),
      },
    }),
  ]);

  try {
    const savedScan = await prisma.scan.findUniqueOrThrow({ where: { id } });
    const report = await generateReportPdf(
      {
        id: savedScan.id,
        targetUrl: savedScan.targetUrl,
        status: savedScan.status,
        startedAt: savedScan.startedAt,
        completedAt: savedScan.completedAt,
        durationMs: savedScan.durationMs,
        errorMessage: savedScan.errorMessage,
        completedChecks: JSON.parse(savedScan.completedChecks) as CheckName[],
        failedChecks: JSON.parse(savedScan.failedChecks) as CheckName[],
        skippedChecks: JSON.parse(savedScan.skippedChecks) as CheckName[],
        zapExecution: scanFieldsToZapExecution(savedScan),
      },
      scored,
      score,
    );
    await prisma.report.upsert({
      where: { scanId: id },
      create: { scanId: id, filePath: report.filePath, sha256: report.sha256 },
      update: { filePath: report.filePath, sha256: report.sha256, generatedAt: new Date() },
    });
  } catch (err) {
    // PDF generation failing must not erase the completed scan results —
    // the site still shows real findings; only the download button is unavailable.
    console.error("Report generation failed for scan", id, err);
  }

  return NextResponse.json({ id: scan.id, status: result.status, displayedScore: score.displayedScore });
}
