import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { runScan } from "@/lib/run-scan";
import { deduplicateFindings } from "@/lib/dedup";
import { attachPenalties, calculateSecurityScore } from "@/lib/scoring";
import { checklistToJson, findingToCreateData, zapExecutionToScanFields } from "@/lib/persist";


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

  return NextResponse.json({ id: scan.id, status: result.status, displayedScore: score.displayedScore });
}
