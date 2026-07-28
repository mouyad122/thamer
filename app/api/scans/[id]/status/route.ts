import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { deserializeChecklistPart, scanFieldsToZapExecution } from "@/lib/persist";
import { CHECK_NAMES } from "@/lib/types";
import { computeScanCoverage } from "@/lib/run-scan";

export const runtime = "nodejs";

/** Lightweight polling endpoint: real status + real check counts, never a simulated percentage. */
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const scan = await prisma.scan.findUnique({ where: { id } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }

  const completed = deserializeChecklistPart(scan.completedChecks);
  const failed = deserializeChecklistPart(scan.failedChecks);
  const skipped = deserializeChecklistPart(scan.skippedChecks);
  const coverage = computeScanCoverage({ completed, failed, skipped });

  return NextResponse.json({
    id: scan.id,
    status: scan.status,
    currentStep: scan.currentStep,
    // Number of checks attempted so far (completed+failed+skipped), used only
    // to show progress while scanning — the final Scan Coverage figure
    // (completedChecks / totalChecks) is reported separately below.
    checksCompleted: completed.length + failed.length + skipped.length,
    checksTotal: CHECK_NAMES.length,
    completedChecks: completed,
    failedChecks: failed,
    skippedChecks: skipped,
    coverage,
    displayedScore: scan.displayedScore,
    rating: scan.rating,
    isPartial: scan.status === "PARTIAL",
    errorMessage: scan.errorMessage,
    zapExecution: scanFieldsToZapExecution(scan),
  });
}
