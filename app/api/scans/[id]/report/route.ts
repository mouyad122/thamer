import { NextResponse } from "next/server";
import { readFile } from "node:fs/promises";
import { prisma } from "@/lib/prisma";

export const runtime = "nodejs";

/** Streams the previously generated PDF report for a completed scan. */
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const scan = await prisma.scan.findUnique({ where: { id }, include: { report: true } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  }
  if (!scan.report) {
    return NextResponse.json({ error: "No report has been generated for this scan yet." }, { status: 404 });
  }

  let pdfBuffer: Buffer;
  try {
    pdfBuffer = await readFile(scan.report.filePath);
  } catch {
    return NextResponse.json({ error: "The report file could not be read." }, { status: 500 });
  }

  return new NextResponse(new Uint8Array(pdfBuffer), {
    status: 200,
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="scan-report-${scan.id}.pdf"`,
      "Content-Length": String(pdfBuffer.byteLength),
      "X-Report-SHA256": scan.report.sha256,
    },
  });
}
