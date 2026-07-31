import { NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { MAX_URL_LENGTH } from "@/lib/url-validation";

export const runtime = "nodejs";

const createScanSchema = z.object({
  url: z.string().trim().min(1).max(MAX_URL_LENGTH),
});

/** Creates a new Scan record in PENDING state. The actual scan is started by a follow-up call to /run. */
export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
  }

  const parsed = createScanSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "A valid target URL is required." }, { status: 400 });
  }

  try {
    const scan = await prisma.scan.create({
      data: {
        targetUrl: parsed.data.url,
        normalizedUrl: parsed.data.url,
        status: "PENDING",
      },
    });
    return NextResponse.json({ id: scan.id }, { status: 201 });
  } catch (error) {
    console.error("Failed to create scan in DB:", error);
    const message = error instanceof Error ? error.message : "Unknown error";
    return NextResponse.json({ error: `Database error: ${message}` }, { status: 500 });
  }
}
