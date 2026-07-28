import { createHmac, timingSafeEqual } from "node:crypto";
import type { ZapBaselineReport } from "./checks/zap";
import type { ZapExecutionResult } from "./types";

/**
 * Client for the separate scanner-worker service (Docker + OWASP ZAP), which
 * cannot run inside a Vercel serverless function. Every outcome — including
 * "not configured", "unreachable", and "timed out" — is returned as a
 * structured ZapExecutionResult with a real reason code and message, never
 * collapsed into a single generic "Not Tested" with no explanation.
 */

const DEFAULT_ZAP_TIMEOUT_MS = 120000;

function sign(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

export function verifyWorkerSignature(body: string, signature: string, secret: string): boolean {
  const expected = sign(body, secret);
  const expectedBuf = Buffer.from(expected, "hex");
  const actualBuf = Buffer.from(signature, "hex");
  if (expectedBuf.length !== actualBuf.length) return false;
  return timingSafeEqual(expectedBuf, actualBuf);
}

interface WorkerBaselineResponse {
  report?: ZapBaselineReport;
}

export interface ZapRunOutcome {
  execution: ZapExecutionResult;
  report: ZapBaselineReport | null;
}

function elapsed(startedAt: Date, completedAt: Date): number {
  return completedAt.getTime() - startedAt.getTime();
}

/**
 * Calls the scanner-worker to run an OWASP ZAP Baseline (passive) scan.
 * Always resolves (never throws) with a full execution record so the caller
 * can persist and display exactly what happened and why.
 */
export async function requestZapBaseline(
  targetUrl: string,
  timeoutMs = DEFAULT_ZAP_TIMEOUT_MS,
): Promise<ZapRunOutcome> {
  const workerUrl = process.env.SCANNER_WORKER_URL;
  const secret = process.env.SCANNER_WORKER_SECRET;

  if (!workerUrl || !secret) {
    return {
      execution: {
        status: "NOT_TESTED",
        reasonCode: "ZAP_WORKER_NOT_CONFIGURED",
        reasonMessage:
          "SCANNER_WORKER_URL and/or SCANNER_WORKER_SECRET are not configured for this deployment, so the OWASP ZAP Baseline (passive) scan was not attempted.",
        startedAt: null,
        completedAt: null,
        durationMs: null,
      },
      report: null,
    };
  }

  const startedAt = new Date();
  const body = JSON.stringify({ targetUrl });
  const signature = sign(body, secret);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response: Response;
    try {
      response = await fetch(`${workerUrl.replace(/\/$/, "")}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Signature": signature },
        body,
        signal: controller.signal,
      });
    } catch (err) {
      const completedAt = new Date();
      const aborted = err instanceof Error && err.name === "AbortError";
      return {
        execution: {
          status: aborted ? "TIMED_OUT" : "FAILED",
          reasonCode: aborted ? "ZAP_TIMEOUT" : "ZAP_WORKER_UNREACHABLE",
          reasonMessage: aborted
            ? `The scanner worker did not respond within ${timeoutMs}ms and the request was aborted.`
            : `The scanner worker at "${workerUrl}" could not be reached: ${err instanceof Error ? err.message : String(err)}`,
          startedAt: startedAt.toISOString(),
          completedAt: completedAt.toISOString(),
          durationMs: elapsed(startedAt, completedAt),
        },
        report: null,
      };
    }

    const completedAtHeaders = new Date();

    if (!response.ok) {
      return {
        execution: {
          status: "FAILED",
          reasonCode: "ZAP_START_FAILED",
          reasonMessage: `The scanner worker returned HTTP ${response.status} while starting the ZAP baseline scan.`,
          startedAt: startedAt.toISOString(),
          completedAt: completedAtHeaders.toISOString(),
          durationMs: elapsed(startedAt, completedAtHeaders),
        },
        report: null,
      };
    }

    let json: WorkerBaselineResponse;
    try {
      json = (await response.json()) as WorkerBaselineResponse;
    } catch {
      const completedAt = new Date();
      return {
        execution: {
          status: "FAILED",
          reasonCode: "ZAP_INVALID_RESPONSE",
          reasonMessage: "The scanner worker's response could not be parsed as JSON.",
          startedAt: startedAt.toISOString(),
          completedAt: completedAt.toISOString(),
          durationMs: elapsed(startedAt, completedAt),
        },
        report: null,
      };
    }

    const completedAt = new Date();
    const durationMs = elapsed(startedAt, completedAt);

    if (!json.report) {
      return {
        execution: {
          status: "FAILED",
          reasonCode: "ZAP_REPORT_MISSING",
          reasonMessage: "The scanner worker responded successfully but did not include a ZAP baseline report.",
          startedAt: startedAt.toISOString(),
          completedAt: completedAt.toISOString(),
          durationMs,
        },
        report: null,
      };
    }

    return {
      execution: {
        status: "COMPLETED",
        reasonCode: null,
        reasonMessage: "OWASP ZAP Baseline (passive) scan completed successfully.",
        startedAt: startedAt.toISOString(),
        completedAt: completedAt.toISOString(),
        durationMs,
      },
      report: json.report,
    };
  } finally {
    clearTimeout(timeout);
  }
}
