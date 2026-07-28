import { CHECK_NAMES, type CheckName, type RawFinding, type ScanChecklist, type ScanStatus, type ZapExecutionResult } from "./types";
import { UrlSecurityError, validateTargetUrl } from "./url-validation";
import { safeFetch, safeFetchWithOrigin } from "./safe-fetch";
import { analyzeHttpsEnforcement } from "./checks/https";
import { analyzeTlsCertificate, summarizeCertificate, type CertificateSummary } from "./checks/tls";
import { analyzeSecurityHeaders } from "./checks/headers";
import { analyzeCookies } from "./checks/cookies";
import { analyzeCors } from "./checks/cors";
import { analyzeInformationDisclosure, buildSourceMapFinding } from "./checks/disclosure";
import { analyzeHtmlSecurity, extractResourceUrls } from "./checks/html";
import { checkCommonSafeFiles } from "./checks/common-files";
import { normalizeZapReport } from "./checks/zap";
import { requestZapBaseline } from "./worker-client";
import { STEP_LABELS } from "./step-labels";

const UNTRUSTED_TEST_ORIGIN = "https://untrusted-scan-probe.example.org";

export interface ScanRunResult {
  status: Extract<ScanStatus, "COMPLETED" | "PARTIAL" | "FAILED">;
  errorMessage?: string;
  findings: RawFinding[];
  checklist: ScanChecklist;
  finalUrl?: string;
  usedTls?: boolean;
  certificate?: CertificateSummary;
  zapExecution: ZapExecutionResult;
}

/** Real coverage: checks actually completed vs. every check the scanner is configured to run — never derived from finding counts. */
export function computeScanCoverage(checklist: ScanChecklist): {
  completedChecks: number;
  totalChecks: number;
  coveragePercent: number;
} {
  const totalChecks: number = CHECK_NAMES.length;
  const completedChecks = checklist.completed.length;
  return {
    completedChecks,
    totalChecks,
    coveragePercent: totalChecks === 0 ? 0 : Math.round((completedChecks / totalChecks) * 100),
  };
}

export interface RunScanOptions {
  onStep?: (step: string, checklist: ScanChecklist) => Promise<void> | void;
}

function emptyChecklist(): ScanChecklist {
  return { completed: [], failed: [], skipped: [] };
}

/** ZAP execution record for scans that never reached the ZAP step at all (e.g. failed before it). */
function zapNeverAttempted(reasonMessage: string): ZapExecutionResult {
  return {
    status: "NOT_TESTED",
    reasonCode: null,
    reasonMessage,
    startedAt: null,
    completedAt: null,
    durationMs: null,
  };
}

async function runStep<T>(
  name: CheckName,
  checklist: ScanChecklist,
  onStep: RunScanOptions["onStep"],
  fn: () => Promise<T>,
): Promise<T | null> {
  if (onStep) await onStep(STEP_LABELS[name], checklist);
  try {
    const result = await fn();
    checklist.completed.push(name);
    return result;
  } catch {
    checklist.failed.push(name);
    return null;
  }
}

/**
 * Runs every real check against the target and returns raw (not yet
 * deduplicated/scored) findings, plus an honest record of which checks
 * completed, failed, or were skipped. Never fabricates a finding and never
 * marks a check that didn't run as completed.
 */
export async function runScan(targetUrlInput: string, options: RunScanOptions = {}): Promise<ScanRunResult> {
  const { onStep } = options;
  const checklist = emptyChecklist();
  const findings: RawFinding[] = [];

  if (onStep) await onStep(STEP_LABELS.URL_VALIDATION, checklist);
  let target;
  try {
    target = await validateTargetUrl(targetUrlInput);
    checklist.completed.push("URL_VALIDATION");
  } catch (err) {
    if (err instanceof UrlSecurityError) {
      return {
        status: "FAILED",
        errorMessage: `Target blocked by URL security policy: ${err.message}`,
        findings: [],
        checklist: { completed: [], failed: ["URL_VALIDATION"], skipped: [...CHECK_NAMES].filter((c) => c !== "URL_VALIDATION") },
        zapExecution: zapNeverAttempted("The scan was blocked before any checks (including ZAP) could run."),
      };
    }
    throw err;
  }

  let mainResponse;
  try {
    if (onStep) await onStep(STEP_LABELS.HTTPS_CHECK, checklist);
    mainResponse = await safeFetch(target.url.toString());
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown connection error";
    return {
      status: "FAILED",
      errorMessage: `Connection to target failed: ${message}`,
      findings: [],
      checklist: { completed: ["URL_VALIDATION"], failed: [], skipped: [...CHECK_NAMES].filter((c) => c !== "URL_VALIDATION") },
      zapExecution: zapNeverAttempted("The scan failed to connect to the target before ZAP could run."),
    };
  }

  // HTTPS enforcement: also probe the plain-http version of the same host, best-effort.
  await runStep("HTTPS_CHECK", checklist, undefined, async () => {
    let httpProbe: { reachable: boolean; redirectedToHttps: boolean; finalUsedTls: boolean } | null = null;
    if (target.url.protocol === "https:") {
      try {
        const httpUrl = new URL(target.url.toString());
        httpUrl.protocol = "http:";
        const httpResult = await safeFetch(httpUrl.toString(), { timeoutMs: 6000 });
        httpProbe = {
          reachable: true,
          redirectedToHttps: httpResult.usedTls,
          finalUsedTls: httpResult.usedTls,
        };
      } catch {
        httpProbe = null; // Genuinely not tested — never counted as "redirects fine".
      }
    }
    findings.push(
      ...analyzeHttpsEnforcement({
        finalUsedTls: mainResponse.usedTls,
        affectedUrl: mainResponse.finalUrl,
        httpProbe,
      }),
    );
  });

  const certSummary = summarizeCertificate(mainResponse.tlsCertificate, target.hostname);
  await runStep("TLS_CERTIFICATE", checklist, onStep, async () => {
    findings.push(
      ...analyzeTlsCertificate(mainResponse.tlsCertificate, target.hostname, mainResponse.usedTls, mainResponse.finalUrl),
    );
  });

  await runStep("SECURITY_HEADERS", checklist, onStep, async () => {
    findings.push(...analyzeSecurityHeaders(mainResponse.headers, mainResponse.finalUrl, mainResponse.usedTls));
  });

  await runStep("COOKIE_SECURITY", checklist, onStep, async () => {
    const setCookie = mainResponse.headers["set-cookie"];
    const cookies = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : undefined;
    findings.push(...analyzeCookies(cookies, mainResponse.finalUrl, mainResponse.usedTls));
  });

  await runStep("CORS_ANALYSIS", checklist, onStep, async () => {
    const corsResponse = await safeFetchWithOrigin(mainResponse.finalUrl, UNTRUSTED_TEST_ORIGIN, 6000);
    const acao = corsResponse.headers["access-control-allow-origin"];
    const acac = corsResponse.headers["access-control-allow-credentials"];
    findings.push(
      ...analyzeCors(
        {
          requestOrigin: UNTRUSTED_TEST_ORIGIN,
          accessControlAllowOrigin: Array.isArray(acao) ? acao[0] : acao,
          accessControlAllowCredentials: Array.isArray(acac) ? acac[0] : acac,
        },
        mainResponse.finalUrl,
      ),
    );
  });

  await runStep("INFORMATION_DISCLOSURE", checklist, onStep, async () => {
    findings.push(...analyzeInformationDisclosure(mainResponse.headers, mainResponse.body, mainResponse.finalUrl));
  });

  await runStep("HTML_SECURITY", checklist, onStep, async () => {
    findings.push(
      ...analyzeHtmlSecurity({
        html: mainResponse.body,
        pageUrl: mainResponse.finalUrl,
        usedTls: mainResponse.usedTls,
      }),
    );

    // Limited, non-exhaustive source-map check on the first few referenced scripts only.
    const scripts = extractResourceUrls(mainResponse.body)
      .filter((r) => r.tag === "script")
      .slice(0, 5);
    for (const script of scripts) {
      try {
        const scriptUrl = new URL(script.url, mainResponse.finalUrl).toString();
        const mapUrl = `${scriptUrl}.map`;
        const mapResponse = await safeFetch(mapUrl, { timeoutMs: 5000 });
        if (mapResponse.status === 200 && mapResponse.body.trim().startsWith("{")) {
          findings.push(buildSourceMapFinding(scriptUrl, mapUrl));
        }
      } catch {
        // Not reachable — simply not a finding, not an error worth failing the check over.
      }
    }
  });

  await runStep("COMMON_SAFE_FILES", checklist, onStep, async () => {
    findings.push(...(await checkCommonSafeFiles(mainResponse.finalUrl)));
  });

  if (onStep) await onStep(STEP_LABELS.ZAP_BASELINE, checklist);
  const { execution: zapExecution, report: zapReport } = await requestZapBaseline(mainResponse.finalUrl);
  if (zapExecution.status === "COMPLETED" && zapReport) {
    findings.push(...normalizeZapReport(zapReport));
    checklist.completed.push("ZAP_BASELINE");
  } else if (zapExecution.status === "NOT_TESTED") {
    checklist.skipped.push("ZAP_BASELINE");
  } else {
    // FAILED or TIMED_OUT — a real attempt was made and it did not succeed;
    // tracked as a failed check (not silently "skipped") so Partial Scan
    // reporting reflects that ZAP was actually attempted.
    checklist.failed.push("ZAP_BASELINE");
  }

  // Any check in NOT_TESTED/FAILED/TIMED_OUT/SKIPPED state means the overall
  // scan is only PARTIAL — the score must never be presented as final.
  const status: ScanRunResult["status"] =
    checklist.failed.length === 0 && checklist.skipped.length === 0 ? "COMPLETED" : "PARTIAL";

  return {
    status,
    findings,
    checklist,
    finalUrl: mainResponse.finalUrl,
    usedTls: mainResponse.usedTls,
    certificate: certSummary,
    zapExecution,
  };
}
