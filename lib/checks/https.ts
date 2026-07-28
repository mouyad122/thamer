import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";

const SOURCE = "Custom HTTPS Scanner";

export interface HttpsProbeInput {
  /** Whether the final scanned page (after following any redirects) was served over TLS. */
  finalUsedTls: boolean;
  affectedUrl: string;
  /**
   * Result of a best-effort separate probe against the plain http:// version of
   * the same host/path. `null` when that probe could not be made at all
   * (network error) — treated as "not tested", never as a pass.
   */
  httpProbe: {
    reachable: boolean;
    redirectedToHttps: boolean;
    finalUsedTls: boolean;
  } | null;
}

/**
 * Reports only what was actually observed: if the final page isn't HTTPS,
 * that is HIGH and CONFIRMED because it was directly witnessed. If the plain
 * HTTP endpoint was reachable and did NOT redirect to HTTPS, that is also a
 * real, confirmed finding — visitors typing the bare domain stay unencrypted.
 */
export function analyzeHttpsEnforcement(input: HttpsProbeInput): RawFinding[] {
  const findings: RawFinding[] = [];

  if (!input.finalUsedTls) {
    findings.push({
      ruleId: "SITE_NOT_HTTPS",
      title: "The scanned page is served over plain HTTP",
      severity: "HIGH",
      confidence: "CONFIRMED",
      exposure: "DIRECT_PROVEN",
      affectedUrl: input.affectedUrl,
      description: "The final page loaded over HTTP (not HTTPS), so all traffic — including any form submissions — is transmitted in clear text and can be read or modified in transit.",
      remediation: "Serve the site exclusively over HTTPS with a valid certificate, and redirect all HTTP requests to HTTPS.",
      owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
      cweId: "CWE-319",
      source: SOURCE,
      detailKey: "protocol",
    });
    return findings;
  }

  if (input.httpProbe && input.httpProbe.reachable && !input.httpProbe.redirectedToHttps) {
    findings.push({
      ruleId: "HTTP_NOT_REDIRECTED_TO_HTTPS",
      title: "Plain HTTP is served without redirecting to HTTPS",
      severity: "HIGH",
      confidence: "CONFIRMED",
      exposure: "DIRECT_PROVEN",
      affectedUrl: input.affectedUrl,
      description: "The site responds to plain HTTP requests without redirecting to HTTPS, so a visitor who types the domain without \"https://\" (or follows an old http:// link) will load the page unencrypted, exposing them to interception.",
      remediation: "Configure the web server/load balancer to redirect all HTTP requests (301/308) to the HTTPS equivalent URL.",
      owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
      cweId: "CWE-319",
      source: SOURCE,
      detailKey: "http-redirect",
    });
  }

  return findings;
}
