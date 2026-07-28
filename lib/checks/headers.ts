import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";
import { analyzeCspDirectives } from "./csp";

export type HeaderMap = Record<string, string | string[] | undefined>;

function getHeader(headers: HeaderMap, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(", ");
  return value;
}

const SOURCE = "Custom Header Scanner";

/**
 * Analyzes the *real* response headers of the final scanned page. Every
 * finding here is CONFIRMED confidence because presence/absence/value of a
 * header is read directly from the actual HTTP response — nothing is guessed.
 * Missing optional headers stay at LOW/INFORMATIONAL severity per project
 * policy: we never inflate a missing best-practice header into a high-risk
 * finding just because it's absent. For headers that are pure
 * defense-in-depth (COOP, CORP, Permissions-Policy), a missing header is
 * always CONFIRMED-observed but NOT_DEMONSTRATED-exploitable — the
 * observation is certain, the exploit is not.
 */
export function analyzeSecurityHeaders(
  headers: HeaderMap,
  affectedUrl: string,
  usedTls: boolean,
): RawFinding[] {
  const findings: RawFinding[] = [];

  const hsts = getHeader(headers, "strict-transport-security");
  if (usedTls && !hsts) {
    findings.push({
      ruleId: "HSTS_MISSING",
      title: "Strict-Transport-Security header is missing",
      severity: "LOW",
      confidence: "CONFIRMED",
      exposure: "BEST_PRACTICE",
      affectedUrl,
      description:
        "The site serves HTTPS but does not send Strict-Transport-Security, so browsers are not told to always use HTTPS for this host, leaving a window for SSL-stripping attacks on future visits.",
      remediation:
        'Send "Strict-Transport-Security: max-age=31536000; includeSubDomains" on every HTTPS response.',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-319",
      source: SOURCE,
      detailKey: "Strict-Transport-Security",
      exploitability: "NOT_DEMONSTRATED",
    });
  } else if (usedTls && hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
    if (maxAge < 15552000) {
      // 180 days
      findings.push({
        ruleId: "HSTS_WEAK_MAX_AGE",
        title: "Strict-Transport-Security max-age is too short",
        severity: "LOW",
        confidence: "CONFIRMED",
        exposure: "BEST_PRACTICE",
        affectedUrl,
        description: `The HSTS header is present but max-age is only ${maxAge || 0} seconds, well under the recommended 6 months (15552000s), reducing its protective value.`,
        remediation: "Set max-age to at least 15552000 (180 days), ideally 31536000 with includeSubDomains and preload.",
        owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
        cweId: "CWE-319",
        source: SOURCE,
        detailKey: "Strict-Transport-Security",
        exploitability: "NOT_DEMONSTRATED",
      });
    }
  }

  const csp = getHeader(headers, "content-security-policy");
  const frameAncestorsInCsp = csp ? /frame-ancestors/i.test(csp) : false;
  if (!csp) {
    findings.push({
      ruleId: "CSP_MISSING",
      title: "Content-Security-Policy header is missing",
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      exposure: "BEST_PRACTICE",
      affectedUrl,
      description:
        "No Content-Security-Policy header was sent, so the browser has no restriction on which scripts/styles/frames the page may load, weakening defense-in-depth against XSS and data injection.",
      remediation:
        "Introduce a Content-Security-Policy tailored to the site's actual script/style/image sources, starting in report-only mode if needed.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      // No single CWE precisely captures "no CSP at all" without overstating
      // a specific weakness class — left unmapped rather than reusing the
      // clickjacking CWE (CWE-1021), which only applies to framing issues.
      source: SOURCE,
      detailKey: "Content-Security-Policy",
      exploitability: "NOT_DEMONSTRATED",
    });
  } else {
    // Per-directive analysis — never scans the whole CSP string for
    // 'unsafe-inline'/'unsafe-eval' as one undifferentiated blob (that would
    // misreport a style-src-only weakness as inline/eval script execution).
    findings.push(...analyzeCspDirectives(csp, affectedUrl));
  }

  const xfo = getHeader(headers, "x-frame-options");
  if (!xfo && !frameAncestorsInCsp) {
    findings.push({
      ruleId: "CLICKJACKING_PROTECTION_MISSING",
      title: "No clickjacking protection (X-Frame-Options / frame-ancestors)",
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      exposure: "CONFIG_WEAKNESS",
      affectedUrl,
      description:
        "Neither X-Frame-Options nor a CSP frame-ancestors directive was found, so the page can be embedded in an <iframe> on an attacker-controlled site for clickjacking.",
      remediation: 'Send "X-Frame-Options: DENY" or a CSP with "frame-ancestors \'none\'" (or a specific allow-list).',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-1021",
      source: SOURCE,
      detailKey: "X-Frame-Options",
      exploitability: "NOT_DEMONSTRATED",
    });
  } else if (xfo && !/^(deny|sameorigin)$/i.test(xfo.trim())) {
    findings.push({
      ruleId: "X_FRAME_OPTIONS_WEAK_VALUE",
      title: "X-Frame-Options has a non-standard value",
      severity: "LOW",
      confidence: "CONFIRMED",
      exposure: "BEST_PRACTICE",
      affectedUrl,
      description: `X-Frame-Options is set to "${xfo}", which is not DENY/SAMEORIGIN and may be ignored by some browsers.`,
      remediation: 'Use "X-Frame-Options: DENY" or "SAMEORIGIN", or migrate to CSP frame-ancestors.',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-1021",
      source: SOURCE,
      detailKey: "X-Frame-Options",
      exploitability: "NOT_DEMONSTRATED",
    });
  }

  const xcto = getHeader(headers, "x-content-type-options");
  if (!xcto || xcto.toLowerCase().trim() !== "nosniff") {
    findings.push({
      ruleId: "X_CONTENT_TYPE_OPTIONS_MISSING",
      title: "X-Content-Type-Options: nosniff is missing or incorrect",
      severity: "LOW",
      confidence: "CONFIRMED",
      exposure: "BEST_PRACTICE",
      affectedUrl,
      description: xcto
        ? `X-Content-Type-Options is set to "${xcto}" instead of "nosniff".`
        : "X-Content-Type-Options header is missing, allowing browsers to MIME-sniff responses.",
      remediation: 'Send "X-Content-Type-Options: nosniff" on all responses.',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-16",
      source: SOURCE,
      detailKey: "X-Content-Type-Options",
      exploitability: "NOT_DEMONSTRATED",
    });
  }

  const referrerPolicy = getHeader(headers, "referrer-policy");
  if (!referrerPolicy) {
    findings.push({
      ruleId: "REFERRER_POLICY_MISSING",
      title: "Referrer-Policy header is missing",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl,
      description: "No Referrer-Policy header was sent; the browser default may leak full URLs (including query strings) to third parties via the Referer header.",
      remediation: 'Send "Referrer-Policy: strict-origin-when-cross-origin" (a safe, widely-used default).',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-200",
      source: SOURCE,
      detailKey: "Referrer-Policy",
      exploitability: "NOT_DEMONSTRATED",
    });
  }

  const permissionsPolicy = getHeader(headers, "permissions-policy");
  if (!permissionsPolicy) {
    findings.push({
      ruleId: "PERMISSIONS_POLICY_MISSING",
      title: "Permissions-Policy header is missing",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl,
      description:
        "The header is not present. Permissions-Policy can restrict access to powerful browser features (camera, microphone, geolocation, etc.) for this origin, but the scan did not demonstrate an exploitable issue from its absence.",
      remediation: 'Send a Permissions-Policy header disabling unused features, e.g. "geolocation=(), camera=(), microphone=()".',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      // No specific CWE reliably applies to "a defense-in-depth header is
      // merely absent" — left unmapped rather than defaulting to CWE-693.
      source: SOURCE,
      detailKey: "Permissions-Policy",
      exploitability: "NOT_DEMONSTRATED",
    });
  }

  const coop = getHeader(headers, "cross-origin-opener-policy");
  if (!coop) {
    findings.push({
      ruleId: "COOP_MISSING",
      title: "Cross-Origin-Opener-Policy header is missing",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl,
      description:
        "The header is not present. COOP can provide additional browsing-context isolation, but the scan did not demonstrate an exploitable cross-origin issue.",
      remediation: 'Send "Cross-Origin-Opener-Policy: same-origin".',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      source: SOURCE,
      detailKey: "Cross-Origin-Opener-Policy",
      exploitability: "NOT_DEMONSTRATED",
    });
  }

  const corp = getHeader(headers, "cross-origin-resource-policy");
  if (!corp) {
    findings.push({
      ruleId: "CORP_MISSING",
      title: "Cross-Origin-Resource-Policy header is missing",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl,
      description:
        "The header is not present. CORP can restrict which origins may embed this resource, but the scan did not demonstrate an exploitable cross-origin issue from its absence.",
      remediation: 'Send "Cross-Origin-Resource-Policy: same-origin" (or "same-site") for responses that should not be cross-embedded.',
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      source: SOURCE,
      detailKey: "Cross-Origin-Resource-Policy",
      exploitability: "NOT_DEMONSTRATED",
    });
  }

  return findings;
}
