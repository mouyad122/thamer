import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";
import { safeFetch } from "../safe-fetch";

const SOURCE = "Custom Common Files Scanner";

/**
 * Checks a short, fixed, non-destructive list of well-known files — no brute
 * force, no attempts at private/sensitive paths. Missing files here are only
 * ever INFORMATIONAL and never reduce the score (severity points = 0),
 * matching project policy that optional/best-practice files must not be
 * treated as real vulnerabilities.
 */
export async function checkCommonSafeFiles(baseUrl: string): Promise<RawFinding[]> {
  const findings: RawFinding[] = [];
  const origin = new URL(baseUrl).origin;

  const robotsPresent = await isReachable(`${origin}/robots.txt`);
  if (!robotsPresent) {
    findings.push({
      ruleId: "ROBOTS_TXT_MISSING",
      title: "robots.txt is missing",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl: `${origin}/robots.txt`,
      description: "No robots.txt was found at the site root. This is purely informational and does not indicate a vulnerability.",
      remediation: "Optional: add a robots.txt to control search engine crawling behavior.",
      source: SOURCE,
      detailKey: "robots.txt",
    });
  }

  const securityTxtPresent =
    (await isReachable(`${origin}/.well-known/security.txt`)) ||
    (await isReachable(`${origin}/security.txt`));
  if (!securityTxtPresent) {
    findings.push({
      ruleId: "SECURITY_TXT_MISSING",
      title: "security.txt is missing",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl: `${origin}/.well-known/security.txt`,
      description: "No security.txt (RFC 9116) was found, so security researchers have no documented way to responsibly report vulnerabilities to this site.",
      remediation: "Optional: publish a /.well-known/security.txt with a contact and disclosure policy.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      source: SOURCE,
      detailKey: "security.txt",
    });
  }

  return findings;
}

async function isReachable(url: string): Promise<boolean> {
  try {
    const response = await safeFetch(url, { timeoutMs: 5000 });
    return response.status >= 200 && response.status < 400;
  } catch {
    return false;
  }
}
