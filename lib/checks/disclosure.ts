import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";
import type { HeaderMap } from "./headers";

const SOURCE = "Custom Information Disclosure Scanner";

function getHeader(headers: HeaderMap, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(", ") : value;
}

const VERSIONED_SERVER_PATTERN = /\/(\d+\.[\d.]+)/; // e.g. "Apache/2.4.41", "nginx/1.18.0"

const STACK_TRACE_MARKERS = [
  /at\s+[\w.$]+\s+\(.*:\d+:\d+\)/, // Node.js stack frame
  /Traceback \(most recent call last\)/, // Python
  /Fatal error:.*on line \d+/i, // PHP
  /Microsoft\.\w+\.\w+Exception/, // .NET
  /org\.\w+\.\w+Exception/, // Java
  /Whitelabel Error Page/i, // Spring Boot default error page
  /django\.core\.exceptions/i,
];

/**
 * Flags real disclosures observed in headers/body only — a bare "Server:
 * nginx" with no version is treated as low-value informational, but an
 * exact version string (directly readable, so a real fingerprinting aid for
 * attackers picking known CVEs) is scored slightly higher, still capped at
 * LOW/INFORMATIONAL per project policy against over-scoring disclosure.
 */
export function analyzeInformationDisclosure(
  headers: HeaderMap,
  body: string,
  affectedUrl: string,
): RawFinding[] {
  const findings: RawFinding[] = [];

  const server = getHeader(headers, "server");
  if (server && VERSIONED_SERVER_PATTERN.test(server)) {
    findings.push({
      ruleId: "SERVER_VERSION_DISCLOSED",
      title: "Server header discloses a software version",
      severity: "LOW",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl,
      description: `The Server header value "${server}" reveals a specific software version, which helps an attacker narrow down known vulnerabilities for that exact version.`,
      evidence: `Server: ${server}`,
      remediation: "Configure the web server to omit or generalize the Server header (remove the version number).",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-200",
      source: SOURCE,
      detailKey: "Server",
    });
  }

  const poweredBy = getHeader(headers, "x-powered-by");
  if (poweredBy) {
    findings.push({
      ruleId: "X_POWERED_BY_DISCLOSED",
      title: "X-Powered-By header discloses backend technology",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl,
      description: `The X-Powered-By header value "${poweredBy}" reveals the backend framework/technology in use.`,
      evidence: `X-Powered-By: ${poweredBy}`,
      remediation: "Disable or remove the X-Powered-By header at the framework/server level.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-200",
      source: SOURCE,
      detailKey: "X-Powered-By",
    });
  }

  const stackTraceMatch = STACK_TRACE_MARKERS.find((pattern) => pattern.test(body));
  if (stackTraceMatch) {
    findings.push({
      ruleId: "ERROR_PAGE_DISCLOSURE",
      title: "Response body appears to contain a stack trace or debug error page",
      severity: "MEDIUM",
      confidence: "MEDIUM",
      exposure: "CONFIG_WEAKNESS",
      affectedUrl,
      description: "The page content matches patterns typical of framework debug/error pages (stack traces, exception class names), which can reveal file paths, library versions, and internal logic to an attacker.",
      remediation: "Disable debug/development error pages in production and return generic error responses instead.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-209",
      source: SOURCE,
      detailKey: "error-page",
    });
  }

  const generatorMeta = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (generatorMeta && generatorMeta[1]) {
    findings.push({
      ruleId: "GENERATOR_META_DISCLOSED",
      title: "HTML <meta name=\"generator\"> discloses CMS/framework details",
      severity: "INFORMATIONAL",
      confidence: "CONFIRMED",
      exposure: "INFORMATIONAL_ONLY",
      affectedUrl,
      description: `A generator meta tag advertises "${generatorMeta[1]}", helping attackers fingerprint the CMS/framework and its version.`,
      evidence: `<meta name="generator" content="${generatorMeta[1]}">`,
      remediation: "Remove the generator meta tag from the page template.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      cweId: "CWE-200",
      source: SOURCE,
      detailKey: "generator-meta",
    });
  }

  return findings;
}

/** Flags a real, confirmed exposed .map file (fetched and verified as JSON source-map content). */
export function buildSourceMapFinding(scriptUrl: string, mapUrl: string): RawFinding {
  return {
    ruleId: "SOURCE_MAP_EXPOSED",
    title: "Public JavaScript source map is exposed",
    severity: "LOW",
    confidence: "CONFIRMED",
    exposure: "BEST_PRACTICE",
    affectedUrl: mapUrl,
    description: `A source map for "${scriptUrl}" is publicly accessible at "${mapUrl}", exposing original (unminified) source code, comments, and file paths.`,
    remediation: "Do not deploy .map files to production, or restrict access to them (e.g. require authentication or block the path at the web server/CDN).",
    owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
    cweId: "CWE-540",
    source: SOURCE,
    detailKey: mapUrl,
  };
}
