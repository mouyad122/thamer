import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";

const SOURCE = "Custom CORS Scanner";

export interface CorsProbeResult {
  requestOrigin: string;
  accessControlAllowOrigin: string | undefined;
  accessControlAllowCredentials: string | undefined;
}

/**
 * Analyzes a CORS probe made with a deliberately untrusted Origin header.
 * A reflected/wildcard Access-Control-Allow-Origin is only escalated to
 * HIGH when it is proven exploitable (an arbitrary origin is allowed AND
 * credentials are allowed) — a bare "*" on a public resource is normal and
 * is reported as informational, per project policy against inflating
 * severity for common, often-intentional configurations.
 */
export function analyzeCors(probe: CorsProbeResult, affectedUrl: string): RawFinding[] {
  const { requestOrigin, accessControlAllowOrigin: acao, accessControlAllowCredentials: acac } = probe;
  if (!acao) return [];

  const credentialsAllowed = (acac ?? "").toLowerCase().trim() === "true";
  const reflectsUntrustedOrigin = acao.trim() === requestOrigin;
  const isWildcard = acao.trim() === "*";

  if ((reflectsUntrustedOrigin || isWildcard) && credentialsAllowed) {
    return [
      {
        ruleId: "CORS_CREDENTIALED_ANY_ORIGIN",
        title: "CORS allows an arbitrary origin to read credentialed responses",
        severity: "HIGH",
        confidence: "CONFIRMED",
        exposure: "DIRECT_PROVEN",
        affectedUrl,
        description: `A request with Origin "${requestOrigin}" (not a real related site) received "Access-Control-Allow-Origin: ${acao}" together with "Access-Control-Allow-Credentials: true". This lets any website read authenticated responses (cookies/session) from this origin on behalf of a logged-in victim.`,
        evidence: `Request Origin: ${requestOrigin} -> Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: ${acac}`,
        remediation:
          "Never combine a wildcard or reflected Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true. Maintain an explicit allow-list of trusted origins for any credentialed endpoint.",
        owaspCategory: owaspLabel("BROKEN_ACCESS_CONTROL"),
        cweId: "CWE-942",
        source: SOURCE,
        detailKey: "Access-Control-Allow-Origin",
      },
    ];
  }

  if (reflectsUntrustedOrigin && !isWildcard) {
    return [
      {
        ruleId: "CORS_ORIGIN_REFLECTION",
        title: "CORS reflects arbitrary request Origin without an allow-list",
        severity: "MEDIUM",
        confidence: "CONFIRMED",
        exposure: "CONFIG_WEAKNESS",
        affectedUrl,
        description: `The server echoed back an unrelated test Origin ("${requestOrigin}") verbatim in Access-Control-Allow-Origin instead of validating it against a known allow-list, which is functionally equivalent to a wildcard for read access to non-credentialed responses.`,
        evidence: `Request Origin: ${requestOrigin} -> Access-Control-Allow-Origin: ${acao}`,
        remediation: "Validate the Origin header against an explicit allow-list before reflecting it back, rather than mirroring any value received.",
        owaspCategory: owaspLabel("BROKEN_ACCESS_CONTROL"),
        cweId: "CWE-942",
        source: SOURCE,
        detailKey: "Access-Control-Allow-Origin",
      },
    ];
  }

  if (isWildcard) {
    return [
      {
        ruleId: "CORS_WILDCARD",
        title: "Access-Control-Allow-Origin is a wildcard (*)",
        severity: "INFORMATIONAL",
        confidence: "CONFIRMED",
        exposure: "INFORMATIONAL_ONLY",
        affectedUrl,
        description: "Access-Control-Allow-Origin is \"*\". Without Allow-Credentials this is a common and often intentional setting for public resources/APIs, not a vulnerability by itself.",
        evidence: `Access-Control-Allow-Origin: ${acao}`,
        remediation: "If this endpoint ever returns non-public or per-user data, replace the wildcard with an explicit origin allow-list.",
        owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
        cweId: "CWE-942",
        source: SOURCE,
        detailKey: "Access-Control-Allow-Origin",
      },
    ];
  }

  return [];
}
