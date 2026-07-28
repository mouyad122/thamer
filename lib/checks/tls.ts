import type { PeerCertificate } from "node:tls";
import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";

const SOURCE = "Custom TLS Scanner";
const EXPIRY_WARNING_DAYS = 14;

export interface CertificateSummary {
  present: boolean;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  hostnameMatches: boolean | null;
}

function wildcardMatch(pattern: string, hostname: string): boolean {
  if (!pattern.startsWith("*.")) return pattern.toLowerCase() === hostname.toLowerCase();
  const suffix = pattern.slice(1).toLowerCase(); // ".example.com"
  const host = hostname.toLowerCase();
  if (!host.endsWith(suffix)) return false;
  // Wildcard covers exactly one label: "sub.example.com" matches, "a.sub.example.com" does not.
  const remainder = host.slice(0, -suffix.length);
  return remainder.length > 0 && !remainder.includes(".");
}

/** DN attributes (CN, O, ...) can be a single string or an array of strings per Node's types. */
function asSingleString(value: string | string[] | undefined): string | null {
  if (!value) return null;
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

function extractSanNames(cert: PeerCertificate): string[] {
  const san = cert.subjectaltname ?? "";
  return san
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.toLowerCase().startsWith("dns:"))
    .map((entry) => entry.slice(4).trim());
}

function hostnameMatchesCertificate(cert: PeerCertificate, hostname: string): boolean {
  const names = [...extractSanNames(cert)];
  const cn = asSingleString(cert.subject?.CN);
  if (cn) names.push(cn);
  return names.some((name) => wildcardMatch(name, hostname));
}

/** Builds a real, non-fabricated summary of the TLS certificate for display/report purposes. */
export function summarizeCertificate(
  cert: PeerCertificate | null,
  hostname: string,
): CertificateSummary {
  if (!cert || !cert.valid_from || !cert.valid_to) {
    return {
      present: false,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      hostnameMatches: null,
    };
  }
  const validTo = new Date(cert.valid_to);
  const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  return {
    present: true,
    issuer: asSingleString(cert.issuer?.O) ?? asSingleString(cert.issuer?.CN),
    subject: asSingleString(cert.subject?.CN),
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    daysRemaining,
    hostnameMatches: hostnameMatchesCertificate(cert, hostname),
  };
}

/**
 * Flags real, observed TLS certificate problems only (expiry, not-yet-valid,
 * hostname mismatch, near-expiry). No finding is invented if the certificate
 * checks out — an empty array is a genuinely good result, not a skipped check.
 */
export function analyzeTlsCertificate(
  cert: PeerCertificate | null,
  hostname: string,
  usedTls: boolean,
  affectedUrl: string,
): RawFinding[] {
  if (!usedTls) return [];
  const summary = summarizeCertificate(cert, hostname);
  if (!summary.present) return [];

  const findings: RawFinding[] = [];
  const now = Date.now();
  const validFromMs = summary.validFrom ? new Date(summary.validFrom).getTime() : NaN;
  const validToMs = summary.validTo ? new Date(summary.validTo).getTime() : NaN;

  if (!Number.isNaN(validToMs) && validToMs < now) {
    findings.push({
      ruleId: "TLS_CERTIFICATE_EXPIRED",
      title: "TLS certificate has expired",
      severity: "HIGH",
      confidence: "CONFIRMED",
      exposure: "DIRECT_PROVEN",
      affectedUrl,
      description: `The TLS certificate for this host expired on ${summary.validTo}, so browsers will show security warnings and encrypted transport can no longer be trusted.`,
      evidence: `valid_to=${summary.validTo}`,
      remediation: "Renew the TLS certificate immediately and verify automatic renewal (e.g. ACME/Let's Encrypt) is configured.",
      owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
      cweId: "CWE-298",
      source: SOURCE,
      detailKey: "certificate-expiry",
    });
  } else if (!Number.isNaN(validFromMs) && validFromMs > now) {
    findings.push({
      ruleId: "TLS_CERTIFICATE_NOT_YET_VALID",
      title: "TLS certificate is not yet valid",
      severity: "HIGH",
      confidence: "CONFIRMED",
      exposure: "DIRECT_PROVEN",
      affectedUrl,
      description: `The TLS certificate's validity period starts on ${summary.validFrom}, which is in the future relative to the scan time, indicating a misconfigured or clock-skewed deployment.`,
      evidence: `valid_from=${summary.validFrom}`,
      remediation: "Verify server/certificate issuance dates and system clock; reissue the certificate if needed.",
      owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
      cweId: "CWE-298",
      source: SOURCE,
      detailKey: "certificate-validity",
    });
  } else if (summary.daysRemaining !== null && summary.daysRemaining <= EXPIRY_WARNING_DAYS) {
    findings.push({
      ruleId: "TLS_CERTIFICATE_EXPIRING_SOON",
      title: "TLS certificate is expiring soon",
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      exposure: "CONFIG_WEAKNESS",
      affectedUrl,
      description: `The TLS certificate expires in ${summary.daysRemaining} day(s) (on ${summary.validTo}). Without timely renewal, the site will start failing TLS validation for visitors.`,
      evidence: `valid_to=${summary.validTo}, daysRemaining=${summary.daysRemaining}`,
      remediation: "Renew the certificate before expiry and confirm the renewal automation actually ran.",
      owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
      cweId: "CWE-298",
      source: SOURCE,
      detailKey: "certificate-expiry",
    });
  }

  if (summary.hostnameMatches === false) {
    findings.push({
      ruleId: "TLS_HOSTNAME_MISMATCH",
      title: "TLS certificate does not match the scanned hostname",
      severity: "HIGH",
      confidence: "CONFIRMED",
      exposure: "DIRECT_PROVEN",
      affectedUrl,
      description: `The certificate's subject/SAN entries do not include "${hostname}", so browsers will reject the connection as untrusted despite HTTPS being used.`,
      evidence: `subject=${summary.subject ?? "n/a"}`,
      remediation: "Issue a certificate that covers this exact hostname (or the correct wildcard), and ensure the web server presents it for this domain.",
      owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
      cweId: "CWE-297",
      source: SOURCE,
      detailKey: "hostname-mismatch",
    });
  }

  return findings;
}
