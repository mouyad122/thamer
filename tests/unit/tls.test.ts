import { describe, expect, it } from "vitest";
import type { PeerCertificate } from "node:tls";
import { analyzeTlsCertificate, summarizeCertificate } from "../../lib/checks/tls";

function cert(overrides: Partial<PeerCertificate> = {}): PeerCertificate {
  const now = Date.now();
  return {
    subject: { CN: "example.com" },
    issuer: { CN: "Test CA", O: "Test CA Org" },
    subjectaltname: "DNS:example.com, DNS:www.example.com",
    valid_from: new Date(now - 30 * 86400000).toUTCString(),
    valid_to: new Date(now + 60 * 86400000).toUTCString(),
    ...overrides,
  } as PeerCertificate;
}

describe("summarizeCertificate", () => {
  it("returns present=false when no certificate was captured", () => {
    expect(summarizeCertificate(null, "example.com").present).toBe(false);
  });

  it("computes daysRemaining and hostname match for a healthy certificate", () => {
    const summary = summarizeCertificate(cert(), "example.com");
    expect(summary.present).toBe(true);
    expect(summary.hostnameMatches).toBe(true);
    expect(summary.daysRemaining).toBeGreaterThan(50);
  });

  it("matches a wildcard SAN against a subdomain", () => {
    const summary = summarizeCertificate(
      cert({ subjectaltname: "DNS:*.example.com", subject: { CN: "*.example.com" } }),
      "app.example.com",
    );
    expect(summary.hostnameMatches).toBe(true);
  });

  it("does not match a wildcard SAN against the bare apex domain", () => {
    const summary = summarizeCertificate(
      cert({ subjectaltname: "DNS:*.example.com", subject: { CN: "*.example.com" } }),
      "example.com",
    );
    expect(summary.hostnameMatches).toBe(false);
  });
});

describe("analyzeTlsCertificate", () => {
  it("returns no findings for a healthy, matching, non-expiring certificate", () => {
    const findings = analyzeTlsCertificate(cert(), "example.com", true, "https://example.com/");
    expect(findings).toHaveLength(0);
  });

  it("flags an expired certificate as HIGH/CONFIRMED", () => {
    const expired = cert({
      valid_from: new Date(Date.now() - 400 * 86400000).toUTCString(),
      valid_to: new Date(Date.now() - 5 * 86400000).toUTCString(),
    });
    const findings = analyzeTlsCertificate(expired, "example.com", true, "https://example.com/");
    expect(findings.map((f) => f.ruleId)).toContain("TLS_CERTIFICATE_EXPIRED");
    expect(findings[0]!.severity).toBe("HIGH");
    expect(findings[0]!.confidence).toBe("CONFIRMED");
  });

  it("flags a certificate expiring within 14 days as MEDIUM, not HIGH", () => {
    const soon = cert({ valid_to: new Date(Date.now() + 5 * 86400000).toUTCString() });
    const findings = analyzeTlsCertificate(soon, "example.com", true, "https://example.com/");
    expect(findings.map((f) => f.ruleId)).toContain("TLS_CERTIFICATE_EXPIRING_SOON");
    expect(findings[0]!.severity).toBe("MEDIUM");
  });

  it("flags a hostname mismatch", () => {
    const findings = analyzeTlsCertificate(cert(), "not-the-cert-host.com", true, "https://not-the-cert-host.com/");
    expect(findings.map((f) => f.ruleId)).toContain("TLS_HOSTNAME_MISMATCH");
  });

  it("returns no findings when the connection did not use TLS at all", () => {
    expect(analyzeTlsCertificate(cert(), "example.com", false, "http://example.com/")).toHaveLength(0);
  });
});
