import { describe, expect, it } from "vitest";
import { analyzeSecurityHeaders } from "../../lib/checks/headers";

describe("analyzeSecurityHeaders", () => {
  it("flags a fully missing header set on an HTTPS response", () => {
    const findings = analyzeSecurityHeaders({}, "https://example.com/", true);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("HSTS_MISSING");
    expect(ruleIds).toContain("CSP_MISSING");
    expect(ruleIds).toContain("CLICKJACKING_PROTECTION_MISSING");
    expect(ruleIds).toContain("X_CONTENT_TYPE_OPTIONS_MISSING");
    expect(ruleIds).toContain("REFERRER_POLICY_MISSING");
  });

  it("does not flag HSTS missing on a plain-HTTP response (not applicable)", () => {
    const findings = analyzeSecurityHeaders({}, "http://example.com/", false);
    expect(findings.map((f) => f.ruleId)).not.toContain("HSTS_MISSING");
  });

  it("does not flag headers that are present and well-configured", () => {
    const findings = analyzeSecurityHeaders(
      {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
      },
      "https://example.com/",
      true,
    );
    expect(findings).toHaveLength(0);
  });

  it("flags a weak CSP that allows unsafe-inline scripts (via default-src fallback)", () => {
    const findings = analyzeSecurityHeaders(
      { "content-security-policy": "default-src 'self' 'unsafe-inline'" },
      "https://example.com/",
      true,
    );
    expect(findings.map((f) => f.ruleId)).toContain("CSP_SCRIPT_UNSAFE_INLINE");
  });

  it("missing COOP alone is INFORMATIONAL with zero penalty impact", () => {
    const findings = analyzeSecurityHeaders(
      {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "cross-origin-resource-policy": "same-origin",
      },
      "https://example.com/",
      true,
    );
    const coop = findings.find((f) => f.ruleId === "COOP_MISSING");
    expect(coop).toBeDefined();
    expect(coop?.severity).toBe("INFORMATIONAL");
    expect(coop?.confidence).toBe("CONFIRMED");
    expect(coop?.exposure).toBe("INFORMATIONAL_ONLY");
    expect(coop?.description).not.toMatch(/enabling certain cross-origin attacks/i);
  });

  it("missing CORP alone is INFORMATIONAL", () => {
    const findings = analyzeSecurityHeaders(
      {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "cross-origin-opener-policy": "same-origin",
      },
      "https://example.com/",
      true,
    );
    const corp = findings.find((f) => f.ruleId === "CORP_MISSING");
    expect(corp?.severity).toBe("INFORMATIONAL");
  });

  it("missing Permissions-Policy alone is INFORMATIONAL and has no CWE-693 default mapping", () => {
    const findings = analyzeSecurityHeaders(
      {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-resource-policy": "same-origin",
      },
      "https://example.com/",
      true,
    );
    const permissionsPolicy = findings.find((f) => f.ruleId === "PERMISSIONS_POLICY_MISSING");
    expect(permissionsPolicy?.severity).toBe("INFORMATIONAL");
    expect(permissionsPolicy?.cweId).toBeUndefined();
  });

  it("uses CWE-1021 only for clickjacking/framing findings, never for COOP/CORP/Permissions-Policy", () => {
    const findings = analyzeSecurityHeaders({}, "https://example.com/", true);
    for (const f of findings) {
      if (f.cweId === "CWE-1021") {
        expect(["CLICKJACKING_PROTECTION_MISSING", "X_FRAME_OPTIONS_WEAK_VALUE"]).toContain(f.ruleId);
      }
      if (["COOP_MISSING", "CORP_MISSING", "PERMISSIONS_POLICY_MISSING"].includes(f.ruleId)) {
        expect(f.cweId).toBeUndefined();
      }
    }
  });

  it("OWASP mapping uses the 2025 category label, never a 2021 one", () => {
    const findings = analyzeSecurityHeaders({}, "https://example.com/", true);
    for (const f of findings) {
      if (f.owaspCategory) {
        expect(f.owaspCategory).not.toMatch(/2021/);
        expect(f.owaspCategory).toMatch(/2025/);
      }
    }
  });

  it("treats CSP frame-ancestors as satisfying clickjacking protection", () => {
    const findings = analyzeSecurityHeaders(
      { "content-security-policy": "frame-ancestors 'none'" },
      "https://example.com/",
      true,
    );
    expect(findings.map((f) => f.ruleId)).not.toContain("CLICKJACKING_PROTECTION_MISSING");
  });

  it("flags a short HSTS max-age as weak, not missing", () => {
    const findings = analyzeSecurityHeaders(
      { "strict-transport-security": "max-age=60" },
      "https://example.com/",
      true,
    );
    expect(findings.map((f) => f.ruleId)).toContain("HSTS_WEAK_MAX_AGE");
    expect(findings.map((f) => f.ruleId)).not.toContain("HSTS_MISSING");
  });

  it("missing optional headers (Referrer-Policy, Permissions-Policy, CORP) are informational only", () => {
    const findings = analyzeSecurityHeaders(
      {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "cross-origin-opener-policy": "same-origin",
      },
      "https://example.com/",
      true,
    );
    for (const f of findings) {
      expect(f.severity).toBe("INFORMATIONAL");
    }
  });
});
