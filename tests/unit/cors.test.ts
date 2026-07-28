import { describe, expect, it } from "vitest";
import { analyzeCors } from "../../lib/checks/cors";

const ORIGIN = "https://untrusted-scan-probe.example.org";

describe("analyzeCors", () => {
  it("returns no findings when Access-Control-Allow-Origin is absent", () => {
    const findings = analyzeCors(
      { requestOrigin: ORIGIN, accessControlAllowOrigin: undefined, accessControlAllowCredentials: undefined },
      "https://example.com/",
    );
    expect(findings).toHaveLength(0);
  });

  it("does NOT auto-escalate a bare wildcard (no credentials) to High severity", () => {
    const findings = analyzeCors(
      { requestOrigin: ORIGIN, accessControlAllowOrigin: "*", accessControlAllowCredentials: undefined },
      "https://example.com/",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("INFORMATIONAL");
  });

  it("flags reflected origin + credentials=true as HIGH and CONFIRMED (proven exploit)", () => {
    const findings = analyzeCors(
      { requestOrigin: ORIGIN, accessControlAllowOrigin: ORIGIN, accessControlAllowCredentials: "true" },
      "https://example.com/",
    );
    expect(findings[0]!.ruleId).toBe("CORS_CREDENTIALED_ANY_ORIGIN");
    expect(findings[0]!.severity).toBe("HIGH");
    expect(findings[0]!.confidence).toBe("CONFIRMED");
  });

  it("flags wildcard + credentials=true as HIGH as well", () => {
    const findings = analyzeCors(
      { requestOrigin: ORIGIN, accessControlAllowOrigin: "*", accessControlAllowCredentials: "true" },
      "https://example.com/",
    );
    expect(findings[0]!.ruleId).toBe("CORS_CREDENTIALED_ANY_ORIGIN");
  });

  it("flags reflected origin without credentials as MEDIUM, not HIGH", () => {
    const findings = analyzeCors(
      { requestOrigin: ORIGIN, accessControlAllowOrigin: ORIGIN, accessControlAllowCredentials: undefined },
      "https://example.com/",
    );
    expect(findings[0]!.ruleId).toBe("CORS_ORIGIN_REFLECTION");
    expect(findings[0]!.severity).toBe("MEDIUM");
  });

  it("does not flag a specific, non-reflected allow-listed origin", () => {
    const findings = analyzeCors(
      {
        requestOrigin: ORIGIN,
        accessControlAllowOrigin: "https://trusted-partner.example.com",
        accessControlAllowCredentials: "true",
      },
      "https://example.com/",
    );
    expect(findings).toHaveLength(0);
  });
});
