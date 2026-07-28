import { describe, expect, it } from "vitest";
import { analyzeCookies, classifyCookieSensitivity, parseSetCookies } from "../../lib/checks/cookies";
import { computePenalty } from "../../lib/scoring";

describe("parseSetCookies", () => {
  it("extracts name and attributes without exposing the cookie value", () => {
    const [cookie] = parseSetCookies(["sessionid=SECRETVALUE123; Path=/; HttpOnly; Secure; SameSite=Lax"]);
    expect(cookie!.name).toBe("sessionid");
    expect(cookie!.secure).toBe(true);
    expect(cookie!.httpOnly).toBe(true);
    expect(cookie!.sameSite).toBe("Lax");
    expect(cookie!.path).toBe("/");
    expect(JSON.stringify(cookie)).not.toContain("SECRETVALUE123");
  });

  it("defaults missing attributes to false/null", () => {
    const [cookie] = parseSetCookies(["theme=dark"]);
    expect(cookie!.secure).toBe(false);
    expect(cookie!.httpOnly).toBe(false);
    expect(cookie!.sameSite).toBeNull();
  });
});

describe("analyzeCookies", () => {
  it("returns no findings when no Set-Cookie headers are present", () => {
    expect(analyzeCookies(undefined, "https://example.com/", true)).toHaveLength(0);
  });

  it("flags a session-like cookie missing Secure/HttpOnly/SameSite as MEDIUM", () => {
    const findings = analyzeCookies(["sessionid=abc123"], "https://example.com/", true);
    const secureFinding = findings.find((f) => f.ruleId === "COOKIE_MISSING_SECURE");
    const httpOnlyFinding = findings.find((f) => f.ruleId === "COOKIE_MISSING_HTTPONLY");
    expect(secureFinding?.severity).toBe("MEDIUM");
    expect(httpOnlyFinding?.severity).toBe("MEDIUM");
  });

  it("a known non-sensitive cookie (GitHub's _octo) missing HttpOnly does not deduct from the score", () => {
    const findings = analyzeCookies(["_octo=GH1.1.abc123; Path=/"], "https://example.com/", true);
    const httpOnlyFinding = findings.find((f) => f.ruleId === "COOKIE_MISSING_HTTPONLY");
    expect(httpOnlyFinding).toBeDefined();
    expect(httpOnlyFinding?.severity).toBe("INFORMATIONAL");
    expect(httpOnlyFinding?.confidence).toBe("MEDIUM");
    expect(httpOnlyFinding?.exposure).toBe("INFORMATIONAL_ONLY");
    expect(httpOnlyFinding?.reviewStatus).toBe("REQUIRES_MANUAL_REVIEW");
    expect(httpOnlyFinding?.description).toBe(
      "The cookie does not use HttpOnly, but the scanner could not confirm that it stores sensitive or authentication data. This is reported for manual review and does not affect the score.",
    );
    expect(httpOnlyFinding?.cweId).toBeUndefined();
    // Confirm this really is zero-penalty through the actual scoring formula, not just by severity label.
    expect(computePenalty({ ...httpOnlyFinding!, occurrences: 1 }).finalPenalty).toBe(0);
  });

  it("an unrecognized/unknown cookie name missing HttpOnly also does not deduct (sensitivity unconfirmed)", () => {
    const findings = analyzeCookies(["xk7f2a=zzz"], "https://example.com/", true);
    const httpOnlyFinding = findings.find((f) => f.ruleId === "COOKIE_MISSING_HTTPONLY");
    expect(httpOnlyFinding?.severity).toBe("INFORMATIONAL");
    expect(computePenalty({ ...httpOnlyFinding!, occurrences: 1 }).finalPenalty).toBe(0);
  });

  it("a confirmed sensitive session cookie missing HttpOnly DOES deduct from the score", () => {
    const findings = analyzeCookies(["sessionid=abc123"], "https://example.com/", true);
    const httpOnlyFinding = findings.find((f) => f.ruleId === "COOKIE_MISSING_HTTPONLY");
    expect(httpOnlyFinding?.severity).toBe("MEDIUM");
    expect(httpOnlyFinding?.confidence).toBe("CONFIRMED");
    expect(httpOnlyFinding?.cweId).toBe("CWE-1004");
    expect(computePenalty({ ...httpOnlyFinding!, occurrences: 1 }).finalPenalty).toBeGreaterThan(0);
  });

  it("classifies cookie names into sensitivity tiers by name only", () => {
    expect(classifyCookieSensitivity("sessionid")).toBe("SENSITIVE_AUTH");
    expect(classifyCookieSensitivity("auth_token")).toBe("SENSITIVE_AUTH");
    expect(classifyCookieSensitivity("_octo")).toBe("FUNCTIONAL");
    expect(classifyCookieSensitivity("theme")).toBe("FUNCTIONAL");
    expect(classifyCookieSensitivity("account_ref")).toBe("LIKELY_SENSITIVE");
    expect(classifyCookieSensitivity("xk7f2a")).toBe("UNKNOWN");
  });

  it("does not flag Secure when the cookie is already fully secure", () => {
    const findings = analyzeCookies(
      ["sessionid=abc; Secure; HttpOnly; SameSite=Strict"],
      "https://example.com/",
      true,
    );
    expect(findings).toHaveLength(0);
  });

  it("flags SameSite=None without Secure as a real, direct issue", () => {
    const findings = analyzeCookies(["sessionid=abc; SameSite=None"], "https://example.com/", true);
    expect(findings.map((f) => f.ruleId)).toContain("COOKIE_SAMESITE_NONE_INSECURE");
  });

  it("never includes the cookie's raw value in any finding field", () => {
    const findings = analyzeCookies(["sessionid=TOP_SECRET_VALUE"], "https://example.com/", true);
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain("TOP_SECRET_VALUE");
  });
});
