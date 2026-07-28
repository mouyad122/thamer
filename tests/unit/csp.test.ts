import { describe, expect, it } from "vitest";
import { analyzeCspDirectives, parseCsp } from "../../lib/checks/csp";

const GITHUB_LIKE_CSP =
  "default-src 'none'; script-src github.githubassets.com; style-src 'unsafe-inline' github.githubassets.com; frame-ancestors 'none'";

describe("parseCsp", () => {
  it("splits directives and their value lists", () => {
    const directives = parseCsp(GITHUB_LIKE_CSP);
    expect(directives["default-src"]).toEqual(["'none'"]);
    expect(directives["script-src"]).toEqual(["github.githubassets.com"]);
    expect(directives["style-src"]).toEqual(["'unsafe-inline'", "github.githubassets.com"]);
    expect(directives["frame-ancestors"]).toEqual(["'none'"]);
  });
});

describe("analyzeCspDirectives — GitHub-like policy fixture (mandated test)", () => {
  const findings = analyzeCspDirectives(GITHUB_LIKE_CSP, "https://github.com/");
  const ruleIds = findings.map((f) => f.ruleId);

  it("does NOT detect script-src unsafe-inline", () => {
    expect(ruleIds).not.toContain("CSP_SCRIPT_UNSAFE_INLINE");
  });

  it("does NOT detect unsafe-eval anywhere", () => {
    expect(ruleIds).not.toContain("CSP_SCRIPT_UNSAFE_EVAL");
  });

  it("detects ONLY style-src unsafe-inline", () => {
    expect(ruleIds).toEqual(["CSP_STYLE_UNSAFE_INLINE"]);
  });

  it("the description never mentions inline/eval JavaScript execution", () => {
    const styleFinding = findings.find((f) => f.ruleId === "CSP_STYLE_UNSAFE_INLINE")!;
    expect(styleFinding.description.toLowerCase()).not.toContain("inline javascript execution");
    expect(styleFinding.description.toLowerCase()).not.toContain("eval");
    expect(styleFinding.title).not.toMatch(/inline\/eval scripts?/i);
  });

  it("severity is LOW/INFORMATIONAL, never MEDIUM-for-script-execution", () => {
    const styleFinding = findings.find((f) => f.ruleId === "CSP_STYLE_UNSAFE_INLINE")!;
    expect(["LOW", "INFORMATIONAL"]).toContain(styleFinding.severity);
  });

  it("matches the exact evidence/title/confidence specified for this fixture", () => {
    const styleFinding = findings.find((f) => f.ruleId === "CSP_STYLE_UNSAFE_INLINE")!;
    expect(styleFinding.title).toBe("CSP allows inline styles");
    expect(styleFinding.confidence).toBe("CONFIRMED");
    expect(styleFinding.evidence).toBe("style-src contains 'unsafe-inline'");
  });

  it("attaches the full raw CSP only as rawEvidence, never inlined into the description", () => {
    const styleFinding = findings.find((f) => f.ruleId === "CSP_STYLE_UNSAFE_INLINE")!;
    expect(styleFinding.rawEvidence).toBe(GITHUB_LIKE_CSP);
    expect(styleFinding.description).not.toContain("script-src github.githubassets.com");
  });
});

describe("analyzeCspDirectives — other cases", () => {
  it("detects script-src unsafe-inline when actually present in script-src", () => {
    const findings = analyzeCspDirectives("script-src 'unsafe-inline'", "https://example.com/");
    expect(findings.map((f) => f.ruleId)).toContain("CSP_SCRIPT_UNSAFE_INLINE");
    expect(findings.map((f) => f.ruleId)).not.toContain("CSP_STYLE_UNSAFE_INLINE");
  });

  it("detects script-src unsafe-eval only when actually present", () => {
    const findings = analyzeCspDirectives("script-src 'unsafe-eval' https://cdn.example.com", "https://example.com/");
    expect(findings.map((f) => f.ruleId)).toContain("CSP_SCRIPT_UNSAFE_EVAL");
  });

  it("inherits unsafe-inline from default-src when script-src is not set", () => {
    const findings = analyzeCspDirectives("default-src 'unsafe-inline'", "https://example.com/");
    expect(findings.map((f) => f.ruleId)).toContain("CSP_SCRIPT_UNSAFE_INLINE");
    expect(findings.map((f) => f.ruleId)).toContain("CSP_STYLE_UNSAFE_INLINE");
  });

  it("does not flag anything for a clean, restrictive policy", () => {
    const findings = analyzeCspDirectives("default-src 'self'; script-src 'self'; style-src 'self'", "https://example.com/");
    expect(findings).toHaveLength(0);
  });

  it("never guesses a CWE for CSP directive weaknesses (accuracy over a wrong number)", () => {
    const findings = analyzeCspDirectives(GITHUB_LIKE_CSP + "; script-src 'unsafe-inline' 'unsafe-eval'", "https://example.com/");
    for (const f of findings) {
      expect(f.cweId).toBeUndefined();
    }
  });

  it("uses the 2025 OWASP category label", () => {
    const findings = analyzeCspDirectives("script-src 'unsafe-inline'", "https://example.com/");
    expect(findings[0]!.owaspCategory).toBe("A02:2025 - Security Misconfiguration");
  });
});
