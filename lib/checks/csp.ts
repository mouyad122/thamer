import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";

const SOURCE = "Custom Header Scanner";

export type CspDirectives = Record<string, string[]>;

/** Parses a raw Content-Security-Policy header into { directiveName: [values] }, lowercasing directive names only. */
export function parseCsp(header: string): CspDirectives {
  const directives: CspDirectives = {};
  for (const rawPart of header.split(";")) {
    const part = rawPart.trim();
    if (!part) continue;
    const [name, ...values] = part.split(/\s+/);
    if (!name) continue;
    directives[name.toLowerCase()] = values;
  }
  return directives;
}

/**
 * Resolves the *effective* source list for a fetch directive, applying CSP's
 * own fallback rule: `script-src` and `style-src` each fall back to
 * `default-src` when not explicitly set. This is the difference between
 * correctly reading a policy and wrongly scanning the raw header text for
 * keywords regardless of which directive they appear under.
 */
function effectiveDirective(directives: CspDirectives, name: "script-src" | "style-src"): string[] | null {
  if (directives[name]) return directives[name];
  if (directives["default-src"]) return directives["default-src"];
  return null;
}

function hasKeyword(values: string[], keyword: string): boolean {
  return values.some((v) => v.toLowerCase() === keyword);
}

/**
 * Per-directive CSP analysis. Each weakening keyword is attributed only to
 * the directive it actually appears in (or inherits into via `default-src`
 * fallback) — `style-src 'unsafe-inline'` is reported as an inline-*styles*
 * weakness, never as inline/eval *script* execution, and `'unsafe-eval'` is
 * never mentioned unless it is genuinely present in an effective
 * `script-src`. The full policy is attached as `rawEvidence` only, for an
 * expandable "Raw Evidence" section — never spelled out inside the
 * description itself.
 */
export function analyzeCspDirectives(cspHeader: string, affectedUrl: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const directives = parseCsp(cspHeader);

  const scriptSrc = effectiveDirective(directives, "script-src");
  const styleSrc = effectiveDirective(directives, "style-src");

  if (scriptSrc && hasKeyword(scriptSrc, "'unsafe-inline'")) {
    findings.push({
      ruleId: "CSP_SCRIPT_UNSAFE_INLINE",
      title: "CSP allows inline JavaScript execution",
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      exposure: "CONFIG_WEAKNESS",
      affectedUrl,
      description:
        "The script-src directive (or the default-src it falls back to) includes 'unsafe-inline', allowing inline <script> execution. This removes one of CSP's main protections against script injection.",
      evidence: "script-src contains 'unsafe-inline'",
      rawEvidence: cspHeader,
      remediation: "Remove 'unsafe-inline' from script-src and use nonces or hashes for any required inline scripts.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      source: SOURCE,
      detailKey: "script-src:unsafe-inline",
    });
  }

  if (scriptSrc && hasKeyword(scriptSrc, "'unsafe-eval'")) {
    findings.push({
      ruleId: "CSP_SCRIPT_UNSAFE_EVAL",
      title: "CSP allows JavaScript eval()-family execution",
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      exposure: "CONFIG_WEAKNESS",
      affectedUrl,
      description:
        "The script-src directive (or the default-src it falls back to) includes 'unsafe-eval', allowing eval()/Function()/similar dynamic code execution, which widens the attack surface for script injection.",
      evidence: "script-src contains 'unsafe-eval'",
      rawEvidence: cspHeader,
      remediation: "Remove 'unsafe-eval' from script-src; refactor code that depends on eval()-style execution.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      source: SOURCE,
      detailKey: "script-src:unsafe-eval",
    });
  }

  if (styleSrc && hasKeyword(styleSrc, "'unsafe-inline'")) {
    findings.push({
      ruleId: "CSP_STYLE_UNSAFE_INLINE",
      title: "CSP allows inline styles",
      severity: "LOW",
      confidence: "CONFIRMED",
      exposure: "BEST_PRACTICE",
      affectedUrl,
      description:
        "The style-src directive (or the default-src it falls back to) includes 'unsafe-inline'. This weakens style restrictions but does not permit inline JavaScript — it has no bearing on script execution.",
      evidence: "style-src contains 'unsafe-inline'",
      rawEvidence: cspHeader,
      remediation: "Remove 'unsafe-inline' from style-src and use nonces or hashes for required inline styles, if feasible.",
      owaspCategory: owaspLabel("SECURITY_MISCONFIGURATION"),
      source: SOURCE,
      detailKey: "style-src:unsafe-inline",
    });
  }

  return findings;
}
