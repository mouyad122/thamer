import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";

const SOURCE = "Custom Cookie Scanner";

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None" | null;
  domain: string | null;
  path: string | null;
}

/**
 * How confident the scanner is that a cookie actually carries sensitive
 * session/authentication state, based on its name only (values are never
 * inspected). Only `SENSITIVE_AUTH` is treated as proven enough to justify a
 * real, score-affecting finding for missing Secure/HttpOnly/SameSite — the
 * other three tiers produce a zero-penalty note for manual review instead of
 * an unproven claim of impact.
 */
export type CookieSensitivity = "SENSITIVE_AUTH" | "LIKELY_SENSITIVE" | "FUNCTIONAL" | "UNKNOWN";

/** Strong, conservative signal that a cookie name is session/auth-related. */
const SENSITIVE_AUTH_PATTERN =
  /(sess|sid|auth|token|jwt|jsessionid|phpsessid|connect\.sid|_session|csrftoken|xsrf|bearer|access[-_]?token|refresh[-_]?token)/i;

/**
 * Well-known non-auth cookie name patterns (analytics/preferences/device
 * IDs) that are commonly read by client-side JavaScript by design. `_octo`
 * is GitHub's own device-identifier cookie and is included here as a named,
 * concrete example rather than left to fall through to the generic
 * "unknown" bucket.
 */
const KNOWN_FUNCTIONAL_PATTERN =
  /^(_ga|_gid|_gat|_fbp|_octo|_hp2|_dd_s|_pk_id|_pk_ses)(_|$)|^(theme|color[-_]?scheme|locale|lang|language|consent|cookie[-_]?consent|preferences?)$/i;

/** Ambiguous names that plausibly relate to user/account state without matching the strong auth pattern. */
const LIKELY_SENSITIVE_PATTERN = /(user|account|acct|profile|remember|logged[-_]?in|cart|order)/i;

/** Classifies a cookie by name only — never by inspecting its value. */
export function classifyCookieSensitivity(name: string): CookieSensitivity {
  if (SENSITIVE_AUTH_PATTERN.test(name)) return "SENSITIVE_AUTH";
  if (KNOWN_FUNCTIONAL_PATTERN.test(name)) return "FUNCTIONAL";
  if (LIKELY_SENSITIVE_PATTERN.test(name)) return "LIKELY_SENSITIVE";
  return "UNKNOWN";
}

/** Parses raw Set-Cookie header strings into structured attributes. Never returns cookie values. */
export function parseSetCookies(setCookieHeaders: string[]): ParsedCookie[] {
  return setCookieHeaders.map((raw) => {
    const parts = raw.split(";").map((p) => p.trim());
    const [nameValue, ...attrParts] = parts;
    const name = (nameValue ?? "").split("=")[0]?.trim() ?? "unknown";

    let secure = false;
    let httpOnly = false;
    let sameSite: ParsedCookie["sameSite"] = null;
    let domain: string | null = null;
    let path: string | null = null;

    for (const attr of attrParts) {
      const [key, value] = attr.split("=").map((s) => s.trim());
      const lowerKey = key?.toLowerCase();
      if (lowerKey === "secure") secure = true;
      else if (lowerKey === "httponly") httpOnly = true;
      else if (lowerKey === "samesite" && value) {
        const normalized = value.toLowerCase();
        if (normalized === "strict") sameSite = "Strict";
        else if (normalized === "lax") sameSite = "Lax";
        else if (normalized === "none") sameSite = "None";
      } else if (lowerKey === "domain" && value) domain = value;
      else if (lowerKey === "path" && value) path = value;
    }

    return { name, secure, httpOnly, sameSite, domain, path };
  });
}

type AttributeKind = "Secure" | "HttpOnly" | "SameSite";

const ATTRIBUTE_CWE: Record<AttributeKind, string> = {
  Secure: "CWE-614",
  HttpOnly: "CWE-1004",
  SameSite: "CWE-352",
};

const ATTRIBUTE_IMPACT_TEXT: Record<AttributeKind, string> = {
  Secure: "could still be sent over an accidental plain-HTTP request",
  HttpOnly: "could be read by JavaScript, so a successful XSS on this site could steal it",
  SameSite: "relies on browser defaults for CSRF-relevant cross-site behavior",
};

/**
 * Builds either a real, score-affecting finding (cookie name is confirmed
 * session/auth-like) or a zero-penalty, manual-review note (sensitivity
 * could not be confirmed) for a missing cookie attribute. This is the single
 * place that decides whether a missing attribute is treated as a proven
 * issue or an open question — no cookie without a confirmed sensitive name
 * is ever scored as if XSS/CSRF impact were demonstrated.
 */
function buildAttributeFinding(
  attribute: AttributeKind,
  cookieName: string,
  sensitivity: CookieSensitivity,
  affectedUrl: string,
): RawFinding {
  const ruleId = `COOKIE_MISSING_${attribute.toUpperCase()}`;
  const title = `Cookie "${cookieName}" is missing the ${attribute} attribute`;

  if (sensitivity === "SENSITIVE_AUTH") {
    return {
      ruleId,
      title,
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      exposure: attribute === "SameSite" ? "CONFIG_WEAKNESS" : "CONFIG_WEAKNESS",
      affectedUrl,
      description: `Cookie "${cookieName}" ${ATTRIBUTE_IMPACT_TEXT[attribute]}. This cookie's name matches a known session/authentication pattern, so the practical impact of the missing ${attribute} attribute is meaningful.`,
      remediation: `Set the ${attribute} attribute on cookie "${cookieName}"${attribute === "SameSite" ? " (Lax or Strict, or None with Secure if it must be sent cross-site)" : ""}.`,
      owaspCategory: owaspLabel(attribute === "SameSite" ? "BROKEN_ACCESS_CONTROL" : "SECURITY_MISCONFIGURATION"),
      cweId: ATTRIBUTE_CWE[attribute],
      source: SOURCE,
      detailKey: cookieName,
    };
  }

  return {
    ruleId,
    title,
    severity: "INFORMATIONAL",
    confidence: "MEDIUM",
    exposure: "INFORMATIONAL_ONLY",
    affectedUrl,
    description: `The cookie does not use ${attribute}, but the scanner could not confirm that it stores sensitive or authentication data. This is reported for manual review and does not affect the score.`,
    remediation: `If cookie "${cookieName}" ever carries session/authentication state, set the ${attribute} attribute; otherwise no action is required.`,
    // No CWE/OWASP mapping is attached — attaching one would assert a
    // vulnerability class (e.g. CWE-1004) that has not been shown to apply,
    // since sensitivity could not be confirmed.
    source: SOURCE,
    detailKey: cookieName,
    reviewStatus: "REQUIRES_MANUAL_REVIEW",
  };
}

/**
 * Analyzes cookie attributes only (never values). A missing attribute only
 * produces a real, score-affecting finding when the cookie's name confirms
 * session/authentication use; otherwise it is logged as a zero-penalty note
 * for manual review rather than an assumed vulnerability.
 */
export function analyzeCookies(
  setCookieHeaders: string[] | undefined,
  affectedUrl: string,
  usedTls: boolean,
): RawFinding[] {
  if (!setCookieHeaders || setCookieHeaders.length === 0) return [];
  const findings: RawFinding[] = [];
  const cookies = parseSetCookies(setCookieHeaders);

  for (const cookie of cookies) {
    const sensitivity = classifyCookieSensitivity(cookie.name);

    if (usedTls && !cookie.secure) {
      findings.push(buildAttributeFinding("Secure", cookie.name, sensitivity, affectedUrl));
    }

    if (!cookie.httpOnly) {
      findings.push(buildAttributeFinding("HttpOnly", cookie.name, sensitivity, affectedUrl));
    }

    if (!cookie.sameSite) {
      findings.push(buildAttributeFinding("SameSite", cookie.name, sensitivity, affectedUrl));
    } else if (cookie.sameSite === "None" && !cookie.secure) {
      // This is a protocol-correctness issue independent of sensitivity:
      // modern browsers reject/mishandle SameSite=None without Secure
      // regardless of what the cookie is used for.
      findings.push({
        ruleId: "COOKIE_SAMESITE_NONE_INSECURE",
        title: `Cookie "${cookie.name}" uses SameSite=None without Secure`,
        severity: "MEDIUM",
        confidence: "CONFIRMED",
        exposure: "DIRECT_PROVEN",
        affectedUrl,
        description: `Cookie "${cookie.name}" sets SameSite=None but not Secure; modern browsers reject or may mishandle this combination, and it removes cross-site request protection entirely.`,
        remediation: `Add the Secure attribute whenever SameSite=None is used, on cookie "${cookie.name}".`,
        owaspCategory: owaspLabel("BROKEN_ACCESS_CONTROL"),
        cweId: "CWE-352",
        source: SOURCE,
        detailKey: cookie.name,
      });
    }
  }

  return findings;
}
