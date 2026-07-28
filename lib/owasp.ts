/**
 * Single source of truth for OWASP Top 10 category labels shown in the UI,
 * PDF report, and stored on Finding rows. Every check module resolves a
 * semantic key through `owaspLabel()` instead of writing a literal
 * "A0X:2021 - ..." string inline — this is the only place that needs to
 * change if OWASP revises the list again, and it is the only place a 2021
 * label can leak back in.
 *
 * Mapping to the OWASP Top 10:2025 categories below reflects the project's
 * best knowledge at the time this was written, but was NOT re-verified
 * against a live copy of https://owasp.org/Top10/2025/ in this environment
 * (no network access at implementation time). `SECURITY_MISCONFIGURATION`
 * and `BROKEN_ACCESS_CONTROL` are the two categories explicitly confirmed
 * by the project owner; the rest should be spot-checked against the
 * official page before relying on them for grading/production use — see
 * docs/decisions.md.
 */
export type OwaspCategoryKey =
  | "BROKEN_ACCESS_CONTROL"
  | "SECURITY_MISCONFIGURATION"
  | "SOFTWARE_SUPPLY_CHAIN_FAILURES"
  | "CRYPTOGRAPHIC_FAILURES"
  | "INJECTION"
  | "INSECURE_DESIGN"
  | "AUTHENTICATION_FAILURES"
  | "SOFTWARE_DATA_INTEGRITY_FAILURES"
  | "LOGGING_ALERTING_FAILURES"
  | "MISHANDLING_EXCEPTIONAL_CONDITIONS";

const OWASP_2025_LABELS: Record<OwaspCategoryKey, string> = {
  BROKEN_ACCESS_CONTROL: "A01:2025 - Broken Access Control",
  SECURITY_MISCONFIGURATION: "A02:2025 - Security Misconfiguration",
  SOFTWARE_SUPPLY_CHAIN_FAILURES: "A03:2025 - Software Supply Chain Failures",
  CRYPTOGRAPHIC_FAILURES: "A04:2025 - Cryptographic Failures",
  INJECTION: "A05:2025 - Injection",
  INSECURE_DESIGN: "A06:2025 - Insecure Design",
  AUTHENTICATION_FAILURES: "A07:2025 - Authentication Failures",
  SOFTWARE_DATA_INTEGRITY_FAILURES: "A08:2025 - Software or Data Integrity Failures",
  LOGGING_ALERTING_FAILURES: "A09:2025 - Logging & Alerting Failures",
  MISHANDLING_EXCEPTIONAL_CONDITIONS: "A10:2025 - Mishandling of Exceptional Conditions",
};

/**
 * Resolves a semantic OWASP category key to its display label. There is no
 * "unsure" input here on purpose: a check either knows which category
 * applies (pass the key) or it doesn't (omit `owaspCategory` on the finding
 * entirely, which the UI/PDF render as "Not mapped") — there is no third
 * option where a wrong label gets attached "just in case".
 */
export function owaspLabel(key: OwaspCategoryKey): string {
  return OWASP_2025_LABELS[key];
}

/** Text shown in the UI/PDF whenever a finding has no confident OWASP mapping. */
export const OWASP_NOT_MAPPED_LABEL = "Not mapped";
