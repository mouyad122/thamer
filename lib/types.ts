export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
export type Confidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW";
export type Exposure =
  | "DIRECT_PROVEN"
  | "REQUIRES_AUTH"
  | "CONFIG_WEAKNESS"
  | "BEST_PRACTICE"
  | "INFORMATIONAL_ONLY";

export type ScanStatus =
  | "PENDING"
  | "VALIDATING"
  | "SCANNING"
  | "COMPLETED"
  | "PARTIAL"
  | "FAILED";

/** Names of every check the scanner can attempt, used for completed/failed/skipped tracking. */
export const CHECK_NAMES = [
  "URL_VALIDATION",
  "HTTPS_CHECK",
  "TLS_CERTIFICATE",
  "SECURITY_HEADERS",
  "COOKIE_SECURITY",
  "CORS_ANALYSIS",
  "INFORMATION_DISCLOSURE",
  "HTML_SECURITY",
  "COMMON_SAFE_FILES",
  "ZAP_BASELINE",
] as const;
export type CheckName = (typeof CHECK_NAMES)[number];

/**
 * Whether an exploitable, concrete impact was actually demonstrated by the
 * scan (e.g. a proven CORS bypass) versus only the *absence* of a
 * defense-in-depth control being observed (e.g. a missing COOP header).
 * `confidence` measures how sure we are about the observation itself
 * (the "observation confidence"); `exploitability` measures whether that
 * observation was shown to be exploitable. Both can be CONFIRMED/true at
 * once (e.g. a missing header is CONFIRMED, and if we also proved impact,
 * exploitability is DEMONSTRATED) or independent (missing-header findings
 * are routinely CONFIRMED + NOT_DEMONSTRATED).
 */
export type Exploitability = "NOT_DEMONSTRATED" | "DEMONSTRATED";

/** Marks a finding as needing a human look rather than being an automatically-scored issue. */
export type ReviewStatus = "REQUIRES_MANUAL_REVIEW";

export interface RawFinding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  exposure: Exposure;
  affectedUrl: string;
  description: string;
  evidence?: string;
  /** Full raw evidence (e.g. the entire CSP header) for an expandable "Raw Evidence" UI section — never inlined into `description`. */
  rawEvidence?: string;
  remediation: string;
  owaspCategory?: string;
  cweId?: string;
  source: string;
  /** Header/parameter/plugin name distinguishing findings that share a ruleId, used in fingerprinting. */
  detailKey?: string;
  exploitability?: Exploitability;
  reviewStatus?: ReviewStatus;
}

export type ZapStatus = "NOT_TESTED" | "FAILED" | "TIMED_OUT" | "COMPLETED";

export type ZapReasonCode =
  | "ZAP_WORKER_NOT_CONFIGURED"
  | "ZAP_WORKER_UNREACHABLE"
  | "ZAP_START_FAILED"
  | "ZAP_TIMEOUT"
  | "ZAP_REPORT_MISSING"
  | "ZAP_INVALID_RESPONSE";

export interface ZapExecutionResult {
  status: ZapStatus;
  reasonCode: ZapReasonCode | null;
  reasonMessage: string;
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
}

export interface DedupedFinding extends RawFinding {
  fingerprint: string;
  sources: string[];
  occurrences: number;
}

export interface ScoredFinding extends DedupedFinding {
  id: string;
  penalty: number;
  severityPoints: number;
  confidenceMultiplier: number;
  exposureMultiplier: number;
}

export interface ScoreBreakdownEntry {
  findingId: string;
  ruleId: string;
  title: string;
  severity: Severity;
  severityPoints: number;
  confidence: Confidence;
  confidenceMultiplier: number;
  exposure: Exposure;
  exposureMultiplier: number;
  occurrences: number;
  repetitionMultiplier: number;
  finalPenalty: number;
}

export interface ScoreResult {
  exactScore: number;
  displayedScore: number;
  rating: "Very Good" | "Good" | "Needs Improvement" | "Weak" | "Critical";
  totalPenalty: number;
  breakdown: ScoreBreakdownEntry[];
}

export interface ScanChecklist {
  completed: CheckName[];
  failed: CheckName[];
  skipped: CheckName[];
}
