import type {
  Confidence,
  DedupedFinding,
  Exposure,
  ScoreBreakdownEntry,
  ScoredFinding,
  ScoreResult,
  Severity,
} from "./types";

/**
 * Deterministic, non-random scoring engine. Given the same set of findings
 * (in any order), `calculateSecurityScore` always returns the same exact
 * score. This is the single source of truth for the "Automated Security
 * Score" shown on the site and printed in the PDF report — it is NOT an
 * official OWASP certification, only a score this project computes from its
 * own findings.
 */

const SEVERITY_POINTS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 7,
  LOW: 2,
  INFORMATIONAL: 0,
};

const CONFIDENCE_MULTIPLIER: Record<Confidence, number> = {
  CONFIRMED: 1.0,
  HIGH: 0.85,
  MEDIUM: 0.6,
  LOW: 0.3,
};

const EXPOSURE_MULTIPLIER: Record<Exposure, number> = {
  DIRECT_PROVEN: 1.0,
  REQUIRES_AUTH: 0.75,
  CONFIG_WEAKNESS: 0.5,
  BEST_PRACTICE: 0.3,
  INFORMATIONAL_ONLY: 0.0,
};

const MAX_REPETITION_MULTIPLIER = 1.25;
const REPETITION_STEP = 0.05;

/** Caps the extra weight given to an issue repeated across many pages/requests. */
function repetitionMultiplier(occurrences: number): number {
  if (occurrences <= 1) return 1.0;
  return Math.min(MAX_REPETITION_MULTIPLIER, 1 + (occurrences - 1) * REPETITION_STEP);
}

function ratingFor(displayedScore: number): ScoreResult["rating"] {
  if (displayedScore >= 90) return "Very Good";
  if (displayedScore >= 75) return "Good";
  if (displayedScore >= 60) return "Needs Improvement";
  if (displayedScore >= 40) return "Weak";
  return "Critical";
}

export interface PenaltyInput {
  severity: Severity;
  confidence: Confidence;
  exposure: Exposure;
  occurrences: number;
}

/**
 * Computes the four penalty factors and final per-finding penalty from just
 * the four fields that are actually persisted on a Finding row. This is the
 * ONLY place the penalty formula is implemented — `calculateSecurityScore`
 * and any later recomputation (API responses, the PDF report) both call
 * this, so the breakdown shown in the UI and the one printed in the PDF can
 * never drift apart from each other or from the stored score.
 */
export function computePenalty(input: PenaltyInput): {
  severityPoints: number;
  confidenceMultiplier: number;
  exposureMultiplier: number;
  repetitionMultiplier: number;
  finalPenalty: number;
} {
  const severityPoints = SEVERITY_POINTS[input.severity];
  const confidenceMultiplier = CONFIDENCE_MULTIPLIER[input.confidence];
  const exposureMultiplier = EXPOSURE_MULTIPLIER[input.exposure];
  const repetition = repetitionMultiplier(input.occurrences);
  return {
    severityPoints,
    confidenceMultiplier,
    exposureMultiplier,
    repetitionMultiplier: repetition,
    finalPenalty: severityPoints * confidenceMultiplier * exposureMultiplier * repetition,
  };
}

/**
 * Computes the Automated Security Score from a deduplicated finding set.
 * Sorting/order of the input array never affects the result: penalties are
 * summed (commutative), and the breakdown is sorted by penalty afterward
 * purely for display.
 */
export function calculateSecurityScore(findings: DedupedFinding[]): ScoreResult {
  const breakdown: ScoreBreakdownEntry[] = findings.map((finding) => {
    const penalty = computePenalty(finding);

    return {
      findingId: finding.fingerprint,
      ruleId: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
      severityPoints: penalty.severityPoints,
      confidence: finding.confidence,
      confidenceMultiplier: penalty.confidenceMultiplier,
      exposure: finding.exposure,
      exposureMultiplier: penalty.exposureMultiplier,
      occurrences: finding.occurrences,
      repetitionMultiplier: penalty.repetitionMultiplier,
      finalPenalty: penalty.finalPenalty,
    };
  });

  const totalPenalty = breakdown.reduce((sum, entry) => sum + entry.finalPenalty, 0);
  const rawExactScore = Math.max(0, Math.min(100, 100 - totalPenalty));
  // Round to 2 decimals FIRST and derive displayedScore from that exact
  // stored value, so `displayedScore === Math.round(exactScore)` holds by
  // construction rather than by coincidence between two separate roundings.
  const exactScore = Math.round(rawExactScore * 100) / 100;
  const displayedScore = Math.round(exactScore);

  // Sort breakdown by descending impact for display; does not affect totals.
  breakdown.sort((a, b) => b.finalPenalty - a.finalPenalty);

  return {
    exactScore,
    displayedScore,
    rating: ratingFor(displayedScore),
    totalPenalty: Math.round(totalPenalty * 100) / 100,
    breakdown,
  };
}

/** Merges each deduplicated finding with its computed penalty/breakdown for persistence/display. */
export function attachPenalties(
  findings: DedupedFinding[],
  breakdown: ScoreBreakdownEntry[],
): ScoredFinding[] {
  const byFingerprint = new Map(breakdown.map((entry) => [entry.findingId, entry]));
  return findings.map((finding) => {
    const entry = byFingerprint.get(finding.fingerprint);
    return {
      ...finding,
      id: finding.fingerprint,
      penalty: entry?.finalPenalty ?? 0,
      severityPoints: entry?.severityPoints ?? 0,
      confidenceMultiplier: entry?.confidenceMultiplier ?? 0,
      exposureMultiplier: entry?.exposureMultiplier ?? 0,
    };
  });
}

export interface PersistedFindingLike extends PenaltyInput {
  id: string;
  ruleId: string;
  title: string;
}

/**
 * Recomputes the display breakdown directly from persisted Finding rows
 * (severity/confidence/exposure/occurrences), using the exact same formula
 * as `calculateSecurityScore`. Used by both the results API and the PDF
 * report so "How this score was calculated" is always derived from the same
 * stored data, never a second, potentially-drifted calculation. Informational
 * findings (zero severity points) are excluded — they never affected the
 * score, so they don't belong in a list of what was deducted.
 */
export function computeScoreAffectingBreakdown(
  findings: PersistedFindingLike[],
): (ScoreBreakdownEntry & { findingRowId: string })[] {
  return findings
    .map((finding) => {
      const penalty = computePenalty(finding);
      return {
        findingId: finding.id,
        findingRowId: finding.id,
        ruleId: finding.ruleId,
        title: finding.title,
        severity: finding.severity,
        severityPoints: penalty.severityPoints,
        confidence: finding.confidence,
        confidenceMultiplier: penalty.confidenceMultiplier,
        exposure: finding.exposure,
        exposureMultiplier: penalty.exposureMultiplier,
        occurrences: finding.occurrences,
        repetitionMultiplier: penalty.repetitionMultiplier,
        finalPenalty: penalty.finalPenalty,
      };
    })
    .filter((entry) => entry.finalPenalty > 0)
    .sort((a, b) => b.finalPenalty - a.finalPenalty);
}
