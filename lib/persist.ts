import type { CheckName, ScanChecklist, ScoredFinding, ZapExecutionResult } from "./types";

export function serializeChecklistPart(names: CheckName[]): string {
  return JSON.stringify(names);
}

export function deserializeChecklistPart(json: string): CheckName[] {
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) ? (parsed as CheckName[]) : [];
  } catch {
    return [];
  }
}

export function checklistToJson(checklist: ScanChecklist) {
  return {
    completedChecks: serializeChecklistPart(checklist.completed),
    failedChecks: serializeChecklistPart(checklist.failed),
    skippedChecks: serializeChecklistPart(checklist.skipped),
  };
}

export function findingToCreateData(finding: ScoredFinding, scanId: string) {
  return {
    scanId,
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    exposure: finding.exposure,
    affectedUrl: finding.affectedUrl,
    description: finding.description,
    evidence: finding.evidence ?? null,
    rawEvidence: finding.rawEvidence ?? null,
    remediation: finding.remediation,
    owaspCategory: finding.owaspCategory ?? null,
    cweId: finding.cweId ?? null,
    source: JSON.stringify(finding.sources),
    fingerprint: finding.fingerprint,
    penalty: finding.penalty,
    occurrences: finding.occurrences,
    exploitability: finding.exploitability ?? null,
    reviewStatus: finding.reviewStatus ?? null,
  };
}

/** Maps a ZapExecutionResult onto the flat Scan columns used to persist it. */
export function zapExecutionToScanFields(execution: ZapExecutionResult) {
  return {
    zapStatus: execution.status,
    zapReasonCode: execution.reasonCode,
    zapReasonMessage: execution.reasonMessage,
    zapStartedAt: execution.startedAt ? new Date(execution.startedAt) : null,
    zapCompletedAt: execution.completedAt ? new Date(execution.completedAt) : null,
    zapDurationMs: execution.durationMs,
  };
}

/** Reconstructs a ZapExecutionResult from the flat Scan columns for API/PDF display. */
export function scanFieldsToZapExecution(scan: {
  zapStatus: string;
  zapReasonCode: string | null;
  zapReasonMessage: string | null;
  zapStartedAt: Date | null;
  zapCompletedAt: Date | null;
  zapDurationMs: number | null;
}): ZapExecutionResult {
  return {
    status: scan.zapStatus as ZapExecutionResult["status"],
    reasonCode: scan.zapReasonCode as ZapExecutionResult["reasonCode"],
    reasonMessage: scan.zapReasonMessage ?? "",
    startedAt: scan.zapStartedAt ? scan.zapStartedAt.toISOString() : null,
    completedAt: scan.zapCompletedAt ? scan.zapCompletedAt.toISOString() : null,
    durationMs: scan.zapDurationMs,
  };
}
