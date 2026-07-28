import { SeverityBadge } from "./SeverityBadge";

export interface FindingView {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  affectedUrl: string;
  description: string;
  evidence: string | null;
  rawEvidence?: string | null;
  remediation: string;
  owaspCategory: string | null;
  cweId: string | null;
  sources: string[];
  occurrences: number;
  reviewStatus?: string | null;
}

export function FindingCard({ finding }: { finding: FindingView }) {
  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">{finding.title}</h3>
        <SeverityBadge severity={finding.severity} />
        <span className="text-xs text-muted">Confidence: {finding.confidence}</span>
        {finding.occurrences > 1 && (
          <span className="text-xs text-muted">Observed {finding.occurrences}×</span>
        )}
        {finding.reviewStatus && (
          <span className="rounded-full border border-medium px-2 py-0.5 text-xs text-medium">
            {finding.reviewStatus.replace(/_/g, " ")}
          </span>
        )}
      </div>
      <div className="mt-1 break-all text-xs text-muted">{finding.affectedUrl}</div>
      <p className="mt-2 text-sm">{finding.description}</p>
      {finding.evidence && (
        <pre className="mt-2 overflow-x-auto rounded bg-bg p-2 text-xs">{finding.evidence}</pre>
      )}
      {finding.rawEvidence && (
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer font-semibold text-muted">Raw Evidence</summary>
          <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded bg-bg p-2">{finding.rawEvidence}</pre>
        </details>
      )}
      <p className="mt-2 text-sm">
        <span className="font-semibold">Remediation: </span>
        {finding.remediation}
      </p>
      <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted">
        <span>OWASP Mapping: {finding.owaspCategory ?? "Not mapped"}</span>
        <span>CWE: {finding.cweId ?? "Not mapped"}</span>
        <span>Source: {finding.sources.join(", ")}</span>
      </div>
    </div>
  );
}
