"use client";

import { useEffect, useRef, useState } from "react";
import { ScoreGauge } from "@/components/ScoreGauge";
import { FindingCard, type FindingView } from "@/components/FindingCard";
import { CHECK_NAMES, type CheckName, type ZapExecutionResult } from "@/lib/types";
import { STEP_LABELS } from "@/lib/step-labels";

type UiState =
  | { phase: "idle" }
  | { phase: "starting" }
  | { phase: "scanning"; scanId: string; status: StatusResponse }
  | { phase: "done"; scanId: string; result: ScanDetail }
  | { phase: "error"; message: string };

interface Coverage {
  completedChecks: number;
  totalChecks: number;
  coveragePercent: number;
}

interface StatusResponse {
  status: string;
  currentStep: string | null;
  completedChecks: CheckName[];
  failedChecks: CheckName[];
  skippedChecks: CheckName[];
  errorMessage: string | null;
}

interface ScoreBreakdownEntry {
  findingId: string;
  title: string;
  severityPoints: number;
  confidenceMultiplier: number;
  exposureMultiplier: number;
  finalPenalty: number;
}

interface ScanDetail {
  id: string;
  targetUrl: string;
  status: string;
  isPartial: boolean;
  displayedScore: number | null;
  rating: string | null;
  durationMs: number | null;
  errorMessage: string | null;
  completedChecks: CheckName[];
  failedChecks: CheckName[];
  skippedChecks: CheckName[];
  coverage: Coverage;
  zapExecution: ZapExecutionResult;
  scoreBreakdown: ScoreBreakdownEntry[];
  hasReport: boolean;
  findings: FindingView[];
}

export default function HomePage() {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<UiState>({ phase: "idle" });
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  async function startScan() {
    if (!url.trim()) return;
    setState({ phase: "starting" });
    try {
      const createRes = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!createRes.ok) {
        const body = await createRes.json().catch(() => ({}));
        setState({ phase: "error", message: body.error ?? "Could not start the scan." });
        return;
      }
      const { id } = (await createRes.json()) as { id: string };

      // Fire the long-running scan; do not await it here so polling can show live progress.
      fetch(`/api/scans/${id}/run`, { method: "POST" }).catch(() => {
        /* surfaced via status polling */
      });

      setState({
        phase: "scanning",
        scanId: id,
        status: {
          status: "PENDING",
          currentStep: "Validating URL",
          completedChecks: [],
          failedChecks: [],
          skippedChecks: [],
          errorMessage: null,
        },
      });

      pollRef.current = setInterval(() => pollStatus(id), 1500);
    } catch {
      setState({ phase: "error", message: "Network error while starting the scan." });
    }
  }

  async function pollStatus(id: string) {
    try {
      const res = await fetch(`/api/scans/${id}/status`);
      if (!res.ok) return;
      const status = (await res.json()) as StatusResponse;

      if (status.status === "COMPLETED" || status.status === "PARTIAL" || status.status === "FAILED") {
        if (pollRef.current) clearInterval(pollRef.current);
        const detailRes = await fetch(`/api/scans/${id}`);
        const detail = (await detailRes.json()) as ScanDetail;
        setState({ phase: "done", scanId: id, result: detail });
        return;
      }

      setState((prev) => (prev.phase === "scanning" ? { ...prev, status } : prev));
    } catch {
      // Transient polling error — next tick will retry.
    }
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <header className="mb-8">
        <h1 className="text-2xl font-bold">Web Security Scanner</h1>
        <p className="mt-1 text-muted">
          Enter a website URL to run a real, automated security scan and get an Automated Security
          Score based on actual findings — not a random number.
        </p>
      </header>

      <div className="rounded-lg border border-border bg-surface p-5">
        <label htmlFor="target-url" className="mb-1 block text-sm font-medium">
          Website URL
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            id="target-url"
            type="text"
            placeholder="https://example.com"
            className="flex-1 rounded border border-border bg-bg px-3 py-2 text-base outline-none focus:ring-2 focus:ring-accent"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={state.phase === "starting" || state.phase === "scanning"}
          />
          <button
            type="button"
            onClick={startScan}
            disabled={state.phase === "starting" || state.phase === "scanning" || !url.trim()}
            className="rounded bg-accent px-5 py-2 font-semibold text-white disabled:opacity-50"
          >
            {state.phase === "scanning" || state.phase === "starting" ? "Scanning…" : "Start Scan"}
          </button>
        </div>
        <p className="mt-3 text-xs text-muted">
          Only scan a website you own or have explicit legal authorization to test. Scans of
          localhost, private networks, and cloud metadata endpoints are blocked automatically.
        </p>
      </div>

      {state.phase === "error" && (
        <div className="mt-6 rounded-lg border border-critical bg-surface p-4 text-critical">
          {state.message}
        </div>
      )}

      {state.phase === "scanning" && <ScanningPanel status={state.status} />}

      {state.phase === "done" && <ResultsPanel result={state.result} />}
    </main>
  );
}

function ScanningPanel({ status }: { status: StatusResponse }) {
  return (
    <section className="mt-6 rounded-lg border border-border bg-surface p-5">
      <div className="font-semibold">{status.currentStep ?? "Starting…"}</div>
      <div className="mt-1 text-sm text-muted">
        {status.completedChecks.length + status.failedChecks.length + status.skippedChecks.length} of{" "}
        {CHECK_NAMES.length} checks completed
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {CHECK_NAMES.map((name) => {
          const done = status.completedChecks.includes(name);
          const failed = status.failedChecks.includes(name);
          const skipped = status.skippedChecks.includes(name);
          const cls = done
            ? "border-low text-low"
            : failed
              ? "border-critical text-critical"
              : skipped
                ? "border-muted text-muted"
                : "border-border text-muted";
          return (
            <span key={name} className={`rounded-full border px-3 py-1 text-xs ${cls}`}>
              {STEP_LABELS[name]}
            </span>
          );
        })}
      </div>
    </section>
  );
}

function ResultsPanel({ result }: { result: ScanDetail }) {
  if (result.status === "FAILED") {
    return (
      <section className="mt-6 rounded-lg border border-critical bg-surface p-5">
        <h2 className="text-lg font-semibold text-critical">Scan Failed</h2>
        <p className="mt-2">{result.errorMessage ?? "The scan could not be completed."}</p>
      </section>
    );
  }

  return (
    <section className="mt-6 space-y-6">
      {result.isPartial && (
        <div className="rounded-lg border border-medium bg-surface p-4 text-medium">
          Partial Scan: some checks did not complete. Results below only reflect checks that
          actually ran — see the list below for what was skipped or failed.
          {result.zapExecution.status !== "COMPLETED" && " OWASP ZAP Passive Scan was not executed."}
        </div>
      )}

      {result.displayedScore !== null && result.rating && (
        <div>
          <div className="mb-1 text-sm font-semibold text-muted">
            {result.isPartial ? "Provisional Automated Security Score" : "Automated Security Score"}
          </div>
          <ScoreGauge score={result.displayedScore} rating={result.rating} />
          {result.isPartial && <p className="mt-1 text-xs text-muted">Based only on completed checks.</p>}
        </div>
      )}

      <div className="rounded-lg border border-border bg-surface p-4 text-sm">
        <div className="font-semibold">Scan Coverage</div>
        <div className="mt-1">
          {result.coverage.completedChecks} completed checks out of {result.coverage.totalChecks} configured checks
          = {result.coverage.coveragePercent}% coverage.
        </div>
        <div className="mt-1 text-xs text-muted">
          Coverage measures how many checks actually ran — it is separate from the Automated Security Score above.
        </div>
      </div>

      {result.scoreBreakdown.length > 0 && (
        <div className="rounded-lg border border-border bg-surface p-4 text-sm">
          <h2 className="mb-2 font-semibold">How this score was calculated</h2>
          <div className="space-y-1">
            {result.scoreBreakdown.map((entry) => (
              <div key={entry.findingId} className="flex flex-wrap justify-between gap-2 border-b border-border py-1 last:border-b-0">
                <span>{entry.title}</span>
                <span className="text-muted">
                  {entry.severityPoints} &times; {entry.confidenceMultiplier.toFixed(2)} &times; {entry.exposureMultiplier.toFixed(2)} =
                  <strong className="ml-1 text-text">{entry.finalPenalty.toFixed(2)}</strong>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="rounded-lg border border-border bg-surface p-4 text-sm">
        <h2 className="mb-1 font-semibold">OWASP ZAP Baseline Scan</h2>
        <div>
          Status: <strong>{result.zapExecution.status}</strong>
          {result.zapExecution.reasonCode && ` (${result.zapExecution.reasonCode})`}
        </div>
        <div className="mt-1 text-muted">{result.zapExecution.reasonMessage}</div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-surface p-4 text-sm">
        <div>
          <div>
            <span className="font-semibold">Target:</span> {result.targetUrl}
          </div>
          <div>
            <span className="font-semibold">Duration:</span>{" "}
            {result.durationMs !== null ? `${(result.durationMs / 1000).toFixed(1)}s` : "N/A"}
          </div>
        </div>
        {result.hasReport && (
          <a
            href={`/api/scans/${result.id}/report`}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg bg-green-600 px-6 py-3 font-bold text-white shadow-lg transition-transform hover:scale-105 hover:bg-green-700 flex items-center gap-2"
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            Download PDF Report
          </a>
        )}
      </div>

      <div className="rounded-lg border border-border bg-surface p-4">
        <h2 className="mb-2 font-semibold">Checks Performed</h2>
        <div className="flex flex-wrap gap-2 text-xs">
          {[...result.completedChecks, ...result.failedChecks, ...result.skippedChecks].map((name) => {
            const cls = result.completedChecks.includes(name)
              ? "border-low text-low"
              : result.failedChecks.includes(name)
                ? "border-critical text-critical"
                : "border-muted text-muted";
            const label = result.failedChecks.includes(name)
              ? "Failed"
              : result.skippedChecks.includes(name)
                ? "Not Tested"
                : "Completed";
            return (
              <span key={name} className={`rounded-full border px-3 py-1 ${cls}`}>
                {STEP_LABELS[name]} — {label}
              </span>
            );
          })}
        </div>
      </div>

      <div>
        <h2 className="mb-3 text-lg font-semibold">Findings ({result.findings.length})</h2>
        {result.findings.length === 0 ? (
          <p className="text-muted">No issues were found by the checks that completed.</p>
        ) : (
          <div className="space-y-3">
            {result.findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
