# Scoring Methodology — Automated Security Score

Implemented in [`lib/scoring.ts`](../lib/scoring.ts), tested in
[`tests/unit/scoring.test.ts`](../tests/unit/scoring.test.ts).

This is **not** an official OWASP/industry-standard score. It is a score this
project designed and computes deterministically from its own findings. It is
always labeled "Automated Security Score" in the UI and PDF report.

## Inputs

The engine only ever sees findings that were actually produced by a
completed check (`lib/checks/*.ts`) or a real OWASP ZAP Baseline report
(`lib/checks/zap.ts`). It has no knowledge of the target's identity, name, or
appearance — the score cannot depend on anything except the finding list.

## Step 1 — Deduplication

Findings from different scanners (e.g. the custom header scanner and OWASP
ZAP both reporting "CSP missing") are merged by a stable fingerprint:
`sha256(ruleId + affectedUrl-without-query + detailKey)`. A merged finding
keeps every distinct source name and an `occurrences` count. See
[`lib/dedup.ts`](../lib/dedup.ts).

## Step 2 — Per-finding penalty

```
penalty = severityPoints × confidenceMultiplier × exposureMultiplier × repetitionMultiplier
```

| Severity        | Points |
|-----------------|--------|
| CRITICAL        | 25     |
| HIGH            | 15     |
| MEDIUM          | 7      |
| LOW             | 2      |
| INFORMATIONAL   | 0      |

| Confidence | Multiplier |
|------------|------------|
| CONFIRMED  | 1.00       |
| HIGH       | 0.85       |
| MEDIUM     | 0.60       |
| LOW        | 0.30       |

| Exposure                  | Multiplier |
|----------------------------|-----------|
| Directly exposed & proven  | 1.00      |
| Requires authentication    | 0.75      |
| Configuration weakness     | 0.50      |
| Best-practice issue        | 0.30      |
| Informational only         | 0.00      |

**Repetition multiplier** (caps double-charging when one issue repeats
across many pages/instances): `min(1.25, 1 + (occurrences - 1) × 0.05)`. A
CSP-missing finding seen on 20 pages is merged into one Finding with
`occurrences=20`, and its penalty is multiplied by at most 1.25×, never 20×.

## Step 3 — Total score

```
totalPenalty = sum of every finding's penalty
exactScore   = clamp(100 - totalPenalty, 0, 100)
displayedScore = round(exactScore)
```

`exactScore` (e.g. `78.45`) is stored; `displayedScore` (e.g. `78`) is shown
to the user as `78%`.

## Step 4 — Rating

| displayedScore | Rating              |
|-----------------|---------------------|
| 90–100          | Very Good           |
| 75–89           | Good                |
| 60–74           | Needs Improvement   |
| 40–59           | Weak                |
| 0–39            | Critical            |

## Guarantees enforced by tests

- **Deterministic**: identical findings always produce identical output
  (`calculateSecurityScore` has no randomness, no clock reads, no I/O).
- **Order-independent**: the score does not change if the findings array is
  reordered (penalty summation is commutative).
- **Never below 0, never above 100.**
- **Informational findings never subtract points** (0 severity points,
  regardless of confidence/exposure).
- **Critical deducts more than High**, all else equal; **Low-confidence
  deducts less than Confirmed**, all else equal.
- **Repeated issues are capped**, never linearly multiplied.

## Failed / partial scans

If the scan cannot reach the target at all, the Scan's `status` is `FAILED`
and **no score is computed** — the UI shows "Scan Failed" with the real
reason (DNS failure, connection timeout, TLS failure, blocked by URL
security policy, or scanner worker unavailable), never `0%` or `100%`.

If some checks completed and others failed/were skipped, `status` is
`PARTIAL`. The score is still computed from whatever findings the
completed checks produced, but the UI and PDF both clearly list which checks
did not run — a skipped check is never treated as "passed".
