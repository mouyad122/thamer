# Testing

## Commands

```bash
npm run typecheck   # tsc --noEmit, strict mode
npm run lint        # eslint . (next/core-web-vitals + next/typescript)
npm test            # vitest run — 132 unit tests as of this writing
```

## What's covered by automated unit tests (`tests/unit/`)

All ten categories the project brief requires are covered:

1. **URL validation** — `url-validation.test.ts`
2. **SSRF protection** — `url-validation.test.ts` (decimal/hex/octal/partial
   IP-encoding bypasses, private/loopback/link-local/metadata ranges, IPv6
   loopback/unique-local/mapped-IPv4), plus `url-validation-override.test.ts`
   for the local-demo escape hatch.
3. **Security Headers parsing** — `headers.test.ts`
4. **Cookie parsing** — `cookies.test.ts` (including "never expose the raw
   cookie value" assertions)
5. **CORS analysis** — `cors.test.ts` (wildcard-without-credentials must stay
   informational; reflected-origin-with-credentials must be flagged HIGH)
6. **TLS result parsing** — `tls.test.ts` (expiry, not-yet-valid,
   near-expiry, hostname/wildcard matching)
7. **ZAP result normalization** — `zap.test.ts` (confidence is preserved from
   ZAP's own report, never auto-promoted to CONFIRMED; unknown risk levels
   are skipped rather than guessed)
8. **Finding deduplication** — `dedup.test.ts` (fingerprint stability, merge
   vs. no-merge cases)
9. **Score calculation** — `scoring.test.ts`, including the exact fixed
   fixtures from the brief:
   - No findings → 100
   - One confirmed High, full exposure → 85
   - One confirmed Medium, full exposure → 93
   - One confirmed Low, full exposure → 98
   - One informational finding → 100
   plus determinism, order-independence, clamping, and repetition-cap checks.
10. **PDF report data generation** — `report.test.ts` (the report only ever
    contains findings that were passed in, shows the real error message for a
    FAILED scan, marks skipped checks as "Not Tested", and redacts
    sensitive-looking evidence text before embedding it).

Also: `html.test.ts` for form/mixed-content/password-over-HTTP detection.

## Manual / integration verification performed during development

The full pipeline (`lib/run-scan.ts` → dedup → scoring → Prisma persistence →
API routes) was exercised end-to-end against:

- A local fixture server (`tests/fixtures/server.mjs`) serving `/secure`
  (good headers, secure cookie, safe CORS) and `/insecure` (missing headers,
  insecure cookie, credentialed-wildcard CORS, HTTP password form,
  disclosure headers) — confirms the scanner flags exactly the intentionally
  broken behavior and nothing on the secure page beyond what the fixture
  itself is missing (it is served over plain HTTP, so `SITE_NOT_HTTPS` is a
  correct, real finding, not a false positive).
- A real public HTTPS site (`https://example.com`) — confirms live TLS
  certificate reading, live header analysis, live CORS probing, and
  `robots.txt`/`security.txt` checks all work against a real target.
- A failed-DNS target — confirms the scan status becomes `FAILED` with a
  real, specific reason rather than a fabricated score.
- The full HTTP API (`POST /api/scans`, `POST /api/scans/:id/run`,
  `GET /api/scans/:id/status`, `GET /api/scans/:id`,
  `GET /api/scans/:id/report`) via curl against a running `next dev` server
  backed by a real SQLite database.

### Known gap: PDF rendering not exercised in the authoring sandbox

The sandbox this project was built in has no outbound network access to
`storage.googleapis.com`, so `npx playwright install chromium` could not
download a browser binary and the actual PDF file (Playwright →
Chromium → PDF bytes) was **not** rendered end-to-end here. This is recorded
here explicitly rather than claimed as verified. What **was** verified:

- `lib/report.ts`'s `buildReportHtml()` (the pure HTML-building function,
  independent of Chromium) is fully unit-tested in `report.test.ts`.
- The API route (`app/api/scans/[id]/run/route.ts`) is written so that a
  `generateReportPdf()` failure is caught and logged, and does **not** mark
  the scan as failed or erase its findings — confirmed live: after running a
  real scan in this sandbox (Chromium unavailable), the scan still completed
  with real findings and `hasReport: false`, and `GET /api/scans/:id/report`
  correctly returned a 404 with a clear message instead of crashing.

Run `npx playwright install chromium` on a machine with normal internet
access, then re-run a scan, to confirm the actual PDF file is produced
(`reports/<scanId>.pdf`) with a real SHA-256 stored on the `Report` row.

## OWASP ZAP Baseline (worker)

Not run in this sandbox (no Docker available). The worker code
(`scanner-worker/src/*.js`) shells out to the official `zap-baseline.py`
inside a container built from the pinned `zaproxy/zap-stable:2.16.0` image
and parses its real JSON output (`lib/checks/zap.ts`, unit-tested against a
realistic sample report). To verify locally:

```bash
docker compose up --build
# then, with SCANNER_WORKER_URL/SCANNER_WORKER_SECRET set in .env:
npm run dev
# scan http://localhost:3001 (Juice Shop) from the UI
```

If the worker is unreachable or unconfigured, `ZAP_BASELINE` is recorded as
**skipped** ("Not Tested") and the scan is marked `PARTIAL` —
never silently treated as a completed/passed check.

## E2E critical path (documented, not automated in this repo)

Given the "no accounts, no admin panel" scope, the critical path is short:
submit a URL → watch real step names → see score + findings →
download PDF. This was manually verified via the HTTP API in this sandbox
(see above); a Playwright E2E test exercising the actual browser UI can be
added once a Chromium binary is available in the CI/dev environment.
