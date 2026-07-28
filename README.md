# Web Security Scanner

A university graduation project: enter a website URL, run a real automated
security scan (no mocks, no `Math.random()`, no invented findings), and get:

1. An **Automated Security Score** out of 100.
2. A rating (Very Good / Good / Needs Improvement / Weak / Critical).
3. A summary and detailed list of real findings.
4. A downloadable PDF report built from those exact findings.

See [docs/theoretical-requirements background](docs/pdf-requirements.md) and
[docs/decisions.md](docs/decisions.md) for how this implementation relates to
the team's theoretical graduation-project documents.

## What this is not

No login, no accounts, no admin dashboard, no subscriptions/payments, no
organizations/teams, no public API, no social features. Only scan a website
you own or are explicitly authorized to test.

## Architecture

```
Browser (single page)
  -> Next.js App Router (TypeScript, Tailwind) on Vercel
       -> Custom checks run in-process (Node runtime): HTTPS/TLS/headers/
          cookies/CORS/disclosure/HTML/common-files — all real HTTP/TLS
          calls behind an SSRF-safe client (lib/safe-fetch.ts)
       -> scanner-worker (separate Docker service) for OWASP ZAP Baseline
          (ZAP cannot run inside a Vercel serverless function)
  -> SQLite (dev) / PostgreSQL (prod) via Prisma: Scan, Finding, Report
  -> Playwright renders the PDF report from the scan's own stored findings
```

The scan runs as a single request to `POST /api/scans/:id/run`; the browser
polls `GET /api/scans/:id/status` concurrently, so the UI shows real,
already-completed check names — never a fake animated progress bar.

## Prerequisites

- Node.js 20+
- npm (this repo uses `package-lock.json`)
- Docker (only needed for the ZAP baseline worker / local demo environment)

## Local setup (Windows PowerShell)

```powershell
npm install
Copy-Item .env.example .env
npx prisma generate
npx prisma db push
npx playwright install chromium
npm run dev
```

Open http://localhost:3000.

## Local setup (Linux/macOS)

```bash
npm install
cp .env.example .env
npx prisma generate
npx prisma db push
npx playwright install chromium
npm run dev
```

## Running the scanner-worker (OWASP ZAP Baseline)

The main app works fully without the worker — ZAP Baseline is simply marked
"Not Tested" (skipped) and the scan is reported as a **Partial Scan**. To
enable it locally:

```bash
docker compose up --build
```

This starts:
- `juice-shop` — OWASP Juice Shop, a deliberately vulnerable app, for demoing
  the scanner against a known target.
- `scanner-worker` — a container built from `zaproxy/zap-stable` (pinned
  version) with a small Node/Express wrapper that runs the real
  `zap-baseline.py` (passive-only) and returns its JSON report.

Then set in your local `.env`:

```
SCANNER_WORKER_URL="http://localhost:8080"
SCANNER_WORKER_SECRET="dev-secret-change-me"
SCAN_ALLOW_PRIVATE_NETWORKS=true
```

`SCAN_ALLOW_PRIVATE_NETWORKS=true` is required only so the app is allowed to
target `http://localhost:3001` (Juice Shop's published port) for the demo —
**never enable this on a deployment reachable from the public internet**; see
[docs/decisions.md](docs/decisions.md) for why this exists and what it does
and does not bypass (cloud metadata addresses stay blocked unconditionally).

## Adding the graduation project's theoretical PDF files

Per the brief, theoretical PDFs were expected in `thamer project-docs/`. That
folder and no PDFs existed at implementation time — see the note at the top
of [docs/pdf-requirements.md](docs/pdf-requirements.md). If you add PDFs
later:

1. Place them in `theoretical-docs/`.
2. Extract their text/requirements and update
   [docs/pdf-requirements.md](docs/pdf-requirements.md) accordingly — do not
   invent content for pages that can't be extracted; note that explicitly.
3. Record any new conflict with the working system in
   [docs/decisions.md](docs/decisions.md).

## Deploying

- Web app → Vercel: see [docs/deployment.md](docs/deployment.md).
- Scanner worker → Railway/Render/Fly.io/VPS via the provided `Dockerfile` in
  `scanner-worker/`: see [docs/deployment.md](docs/deployment.md).
- Database → any managed PostgreSQL (e.g. Neon) for production; SQLite is
  used for local development only (Vercel functions have no persistent
  filesystem).

## How the score is calculated

See [docs/scoring-methodology.md](docs/scoring-methodology.md). Short
version: deterministic, starts at 100, subtracts
`severityPoints × confidenceMultiplier × exposureMultiplier × repetitionMultiplier`
per deduplicated finding, clamped to `[0, 100]`. Never random, never
finding-count-independent, never invented for a failed scan.

## How the PDF is generated

`lib/report.ts` renders the scan's own stored findings/score to HTML, then
[Playwright](https://playwright.dev/) prints that HTML to PDF (headless
Chromium). The PDF is SHA-256 hashed and the hash is stored alongside the
`Report` row. No finding is added to the PDF that isn't already in the
scan's own `Finding` records; cookie values, Authorization headers, and
tokens are never rendered (see `lib/redact.ts`).

## Limits of this scan

This is an automated, non-intrusive scanner. It does not perform business
logic testing, does not review server-side source code, does not test
authenticated/logged-in areas, and does not replace a full manual
penetration test. A check that failed or was skipped is always reported as
such — never silently treated as passed.

## Testing

See [docs/testing.md](docs/testing.md).

```bash
npm run typecheck
npm run lint
npm test
```
