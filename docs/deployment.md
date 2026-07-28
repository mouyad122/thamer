# Deployment

## Web app → Vercel

1. Push this repo to GitHub and import it in Vercel.
2. Set environment variables in the Vercel project (Production +
   Preview):
   - `DATABASE_URL` — a managed PostgreSQL connection string (see below).
     **Do not use SQLite on Vercel** — serverless functions have no
     persistent filesystem, so a SQLite file would reset/corrupt between
     invocations.
   - `REPORTS_DIR` — set to a path Vercel can write to at runtime, e.g.
     `/tmp/reports`. `/tmp` is the only writable directory in a Vercel
     function, and its contents do not persist across invocations/regions —
     for real production use, upload the generated PDF to object storage
     (S3-compatible bucket) instead of relying on local disk, and store that
     URL on the `Report` row. This repo's `lib/report.ts` currently writes to
     local disk (`REPORTS_DIR`) for simplicity, matching the project's
     "keep it as simple as it can actually work" priority — swapping the
     final `writeFile` call for an object-storage upload is a small, isolated
     change if you need it to survive across Vercel invocations.
   - `SCANNER_WORKER_URL` / `SCANNER_WORKER_SECRET` — point at your deployed
     scanner-worker (see below). Leave empty to run without ZAP Baseline
     (scans will be marked Partial with `ZAP_BASELINE` skipped).
   - `SCAN_ALLOW_PRIVATE_NETWORKS` — **do not set this to `true` on Vercel**.
     It exists only for the local Docker Compose demo against Juice Shop.
   - `SCAN_HTTP_TIMEOUT_MS` — optional, defaults to `10000`.
3. Because a scan (especially with ZAP Baseline) can take longer than the
   default serverless timeout, set a longer `maxDuration` for the run route.
   This repo already exports `export const maxDuration = 300;` from
   `app/api/scans/[id]/run/route.ts` — on the Vercel Hobby plan the actual
   enforced ceiling is lower (10s); Pro/Enterprise plans allow up to 300s+.
   For a course demo on the Hobby plan, keep the worker disabled (skip ZAP)
   so the request finishes well under the limit, or run the app locally
   (`npm run dev`) for the live demo instead of the deployed instance.
4. Run database migrations against the production database before first
   deploy:
   ```bash
   DATABASE_URL="<your-postgres-url>" npx prisma migrate deploy
   ```
   (Switch `provider = "sqlite"` to `provider = "postgresql"` in
   `prisma/schema.prisma` first, then run `npx prisma migrate dev` locally
   once against a Postgres instance to generate the initial migration.)

### Managed PostgreSQL (recommended: Neon)

1. Create a free Neon project, copy the pooled connection string.
2. Set it as `DATABASE_URL` in Vercel.
3. `schema.prisma`'s `datasource db { provider = "postgresql" }`.

## Scanner worker → Railway / Render / Fly.io / a VPS

The worker is a plain Docker image (`scanner-worker/Dockerfile`), so any of
these work the same way: build the image from `scanner-worker/`, deploy it,
and set two environment variables on it:

- `SCANNER_WORKER_SECRET` — must match the value set in the web app's
  `SCANNER_WORKER_SECRET`. This is the HMAC key used to authenticate
  requests from the web app to the worker (`X-Signature` header).
- `SCAN_ALLOW_PRIVATE_NETWORKS` — leave unset/`false` in any real deployment.

### Railway / Render

Point the service at the `scanner-worker/` directory (or use their "Docker
build from subdirectory" option), expose port `8080`, and set the two
environment variables above. Both platforms auto-detect the `Dockerfile`.

### Fly.io

```bash
cd scanner-worker
fly launch --no-deploy   # creates fly.toml, choose a region
fly secrets set SCANNER_WORKER_SECRET=<your-secret>
fly deploy
```

### Plain VPS

```bash
cd scanner-worker
docker build -t scanner-worker .
docker run -d --restart unless-stopped -p 8080:8080 \
  -e SCANNER_WORKER_SECRET=<your-secret> \
  scanner-worker
```

Put a reverse proxy (Caddy/Nginx) with TLS in front of it if the web app and
worker are on different hosts, and set `SCANNER_WORKER_URL` to the HTTPS
URL.

## What is NOT deployed together

- **OWASP ZAP does not run inside the Vercel function.** It only runs inside
  the scanner-worker container (built from `zaproxy/zap-stable`), which is
  why it needs its own deployment target.
- **No queue/broker is required.** The scan runs as one (potentially long)
  HTTP request to `/api/scans/:id/run`; the browser polls `/status`
  concurrently against the same database for live progress. This matches the
  brief's instruction to avoid unnecessary microservices/queues for a
  student project of this scope.
