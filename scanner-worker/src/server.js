const dns = require("node:dns/promises");
const express = require("express");
const { verifySignature } = require("./verify-signature");
const { runZapBaseline } = require("./zap-runner");
const { isBlockedTargetIp } = require("./ssrf-guard");

const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
const SECRET = process.env.SCANNER_WORKER_SECRET;

if (!SECRET) {
  console.error("SCANNER_WORKER_SECRET is required — refusing to start unauthenticated.");
  process.exit(1);
}

const app = express();
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf.toString("utf-8"); } }));

// Simple in-memory per-domain lock: refuse a second concurrent scan of the same host.
const activeDomains = new Set();

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/scan", async (req, res) => {
  const signature = req.header("X-Signature");
  if (!verifySignature(req.rawBody ?? "", signature, SECRET)) {
    return res.status(401).json({ error: "Invalid or missing signature." });
  }

  const { targetUrl } = req.body ?? {};
  if (typeof targetUrl !== "string" || !targetUrl) {
    return res.status(400).json({ error: "targetUrl is required." });
  }

  let hostname;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return res.status(400).json({ error: "targetUrl is not a valid URL." });
  }

  if (activeDomains.has(hostname)) {
    return res.status(409).json({ error: `A scan for ${hostname} is already in progress.` });
  }

  // The worker's own SSRF guard: zap-baseline.py talks to the target
  // directly and never passes through the main app's URL Security Policy,
  // so this check is duplicated here rather than trusted to have already
  // happened upstream.
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    const blocked = addresses.find((a) => isBlockedTargetIp(a.address));
    if (blocked) {
      return res.status(403).json({ error: `Target resolves to a blocked address (${blocked.address}).` });
    }
  } catch {
    return res.status(400).json({ error: `DNS resolution failed for "${hostname}".` });
  }

  activeDomains.add(hostname);
  try {
    const report = await runZapBaseline(targetUrl);
    return res.json({ report });
  } catch (err) {
    console.error("ZAP baseline scan failed:", err);
    return res.status(502).json({ error: "ZAP baseline scan failed to run." });
  } finally {
    activeDomains.delete(hostname);
  }
});

const server = app.listen(PORT, () => {
  console.log(`scanner-worker listening on port ${PORT}`);
});

// Graceful shutdown: stop accepting new work and let in-flight scans finish.
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    console.log(`Received ${signal}, shutting down gracefully...`);
    server.close(() => process.exit(0));
  });
}
