const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");

/**
 * Runs the official OWASP ZAP Baseline scan (zap-baseline.py) against a
 * single target — a short spider followed by PASSIVE scanning only. No
 * active/attack scan policy is invoked, matching the project's passive-only
 * scope. Returns the parsed JSON report, or throws if ZAP could not run.
 */
async function runZapBaseline(targetUrl, { timeoutMinutes = 2 } = {}) {
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "zap-scan-"));
  const reportFile = "report.json";

  await new Promise((resolve, reject) => {
    const proc = spawn(
      "zap-baseline.py",
      ["-t", targetUrl, "-J", reportFile, "-m", String(timeoutMinutes), "-I"],
      { cwd: workDir },
    );

    let stderr = "";
    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("error", reject);
    proc.on("close", (code) => {
      // zap-baseline.py exits non-zero when it finds alerts above the
      // configured threshold — that is expected and not a failure of the
      // scan itself, so only treat a missing report file as a real error.
      resolve({ code, stderr });
    });
  });

  const reportPath = path.join(workDir, reportFile);
  const raw = await fs.readFile(reportPath, "utf-8").catch(async () => {
    // Some ZAP versions ignore relative -J paths and always write under /zap/wrk.
    const fallback = path.join("/zap/wrk", reportFile);
    return fs.readFile(fallback, "utf-8");
  });

  const report = JSON.parse(raw);
  await fs.rm(workDir, { recursive: true, force: true });
  return report;
}

module.exports = { runZapBaseline };
