const net = require("node:net");

const METADATA_IPS = new Set(["169.254.169.254", "fd00:ec2::254"]);

/**
 * Lighter-weight mirror of the main app's private-IP policy (see
 * lib/url-validation.ts), duplicated here because the worker is a
 * standalone deployable without access to the main app's TypeScript lib.
 * Cloud metadata addresses are always blocked. Other private ranges are
 * blocked unless SCAN_ALLOW_PRIVATE_NETWORKS=true (the same local/demo-only
 * escape hatch documented in docs/decisions.md, needed so this worker can
 * scan a Docker Compose neighbor like OWASP Juice Shop during the demo).
 */
function isBlockedTargetIp(ip) {
  if (METADATA_IPS.has(ip)) return true;
  if (process.env.SCAN_ALLOW_PRIVATE_NETWORKS === "true") return false;

  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (normalized === "::1" || normalized === "::") return true;
    if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    if (normalized.startsWith("ff")) return true;
    return false;
  }
  return true; // unrecognized format — fail closed
}

module.exports = { isBlockedTargetIp };
