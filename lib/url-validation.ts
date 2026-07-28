import { z } from "zod";
import dns from "node:dns/promises";
import net from "node:net";

/**
 * Central URL Security Policy: validates a user-supplied target URL and blocks
 * SSRF vectors. Never relies on regex alone — private/loopback/link-local/
 * metadata detection is done via real numeric IP parsing (IPv4 + IPv6), and
 * every hostname is resolved via DNS before use so redirects and rebinding
 * can be re-checked against the same policy.
 */

export const MAX_URL_LENGTH = 2048;
const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

export class UrlSecurityError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
  ) {
    super(message);
    this.name = "UrlSecurityError";
  }
}

const urlInputSchema = z
  .string()
  .trim()
  .min(1, "URL is required")
  .max(MAX_URL_LENGTH, "URL is too long");

/** Cloud metadata endpoints that must never be reachable, across common providers. */
const METADATA_IPS = new Set(["169.254.169.254", "fd00:ec2::254"]);

/** Parses a dotted-decimal, decimal, hex, or octal-encoded IPv4 literal into 4 octets. */
function parseIPv4Bypass(host: string): number[] | null {
  // Reject anything that isn't purely numeric/dot/hex-prefixed segments — this
  // stops embedding letters or path traversal tricks disguised as an IP.
  if (!/^(0x[0-9a-f]+|0[0-7]+|[0-9]+)(\.(0x[0-9a-f]+|0[0-7]+|[0-9]+)){0,3}$/i.test(host)) {
    return null;
  }
  const parts = host.split(".");
  if (parts.length > 4) return null;

  const toNumber = (part: string): number | null => {
    if (/^0x[0-9a-f]+$/i.test(part)) return parseInt(part, 16);
    if (/^0[0-7]+$/.test(part)) return parseInt(part, 8);
    if (/^[0-9]+$/.test(part)) return parseInt(part, 10);
    return null;
  };

  const nums = parts.map(toNumber);
  if (nums.some((n) => n === null || Number.isNaN(n) || n < 0)) return null;
  const values = nums as number[];

  // Single-number form (decimal/hex/octal IP, e.g. 2130706433 == 127.0.0.1)
  if (values.length === 1) {
    const n = values[0]!;
    if (n > 0xffffffff) return null;
    return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  }
  // Standard or partial dotted form: last part absorbs remaining bits.
  if (values.some((n) => n > 0xffffffff)) return null;
  const last = values[values.length - 1]!;
  const head = values.slice(0, -1);
  if (head.some((n) => n > 255)) return null;
  const remainingBytes = 4 - head.length;
  if (last >= Math.pow(256, remainingBytes)) return null;
  const tail: number[] = [];
  let rem = last;
  for (let i = 0; i < remainingBytes; i++) {
    tail.unshift(rem & 0xff);
    rem = Math.floor(rem / 256);
  }
  return [...head, ...tail];
}

function isPrivateOrReservedIPv4(octets: number[]): boolean {
  const [a, b] = octets as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local + metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 192 && b === 0 && octets[2] === 0) return true; // 192.0.0.0/24 (IETF protocol assignments)
  if (a === 192 && b === 0 && octets[2] === 2) return true; // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 198 && b === 51 && octets[2] === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && octets[2] === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast (224-239) + reserved/broadcast (240-255)
  return false;
}

function isPrivateOrReservedIPv6(address: string): boolean {
  const normalized = address.toLowerCase();
  if (normalized === "::1") return true; // loopback
  if (normalized === "::") return true; // unspecified
  if (normalized.startsWith("fe80:") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true; // link-local fe80::/10
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true; // unique local fc00::/7
  if (normalized.startsWith("ff")) return true; // multicast
  // IPv4-mapped / IPv4-compatible IPv6 — unwrap and re-check as IPv4.
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) {
    const octets = mapped[1]!.split(".").map(Number);
    return isPrivateOrReservedIPv4(octets);
  }
  if (METADATA_IPS.has(normalized)) return true;
  return false;
}

/**
 * Local/demo-only escape hatch: when explicitly enabled via environment
 * variable, private-network targets (e.g. a Docker Compose service like
 * OWASP Juice Shop on a private bridge network) are allowed so the scanner
 * can be demonstrated end-to-end offline. Cloud metadata addresses remain
 * blocked unconditionally regardless of this flag. This must never be
 * enabled on a deployment reachable from the public internet — see
 * docs/decisions.md and docs/deployment.md.
 */
function isPrivateNetworkScanningAllowed(): boolean {
  return process.env.SCAN_ALLOW_PRIVATE_NETWORKS === "true";
}

/** Returns true if the given resolved IP address must be blocked by policy. */
export function isBlockedIp(ip: string): boolean {
  if (METADATA_IPS.has(ip)) return true;
  if (isPrivateNetworkScanningAllowed()) return false;
  if (net.isIPv4(ip)) {
    return isPrivateOrReservedIPv4(ip.split(".").map(Number));
  }
  if (net.isIPv6(ip)) {
    return isPrivateOrReservedIPv6(ip);
  }
  return true; // unrecognized format — fail closed
}

/** Detects numeric-IP-encoded hostnames (decimal/hex/octal) even without dots. */
export function isEncodedIpBypass(hostname: string): boolean {
  const octets = parseIPv4Bypass(hostname);
  return octets !== null;
}

export interface NormalizedTarget {
  url: URL;
  hostname: string;
}

/**
 * Validates URL shape/protocol/credentials/hostname-format only. Does NOT
 * perform DNS resolution — call `resolveAndCheckHost` separately (and again
 * after every redirect) before opening any network connection.
 */
export function validateAndNormalizeUrl(input: string): NormalizedTarget {
  const trimmed = urlInputSchema.parse(input);

  // Only prepend a protocol when the input has none at all — any existing
  // scheme (including disallowed ones like ftp:// or file://) must reach the
  // protocol check below and be rejected there, never silently coerced.
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed);
  const candidate = hasScheme ? trimmed : `https://${trimmed}`;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new UrlSecurityError("The URL could not be parsed.", "INVALID_URL");
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new UrlSecurityError(
      `Protocol "${url.protocol}" is not allowed. Only http and https are permitted.`,
      "PROTOCOL_NOT_ALLOWED",
    );
  }

  if (url.username || url.password) {
    throw new UrlSecurityError(
      "URLs containing embedded credentials are not allowed.",
      "EMBEDDED_CREDENTIALS",
    );
  }

  // Strip IPv6 brackets ("[::1]" -> "::1") so net.isIP()/DNS/IP-policy checks
  // work uniformly; the original `url` object (used for the actual request)
  // keeps its bracketed form as required by the URL/HTTP specs.
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (!isPrivateNetworkScanningAllowed() && (hostname === "localhost" || hostname.endsWith(".localhost"))) {
    throw new UrlSecurityError("Scanning localhost is not allowed.", "LOCALHOST_BLOCKED");
  }

  // Punycode/IDN normalization happens automatically via the URL constructor
  // (url.hostname is already ASCII/punycode-encoded), so downstream code
  // never has to special-case Unicode hostnames.

  if (isEncodedIpBypass(hostname)) {
    const octets = parseIPv4Bypass(hostname)!;
    const dotted = octets.join(".");
    if (isBlockedIp(dotted)) {
      throw new UrlSecurityError(
        "The target address resolves to a private, loopback, or reserved network.",
        "PRIVATE_IP_BLOCKED",
      );
    }
  }

  if (net.isIP(hostname) && isBlockedIp(hostname)) {
    throw new UrlSecurityError(
      "The target address resolves to a private, loopback, or reserved network.",
      "PRIVATE_IP_BLOCKED",
    );
  }

  return { url, hostname };
}

export interface ResolvedHost {
  hostname: string;
  addresses: string[];
}

/**
 * Resolves a hostname via DNS and verifies every returned address against the
 * URL Security Policy. Must be called before the initial connection AND again
 * for the Location host after every HTTP redirect (prevents DNS rebinding and
 * redirect-based SSRF).
 */
export async function resolveAndCheckHost(hostname: string): Promise<ResolvedHost> {
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new UrlSecurityError(
        "The target address resolves to a private, loopback, or reserved network.",
        "PRIVATE_IP_BLOCKED",
      );
    }
    return { hostname, addresses: [hostname] };
  }

  let records: { address: string }[];
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new UrlSecurityError(
      `DNS resolution failed for "${hostname}".`,
      "DNS_RESOLUTION_FAILED",
    );
  }

  if (records.length === 0) {
    throw new UrlSecurityError(
      `DNS resolution returned no addresses for "${hostname}".`,
      "DNS_RESOLUTION_FAILED",
    );
  }

  const addresses = records.map((r) => r.address);
  const blocked = addresses.filter((addr) => isBlockedIp(addr));
  if (blocked.length > 0) {
    throw new UrlSecurityError(
      `"${hostname}" resolves to a blocked address (${blocked.join(", ")}).`,
      "PRIVATE_IP_BLOCKED",
    );
  }

  return { hostname, addresses };
}

/** Full validation pipeline: syntax/protocol checks + DNS + IP policy for the initial target. */
export async function validateTargetUrl(input: string): Promise<NormalizedTarget> {
  const target = validateAndNormalizeUrl(input);
  await resolveAndCheckHost(target.hostname);
  return target;
}
