import http from "node:http";
import https from "node:https";
import type { LookupOptions } from "node:dns";
import dns from "node:dns";
import type { PeerCertificate, TLSSocket } from "node:tls";
import { UrlSecurityError, isBlockedIp, validateAndNormalizeUrl } from "./url-validation";

/**
 * SSRF-safe HTTP client used by every custom check. Redirects are handled
 * manually (never automatically) so each hop is re-validated against the URL
 * Security Policy, and DNS resolution is re-verified at actual connect time
 * (not just once upfront) to defeat DNS rebinding attacks.
 */

const MAX_REDIRECTS = 5;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB cap
const DEFAULT_TIMEOUT_MS = Number(process.env.SCAN_HTTP_TIMEOUT_MS ?? 10000);

/**
 * `autoSelectFamily` (Node 18.13+) is a real, documented `net.connect`/
 * `http.request` option that disables dual-stack "Happy Eyeballs" racing —
 * the installed @types/node version just hasn't caught up to it yet, so it's
 * added via this narrow extension rather than an untyped `any` request object.
 */
type RequestOptionsWithFamilySelection = http.RequestOptions &
  https.RequestOptions & { autoSelectFamily?: boolean };

export interface SafeResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  finalUrl: string;
  redirectChain: string[];
  tlsCertificate: PeerCertificate | null;
  usedTls: boolean;
}

/**
 * DNS lookup guarded by the URL Security Policy — rejects private/reserved/
 * metadata IPs. Node's http/https internals decide, from the `options.all`
 * flag THEY pass in, whether they expect a single-address callback
 * `(err, address, family)` or an array-form callback `(err, results[])` —
 * that contract must be mirrored exactly, or Node throws
 * ERR_INVALID_IP_ADDRESS trying to read the mismatched shape.
 */
function guardedLookup(
  hostname: string,
  options: LookupOptions & { all?: boolean },
  callback: (
    err: NodeJS.ErrnoException | null,
    address: string | { address: string; family: number }[],
    family?: number,
  ) => void,
): void {
  const wantsAll = options.all === true;
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) {
      callback(err, wantsAll ? [] : "", wantsAll ? undefined : 0);
      return;
    }
    let results = addresses as unknown as { address: string; family: number }[];
    const blocked = results.find((r) => isBlockedIp(r.address));
    if (blocked) {
      const blockedErr = new Error(
        `Resolved address ${blocked.address} for ${hostname} is blocked by the URL Security Policy`,
      ) as NodeJS.ErrnoException;
      blockedErr.code = "EBLOCKEDIP";
      callback(blockedErr, wantsAll ? [] : "", wantsAll ? undefined : 0);
      return;
    }
    // Prefer IPv4: dual-stack "Happy Eyeballs" connection racing can hang far
    // past our own timeout in environments with no real IPv6 egress route
    // (common in sandboxes/containers). Falling back to IPv6-only results
    // when that's all DNS returned keeps IPv6-only hosts working.
    const ipv4Only = results.filter((r) => r.family === 4);
    if (ipv4Only.length > 0) results = ipv4Only;
    if (wantsAll) {
      callback(null, results);
    } else {
      const first = results[0]!;
      callback(null, first.address, first.family);
    }
  });
}

function requestOnce(target: URL, timeoutMs: number): Promise<{
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  tlsCertificate: PeerCertificate | null;
  usedTls: boolean;
}> {
  return new Promise((resolve, reject) => {
    const isHttps = target.protocol === "https:";
    const lib = isHttps ? https : http;

    // A hard, unconditional deadline: Node's `timeout` request option only
    // starts a socket-inactivity timer once a socket exists, so a slow/stuck
    // DNS lookup or a stalled dual-stack connection race can hang well past
    // `timeoutMs` without ever firing the request's own 'timeout' event.
    // This timer fires regardless of connection state and always wins.
    const hardDeadline = setTimeout(() => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const requestOptions: RequestOptionsWithFamilySelection = {
      method: "GET",
      timeout: timeoutMs,
      lookup: guardedLookup,
      // Disable Node's automatic IPv4/IPv6 "Happy Eyeballs" racing — we
      // already resolve and filter addresses ourselves in guardedLookup,
      // and the built-in race can outlive our own timeout in environments
      // without real IPv6 connectivity.
      autoSelectFamily: false,
      headers: {
        "User-Agent": "WebSecurityScanner/1.0 (+authorized-scan)",
        Accept: "text/html,application/json;q=0.9,*/*;q=0.8",
      },
      // Do not verify against system CAs failing silently — we want to know
      // if the cert is invalid, so we still connect but read cert details.
      rejectUnauthorized: false,
    };

    const req = lib.request(
      target,
      requestOptions,
      (res) => {
        // Capture the certificate as soon as headers arrive — by the 'end'
        // event, a keep-alive socket may already be detached (res.socket
        // becomes null), so reading it later is unreliable.
        const socket = res.socket as TLSSocket | null;
        const cert =
          isHttps && socket && typeof socket.getPeerCertificate === "function"
            ? socket.getPeerCertificate(false)
            : null;

        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_RESPONSE_BYTES) {
            req.destroy(new Error("Response exceeded maximum allowed size"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          clearTimeout(hardDeadline);
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf-8"),
            tlsCertificate: cert && Object.keys(cert).length > 0 ? cert : null,
            usedTls: isHttps,
          });
        });
      },
    );

    req.on("timeout", () => req.destroy(new Error("Request timed out")));
    req.on("error", (err) => {
      clearTimeout(hardDeadline);
      reject(err);
    });
    req.end();
  });
}

/**
 * Performs a GET request to `input`, following redirects manually while
 * re-validating each hop's protocol, hostname, and resolved IP. Throws
 * UrlSecurityError if any hop violates the URL Security Policy.
 */
export async function safeFetch(
  input: string,
  opts: { timeoutMs?: number } = {},
): Promise<SafeResponse> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  let { url } = validateAndNormalizeUrl(input);
  const redirectChain: string[] = [];

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const result = await requestOnce(url, timeoutMs);

    if ([301, 302, 303, 307, 308].includes(result.status) && result.headers.location) {
      if (hop === MAX_REDIRECTS) {
        throw new UrlSecurityError("Too many redirects.", "TOO_MANY_REDIRECTS");
      }
      const nextUrl = new URL(result.headers.location, url);
      // Re-run the full policy (protocol, credentials, private-IP-literal checks)
      // on the redirect target before following it.
      const { url: validatedNext } = validateAndNormalizeUrl(nextUrl.toString());
      redirectChain.push(url.toString());
      url = validatedNext;
      continue;
    }

    return {
      status: result.status,
      headers: result.headers as Record<string, string | string[] | undefined>,
      body: result.body,
      finalUrl: url.toString(),
      redirectChain,
      tlsCertificate: result.tlsCertificate,
      usedTls: result.usedTls,
    };
  }

  throw new UrlSecurityError("Too many redirects.", "TOO_MANY_REDIRECTS");
}

export async function safeFetchWithOrigin(
  input: string,
  origin: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<SafeResponse> {
  const { url } = validateAndNormalizeUrl(input);
  const isHttps = url.protocol === "https:";
  const lib = isHttps ? https : http;
  return new Promise((resolve, reject) => {
    const hardDeadline = setTimeout(() => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const requestOptions: RequestOptionsWithFamilySelection = {
      method: "GET",
      timeout: timeoutMs,
      lookup: guardedLookup,
      autoSelectFamily: false,
      headers: {
        "User-Agent": "WebSecurityScanner/1.0 (+authorized-scan)",
        Origin: origin,
      },
      rejectUnauthorized: false,
    };

    const req = lib.request(
      url,
      requestOptions,
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          clearTimeout(hardDeadline);
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers as Record<string, string | string[] | undefined>,
            body: Buffer.concat(chunks).toString("utf-8"),
            finalUrl: url.toString(),
            redirectChain: [],
            tlsCertificate: null,
            usedTls: isHttps,
          });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("Request timed out")));
    req.on("error", (err) => {
      clearTimeout(hardDeadline);
      reject(err);
    });
    req.end();
  });
}
