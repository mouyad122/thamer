import { describe, expect, it } from "vitest";
import {
  UrlSecurityError,
  isBlockedIp,
  isEncodedIpBypass,
  validateAndNormalizeUrl,
} from "../../lib/url-validation";

describe("validateAndNormalizeUrl — protocol & shape", () => {
  it("accepts a plain https URL", () => {
    expect(() => validateAndNormalizeUrl("https://example.com")).not.toThrow();
  });

  it("adds https:// when no protocol is given", () => {
    const { url } = validateAndNormalizeUrl("example.com");
    expect(url.protocol).toBe("https:");
  });

  it("rejects non-http(s) protocols", () => {
    expect(() => validateAndNormalizeUrl("ftp://example.com")).toThrow(UrlSecurityError);
    expect(() => validateAndNormalizeUrl("file:///etc/passwd")).toThrow(UrlSecurityError);
    expect(() => validateAndNormalizeUrl("gopher://example.com")).toThrow(UrlSecurityError);
  });

  it("rejects URLs with embedded credentials", () => {
    expect(() => validateAndNormalizeUrl("https://user:pass@example.com")).toThrow(
      UrlSecurityError,
    );
  });

  it("rejects an empty string", () => {
    expect(() => validateAndNormalizeUrl("")).toThrow();
  });

  it("rejects an implausibly long URL", () => {
    expect(() => validateAndNormalizeUrl("https://example.com/" + "a".repeat(3000))).toThrow();
  });
});

describe("validateAndNormalizeUrl — SSRF blocking", () => {
  it("rejects localhost", () => {
    expect(() => validateAndNormalizeUrl("http://localhost")).toThrow(UrlSecurityError);
    expect(() => validateAndNormalizeUrl("http://sub.localhost")).toThrow(UrlSecurityError);
  });

  it("rejects loopback IPv4 and IPv6 literals", () => {
    expect(() => validateAndNormalizeUrl("http://127.0.0.1")).toThrow(UrlSecurityError);
    expect(() => validateAndNormalizeUrl("http://[::1]")).toThrow(UrlSecurityError);
  });

  it("rejects private IPv4 ranges", () => {
    expect(() => validateAndNormalizeUrl("http://10.1.2.3")).toThrow(UrlSecurityError);
    expect(() => validateAndNormalizeUrl("http://172.16.0.5")).toThrow(UrlSecurityError);
    expect(() => validateAndNormalizeUrl("http://192.168.1.10")).toThrow(UrlSecurityError);
  });

  it("rejects link-local and cloud metadata addresses", () => {
    expect(() => validateAndNormalizeUrl("http://169.254.1.1")).toThrow(UrlSecurityError);
    expect(() => validateAndNormalizeUrl("http://169.254.169.254")).toThrow(UrlSecurityError);
  });

  it("rejects 0.0.0.0", () => {
    expect(() => validateAndNormalizeUrl("http://0.0.0.0")).toThrow(UrlSecurityError);
  });

  it("rejects decimal-encoded IP bypass of 127.0.0.1", () => {
    expect(() => validateAndNormalizeUrl("http://2130706433")).toThrow(UrlSecurityError);
  });

  it("rejects hex-encoded IP bypass of 127.0.0.1", () => {
    expect(() => validateAndNormalizeUrl("http://0x7f000001")).toThrow(UrlSecurityError);
  });

  it("rejects octal-encoded IP bypass of 127.0.0.1", () => {
    expect(() => validateAndNormalizeUrl("http://0177.0.0.1")).toThrow(UrlSecurityError);
  });

  it("rejects partial dotted-decimal bypass (127.1 == 127.0.0.1)", () => {
    expect(() => validateAndNormalizeUrl("http://127.1")).toThrow(UrlSecurityError);
  });

  it("accepts a normal public IP literal", () => {
    expect(() => validateAndNormalizeUrl("http://93.184.216.34")).not.toThrow();
  });
});

describe("isBlockedIp / isEncodedIpBypass helpers", () => {
  it("flags reserved/multicast ranges", () => {
    expect(isBlockedIp("224.0.0.1")).toBe(true);
    expect(isBlockedIp("240.0.0.1")).toBe(true);
  });

  it("flags IPv4-mapped IPv6 loopback bypass", () => {
    expect(isBlockedIp("::ffff:127.0.0.1")).toBe(true);
  });

  it("flags IPv6 unique-local and link-local ranges", () => {
    expect(isBlockedIp("fc00::1")).toBe(true);
    expect(isBlockedIp("fe80::1")).toBe(true);
  });

  it("does not flag a normal public IPv4 address", () => {
    expect(isBlockedIp("93.184.216.34")).toBe(false);
  });

  it("detects numeric-only hostnames as IP-encoding bypass attempts", () => {
    expect(isEncodedIpBypass("2130706433")).toBe(true);
    expect(isEncodedIpBypass("0x7f000001")).toBe(true);
  });

  it("does not misclassify a normal hostname as an IP bypass", () => {
    expect(isEncodedIpBypass("example.com")).toBe(false);
  });
});
