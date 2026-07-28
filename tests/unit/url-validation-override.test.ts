import { afterEach, describe, expect, it } from "vitest";
import { isBlockedIp, validateAndNormalizeUrl } from "../../lib/url-validation";

describe("SCAN_ALLOW_PRIVATE_NETWORKS demo override", () => {
  const original = process.env.SCAN_ALLOW_PRIVATE_NETWORKS;

  afterEach(() => {
    if (original === undefined) delete process.env.SCAN_ALLOW_PRIVATE_NETWORKS;
    else process.env.SCAN_ALLOW_PRIVATE_NETWORKS = original;
  });

  it("blocks private IPs by default", () => {
    delete process.env.SCAN_ALLOW_PRIVATE_NETWORKS;
    expect(() => validateAndNormalizeUrl("http://192.168.1.10")).toThrow();
  });

  it("allows private IPs and localhost when explicitly enabled", () => {
    process.env.SCAN_ALLOW_PRIVATE_NETWORKS = "true";
    expect(() => validateAndNormalizeUrl("http://192.168.1.10")).not.toThrow();
    expect(() => validateAndNormalizeUrl("http://localhost:3000")).not.toThrow();
  });

  it("still blocks cloud metadata addresses even with the override enabled", () => {
    process.env.SCAN_ALLOW_PRIVATE_NETWORKS = "true";
    expect(isBlockedIp("169.254.169.254")).toBe(true);
  });
});
