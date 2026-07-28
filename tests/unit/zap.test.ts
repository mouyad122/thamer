import { describe, expect, it } from "vitest";
import { normalizeZapReport, type ZapBaselineReport } from "../../lib/checks/zap";

describe("normalizeZapReport", () => {
  it("maps a ZAP alert to a RawFinding preserving ZAP's own confidence (not auto-confirmed)", () => {
    const report: ZapBaselineReport = {
      site: [
        {
          "@name": "https://example.com",
          alerts: [
            {
              pluginid: "10038",
              name: "Content Security Policy (CSP) Header Not Set",
              riskdesc: "Medium (High)",
              confidence: "Medium",
              desc: "<p>CSP is not set</p>",
              solution: "<p>Add a CSP header</p>",
              cweid: "693",
              instances: [{ uri: "https://example.com/", method: "GET" }],
            },
          ],
        },
      ],
    };
    const findings = normalizeZapReport(report);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("MEDIUM");
    expect(findings[0]!.confidence).toBe("MEDIUM");
    expect(findings[0]!.confidence).not.toBe("CONFIRMED");
    expect(findings[0]!.cweId).toBe("CWE-693");
    expect(findings[0]!.source).toBe("OWASP ZAP");
    expect(findings[0]!.description).not.toContain("<p>");
  });

  it("preserves CONFIRMED when ZAP itself reports Confirmed confidence", () => {
    const report: ZapBaselineReport = {
      site: [
        {
          alerts: [
            {
              pluginid: "1",
              name: "Test",
              riskdesc: "High (Confirmed)",
              confidence: "Confirmed",
              instances: [{ uri: "https://example.com/" }],
            },
          ],
        },
      ],
    };
    const [finding] = normalizeZapReport(report);
    expect(finding!.confidence).toBe("CONFIRMED");
    expect(finding!.severity).toBe("HIGH");
  });

  it("creates one finding per instance so duplicated-page issues are all tracked", () => {
    const report: ZapBaselineReport = {
      site: [
        {
          alerts: [
            {
              pluginid: "1",
              name: "Test",
              riskdesc: "Low (Low)",
              confidence: "Low",
              instances: [{ uri: "https://example.com/a" }, { uri: "https://example.com/b" }],
            },
          ],
        },
      ],
    };
    expect(normalizeZapReport(report)).toHaveLength(2);
  });

  it("skips alerts with an unrecognized risk level rather than guessing a severity", () => {
    const report: ZapBaselineReport = {
      site: [{ alerts: [{ pluginid: "1", name: "Weird", riskdesc: "Unknown (Low)", confidence: "Low" }] }],
    };
    expect(normalizeZapReport(report)).toHaveLength(0);
  });
});
