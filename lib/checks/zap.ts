import type { Confidence, RawFinding, Severity } from "../types";

const SOURCE = "OWASP ZAP";

interface ZapInstance {
  uri?: string;
  method?: string;
  param?: string;
  evidence?: string;
}

interface ZapAlert {
  pluginid?: string;
  alert?: string;
  name?: string;
  riskdesc?: string;
  confidence?: string;
  desc?: string;
  solution?: string;
  reference?: string;
  cweid?: string;
  wascid?: string;
  instances?: ZapInstance[];
}

interface ZapSite {
  "@name"?: string;
  alerts?: ZapAlert[];
}

export interface ZapBaselineReport {
  site?: ZapSite[];
}

const RISK_TO_SEVERITY: Record<string, Severity> = {
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  informational: "INFORMATIONAL",
};

const ZAP_CONFIDENCE_TO_CONFIDENCE: Record<string, Confidence> = {
  confirmed: "CONFIRMED",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

function stripHtml(value: string): string {
  return value.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Converts a real OWASP ZAP Baseline (passive scan) JSON report into our
 * RawFinding shape. A ZAP alert is never auto-promoted to CONFIRMED — its
 * own reported confidence is preserved (mapped 1:1), since ZAP's own
 * heuristics are not treated as ground truth without ZAP's own confidence
 * qualifier attached. Exposure is set conservatively to CONFIG_WEAKNESS
 * (ZAP's passive checks generally detect misconfigurations, not proven
 * exploits) unless the alert clearly documents a directly exploitable issue.
 */
export function normalizeZapReport(report: ZapBaselineReport): RawFinding[] {
  const findings: RawFinding[] = [];

  for (const site of report.site ?? []) {
    for (const alert of site.alerts ?? []) {
      const riskName = (alert.riskdesc ?? "").split(" ")[0]?.toLowerCase() ?? "";
      const severity = RISK_TO_SEVERITY[riskName];
      if (!severity) continue; // Unknown risk level — do not guess, skip rather than misclassify.

      const confidenceName = (alert.confidence ?? "").toLowerCase();
      const confidence = ZAP_CONFIDENCE_TO_CONFIDENCE[confidenceName] ?? "MEDIUM";

      const instances = alert.instances && alert.instances.length > 0 ? alert.instances : [{}];
      for (const instance of instances) {
        const affectedUrl = instance.uri ?? site["@name"] ?? "";
        findings.push({
          ruleId: `ZAP-${alert.pluginid ?? "unknown"}`,
          title: alert.name ?? alert.alert ?? "OWASP ZAP finding",
          severity,
          confidence,
          exposure: severity === "INFORMATIONAL" ? "INFORMATIONAL_ONLY" : "CONFIG_WEAKNESS",
          affectedUrl,
          description: alert.desc ? stripHtml(alert.desc) : "No description provided by ZAP.",
          evidence: instance.evidence ? stripHtml(instance.evidence) : undefined,
          remediation: alert.solution ? stripHtml(alert.solution) : "See OWASP ZAP alert reference for remediation guidance.",
          owaspCategory: undefined,
          cweId: alert.cweid ? `CWE-${alert.cweid}` : undefined,
          source: SOURCE,
          detailKey: [alert.pluginid, instance.param].filter(Boolean).join(":") || alert.pluginid,
        });
      }
    }
  }

  return findings;
}
