import type { RawFinding } from "../types";
import { owaspLabel } from "../owasp";

const SOURCE = "Custom HTML Scanner";

export interface HtmlForm {
  action: string;
  method: string;
  hasPasswordField: boolean;
}

export interface HtmlAnalysisInput {
  html: string;
  pageUrl: string;
  usedTls: boolean;
}

function extractAttr(tag: string, attr: string): string | null {
  const match = tag.match(new RegExp(`${attr}\\s*=\\s*["']([^"']*)["']`, "i"));
  return match ? match[1]! : null;
}

export function extractForms(html: string): HtmlForm[] {
  const forms: HtmlForm[] = [];
  const formTagRegex = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
  let match: RegExpExecArray | null;
  while ((match = formTagRegex.exec(html)) !== null) {
    const openTag = match[0].match(/<form\b[^>]*>/i)?.[0] ?? "<form>";
    const body = match[1] ?? "";
    forms.push({
      action: extractAttr(openTag, "action") ?? "",
      method: (extractAttr(openTag, "method") ?? "get").toLowerCase(),
      hasPasswordField: /<input\b[^>]*type\s*=\s*["']password["']/i.test(body),
    });
  }
  return forms;
}

export function extractResourceUrls(html: string): { tag: string; url: string }[] {
  const results: { tag: string; url: string }[] = [];
  const patterns: [string, RegExp][] = [
    ["script", /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi],
    ["img", /<img\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi],
    ["iframe", /<iframe\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi],
    ["link", /<link\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi],
  ];
  for (const [tag, regex] of patterns) {
    let m: RegExpExecArray | null;
    while ((m = regex.exec(html)) !== null) {
      results.push({ tag, url: m[1]! });
    }
  }
  return results;
}

function resolveUrl(base: string, url: string): string | null {
  try {
    return new URL(url, base).toString();
  } catch {
    return null;
  }
}

/**
 * Analyzes the already-fetched HTML body (no extra requests) for real,
 * directly-observable issues: password forms submitting to plain HTTP, and
 * mixed content (HTTP sub-resources loaded on an HTTPS page).
 */
export function analyzeHtmlSecurity(input: HtmlAnalysisInput): RawFinding[] {
  const findings: RawFinding[] = [];
  const forms = extractForms(input.html);

  for (const form of forms) {
    if (!form.hasPasswordField) continue;
    const actionUrl = form.action ? resolveUrl(input.pageUrl, form.action) : input.pageUrl;
    const submitsOverHttp = actionUrl ? actionUrl.startsWith("http://") : !input.usedTls;
    if (submitsOverHttp) {
      findings.push({
        ruleId: "PASSWORD_FORM_OVER_HTTP",
        title: "A password field submits to a plain HTTP endpoint",
        severity: "HIGH",
        confidence: "CONFIRMED",
        exposure: "DIRECT_PROVEN",
        affectedUrl: actionUrl ?? input.pageUrl,
        description: `A <form> containing a password input submits (method=${form.method.toUpperCase()}) to "${actionUrl ?? input.pageUrl}", which is not HTTPS. The password would be sent in clear text.`,
        remediation: "Serve the page and its form action exclusively over HTTPS so credentials are never transmitted unencrypted.",
        owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
        cweId: "CWE-319",
        source: SOURCE,
        detailKey: actionUrl ?? "form-action",
      });
    }
  }

  if (input.usedTls) {
    const resources = extractResourceUrls(input.html);
    const mixedActive: string[] = [];
    const mixedPassive: string[] = [];
    for (const resource of resources) {
      const resolved = resolveUrl(input.pageUrl, resource.url);
      if (!resolved || !resolved.startsWith("http://")) continue;
      if (resource.tag === "script" || resource.tag === "iframe" || resource.tag === "link") {
        mixedActive.push(resolved);
      } else {
        mixedPassive.push(resolved);
      }
    }

    if (mixedActive.length > 0) {
      findings.push({
        ruleId: "MIXED_CONTENT_ACTIVE",
        title: "Active mixed content (HTTP script/iframe/stylesheet on an HTTPS page)",
        severity: "MEDIUM",
        confidence: "CONFIRMED",
        exposure: "DIRECT_PROVEN",
        affectedUrl: input.pageUrl,
        description: `This HTTPS page loads ${mixedActive.length} script/iframe/stylesheet resource(s) over plain HTTP, which browsers typically block and which can be tampered with in transit if not blocked.`,
        evidence: mixedActive.slice(0, 5).join(", "),
        remediation: "Serve all scripts, iframes, and stylesheets over HTTPS (protocol-relative or absolute https:// URLs).",
        owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
        cweId: "CWE-319",
        source: SOURCE,
        detailKey: "mixed-content-active",
      });
    }
    if (mixedPassive.length > 0) {
      findings.push({
        ruleId: "MIXED_CONTENT_PASSIVE",
        title: "Passive mixed content (HTTP images on an HTTPS page)",
        severity: "LOW",
        confidence: "CONFIRMED",
        exposure: "BEST_PRACTICE",
        affectedUrl: input.pageUrl,
        description: `This HTTPS page loads ${mixedPassive.length} image resource(s) over plain HTTP, which most browsers show as a "not fully secure" indicator.`,
        evidence: mixedPassive.slice(0, 5).join(", "),
        remediation: "Serve all images over HTTPS.",
        owaspCategory: owaspLabel("CRYPTOGRAPHIC_FAILURES"),
        cweId: "CWE-319",
        source: SOURCE,
        detailKey: "mixed-content-passive",
      });
    }
  }

  return findings;
}
