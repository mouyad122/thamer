import { describe, expect, it } from "vitest";
import { analyzeHtmlSecurity, extractForms, extractResourceUrls } from "../../lib/checks/html";

describe("extractForms", () => {
  it("detects a password field inside a form", () => {
    const html = `<form action="/login" method="post"><input type="text" name="u"><input type="password" name="p"></form>`;
    const [form] = extractForms(html);
    expect(form!.hasPasswordField).toBe(true);
    expect(form!.action).toBe("/login");
    expect(form!.method).toBe("post");
  });

  it("does not flag a form with no password field", () => {
    const html = `<form action="/search"><input type="text" name="q"></form>`;
    const [form] = extractForms(html);
    expect(form!.hasPasswordField).toBe(false);
  });
});

describe("analyzeHtmlSecurity", () => {
  it("flags a password form submitting to a plain-http action on an https page", () => {
    const html = `<form action="http://example.com/login" method="post"><input type="password" name="p"></form>`;
    const findings = analyzeHtmlSecurity({ html, pageUrl: "https://example.com/", usedTls: true });
    expect(findings.map((f) => f.ruleId)).toContain("PASSWORD_FORM_OVER_HTTP");
    expect(findings[0]!.severity).toBe("HIGH");
  });

  it("does not flag a password form submitting over https", () => {
    const html = `<form action="https://example.com/login" method="post"><input type="password" name="p"></form>`;
    const findings = analyzeHtmlSecurity({ html, pageUrl: "https://example.com/", usedTls: true });
    expect(findings.map((f) => f.ruleId)).not.toContain("PASSWORD_FORM_OVER_HTTP");
  });

  it("flags active mixed content (http script on an https page)", () => {
    const html = `<script src="http://cdn.example.com/lib.js"></script>`;
    const findings = analyzeHtmlSecurity({ html, pageUrl: "https://example.com/", usedTls: true });
    expect(findings.map((f) => f.ruleId)).toContain("MIXED_CONTENT_ACTIVE");
  });

  it("flags passive mixed content (http image) as LOW, separate from active", () => {
    const html = `<img src="http://cdn.example.com/pic.jpg">`;
    const findings = analyzeHtmlSecurity({ html, pageUrl: "https://example.com/", usedTls: true });
    const finding = findings.find((f) => f.ruleId === "MIXED_CONTENT_PASSIVE");
    expect(finding?.severity).toBe("LOW");
  });

  it("does not flag mixed content when the page itself is plain http", () => {
    const html = `<img src="http://cdn.example.com/pic.jpg">`;
    const findings = analyzeHtmlSecurity({ html, pageUrl: "http://example.com/", usedTls: false });
    expect(findings.map((f) => f.ruleId)).not.toContain("MIXED_CONTENT_PASSIVE");
  });
});

describe("extractResourceUrls", () => {
  it("extracts script, img, iframe, and link resource URLs", () => {
    const html = `
      <script src="/a.js"></script>
      <img src="/b.png">
      <iframe src="/c.html"></iframe>
      <link href="/d.css">
    `;
    const urls = extractResourceUrls(html);
    expect(urls.map((u) => u.tag).sort()).toEqual(["iframe", "img", "link", "script"]);
  });
});
