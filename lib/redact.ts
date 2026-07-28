/**
 * Defense-in-depth redaction applied to any free-text field before it is
 * shown in the UI or embedded in a PDF report, in case a scanner ever
 * captures something sensitive in evidence/response text. Cookie values,
 * Authorization headers, and tokens must never reach the report even if a
 * check's evidence text happens to include them.
 */
const REDACTION_PATTERNS: [RegExp, string][] = [
  [/authorization:\s*[^\n\r]+/gi, "Authorization: [REDACTED]"],
  [/bearer\s+[a-z0-9._-]+/gi, "Bearer [REDACTED]"],
  [/set-cookie:\s*[^;\n\r]+/gi, "Set-Cookie: [REDACTED]=[REDACTED]"],
  [/(api[_-]?key["'=:\s]+)[a-z0-9_-]{10,}/gi, "$1[REDACTED]"],
  [/(password["'=:\s]+)\S+/gi, "$1[REDACTED]"],
];

export function redact(text: string): string {
  let result = text;
  for (const [pattern, replacement] of REDACTION_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}
