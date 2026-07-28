import type { CheckName } from "./types";

/** Human-readable, real (non-simulated) step names shown to the user during a scan. */
export const STEP_LABELS: Record<CheckName, string> = {
  URL_VALIDATION: "Validating URL",
  HTTPS_CHECK: "Checking HTTPS",
  TLS_CERTIFICATE: "Checking TLS Certificate",
  SECURITY_HEADERS: "Checking Security Headers",
  COOKIE_SECURITY: "Checking Cookies",
  CORS_ANALYSIS: "Checking CORS",
  INFORMATION_DISCLOSURE: "Checking Information Disclosure",
  HTML_SECURITY: "Checking HTML Security",
  COMMON_SAFE_FILES: "Checking Common Files",
  ZAP_BASELINE: "Running Passive Security Scan",
};

export const CALCULATING_RESULT_STEP = "Calculating Result";
export const GENERATING_REPORT_STEP = "Generating Report";
export const SCAN_FAILED_STEP = "Scan Failed";
export const SCAN_COMPLETE_STEP = "Scan Complete";
