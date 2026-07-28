import { createHash } from "node:crypto";
import type { DedupedFinding, RawFinding } from "./types";

/**
 * Builds a stable fingerprint for a finding from its rule, affected URL path
 * (query string stripped so the same issue on `/x?a=1` and `/x?a=2` merges),
 * and an optional detail key (header/parameter/plugin name). Two scanners
 * reporting the same underlying issue produce the same fingerprint and are
 * merged into a single Finding with both sources recorded.
 */
export function computeFingerprint(finding: Pick<RawFinding, "ruleId" | "affectedUrl" | "detailKey">): string {
  let pathOnly = finding.affectedUrl;
  try {
    const u = new URL(finding.affectedUrl);
    pathOnly = `${u.origin}${u.pathname}`;
  } catch {
    // Not a full URL (e.g. a bare path) — use as-is.
  }
  const raw = [finding.ruleId, pathOnly.toLowerCase(), (finding.detailKey ?? "").toLowerCase()].join("::");
  return createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

/**
 * Deduplicates raw findings from all scanners (custom checks + ZAP) using the
 * fingerprint. Merged findings keep every distinct source and an occurrence
 * count (used later to cap repeated-issue penalties instead of double-charging).
 */
export function deduplicateFindings(findings: RawFinding[]): DedupedFinding[] {
  const byFingerprint = new Map<string, DedupedFinding>();

  for (const finding of findings) {
    const fingerprint = computeFingerprint(finding);
    const existing = byFingerprint.get(fingerprint);
    if (!existing) {
      byFingerprint.set(fingerprint, {
        ...finding,
        fingerprint,
        sources: [finding.source],
        occurrences: 1,
      });
      continue;
    }
    if (!existing.sources.includes(finding.source)) {
      existing.sources.push(finding.source);
    }
    existing.occurrences += 1;
    // Keep the more complete evidence/description if the first source lacked one.
    if (!existing.evidence && finding.evidence) existing.evidence = finding.evidence;
  }

  return [...byFingerprint.values()];
}
