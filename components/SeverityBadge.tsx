const CLASS_BY_SEVERITY: Record<string, string> = {
  CRITICAL: "bg-critical text-white",
  HIGH: "bg-high text-white",
  MEDIUM: "bg-medium text-white",
  LOW: "bg-low text-white",
  INFORMATIONAL: "bg-info text-white",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = CLASS_BY_SEVERITY[severity] ?? "bg-muted text-white";
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${cls}`}>
      {severity}
    </span>
  );
}
