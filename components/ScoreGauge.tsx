const RATING_COLOR: Record<string, string> = {
  "Very Good": "text-low",
  Good: "text-low",
  "Needs Improvement": "text-medium",
  Weak: "text-high",
  Critical: "text-critical",
};

export function ScoreGauge({ score, rating }: { score: number; rating: string }) {
  const color = RATING_COLOR[rating] ?? "text-text";
  return (
    <div className="flex items-center gap-6 rounded-lg border border-border bg-surface p-6">
      <div className={`text-5xl font-bold ${color}`}>{score}%</div>
      <div>
        <div className={`text-lg font-semibold ${color}`}>{rating}</div>
        <div className="text-sm text-muted">Automated Security Score</div>
      </div>
    </div>
  );
}
