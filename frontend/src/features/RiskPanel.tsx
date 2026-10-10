import { Info } from "lucide-react";

import { Badge, SeverityBadge, VerdictBadge } from "../components/ui";
import { fmtTime, pct } from "../lib/format";
import type { Ref, RiskAssessment } from "../types/api";
import { RefChips } from "./RefChips";

const BAND_COLOR: Record<string, string> = {
  critical: "text-rose-300",
  high: "text-orange-300",
  medium: "text-yellow-200",
  low: "text-sky-300",
};

export function RiskScore({ risk }: { risk: RiskAssessment }) {
  return (
    <div className="flex items-center gap-4">
      <div className="relative grid size-20 place-items-center">
        <svg viewBox="0 0 36 36" className="absolute inset-0 -rotate-90" aria-hidden>
          <circle cx="18" cy="18" r="15.5" fill="none" stroke="#1d2a42" strokeWidth="3" />
          <circle
            cx="18"
            cy="18"
            r="15.5"
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            strokeDasharray={`${(risk.score / 100) * 97.4} 97.4`}
            strokeLinecap="round"
            className={BAND_COLOR[risk.band]}
          />
        </svg>
        <span className={`text-2xl font-bold tabular-nums ${BAND_COLOR[risk.band]}`} aria-label={`Risk score ${risk.score} of 100`}>
          {risk.score}
        </span>
      </div>
      <div className="space-y-1 text-[13px]">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={risk.band} /> <VerdictBadge verdict={risk.verdict} />
        </div>
        <p className="text-muted">
          Confidence <span className="text-ink">{risk.confidence_band}</span> ({pct(risk.confidence)})
        </p>
        <p className="text-[11px] text-faint">Deterministic · {risk.method} · {risk.weights_version}</p>
      </div>
    </div>
  );
}

export function RiskPanel({ risk, onRef }: { risk: RiskAssessment; onRef: (r: Ref) => void }) {
  return (
    <div className="space-y-4">
      <RiskScore risk={risk} />
      <p className="text-[13px] text-muted">{risk.verdict_reason}</p>
      <div className="rounded-lg border border-line bg-panel-2 p-3 text-[12px]">
        <p className="font-medium text-ink">Formula</p>
        <p className="mt-1 font-mono text-[11px] text-muted">
          score = 100 × Σ(weight × factor) × (1 − {risk.contradiction_penalty.toFixed(2)} contradiction penalty)
        </p>
        <p className="mt-1 font-mono text-[11px] text-muted">
          = 100 × {risk.raw_score.toFixed(3)} × {(1 - risk.contradiction_penalty).toFixed(3)} = {risk.score}
        </p>
        <p className="mt-1 text-[11px] text-faint">
          Contradiction strength {risk.contradiction_strength.toFixed(2)} · evaluated as of {fmtTime(risk.as_of)}
        </p>
      </div>
      <table className="w-full text-[12px]">
        <caption className="sr-only">Risk factor contributions</caption>
        <thead className="text-left text-[11px] uppercase tracking-wider text-faint">
          <tr>
            <th className="pb-1 font-medium">Factor</th>
            <th className="pb-1 font-medium">Weight</th>
            <th className="pb-1 font-medium">Value</th>
            <th className="pb-1 text-right font-medium">Points</th>
          </tr>
        </thead>
        <tbody>
          {risk.factors.map((f) => (
            <tr key={f.key} className="border-t border-line align-top">
              <td className="py-2 pr-2">
                <p className="text-ink">{f.label}</p>
                <p className="mt-0.5 text-[11px] text-muted">{f.explanation}</p>
                {f.refs.length > 0 && <RefChips refs={f.refs} onRef={onRef} />}
              </td>
              <td className="py-2 pr-2 tabular-nums text-muted">{f.weight.toFixed(2)}</td>
              <td className="py-2 pr-2">
                <div className="h-1.5 w-16 rounded bg-line" aria-hidden>
                  <div className="h-1.5 rounded bg-sky-400" style={{ width: `${f.value * 100}%` }} />
                </div>
                <span className="text-[11px] tabular-nums text-muted">{f.value.toFixed(2)}</span>
              </td>
              <td className="py-2 text-right tabular-nums">{(f.contribution * 100).toFixed(1)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {risk.uncertainty_notes.length > 0 && (
        <div>
          <p className="mb-1 flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider text-faint">
            <Info className="size-3" aria-hidden /> Uncertainty & caveats
          </p>
          <ul className="list-disc space-y-0.5 pl-4 text-[12px] text-muted">
            {risk.uncertainty_notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}
      {!risk.calibrated && <Badge tone="neutral">Not statistically calibrated — heuristic triage score</Badge>}
    </div>
  );
}
