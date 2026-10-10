import clsx from "clsx";
import { ShieldAlert } from "lucide-react";

import { Badge, EmptyState, Mono } from "../components/ui";
import { fmtTime, pct } from "../lib/format";
import type { EvidenceItem } from "../types/api";

export function EvidenceCard({ e, highlighted }: { e: EvidenceItem; highlighted?: boolean }) {
  return (
    <li
      id={`evidence-${e.id}`}
      className={clsx(
        "rounded-lg border bg-panel-2 p-3 text-[12px]",
        highlighted ? "border-sky-400" : e.suspected_prompt_injection ? "border-rose-500/50" : "border-line",
      )}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <Mono>{e.id}</Mono>
        <Badge tone={e.stance === "supports" ? "accent" : "warn"}>{e.stance}</Badge>
        <Badge>{e.kind}</Badge>
        <span className="text-faint">→</span>
        <Mono className="text-cyan-200">{e.target_id}</Mono>
        {e.excluded_from_scoring && <Badge tone="bad">excluded from scoring</Badge>}
      </div>
      {e.claim && <p className="mt-1.5 font-medium text-ink">{e.claim}</p>}
      {e.suspected_prompt_injection && (
        <p className="mt-1.5 flex items-start gap-1.5 rounded-md bg-rose-500/10 p-2 text-rose-200">
          <ShieldAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Contains text that looks like instructions to an AI agent ({e.injection_signals.join(", ")}). Shown as untrusted data; it
          had no effect on tools, policy or scoring.
        </p>
      )}
      <blockquote className="mt-1.5 border-l-2 border-line-strong pl-2 text-muted">
        <span className="sr-only">Untrusted source text: </span>
        {e.summary}
      </blockquote>
      <p className="mt-1.5 text-[11px] text-faint">
        {e.source_system} · <span className="font-mono">{e.source_ref}</span> · observed {fmtTime(e.observed_at)} · confidence{" "}
        {pct(e.confidence)} · freshness {e.freshness === null ? "—" : pct(e.freshness)}
      </p>
    </li>
  );
}

export function EvidencePanel({ supporting, contradicting, highlightId }: {
  supporting: EvidenceItem[];
  contradicting: EvidenceItem[];
  highlightId?: string | null;
}) {
  const timeline = [...supporting, ...contradicting].sort((a, b) => (a.observed_at ?? "").localeCompare(b.observed_at ?? ""));
  if (timeline.length === 0) return <EmptyState title="No evidence records linked to the investigated entities" />;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section>
        <h3 className="mb-2 text-[12px] font-semibold text-sky-200">Supporting ({supporting.length})</h3>
        <ul className="space-y-2">
          {supporting.map((e) => (
            <EvidenceCard key={e.id} e={e} highlighted={highlightId === e.id} />
          ))}
        </ul>
      </section>
      <section>
        <h3 className="mb-2 text-[12px] font-semibold text-amber-200">Contradicting ({contradicting.length})</h3>
        {contradicting.length === 0 ? (
          <p className="text-[12px] text-muted">No contradicting records found.</p>
        ) : (
          <ul className="space-y-2">
            {contradicting.map((e) => (
              <EvidenceCard key={e.id} e={e} highlighted={highlightId === e.id} />
            ))}
          </ul>
        )}
      </section>
      <section className="lg:col-span-2">
        <h3 className="mb-2 text-[12px] font-semibold text-muted">Evidence timeline</h3>
        <ol className="relative space-y-2 border-l border-line-strong pl-4">
          {timeline.map((e) => (
            <li key={e.id} className="text-[12px]">
              <span className={clsx("absolute -left-[5px] mt-1 size-2.5 rounded-full", e.stance === "supports" ? "bg-sky-400" : "bg-amber-400")} />
              <span className="text-faint">{fmtTime(e.observed_at)}</span> · <Mono>{e.id}</Mono> · {e.source_system} —{" "}
              <span className="text-muted">{e.claim}</span>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
