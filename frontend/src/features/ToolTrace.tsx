import { CheckCircle2, CircleSlash, XCircle } from "lucide-react";

import { Badge, Mono } from "../components/ui";
import type { ToolCallRecord } from "../types/api";

export function ToolTrace({ calls, running }: { calls: ToolCallRecord[]; running?: boolean }) {
  return (
    <ol className="space-y-2" aria-live="polite">
      {calls.map((t) => (
        <li key={t.id} className="rounded-lg border border-line bg-panel-2 p-2.5 text-[12px]">
          <div className="flex flex-wrap items-center gap-1.5">
            {t.status === "ok" ? (
              <CheckCircle2 className="size-3.5 text-emerald-400" aria-label="ok" />
            ) : t.status === "rejected" ? (
              <CircleSlash className="size-3.5 text-amber-400" aria-label="rejected" />
            ) : (
              <XCircle className="size-3.5 text-rose-400" aria-label="error" />
            )}
            <span className="text-faint">#{t.seq}</span>
            <span className="font-mono font-medium text-ink">{t.tool}</span>
            <Badge tone={t.origin === "llm" ? "accent" : "violet"} title={t.origin === "llm" ? "Selected by the planner/model" : "Enforced by the orchestrator"}>
              {t.origin === "llm" ? "agent-selected" : "orchestrator baseline"}
            </Badge>
            {t.executed_in && <Badge>{t.executed_in}</Badge>}
            <span className="ml-auto tabular-nums text-faint">{t.duration_ms.toFixed(0)} ms</span>
          </div>
          {t.rationale && <p className="mt-1 text-muted">“{t.rationale}”</p>}
          <p className="mt-1 text-ink">{t.error ?? t.summary}</p>
          <details className="mt-1">
            <summary className="cursor-pointer text-[11px] text-faint">arguments & result reference</summary>
            <pre className="mt-1 overflow-x-auto rounded bg-bg p-2 font-mono text-[11px] text-muted">{JSON.stringify(t.arguments, null, 2)}</pre>
            {t.result_hash && (
              <p className="mt-1 text-[11px] text-faint">
                result sha256 <Mono>{t.result_hash.slice(0, 16)}…</Mono> · {t.path_ids.length} paths · {t.evidence_ids.length} evidence ·{" "}
                {t.node_ids.length} nodes
              </p>
            )}
          </details>
        </li>
      ))}
      {running && (
        <li className="flex items-center gap-2 rounded-lg border border-dashed border-line p-2.5 text-[12px] text-muted">
          <span className="size-2 animate-pulse rounded-full bg-sky-400" /> Agent is selecting the next graph tool…
        </li>
      )}
    </ol>
  );
}
