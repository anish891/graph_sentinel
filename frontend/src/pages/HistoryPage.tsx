import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { Badge, Card, EmptyState, ErrorState, Mono, Pagination, SeverityBadge, Spinner, VerdictBadge } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";
import type { InvestigationResult } from "../types/api";

export function HistoryPage() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [compare, setCompare] = useState<string[]>([]);
  const list = useQuery({
    queryKey: ["investigations", page, status],
    queryFn: () => api.investigations({ page, page_size: 15, status }),
    placeholderData: keepPreviousData,
    refetchInterval: 10_000,
  });
  const toggle = (id: string) => setCompare((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id].slice(-2)));
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <h1 className="text-xl font-semibold">Investigation history</h1>
        <label className="text-[12px] text-muted">
          Status{" "}
          <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} className="rounded border border-line-strong bg-bg px-1.5 py-1 text-ink">
            <option value="">All</option>
            {["completed", "inconclusive", "running", "failed"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
      </div>
      <Card>
        {list.isLoading && <Spinner />}
        {list.isError && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}
        {list.data?.items.length === 0 && <EmptyState title="No investigations yet" />}
        {list.data && list.data.items.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead className="text-left text-[11px] uppercase tracking-wider text-faint">
                <tr>
                  <th className="py-2 font-medium"><span className="sr-only">Compare</span></th>
                  <th className="py-2 font-medium">Investigation</th>
                  <th className="py-2 font-medium">Target</th>
                  <th className="py-2 font-medium">Verdict</th>
                  <th className="py-2 font-medium">Risk</th>
                  <th className="py-2 font-medium">Provider</th>
                  <th className="py-2 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((i) => (
                  <tr key={i.id} className="border-t border-line hover:bg-panel-2">
                    <td className="py-2 pr-2"><input type="checkbox" aria-label={`Compare ${i.id}`} checked={compare.includes(i.id)} onChange={() => toggle(i.id)} className="accent-sky-400" /></td>
                    <td className="py-2 pr-3"><Link to={`/investigations/${i.id}`} className="text-sky-300 hover:underline"><Mono>{i.id}</Mono></Link><span className="block max-w-sm truncate text-[11px] text-muted">{i.question}</span></td>
                    <td className="py-2 pr-3"><Mono>{i.target_id}</Mono></td>
                    <td className="py-2 pr-3">{i.status === "failed" ? <Badge tone="bad">failed</Badge> : <VerdictBadge verdict={i.verdict} />}</td>
                    <td className="py-2 pr-3">{i.risk_band ? <span className="flex items-center gap-1.5"><SeverityBadge severity={i.risk_band} /> <span className="tabular-nums">{i.risk_score}</span></span> : "—"}</td>
                    <td className="py-2 pr-3">{i.provider_is_mock ? <Badge tone="warn">mock</Badge> : <Badge tone="accent">{i.provider_name}</Badge>}</td>
                    <td className="py-2 text-muted">{fmtTime(i.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} pageSize={15} total={list.data.total} onPage={setPage} />
          </div>
        )}
      </Card>
      {compare.length === 2 && <Compare a={compare[0]!} b={compare[1]!} />}
      {compare.length === 1 && <p className="text-[12px] text-muted">Select one more investigation to compare.</p>}
    </div>
  );
}

function Compare({ a, b }: { a: string; b: string }) {
  const qa = useQuery({ queryKey: ["investigation", a], queryFn: () => api.investigation(a) });
  const qb = useQuery({ queryKey: ["investigation", b], queryFn: () => api.investigation(b) });
  if (!qa.data || !qb.data) return <Spinner label="Loading comparison" />;
  const rows: [string, (r: InvestigationResult) => React.ReactNode][] = [
    ["Target", (r) => <Mono>{r.target_id}</Mono>],
    ["Verdict", (r) => <VerdictBadge verdict={r.verdict} />],
    ["Risk", (r) => (r.risk ? `${r.risk.score} (${r.risk.band})` : "—")],
    ["Contradiction", (r) => r.risk?.contradiction_strength.toFixed(2) ?? "—"],
    ["Paths found", (r) => r.graph.paths.length],
    ["Supporting / contradicting", (r) => `${r.supporting_evidence.length} / ${r.contradicting_evidence.length}`],
    ["Actions", (r) => r.recommended_actions.map((x) => x.action_type).join(", ") || "none"],
    ["Tool calls", (r) => r.tool_calls.length],
    ["Provider", (r) => r.provider.name],
  ];
  return (
    <Card title="Comparison">
      <table className="w-full text-[13px]">
        <thead><tr className="text-left text-[11px] text-faint"><th /><th className="pb-1"><Mono>{a}</Mono></th><th className="pb-1"><Mono>{b}</Mono></th></tr></thead>
        <tbody>
          {rows.map(([label, fn]) => (
            <tr key={label} className="border-t border-line"><td className="py-1.5 pr-3 text-faint">{label}</td><td className="py-1.5 pr-3">{fn(qa.data!)}</td><td className="py-1.5">{fn(qb.data!)}</td></tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
