import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { Badge, Card, EmptyState, ErrorState, Mono, SeverityBadge, Spinner, Stat, SyntheticNotice, VerdictBadge } from "../components/ui";
import { api } from "../lib/api";
import { isRealLlm, llmLabel } from "../lib/llm";
import { relTime } from "../lib/format";

const SEVS = ["critical", "high", "medium", "low"] as const;
const SEV_BAR: Record<string, string> = { critical: "bg-rose-500", high: "bg-orange-400", medium: "bg-yellow-400", low: "bg-sky-400" };

export function DashboardPage() {
  const d = useQuery({ queryKey: ["dashboard"], queryFn: api.dashboard, refetchInterval: 15_000 });
  const s = useQuery({ queryKey: ["status"], queryFn: api.status });
  if (d.isLoading) return <Spinner label="Loading overview" />;
  if (d.isError) return <ErrorState error={d.error} onRetry={() => void d.refetch()} />;
  const data = d.data!;
  const maxSev = Math.max(1, ...SEVS.map((k) => data.alerts.by_severity[k] ?? 0));
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">Security overview</h1>
          <p className="text-sm text-muted">
            Source: FalkorDB graph <Mono>{String(data.graph.dataset.dataset ?? "—")}</Mono> v{String(data.graph.dataset.dataset_version ?? "?")} ·
            mode {s.data?.llm_is_mock ? "offline demo (mock planner)" : isRealLlm(s.data) ? llmLabel(s.data) : "—"}
          </p>
        </div>
        <SyntheticNotice />
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <Stat label="Alerts" value={data.alerts.total} hint={`${data.alerts.by_status.open ?? 0} open`} />
        <Stat label="Investigations" value={data.investigations.total} hint={`${data.investigations.running} running`} />
        <Stat label="High-risk" value={data.investigations.high_risk} tone="text-orange-300" hint="high or critical band" />
        <Stat label="Pending approvals" value={data.pending_approvals} tone={data.pending_approvals ? "text-amber-300" : ""} hint="simulated actions" />
        <Stat label="Graph nodes" value={data.graph.node_count} />
        <Stat label="Relationships" value={data.graph.edge_count} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Alerts by severity">
          <ul className="space-y-2.5">
            {SEVS.map((k) => (
              <li key={k} className="grid grid-cols-[80px_1fr_28px] items-center gap-2 text-[13px]">
                <SeverityBadge severity={k} />
                <div className="h-2 rounded bg-line" aria-hidden>
                  <div className={`h-2 rounded ${SEV_BAR[k]}`} style={{ width: `${((data.alerts.by_severity[k] ?? 0) / maxSev) * 100}%` }} />
                </div>
                <span className="text-right tabular-nums">{data.alerts.by_severity[k] ?? 0}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Recent investigations" className="lg:col-span-2" actions={<Link to="/investigations" className="text-[12px] text-sky-300 hover:underline">All</Link>}>
          {data.recent_investigations.length === 0 ? (
            <EmptyState title="No investigations yet">
              <Link to="/investigate?alert=ALT-1001" className="text-sky-300 hover:underline">Investigate ALT-1001</Link>
            </EmptyState>
          ) : (
            <ul className="divide-y divide-line">
              {data.recent_investigations.map((i) => (
                <li key={i.id}>
                  <Link to={`/investigations/${i.id}`} className="flex flex-wrap items-center gap-2 py-2 text-[13px] hover:text-sky-200">
                    <Mono>{i.target_id}</Mono>
                    <VerdictBadge verdict={i.verdict} />
                    {i.risk_band && <SeverityBadge severity={i.risk_band} />}
                    {i.risk_score !== null && <span className="tabular-nums text-muted">risk {i.risk_score}</span>}
                    {i.provider_is_mock && <Badge tone="warn">mock</Badge>}
                    <span className="ml-auto text-[11px] text-faint">{relTime(i.created_at)} · {i.requested_by}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Graph composition">
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.graph.nodes_by_label).map(([l, c]) => (
              <Badge key={l} tone="neutral">{l} <span className="tabular-nums text-ink">{c}</span></Badge>
            ))}
          </div>
        </Card>
        <Card title="Integration status">
          <ul className="space-y-1.5 text-[13px]">
            <li className="flex justify-between"><span className="text-muted">Backend API</span><Badge tone="ok">online</Badge></li>
            <li className="flex justify-between"><span className="text-muted">FalkorDB ({s.data?.falkordb.graph})</span>{s.data?.falkordb.reachable ? <Badge tone="ok">reachable</Badge> : <Badge tone="bad">unreachable</Badge>}</li>
            <li className="flex justify-between"><span className="text-muted">LLM provider</span>{isRealLlm(s.data) ? <Badge tone="accent">{llmLabel(s.data)}</Badge> : s.data?.llm_is_mock ? <Badge tone="warn">Mock planner (offline demo)</Badge> : <Badge tone="bad">unavailable</Badge>}</li>
            <li className="flex justify-between"><span className="text-muted">Response actions</span><Badge tone="violet">simulation only</Badge></li>
            <li className="flex justify-between"><span className="text-muted">Policy</span><Mono>{s.data?.policy_version}</Mono></li>
          </ul>
        </Card>
      </div>
    </div>
  );
}
