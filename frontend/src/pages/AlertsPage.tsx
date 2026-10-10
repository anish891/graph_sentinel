import { keepPreviousData, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { Search } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";

import { Badge, Button, Card, EmptyState, ErrorState, KeyValue, Mono, Pagination, SeverityBadge, Spinner, VerdictBadge } from "../components/ui";
import { EvidenceCard } from "../features/EvidencePanel";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";
import { fmtTime, humanize, propText, relTime } from "../lib/format";

const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = ["open", "triaged", "closed"];

function Toggle({ on, children, onClick }: { on: boolean; children: React.ReactNode; onClick: () => void }) {
  return (
    <button
      aria-pressed={on}
      onClick={onClick}
      className={clsx("rounded-md px-2 py-1 text-[12px] ring-1 ring-inset", on ? "bg-sky-500/15 text-sky-200 ring-sky-400/40" : "text-muted ring-line hover:text-ink")}
    >
      {children}
    </button>
  );
}

export function AlertsPage() {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string[]>([]);
  const [status, setStatus] = useState<string[]>([]);
  const [sort, setSort] = useState("detected_at");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const pageSize = 10;
  const alerts = useQuery({
    queryKey: ["alerts", q, sev, status, sort, page],
    queryFn: () => api.alerts({ q, severity: sev, status, sort, order: sort === "id" ? "asc" : "desc", page, page_size: pageSize }),
    placeholderData: keepPreviousData,
  });
  const toggle = (list: string[], set: (v: string[]) => void, v: string) => {
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
    setPage(1);
  };

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Alerts explorer</h1>
      <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
        <Card>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <label className="relative">
              <span className="sr-only">Search alerts</span>
              <Search className="absolute left-2 top-2 size-4 text-faint" aria-hidden />
              <input
                value={q}
                onChange={(e) => {
                  setQ(e.target.value);
                  setPage(1);
                }}
                placeholder="Search id or title"
                maxLength={64}
                className="w-56 rounded-lg border border-line-strong bg-bg py-1.5 pl-8 pr-2 text-[13px] outline-none focus:border-sky-400"
              />
            </label>
            {SEVERITIES.map((s) => (
              <Toggle key={s} on={sev.includes(s)} onClick={() => toggle(sev, setSev, s)}>{s}</Toggle>
            ))}
            <span className="mx-1 h-4 w-px bg-line" />
            {STATUSES.map((s) => (
              <Toggle key={s} on={status.includes(s)} onClick={() => toggle(status, setStatus, s)}>{s}</Toggle>
            ))}
            <label className="ml-auto text-[12px] text-muted">
              Sort{" "}
              <select value={sort} onChange={(e) => setSort(e.target.value)} className="rounded border border-line-strong bg-bg px-1.5 py-1 text-ink">
                <option value="detected_at">Newest</option>
                <option value="severity">Severity</option>
                <option value="id">ID</option>
              </select>
            </label>
          </div>
          {alerts.isLoading && <Spinner />}
          {alerts.isError && <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} />}
          {alerts.data && alerts.data.items.length === 0 && <EmptyState title="No alerts match the filters" />}
          {alerts.data && alerts.data.items.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead className="text-left text-[11px] uppercase tracking-wider text-faint">
                  <tr>
                    <th className="py-2 font-medium">Alert</th>
                    <th className="py-2 font-medium">Severity</th>
                    <th className="py-2 font-medium">Status</th>
                    <th className="py-2 font-medium">Source</th>
                    <th className="py-2 font-medium">Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.data.items.map((a) => (
                    <tr
                      key={a.id}
                      onClick={() => setSelected(a.id)}
                      className={clsx("cursor-pointer border-t border-line hover:bg-panel-2", selected === a.id && "bg-sky-500/5")}
                    >
                      <td className="py-2 pr-3">
                        <button className="text-left" onClick={() => setSelected(a.id)}>
                          <Mono>{a.id}</Mono>
                          <span className="block text-ink">{a.display_name}</span>
                        </button>
                      </td>
                      <td className="py-2 pr-3"><SeverityBadge severity={String(a.properties.severity)} /></td>
                      <td className="py-2 pr-3"><Badge>{propText(a.properties.status)}</Badge></td>
                      <td className="py-2 pr-3 text-muted">{propText(a.properties.source)}</td>
                      <td className="py-2 text-muted" title={fmtTime(String(a.properties.detected_at))}>{relTime(String(a.properties.detected_at))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <Pagination page={page} pageSize={pageSize} total={alerts.data.total} onPage={setPage} />
            </div>
          )}
        </Card>
        {selected ? <AlertDetailPanel id={selected} /> : (
          <Card><EmptyState title="Select an alert">Related entities, evidence and prior investigations appear here.</EmptyState></Card>
        )}
      </div>
    </div>
  );
}

function AlertDetailPanel({ id }: { id: string }) {
  const { can } = useAuth();
  const d = useQuery({ queryKey: ["alert", id], queryFn: () => api.alert(id) });
  if (d.isLoading) return <Card><Spinner /></Card>;
  if (d.isError) return <Card><ErrorState error={d.error} onRetry={() => void d.refetch()} /></Card>;
  const { alert, relationships, evidence, investigations } = d.data!;
  const p = alert.properties;
  return (
    <Card title={<span className="flex items-center gap-2"><Mono>{alert.id}</Mono> <SeverityBadge severity={String(p.severity)} /></span>}>
      <div className="space-y-4">
        <p className="font-medium">{alert.display_name}</p>
        <KeyValue
          rows={[
            ["Status", humanize(String(p.status))],
            ["Rule", <Mono key="r">{propText(p.rule)}</Mono>],
            ["Source", propText(p.source)],
            ["Detected", fmtTime(String(p.detected_at))],
            ["Confidence", propText(p.confidence)],
            ["Description", <span key="d" className="text-muted">{propText(p.description)}</span>],
          ]}
        />
        <section>
          <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Directly related entities</h3>
          <ul className="space-y-1 text-[12px]">
            {relationships.map(({ edge, neighbor }) => (
              <li key={edge.id} className="flex flex-wrap items-center gap-1.5">
                <Badge tone="accent">{edge.type}</Badge>
                {edge.properties.role ? <span className="text-faint">({propText(edge.properties.role)})</span> : null}
                <Link to={`/graph?id=${encodeURIComponent(neighbor.id)}`} className="text-sky-300 hover:underline">{neighbor.display_name}</Link>
                <span className="text-faint">{neighbor.label}</span>
              </li>
            ))}
          </ul>
        </section>
        {evidence.length > 0 && (
          <section>
            <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Evidence on this alert</h3>
            <ul className="space-y-2">{evidence.map((e) => <EvidenceCard key={e.id} e={e} />)}</ul>
          </section>
        )}
        {investigations.length > 0 && (
          <section>
            <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Previous investigations</h3>
            <ul className="space-y-1 text-[12px]">
              {investigations.map((i) => (
                <li key={i.id}>
                  <Link to={`/investigations/${i.id}`} className="text-sky-300 hover:underline">{i.id}</Link> <VerdictBadge verdict={i.verdict} />{" "}
                  <span className="text-faint">{relTime(i.created_at)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {can("investigations:create") ? (
          <Link to={`/investigate?alert=${encodeURIComponent(alert.id)}`}>
            <Button variant="primary" className="w-full">Investigate {alert.id}</Button>
          </Link>
        ) : (
          <p className="text-[12px] text-faint">Investigator role required to start an investigation.</p>
        )}
      </div>
    </Card>
  );
}
