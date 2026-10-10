import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Fingerprint } from "lucide-react";
import { useState } from "react";

import { Badge, Card, EmptyState, ErrorState, Mono, Pagination, Spinner } from "../components/ui";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";
import { fmtTime } from "../lib/format";

export function AuditPage() {
  const { can } = useAuth();
  const [page, setPage] = useState(1);
  const [type, setType] = useState("");
  const allowed = can("audit:read");
  const events = useQuery({
    queryKey: ["audit", page, type],
    queryFn: () => api.audit({ page, page_size: 25, event_type: type }),
    placeholderData: keepPreviousData,
    enabled: allowed,
    refetchInterval: 15_000,
  });
  const verify = useQuery({ queryKey: ["audit", "verify"], queryFn: api.verifyAudit, enabled: allowed });
  if (!allowed) return <Card><EmptyState title="Audit trail requires investigator, approver or admin role" /></Card>;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-xl font-semibold">Audit trail</h1>
        {verify.data && (
          <Badge tone={verify.data.valid ? "ok" : "bad"} title={verify.data.note}>
            <Fingerprint className="size-3" aria-hidden /> Hash chain {verify.data.valid ? "verified" : "BROKEN"} · {verify.data.checked} events
          </Badge>
        )}
        <label className="ml-auto text-[12px] text-muted">
          Event{" "}
          <select value={type} onChange={(e) => { setType(e.target.value); setPage(1); }} className="rounded border border-line-strong bg-bg px-1.5 py-1 text-ink">
            <option value="">All</option>
            {["investigation.created", "investigation.completed", "investigation.failed", "action.pending_approval", "action.approved", "action.executed_simulation", "action.rejected", "action.decision_denied", "action.expired", "auth.demo_login"].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
      </div>
      <Card>
        {events.isLoading && <Spinner />}
        {events.isError && <ErrorState error={events.error} onRetry={() => void events.refetch()} />}
        {events.data?.items.length === 0 && <EmptyState title="No events" />}
        {events.data && events.data.items.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]">
              <thead className="text-left text-[11px] uppercase tracking-wider text-faint">
                <tr><th className="py-2 font-medium">#</th><th className="py-2 font-medium">Time</th><th className="py-2 font-medium">Event</th><th className="py-2 font-medium">Actor</th><th className="py-2 font-medium">Resource</th><th className="py-2 font-medium">Details</th><th className="py-2 font-medium">Hash</th></tr>
              </thead>
              <tbody>
                {events.data.items.map((e) => (
                  <tr key={e.id} className="border-t border-line align-top">
                    <td className="py-2 pr-2 tabular-nums text-faint">{e.seq}</td>
                    <td className="whitespace-nowrap py-2 pr-2 text-muted">{fmtTime(e.ts)}</td>
                    <td className="py-2 pr-2"><Badge tone={e.event_type.includes("denied") ? "bad" : e.event_type.includes("executed") ? "ok" : "neutral"}>{e.event_type}</Badge></td>
                    <td className="py-2 pr-2">{e.actor}{e.actor_role && <span className="text-faint"> · {e.actor_role}</span>}</td>
                    <td className="py-2 pr-2"><Mono>{e.resource_id ?? e.resource_type}</Mono></td>
                    <td className="max-w-xs py-2 pr-2 text-muted"><span className="line-clamp-2 break-all font-mono text-[10px]">{JSON.stringify(e.details)}</span></td>
                    <td className="py-2"><Mono className="text-[10px]" >{e.hash.slice(0, 10)}…</Mono></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} pageSize={25} total={events.data.total} onPage={setPage} />
          </div>
        )}
      </Card>
      {verify.data && <p className="text-[11px] text-faint">{verify.data.note}</p>}
    </div>
  );
}
