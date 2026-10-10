import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";

import { Badge, Card, EmptyState, ErrorState, Pagination, Spinner, Tabs } from "../components/ui";
import { ActionCard } from "../features/ActionCard";
import { api } from "../lib/api";

type View = "pending" | "decided" | "all";
const FILTER: Record<View, string[] | undefined> = {
  pending: ["pending_approval"],
  decided: ["approved", "executed_simulation", "rejected", "expired", "failed", "cancelled"],
  all: undefined,
};

export function ApprovalsPage() {
  const [view, setView] = useState<View>("pending");
  const [page, setPage] = useState(1);
  const list = useQuery({
    queryKey: ["actions", view, page],
    queryFn: () => api.actions({ status: FILTER[view], page, page_size: 10 }),
    placeholderData: keepPreviousData,
    refetchInterval: 10_000,
  });
  const invIds = Array.from(new Set(list.data?.items.map((a) => a.investigation_id) ?? []));
  const invs = useQuery({
    queryKey: ["approval-invs", invIds],
    queryFn: async () => Object.fromEntries(await Promise.all(invIds.map(async (id) => [id, await api.investigation(id)] as const))),
    enabled: invIds.length > 0,
  });
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-xl font-semibold">Action approval center</h1>
        <Badge tone="violet">All execution is simulated</Badge>
        <Badge>Server-enforced: approver role · four-eyes · policy version · idempotency</Badge>
      </div>
      <Card bodyClassName="p-0">
        <div className="px-4 pt-2">
          <Tabs<View>
            label="Action filter"
            value={view}
            onChange={(v) => { setView(v); setPage(1); }}
            tabs={[{ id: "pending", label: "Pending approval" }, { id: "decided", label: "Decided" }, { id: "all", label: "All" }]}
          />
        </div>
        <div className="p-4">
          {list.isLoading && <Spinner />}
          {list.isError && <ErrorState error={list.error} onRetry={() => void list.refetch()} />}
          {list.data?.items.length === 0 && <EmptyState title={view === "pending" ? "Nothing awaiting approval" : "No actions"} />}
          <ul className="space-y-3">
            {list.data?.items.map((a) => {
              const inv = invs.data?.[a.investigation_id];
              return (
                <li key={a.id} className="space-y-1">
                  <p className="text-[11px] text-faint">
                    From <Link className="text-sky-300 hover:underline" to={`/investigations/${a.investigation_id}`}>{a.investigation_id}</Link>
                    {inv && <> · target {inv.target_id} · risk {inv.risk?.score ?? "—"} ({inv.risk?.band ?? "—"}) · verdict {inv.verdict} · requested by {inv.requested_by}</>}
                  </p>
                  <ul><ActionCard action={a} requesterId={inv?.requested_by} /></ul>
                </li>
              );
            })}
          </ul>
          {list.data && list.data.total > 10 && <Pagination page={page} pageSize={10} total={list.data.total} onPage={setPage} />}
        </div>
      </Card>
    </div>
  );
}
