import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";

import { GraphLegend, GraphView } from "../components/graph/GraphView";
import { NodeInspector } from "../components/graph/NodeInspector";
import { Badge, Button, Card, EmptyState, ErrorState, Mono, Spinner } from "../components/ui";
import { api } from "../lib/api";

export function GraphExplorerPage() {
  const [params, setParams] = useSearchParams();
  const root = params.get("id") ?? "ALT-1001";
  const [depth, setDepth] = useState(1);
  const [historical, setHistorical] = useState(false);
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const graph = useQuery({ queryKey: ["neighbors", root, depth, historical], queryFn: () => api.neighbors(root, depth, historical) });
  const search = useQuery({ queryKey: ["search", q], queryFn: () => api.search(q), enabled: q.trim().length >= 2 });
  const stats = useQuery({ queryKey: ["graph-stats"], queryFn: api.graphStats });
  const labels = Array.from(new Set(graph.data?.nodes.map((n) => n.label) ?? [])).sort();
  const go = (id: string) => {
    setParams({ id });
    setSelected(null);
  };
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">Graph explorer</h1>
          <p className="text-sm text-muted">Bounded neighbourhood expansion (depth ≤ 3, ≤ 60 nodes). No raw query console.</p>
        </div>
        {stats.data && (
          <p className="text-[12px] text-muted">
            <Mono>{stats.data.graph_name}</Mono> · {stats.data.node_count} nodes · {stats.data.edge_count} relationships
          </p>
        )}
      </div>
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <form className="relative" onSubmit={(e) => { e.preventDefault(); if (search.data?.[0]) go(search.data[0].id); }}>
            <label>
              <span className="sr-only">Search entity</span>
              <Search className="absolute left-2 top-2 size-4 text-faint" aria-hidden />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by id, host, IP, user…" maxLength={64} className="w-64 rounded-lg border border-line-strong bg-bg py-1.5 pl-8 pr-2 text-[13px] outline-none focus:border-sky-400" />
            </label>
            {search.data && q.length >= 2 && (
              <ul className="absolute z-20 mt-1 max-h-64 w-80 overflow-y-auto rounded-lg border border-line-strong bg-panel shadow-xl">
                {search.data.length === 0 && <li className="px-3 py-2 text-[12px] text-muted">No matches</li>}
                {search.data.map((n) => (
                  <li key={n.id}>
                    <button type="button" className="w-full px-3 py-1.5 text-left text-[12px] hover:bg-panel-2" onClick={() => { go(n.id); setQ(""); }}>
                      <span className="text-ink">{n.display_name}</span> <span className="text-faint">{n.label} · {n.id}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </form>
          <span className="text-[13px] text-muted">Root <Mono>{root}</Mono></span>
          <label className="text-[12px] text-muted">
            Depth{" "}
            <select value={depth} onChange={(e) => setDepth(Number(e.target.value))} className="rounded border border-line-strong bg-bg px-1.5 py-1 text-ink">
              {[1, 2, 3].map((d) => <option key={d}>{d}</option>)}
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-[12px] text-muted">
            <input type="checkbox" checked={historical} onChange={(e) => setHistorical(e.target.checked)} className="accent-sky-400" /> include historical relationships
          </label>
          {selected && selected !== root && <Button size="sm" onClick={() => go(selected)}>Expand from selected</Button>}
          {graph.data?.truncation.truncated && <Badge tone="warn">truncated at {graph.data.truncation.max_nodes} nodes</Badge>}
        </div>
      </Card>
      <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
        <Card bodyClassName="p-0">
          <div className="h-[560px]">
            {graph.isLoading && <Spinner />}
            {graph.isError && <div className="p-4"><ErrorState error={graph.error} onRetry={() => void graph.refetch()} /></div>}
            {graph.data && graph.data.nodes.length > 0 && <GraphView payload={graph.data} targetId={root} selectedNodeId={selected} onSelectNode={setSelected} />}
            {graph.data && graph.data.nodes.length === 0 && <EmptyState title="Entity not found" />}
          </div>
          <div className="border-t border-line px-4 py-2"><GraphLegend labels={labels} /></div>
        </Card>
        <div className="h-[600px]">
          {selected && graph.data ? (
            <NodeInspector payload={graph.data} nodeId={selected} onClose={() => setSelected(null)} onSelect={setSelected} />
          ) : (
            <Card><EmptyState title="Select a node">Inspect properties, provenance and relationships.</EmptyState></Card>
          )}
        </div>
      </div>
    </div>
  );
}
