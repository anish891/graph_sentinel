import { X } from "lucide-react";

import { propText } from "../../lib/format";
import type { GraphPayload } from "../../types/api";
import { Badge, Mono } from "../ui";
import { labelStyle } from "./graphStyle";

const HIDE = new Set(["id", "synthetic"]);

/** Shows a selected node's properties and its relationships *within the returned payload*. */
export function NodeInspector({ payload, nodeId, onClose, onSelect }: {
  payload: GraphPayload;
  nodeId: string;
  onClose: () => void;
  onSelect: (id: string) => void;
}) {
  const node = payload.nodes.find((n) => n.id === nodeId);
  if (!node) return null;
  const st = labelStyle(node.label);
  const rels = payload.edges.filter((e) => e.source === nodeId || e.target === nodeId);
  const paths = payload.paths.filter((p) => p.node_ids.includes(nodeId));
  const byId = new Map(payload.nodes.map((n) => [n.id, n]));
  return (
    <aside aria-label="Node details" className="scrollbar-thin flex h-full flex-col overflow-y-auto rounded-xl border border-line bg-panel">
      <header className="flex items-start justify-between gap-2 border-b border-line p-3">
        <div className="min-w-0">
          <Badge className="mb-1" tone="neutral">
            <span className="size-1.5 rounded-full" style={{ background: st.color }} /> {node.label}
          </Badge>
          <p className="break-words text-sm font-semibold">{node.display_name}</p>
          <Mono>{node.id}</Mono>
        </div>
        <button onClick={onClose} className="rounded p-1 text-muted hover:text-ink" aria-label="Close details">
          <X className="size-4" />
        </button>
      </header>
      <div className="space-y-4 p-3 text-[12px]">
        <section>
          <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Properties (graph record)</h3>
          <dl className="space-y-1">
            {Object.entries(node.properties)
              .filter(([k]) => !HIDE.has(k))
              .map(([k, v]) => (
                <div key={k} className="grid grid-cols-[110px_1fr] gap-2">
                  <dt className="text-faint">{k}</dt>
                  <dd className="break-words text-ink">{propText(v)}</dd>
                </div>
              ))}
          </dl>
        </section>
        <section>
          <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">Relationships ({rels.length})</h3>
          <ul className="space-y-1">
            {rels.map((e) => {
              const other = e.source === nodeId ? e.target : e.source;
              return (
                <li key={e.id} className="flex flex-wrap items-center gap-1">
                  <span className="text-faint">{e.source === nodeId ? "→" : "←"}</span>
                  <Badge tone={e.temporal_status === "historical" ? "neutral" : "accent"}>{e.type}</Badge>
                  <button className="truncate text-left text-sky-300 hover:underline" onClick={() => onSelect(other)}>
                    {byId.get(other)?.display_name ?? other}
                  </button>
                  {e.temporal_status === "historical" && <Badge>historical until {propText(e.properties.valid_to)}</Badge>}
                </li>
              );
            })}
          </ul>
        </section>
        {paths.length > 0 && (
          <section>
            <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-faint">On {paths.length} discovered path(s)</h3>
            <ul className="space-y-1 text-muted">
              {paths.slice(0, 6).map((p) => (
                <li key={p.id}>
                  <Mono>{p.id}</Mono> · {p.hops} hops → {p.end_label}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </aside>
  );
}
