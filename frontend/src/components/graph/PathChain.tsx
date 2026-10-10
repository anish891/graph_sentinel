import { ArrowLeft, ArrowRight } from "lucide-react";
import { Fragment } from "react";

import type { GraphPayload, GraphPath } from "../../types/api";
import { labelStyle } from "./graphStyle";

/** Hop-by-hop rendering of a backend path: node → relationship (with real direction) → node. */
export function PathChain({ payload, path, onSelect }: { payload: GraphPayload; path: GraphPath; onSelect?: (id: string) => void }) {
  const nodes = new Map(payload.nodes.map((n) => [n.id, n]));
  const edges = new Map(payload.edges.map((e) => [e.id, e]));
  return (
    <ol className="flex flex-wrap items-center gap-x-1 gap-y-2" aria-label={`Path ${path.id}, ${path.hops} hops`}>
      {path.node_ids.map((nid, i) => {
        const n = nodes.get(nid);
        const st = labelStyle(n?.label ?? "");
        const Icon = st.icon;
        const edge = i < path.edge_ids.length ? edges.get(path.edge_ids[i]!) : undefined;
        const forward = edge ? edge.source === nid : true;
        return (
          <Fragment key={`${nid}-${i}`}>
            <li>
              <button
                type="button"
                onClick={() => onSelect?.(nid)}
                className="flex items-center gap-1.5 rounded-lg border border-line-strong bg-panel-2 px-2 py-1 text-left hover:border-sky-400/60"
                title={`${n?.label} · ${nid}`}
              >
                <Icon className="size-3.5 shrink-0" style={{ color: st.color }} aria-hidden />
                <span className="max-w-[180px] truncate text-[12px] text-ink">{n?.display_name ?? nid}</span>
              </button>
            </li>
            {edge && (
              <li className="flex items-center gap-0.5 font-mono text-[10px] text-sky-300" aria-label={`${edge.type} ${forward ? "forward" : "backward"}`}>
                {!forward && <ArrowLeft className="size-3" aria-hidden />}
                <span className={edge.temporal_status === "historical" ? "text-slate-500 line-through" : ""}>{edge.type}</span>
                {forward && <ArrowRight className="size-3" aria-hidden />}
              </li>
            )}
          </Fragment>
        );
      })}
    </ol>
  );
}
