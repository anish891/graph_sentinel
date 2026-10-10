import clsx from "clsx";

import type { Ref } from "../types/api";

const TONE: Record<Ref["type"], string> = {
  path: "text-sky-300 ring-sky-400/30 bg-sky-500/10",
  node: "text-cyan-200 ring-cyan-400/25 bg-cyan-500/10",
  edge: "text-indigo-200 ring-indigo-400/25 bg-indigo-500/10",
  evidence: "text-amber-200 ring-amber-400/25 bg-amber-500/10",
  tool_call: "text-slate-300 ring-slate-400/25 bg-slate-500/10",
  calculation: "text-violet-200 ring-violet-400/25 bg-violet-500/10",
};

/** Clickable references from a claim to the graph records that support it. */
export function RefChips({ refs, onRef }: { refs: Ref[]; onRef?: (r: Ref) => void }) {
  return (
    <span className="mt-1 flex flex-wrap gap-1">
      {refs.map((r) => (
        <button
          key={`${r.type}:${r.id}`}
          type="button"
          onClick={() => onRef?.(r)}
          className={clsx("rounded px-1.5 py-0.5 font-mono text-[10px] ring-1 ring-inset hover:brightness-125", TONE[r.type])}
          title={`${r.type}: ${r.id}`}
        >
          {r.type === "edge" ? r.id.split("|")[1] : r.id}
        </button>
      ))}
    </span>
  );
}
