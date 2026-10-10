import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { Fingerprint, GitBranch, Play, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { GraphLegend, GraphView } from "../components/graph/GraphView";
import { NodeInspector } from "../components/graph/NodeInspector";
import { PathChain } from "../components/graph/PathChain";
import { Badge, Button, Card, EmptyState, ErrorState, Mono, SeverityBadge, Spinner, Tabs, VerdictBadge } from "../components/ui";
import { ActionCard } from "../features/ActionCard";
import { EvidencePanel } from "../features/EvidencePanel";
import { RefChips } from "../features/RefChips";
import { RiskPanel, RiskScore } from "../features/RiskPanel";
import { ToolTrace } from "../features/ToolTrace";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";
import { fmtTime, humanize } from "../lib/format";
import type { InvestigationResult, Ref } from "../types/api";

const SUGGESTIONS = [
  "Investigate alert {id}. Is this potentially part of a larger attack? Identify related assets, explain the evidence, calculate the risk, and recommend the safest response.",
  "What is the blast radius of {id}? Which critical services are reachable and are any of them exploitable?",
  "Is {id} connected to any historical incidents? Show the exact relationship chain.",
  "Could {id} be benign? Weigh the contradicting evidence.",
];

// ---------------------------------------------------------------------------------------------
export function NewInvestigationPage() {
  const [params] = useSearchParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const [target, setTarget] = useState(params.get("alert") ?? "ALT-1001");
  const [question, setQuestion] = useState(SUGGESTIONS[0]!.replace("{id}", params.get("alert") ?? "ALT-1001"));
  const alerts = useQuery({ queryKey: ["alerts", "all"], queryFn: () => api.alerts({ page_size: 100, sort: "severity" }) });
  const start = useMutation({
    mutationFn: () => api.startInvestigation(question, target),
    onSuccess: (r) => nav(`/investigations/${r.id}`),
  });
  const allowed = can("investigations:create");
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Start an investigation</h1>
        <p className="text-sm text-muted">
          The agent selects bounded graph tools, every finding is tied to graph records, and risk and response are decided by
          deterministic engines.
        </p>
      </div>
      <Card>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            start.mutate();
          }}
        >
          <label className="block text-[13px]">
            <span className="text-muted">Target alert</span>
            <select
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                setQuestion((q) => q.replace(/ALT-\d+/g, e.target.value));
              }}
              className="mt-1 w-full rounded-lg border border-line-strong bg-bg px-3 py-2 text-ink outline-none focus:border-sky-400"
            >
              {alerts.data?.items.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.id} · {String(a.properties.severity)} · {a.display_name}
                </option>
              )) ?? <option value={target}>{target}</option>}
            </select>
          </label>
          <label className="block text-[13px]">
            <span className="text-muted">Investigation question</span>
            <textarea
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              rows={4}
              maxLength={2000}
              className="mt-1 w-full rounded-lg border border-line-strong bg-bg p-3 text-ink outline-none focus:border-sky-400"
            />
          </label>
          <div>
            <p className="mb-1.5 flex items-center gap-1 text-[11px] uppercase tracking-wider text-faint">
              <Sparkles className="size-3" aria-hidden /> Suggested prompts
            </p>
            <div className="flex flex-wrap gap-2">
              {SUGGESTIONS.map((s) => (
                <button
                  type="button"
                  key={s}
                  onClick={() => setQuestion(s.replace("{id}", target))}
                  className="rounded-lg border border-line bg-panel-2 px-2.5 py-1.5 text-left text-[12px] text-muted hover:border-sky-500/40 hover:text-ink"
                >
                  {s.replace("{id}", target).slice(0, 70)}…
                </button>
              ))}
            </div>
          </div>
          {start.isError && <ErrorState error={start.error} />}
          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" loading={start.isPending} disabled={!allowed || question.trim().length < 3}>
              <Play className="size-4" aria-hidden /> Investigate
            </Button>
            {!allowed && <span className="text-xs text-faint">Your role cannot start investigations (investigator or admin required).</span>}
          </div>
        </form>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
type TabId = "summary" | "evidence" | "risk" | "actions" | "trace" | "paths";

export function InvestigationPage() {
  const { id = "" } = useParams();
  const inv = useQuery({
    queryKey: ["investigation", id],
    queryFn: () => api.investigation(id),
    refetchInterval: (q) => (q.state.data && ["queued", "running"].includes(q.state.data.status) ? 1000 : false),
    // Keep polling while the tab is in the background; stops as soon as the investigation finishes.
    refetchIntervalInBackground: true,
  });
  if (inv.isLoading) return <Spinner label="Loading investigation" />;
  if (inv.isError) return <ErrorState error={inv.error} onRetry={() => void inv.refetch()} />;
  if (!inv.data) return null;
  return <Workspace r={inv.data} />;
}

function Workspace({ r }: { r: InvestigationResult }) {
  const running = r.status === "queued" || r.status === "running";
  const [tab, setTab] = useState<TabId>("summary");
  const [pathId, setPathId] = useState<string | null>(null);
  const [nodeId, setNodeId] = useState<string | null>(null);
  const [evidenceId, setEvidenceId] = useState<string | null>(null);
  const [hideEvidence, setHideEvidence] = useState(false);
  const [pathOnly, setPathOnly] = useState(true);
  const activePath = pathId ?? r.graph.highlighted_path_ids[0] ?? null;
  const activePathObj = r.graph.paths.find((p) => p.id === activePath) ?? null;
  const labels = useMemo(() => Array.from(new Set(r.graph.nodes.map((n) => n.label))).sort(), [r.graph.nodes]);
  const trace = useQuery({ queryKey: ["trace", r.id, r.status], queryFn: () => api.trace(r.id), enabled: tab === "trace" });

  const onRef = (ref: Ref) => {
    if (ref.type === "path") {
      setPathId(ref.id);
      setNodeId(null);
    } else if (ref.type === "node") {
      if (r.graph.nodes.some((n) => n.id === ref.id)) setNodeId(ref.id);
    } else if (ref.type === "edge") {
      const src = ref.id.split("|")[0];
      if (src) setNodeId(src);
    } else if (ref.type === "evidence") {
      setTab("evidence");
      setEvidenceId(ref.id);
      setTimeout(() => document.getElementById(`evidence-${ref.id}`)?.scrollIntoView({ behavior: "smooth", block: "center" }), 50);
    } else if (ref.type === "calculation") {
      setTab("risk");
    } else if (ref.type === "tool_call") {
      setTab("trace");
    }
  };

  const target = r.graph.nodes.find((n) => n.id === r.target_id);
  const pending = r.recommended_actions.filter((a) => a.status === "pending_approval").length;

  return (
    <div className="space-y-4">
      {/* header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-semibold">Investigation</h1>
            <Mono>{r.id}</Mono>
            <Badge tone={running ? "accent" : r.status === "failed" ? "bad" : r.status === "inconclusive" ? "neutral" : "ok"}>
              {running && <span className="size-1.5 animate-pulse rounded-full bg-current" />} {r.status}
            </Badge>
            <Badge tone={r.provider.is_mock ? "warn" : "accent"} title={r.provider.model}>
              {r.provider.is_mock ? "mock planner (not an LLM)" : `${r.provider.name} · ${r.provider.model}`}
            </Badge>
          </div>
          <p className="mt-1 max-w-3xl text-[13px] text-muted">“{r.question}”</p>
          <p className="mt-1 text-[11px] text-faint">
            Target <Mono>{r.target_id}</Mono> {target && <>· {target.display_name} · <SeverityBadge severity={String(target.properties.severity ?? "")} /></>} · requested
            by {r.requested_by} · {fmtTime(r.created_at)}
          </p>
        </div>
        {r.risk && <RiskScore risk={r.risk} />}
      </div>

      {r.error && <ErrorState error={new Error(r.error)} />}
      {running && (
        <div className="rounded-lg border border-sky-500/30 bg-sky-500/5 p-3 text-[13px] text-sky-100">
          Investigating — {r.tool_calls.length} graph tool call(s) so far. Results update live.
        </div>
      )}

      {/* graph + side panel */}
      <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
        <Card
          title={<span className="flex items-center gap-1.5"><GitBranch className="size-3.5" aria-hidden /> Investigation graph</span>}
          actions={
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-1.5 text-[11px] text-muted">
                <input type="checkbox" checked={pathOnly} onChange={(e) => setPathOnly(e.target.checked)} className="accent-sky-400" />
                selected path only
              </label>
              <label className="flex items-center gap-1.5 text-[11px] text-muted">
                <input type="checkbox" checked={hideEvidence} onChange={(e) => setHideEvidence(e.target.checked)} className="accent-sky-400" />
                hide evidence nodes
              </label>
            </div>
          }
          bodyClassName="p-0"
        >
          {activePathObj && (
            <div className="border-b border-line px-4 py-3">
              <p className="mb-2 text-[11px] uppercase tracking-wider text-faint">
                Selected path · {activePathObj.hops} hops · <span className="font-mono normal-case">{activePathObj.id}</span> · returned by FalkorDB
              </p>
              <PathChain payload={r.graph} path={activePathObj} onSelect={setNodeId} />
            </div>
          )}
          <div className="h-[420px]">
            {r.graph.nodes.length ? (
              <GraphView
                payload={r.graph}
                targetId={r.target_id}
                highlightPathId={activePath}
                selectedNodeId={nodeId}
                onSelectNode={setNodeId}
                hideLabels={hideEvidence ? ["Evidence"] : []}
                pathOnly={pathOnly}
              />
            ) : running ? (
              <Spinner label="Waiting for graph results" />
            ) : (
              <EmptyState title="No graph results" />
            )}
          </div>
          <div className="border-t border-line px-4 py-2">
            <GraphLegend labels={labels} />
          </div>
        </Card>
        <div className="flex min-h-0 flex-col gap-4">
          {nodeId ? (
            <div className="h-[520px]">
              <NodeInspector payload={r.graph} nodeId={nodeId} onClose={() => setNodeId(null)} onSelect={setNodeId} />
            </div>
          ) : (
            <Card title="Key paths (from FalkorDB)" bodyClassName="p-2">
              {r.graph.highlighted_path_ids.length === 0 && <p className="p-2 text-[12px] text-muted">No propagation paths found.</p>}
              <ul className="space-y-1">
                {r.graph.highlighted_path_ids.map((pid) => {
                  const p = r.graph.paths.find((x) => x.id === pid);
                  if (!p) return null;
                  return (
                    <li key={pid}>
                      <button
                        onClick={() => setPathId(pid)}
                        className={clsx(
                          "w-full rounded-lg border px-2.5 py-2 text-left text-[12px] transition-colors",
                          activePath === pid ? "border-sky-400/60 bg-sky-500/10" : "border-transparent hover:bg-panel-2",
                        )}
                      >
                        <span className="flex items-center gap-1.5">
                          <Badge tone="accent">{p.hops} hops</Badge> <span className="text-ink">→ {p.end_label}</span>
                          <Mono className="ml-auto text-[10px]">{p.id}</Mono>
                        </span>
                        <span className="mt-1 block text-[11px] leading-snug text-muted">{p.description}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              <p className="px-2 pt-2 text-[11px] text-faint">Click a node to inspect its graph record. Paths are real query results.</p>
            </Card>
          )}
        </div>
      </div>

      {/* tabs */}
      <Card bodyClassName="p-0">
        <div className="px-4 pt-2">
          <Tabs<TabId>
            label="Investigation sections"
            value={tab}
            onChange={setTab}
            tabs={[
              { id: "summary", label: "Findings" },
              { id: "evidence", label: `Evidence (${r.supporting_evidence.length + r.contradicting_evidence.length})` },
              { id: "risk", label: "Risk" },
              { id: "actions", label: <>Actions {pending > 0 && <Badge tone="warn">{pending}</Badge>}</> },
              { id: "trace", label: `Tool trace (${r.tool_calls.length})` },
              { id: "paths", label: `All paths (${r.graph.paths.length})` },
            ]}
          />
        </div>
        <div className="p-4">
          {tab === "summary" && <Summary r={r} onRef={onRef} />}
          {tab === "evidence" && (
            <EvidencePanel supporting={r.supporting_evidence} contradicting={r.contradicting_evidence} highlightId={evidenceId} />
          )}
          {tab === "risk" && (r.risk ? <RiskPanel risk={r.risk} onRef={onRef} /> : <EmptyState title={running ? "Risk is computed when the investigation completes" : "No risk assessment (target not found)"} />)}
          {tab === "actions" && (
            r.recommended_actions.length === 0 ? (
              <EmptyState title={running ? "Pending" : "No response actions proposed"}>
                {!running && <p>The policy engine proposes actions only when evidence supports them.</p>}
              </EmptyState>
            ) : (
              <ul className="space-y-2">
                {r.recommended_actions.map((a) => (
                  <ActionCard key={a.id} action={a} onRef={onRef} requesterId={r.requested_by} />
                ))}
              </ul>
            )
          )}
          {tab === "trace" && (
            <div className="space-y-3">
              {trace.data && (
                <p className="flex flex-wrap items-center gap-2 text-[12px] text-muted">
                  <Fingerprint className="size-3.5" aria-hidden /> Trace chain {trace.data.integrity.valid ? <Badge tone="ok">verified</Badge> : <Badge tone="bad">broken</Badge>} ·{" "}
                  {trace.data.integrity.checked_events} events · head <Mono>{trace.data.integrity.head_hash?.slice(0, 20)}…</Mono>
                </p>
              )}
              <p className="text-[12px] text-muted">
                {r.stats.llm_calls} planner calls · {r.stats.tool_calls} tool calls ({r.stats.rejected_tool_calls} rejected) · {r.stats.input_tokens + r.stats.output_tokens} tokens ·{" "}
                {r.stats.duration_ms.toFixed(0)} ms {r.stats.limits_hit.length > 0 && <>· limits hit: {r.stats.limits_hit.join(", ")}</>}
              </p>
              <ToolTrace calls={r.tool_calls} running={running} />
            </div>
          )}
          {tab === "paths" && (
            <ul className="space-y-1.5">
              {r.graph.paths.map((p) => (
                <li key={p.id}>
                  <button className="w-full rounded-lg px-2 py-1.5 text-left text-[12px] hover:bg-panel-2" onClick={() => setPathId(p.id)}>
                    <Mono>{p.id}</Mono> <Badge>{p.hops} hops</Badge> {p.contains_historical && <Badge>historical</Badge>}{" "}
                    <span className="text-muted">{p.description}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Card>
    </div>
  );
}

function Summary({ r, onRef }: { r: InvestigationResult; onRef: (ref: Ref) => void }) {
  if (!r.narrative) return <Spinner label="Agent is investigating" />;
  const groups: [string, typeof r.findings][] = [
    ["Observed facts (directly in graph records)", r.findings.filter((f) => f.kind === "observed_fact")],
    ["Inferences (follow from graph paths)", r.findings.filter((f) => f.kind === "inference")],
    ["Hypotheses (plausible, not proven)", r.findings.filter((f) => f.kind === "hypothesis")],
  ];
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={r.verdict} />
        <span className="text-[12px] text-muted">A recommendation is not proof of compromise.</span>
      </div>
      <section>
        <h3 className="mb-1 text-[12px] font-semibold text-ink">Explanation (generated by code from graph paths)</h3>
        <p className="text-[13px] leading-relaxed text-muted">{r.narrative.deterministic}</p>
      </section>
      {r.narrative.model_summary && (
        <section>
          <h3 className="mb-1 text-[12px] font-semibold text-ink">
            {r.provider.is_mock ? "Planner summary (mock — not an LLM)" : "Model summary (untrusted; claims validated below)"}
          </h3>
          <p className="text-[13px] text-muted">{r.narrative.model_summary}</p>
        </section>
      )}
      {groups.map(([title, items]) =>
        items.length ? (
          <section key={title}>
            <h3 className="mb-2 text-[12px] font-semibold text-ink">{title}</h3>
            <ul className="space-y-2">
              {items.map((f) => (
                <li key={f.id} className="rounded-lg border border-line bg-panel-2 px-3 py-2 text-[13px]">
                  <div className="flex items-start gap-2">
                    <Badge tone={f.origin === "model" ? "accent" : f.origin === "graph" ? "neutral" : "violet"}>{humanize(f.origin)}</Badge>
                    <span className="min-w-0 flex-1">{f.statement}</span>
                  </div>
                  <RefChips refs={f.refs} onRef={onRef} />
                </li>
              ))}
            </ul>
          </section>
        ) : null,
      )}
      {r.unsupported_claims.length > 0 && (
        <section>
          <h3 className="mb-2 text-[12px] font-semibold text-rose-200">Rejected model claims (not supported by retrieved records)</h3>
          <ul className="space-y-1 text-[12px]">
            {r.unsupported_claims.map((u) => (
              <li key={u.statement} className="rounded-lg border border-rose-500/30 bg-rose-500/5 px-3 py-2">
                <span className="line-through decoration-rose-400/60">{u.statement}</span>
                <span className="block text-[11px] text-rose-200/80">{u.reason}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {r.missing_information.length > 0 && (
        <section>
          <h3 className="mb-1 text-[12px] font-semibold text-ink">Missing information</h3>
          <ul className="list-disc pl-5 text-[12px] text-muted">
            {r.missing_information.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
        </section>
      )}
      {r.prior_investigations.length > 0 && (
        <section>
          <h3 className="mb-1 text-[12px] font-semibold text-ink">Recalled from earlier investigations (graph memory)</h3>
          <ul className="space-y-1 text-[12px] text-muted">
            {r.prior_investigations.map((p) => (
              <li key={p.investigation_id}>
                <Link className="text-sky-300 hover:underline" to={`/investigations/${p.investigation_id}`}>
                  {p.investigation_id}
                </Link>{" "}
                · {humanize(p.verdict)} · risk {p.risk_score ?? "—"} · {fmtTime(p.completed_at)} · shared: {p.shared_entities.join(", ")}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
