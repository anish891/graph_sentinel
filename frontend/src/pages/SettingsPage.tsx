import { useQuery } from "@tanstack/react-query";

import { Badge, Card, ErrorState, KeyValue, Mono, Spinner } from "../components/ui";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";
import { isRealLlm, llmLabel } from "../lib/llm";

interface Diagnostics {
  issues: { setting: string; severity: "error" | "warning" | "info"; message: string }[];
  settings: Record<string, string | number | boolean>;
  graph_indexes: { label: string; properties: string[] }[];
  runtime: Record<string, string>;
}

export function SettingsPage() {
  const { me, can } = useAuth();
  const status = useQuery({ queryKey: ["status"], queryFn: api.status });
  const diag = useQuery({ queryKey: ["diagnostics"], queryFn: () => api.diagnostics() as Promise<unknown> as Promise<Diagnostics>, enabled: can("diagnostics:read") });
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Settings & diagnostics</h1>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Your session">
          {me && (
            <KeyValue rows={[["User", me.name], ["Principal", <Mono key="p">{me.id}</Mono>], ["Role", <Badge key="r" tone="accent">{me.role}</Badge>], ["Tenant", me.tenant], ["Auth", me.auth_method], ["Permissions", <span key="x" className="flex flex-wrap gap-1">{me.permissions.map((p) => <Badge key={p}>{p}</Badge>)}</span>]]} />
          )}
        </Card>
        <Card title="Integration status">
          {status.isLoading && <Spinner />}
          {status.data && (
            <KeyValue
              rows={[
                ["Environment", status.data.app_env],
                ["Demo mode", String(status.data.demo_mode)],
                ["LLM provider", status.data.llm_is_mock ? <Badge key="m" tone="warn">mock-deterministic-planner (not an LLM)</Badge> : <Badge key="a" tone={isRealLlm(status.data) ? "accent" : "bad"}>{llmLabel(status.data)}</Badge>],
                ["Groq configured", status.data.groq_configured ? "yes" : "no — set GROQ_API_KEY in .env"],
                ["Azure OpenAI configured", status.data.azure_configured ? "yes" : "no — needs key, endpoint and deployment"],
                ["FalkorDB", `${status.data.falkordb.graph} · ${status.data.falkordb.reachable ? "reachable" : "unreachable"}`],
                ["Metadata DB", status.data.metadata_db.reachable ? "reachable" : "unreachable"],
                ["Execution", "simulation only"],
                ["Policy", status.data.policy_version],
                ["Risk weights", status.data.risk_weights_version],
              ]}
            />
          )}
        </Card>
      </div>
      {!can("diagnostics:read") && <p className="text-[12px] text-faint">Full configuration diagnostics require the admin role.</p>}
      {diag.isError && <ErrorState error={diag.error} onRetry={() => void diag.refetch()} />}
      {diag.data && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Configuration issues">
            <ul className="space-y-2 text-[13px]">
              {diag.data.issues.length === 0 && <li className="text-muted">No issues detected.</li>}
              {diag.data.issues.map((i) => (
                <li key={i.setting + i.message} className="flex items-start gap-2">
                  <Badge tone={i.severity === "error" ? "bad" : i.severity === "warning" ? "warn" : "neutral"}>{i.severity}</Badge>
                  <span><Mono>{i.setting}</Mono> — <span className="text-muted">{i.message}</span></span>
                </li>
              ))}
            </ul>
          </Card>
          <Card title="Effective settings (secret values never shown)">
            <KeyValue rows={Object.entries(diag.data.settings).map(([k, v]) => [k, <Mono key={k}>{String(v)}</Mono>])} />
          </Card>
          <Card title="FalkorDB indexes" className="lg:col-span-2">
            <div className="flex flex-wrap gap-1.5">
              {diag.data.graph_indexes.map((ix) => <Badge key={ix.label + ix.properties.join()}>{ix.label}({ix.properties.join(", ")})</Badge>)}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
