import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity,
  BellRing,
  CheckSquare,
  History,
  LayoutDashboard,
  LogOut,
  Network,
  ScrollText,
  Search,
  Settings,
  ShieldCheck,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

import { Badge, SyntheticNotice } from "../components/ui";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";
import { isRealLlm, llmLabel } from "../lib/llm";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/alerts", label: "Alerts", icon: BellRing },
  { to: "/investigate", label: "Investigate", icon: Search },
  { to: "/investigations", label: "History", icon: History },
  { to: "/approvals", label: "Approvals", icon: CheckSquare },
  { to: "/graph", label: "Graph explorer", icon: Network },
  { to: "/audit", label: "Audit trail", icon: ScrollText },
  { to: "/settings", label: "Settings", icon: Settings },
];

function StatusDot({ ok, label }: { ok: boolean | undefined; label: string }) {
  return (
    <span className="flex items-center gap-1.5 text-[11px] text-muted" title={`${label}: ${ok ? "reachable" : "unavailable"}`}>
      <span className={clsx("size-1.5 rounded-full", ok === undefined ? "bg-slate-500" : ok ? "bg-emerald-400" : "bg-rose-500")} />
      {label}
    </span>
  );
}

export function Layout() {
  const { me, logout } = useAuth();
  const status = useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: 30_000 });
  const pending = useQuery({
    queryKey: ["actions", "pending-count"],
    queryFn: () => api.actions({ status: ["pending_approval"], page_size: 1 }),
    refetchInterval: 15_000,
  });
  const s = status.data;
  return (
    <div className="flex h-full">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-line bg-panel md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <ShieldCheck className="size-6 text-accent" aria-hidden />
          <div>
            <p className="text-sm font-semibold leading-tight">GraphSentinel AI</p>
            <p className="text-[10px] uppercase tracking-widest text-faint">Investigation console</p>
          </div>
        </div>
        <nav aria-label="Primary" className="flex flex-1 flex-col gap-0.5 px-2">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                clsx(
                  "flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition-colors",
                  isActive ? "bg-sky-500/10 text-sky-200" : "text-muted hover:bg-panel-2 hover:text-ink",
                )
              }
            >
              <Icon className="size-4" aria-hidden />
              <span className="flex-1">{label}</span>
              {to === "/approvals" && !!pending.data?.total && <Badge tone="warn">{pending.data.total}</Badge>}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1.5 border-t border-line px-4 py-3">
          <StatusDot ok={s ? true : status.isError ? false : undefined} label="Backend" />
          <StatusDot ok={s?.falkordb.reachable} label="FalkorDB" />
          <StatusDot ok={s ? isRealLlm(s) : undefined} label={s?.llm_is_mock ? "LLM: mock planner" : `LLM: ${llmLabel(s)}`} />
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center gap-2 border-b border-line bg-panel/70 px-4 py-2 backdrop-blur md:px-6">
          <nav aria-label="Mobile" className="flex gap-1 overflow-x-auto md:hidden">
            {NAV.slice(0, 6).map(({ to, icon: Icon, label, end }) => (
              <NavLink key={to} to={to} end={end} aria-label={label} className={({ isActive }) => clsx("rounded p-1.5", isActive ? "text-sky-300" : "text-muted")}>
                <Icon className="size-4" />
              </NavLink>
            ))}
          </nav>
          <div className="flex flex-1 flex-wrap items-center gap-2">
            <SyntheticNotice compact />
            {s?.llm_is_mock && (
              <Badge tone="warn" title="Offline demo mode: a deterministic rule-based planner chooses graph tools. It is not an LLM.">
                <Activity className="size-3" aria-hidden /> Mock planner (not an LLM)
              </Badge>
            )}
            {isRealLlm(s) && <Badge tone="accent">{llmLabel(s)}</Badge>}
            {s?.simulation_only && <Badge tone="neutral">Actions: simulation only</Badge>}
            {s?.auth_mode === "demo" && <Badge tone="neutral" title="Demo authentication is not production authentication">Demo auth</Badge>}
          </div>
          {me && (
            <div className="flex items-center gap-2 text-[13px]">
              <span className="text-muted">
                {me.name} <span className="text-faint">· {me.role}</span>
              </span>
              <button onClick={() => void logout()} className="rounded p-1.5 text-muted hover:bg-panel-2 hover:text-ink" aria-label="Sign out">
                <LogOut className="size-4" />
              </button>
            </div>
          )}
        </header>
        <main className="scrollbar-thin min-h-0 flex-1 overflow-y-auto px-4 py-5 md:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
