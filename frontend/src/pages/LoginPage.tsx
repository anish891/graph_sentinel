import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { useState } from "react";

import { Badge, Button, ErrorState, Spinner, SyntheticNotice } from "../components/ui";
import { useAuth } from "../hooks/useAuth";
import { api } from "../lib/api";

export function LoginPage() {
  const { login } = useAuth();
  const users = useQuery({ queryKey: ["demo-users"], queryFn: api.demoUsers, retry: false });
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  return (
    <div className="flex min-h-full items-center justify-center p-4">
      <div className="w-full max-w-lg rounded-2xl border border-line bg-panel p-6 shadow-2xl">
        <div className="flex items-center gap-3">
          <ShieldCheck className="size-8 text-accent" aria-hidden />
          <div>
            <h1 className="text-lg font-semibold">GraphSentinel AI</h1>
            <p className="text-sm text-muted">Explainable, graph-native security investigations</p>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <SyntheticNotice />
          <Badge tone="warn">Demo authentication — not production auth</Badge>
        </div>
        <p className="mt-4 text-sm text-muted">Choose a synthetic identity. Each role has different server-enforced permissions.</p>
        {users.isLoading && <Spinner />}
        {users.isError && <ErrorState error={users.error} onRetry={() => void users.refetch()} />}
        <ul className="mt-3 space-y-2">
          {users.data?.users.map((u) => (
            <li key={u.id}>
              <button
                className="flex w-full items-center justify-between gap-3 rounded-xl border border-line bg-panel-2 px-4 py-3 text-left transition-colors hover:border-sky-500/50 hover:bg-line disabled:opacity-60"
                disabled={!!busy}
                onClick={async () => {
                  setBusy(u.id);
                  setError(null);
                  try {
                    await login(u.id);
                  } catch (e) {
                    setError(e);
                  } finally {
                    setBusy(null);
                  }
                }}
              >
                <span>
                  <span className="block text-sm font-medium">{u.name}</span>
                  <span className="block text-xs text-muted">{u.description}</span>
                </span>
                <Badge tone={u.role === "admin" ? "violet" : u.role === "approver" ? "ok" : u.role === "investigator" ? "accent" : "neutral"}>
                  {u.role}
                </Badge>
              </button>
            </li>
          ))}
        </ul>
        {error !== null && <div className="mt-3"><ErrorState error={error} /></div>}
        {busy && <div className="mt-3"><Button variant="ghost" loading disabled>Signing in</Button></div>}
      </div>
    </div>
  );
}
