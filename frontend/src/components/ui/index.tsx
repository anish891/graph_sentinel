import * as Dialog from "@radix-ui/react-dialog";
import clsx from "clsx";
import { AlertTriangle, Inbox, Loader2, RefreshCw, X } from "lucide-react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { useState } from "react";

import { ApiError } from "../../lib/api";
import { humanize } from "../../lib/format";
import type { ActionStatus, RiskBand, Severity, Verdict } from "../../types/api";

// ---- primitives ---------------------------------------------------------------------------
export function Card({ title, actions, children, className, bodyClassName }: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={clsx("rounded-xl border border-line bg-panel shadow-sm shadow-black/30", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="text-[13px] font-semibold tracking-wide text-ink">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={clsx("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

type Variant = "primary" | "secondary" | "ghost" | "danger" | "success";

export function Button({ variant = "secondary", size = "md", loading, className, children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "sm" | "md";
  loading?: boolean;
}) {
  const styles: Record<Variant, string> = {
    primary: "bg-accent-strong text-slate-950 hover:bg-accent font-semibold",
    secondary: "border border-line-strong bg-panel-2 text-ink hover:bg-line",
    ghost: "text-muted hover:text-ink hover:bg-panel-2",
    danger: "bg-rose-600/90 text-white hover:bg-rose-500 font-semibold",
    success: "bg-emerald-500 text-slate-950 hover:bg-emerald-400 font-semibold",
  };
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={clsx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-2 text-sm",
        styles[variant],
        className,
      )}
    >
      {loading && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Badge({ children, tone = "neutral", className, title }: {
  children: ReactNode;
  tone?: "neutral" | "accent" | "ok" | "warn" | "bad" | "critical" | "high" | "medium" | "low" | "violet";
  className?: string;
  title?: string;
}) {
  const tones = {
    neutral: "bg-slate-500/15 text-slate-300 ring-slate-400/20",
    accent: "bg-sky-500/15 text-sky-300 ring-sky-400/25",
    ok: "bg-emerald-500/15 text-emerald-300 ring-emerald-400/25",
    warn: "bg-amber-500/15 text-amber-300 ring-amber-400/25",
    bad: "bg-rose-500/15 text-rose-300 ring-rose-400/25",
    critical: "bg-rose-500/20 text-rose-200 ring-rose-400/40",
    high: "bg-orange-500/15 text-orange-300 ring-orange-400/30",
    medium: "bg-yellow-500/15 text-yellow-200 ring-yellow-400/25",
    low: "bg-sky-500/15 text-sky-300 ring-sky-400/25",
    violet: "bg-violet-500/15 text-violet-300 ring-violet-400/25",
  } as const;
  return (
    <span title={title} className={clsx("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", tones[tone], className)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity | RiskBand | string | null | undefined }) {
  const s = (severity ?? "low") as Severity;
  const tone = (["critical", "high", "medium", "low"].includes(s) ? s : "neutral") as "critical";
  return (
    <Badge tone={tone}>
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {humanize(s)}
    </Badge>
  );
}

export function VerdictBadge({ verdict }: { verdict: Verdict | null | undefined }) {
  if (!verdict) return <Badge>pending</Badge>;
  const tone = { likely_malicious: "critical", suspicious: "warn", likely_benign: "ok", inconclusive: "neutral" } as const;
  return <Badge tone={tone[verdict]}>{humanize(verdict)}</Badge>;
}

export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  const tone = {
    proposed: "neutral",
    pending_approval: "warn",
    approved: "accent",
    executed_simulation: "ok",
    rejected: "bad",
    expired: "neutral",
    failed: "bad",
    cancelled: "neutral",
  } as const;
  return <Badge tone={tone[status]}>{status === "executed_simulation" ? "Executed (simulation)" : humanize(status)}</Badge>;
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={clsx("font-mono text-[12px] text-sky-200/90", className)}>{children}</code>;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 py-6 text-sm text-muted">
      <Loader2 className="size-4 animate-spin" aria-hidden /> {label}…
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center text-sm text-muted">
      <Inbox className="size-6 text-faint" aria-hidden />
      <p className="font-medium text-ink">{title}</p>
      {children}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof ApiError ? error.message : "Something went wrong while loading this data.";
  const rid = error instanceof ApiError ? error.requestId : null;
  return (
    <div role="alert" className="flex flex-col items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/5 p-4 text-sm">
      <div className="flex items-center gap-2 font-medium text-rose-200">
        <AlertTriangle className="size-4" aria-hidden /> {msg}
      </div>
      {rid && <p className="text-xs text-muted">Request ID: <Mono>{rid}</Mono></p>}
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          <RefreshCw className="size-3.5" aria-hidden /> Retry
        </Button>
      )}
    </div>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3">
      <p className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</p>
      <p className={clsx("mt-1 text-2xl font-semibold tabular-nums", tone)}>{value}</p>
      {hint && <p className="mt-0.5 text-xs text-muted">{hint}</p>}
    </div>
  );
}

export function KeyValue({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(90px,auto)_1fr] gap-x-3 gap-y-1.5 text-[13px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-faint">{k}</dt>
          <dd className="min-w-0 break-words text-ink">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange, label }: {
  tabs: { id: T; label: ReactNode }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="flex gap-1 border-b border-line">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={clsx(
            "-mb-px border-b-2 px-3 py-2 text-[13px] transition-colors",
            value === t.id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink",
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <nav aria-label="Pagination" className="flex items-center justify-between gap-2 pt-3 text-xs text-muted">
      <span>
        {total === 0 ? 0 : (page - 1) * pageSize + 1}–{Math.min(total, page * pageSize)} of {total}
      </span>
      <div className="flex gap-1">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Previous
        </Button>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Next
        </Button>
      </div>
    </nav>
  );
}

export function ConfirmDialog({ open, onOpenChange, title, description, children, confirmLabel, confirmVariant = "primary", onConfirm, busy, confirmDisabled }: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  confirmLabel: string;
  confirmVariant?: Variant;
  onConfirm: () => void;
  busy?: boolean;
  confirmDisabled?: boolean;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(560px,calc(100vw-32px))] -translate-x-1/2 -translate-y-1/2 rounded-xl border border-line-strong bg-panel p-5 shadow-2xl">
          <div className="flex items-start justify-between gap-4">
            <Dialog.Title className="text-base font-semibold">{title}</Dialog.Title>
            <Dialog.Close className="rounded p-1 text-muted hover:text-ink" aria-label="Close">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          {description && <Dialog.Description className="mt-1.5 text-sm text-muted">{description}</Dialog.Description>}
          <div className="mt-4">{children}</div>
          <div className="mt-5 flex justify-end gap-2">
            <Dialog.Close asChild>
              <Button variant="ghost">Cancel</Button>
            </Dialog.Close>
            <Button variant={confirmVariant} onClick={onConfirm} loading={busy} disabled={confirmDisabled}>
              {confirmLabel}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function useDisclosure(initial = false) {
  const [open, setOpen] = useState(initial);
  return { open, setOpen, show: () => setOpen(true), hide: () => setOpen(false) };
}

export function SyntheticNotice({ compact }: { compact?: boolean }) {
  return (
    <Badge tone="violet" title="All organisations, people, hosts, IPs and incidents in this environment are fictional.">
      {compact ? "Synthetic data" : "Synthetic dataset — not real security data"}
    </Badge>
  );
}
