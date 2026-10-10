import type { PropertyValue } from "../types/api";

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function relTime(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const diff = (now.getTime() - new Date(iso).getTime()) / 1000;
  if (Number.isNaN(diff)) return iso;
  const abs = Math.abs(diff);
  const unit: [number, string][] = [
    [86400 * 365, "y"],
    [86400, "d"],
    [3600, "h"],
    [60, "m"],
  ];
  for (const [secs, label] of unit) {
    if (abs >= secs) return `${Math.floor(abs / secs)}${label} ${diff >= 0 ? "ago" : "from now"}`;
  }
  return "just now";
}

export function humanize(s: string | null | undefined): string {
  if (!s) return "—";
  return s.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export function propText(v: PropertyValue | undefined): string {
  if (v === undefined || v === null) return "—";
  if (Array.isArray(v)) return v.map((x) => propText(x)).join(", ");
  return String(v);
}

export function pct(v: number | null | undefined, digits = 0): string {
  if (v === null || v === undefined) return "—";
  return `${(v * 100).toFixed(digits)}%`;
}
