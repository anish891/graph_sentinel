// Typed HTTP client. All calls go to the same-origin backend (/api/v1); the browser never talks to
// FalkorDB or the LLM provider. Session = httpOnly cookie; unsafe methods send the CSRF token (double submit).
import type {
  AlertDetail,
  ApiErrorBody,
  AuditEvent,
  DashboardSummary,
  DemoUser,
  EntityDetail,
  GraphNode,
  GraphPayload,
  InvestigationResult,
  InvestigationSummary,
  InvestigationTrace,
  Me,
  Page,
  RecommendedAction,
  SystemStatus,
} from "../types/api";

const BASE = "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly details: Record<string, unknown>;

  constructor(status: number, body: ApiErrorBody | null) {
    super(body?.error.message ?? `Request failed (${status})`);
    this.status = status;
    this.code = body?.error.code ?? "http_error";
    this.requestId = body?.error.request_id ?? null;
    this.details = body?.error.details ?? {};
  }
}

function csrfToken(): string {
  const match = document.cookie.split("; ").find((c) => c.startsWith("gs_csrf="));
  return match ? decodeURIComponent(match.slice("gs_csrf=".length)) : "";
}

type Query = Record<string, string | number | boolean | string[] | undefined | null>;

function qs(query?: Query): string {
  if (!query) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => p.append(k, x));
    else p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

async function request<T>(
  method: "GET" | "POST",
  path: string,
  opts: { query?: Query; body?: unknown; headers?: Record<string, string>; signal?: AbortSignal } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json", ...opts.headers };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();
  const res = await fetch(`${BASE}${path}${qs(opts.query)}`, {
    method,
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });
  const text = await res.text();
  const data = text ? (JSON.parse(text) as unknown) : null;
  if (!res.ok) throw new ApiError(res.status, data as ApiErrorBody | null);
  return data as T;
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

export const api = {
  // auth
  demoUsers: () => request<{ notice: string; users: DemoUser[] }>("GET", "/auth/demo-users"),
  demoLogin: (userId: string) =>
    request<{ user: { id: string; name: string; role: string }; csrf_token: string }>("POST", "/auth/demo-login", {
      body: { user_id: userId },
    }),
  logout: () => request<{ status: string }>("POST", "/auth/logout"),
  me: () => request<Me>("GET", "/auth/me"),
  // system
  status: () => request<SystemStatus>("GET", "/system/status"),
  dashboard: () => request<DashboardSummary>("GET", "/dashboard/summary"),
  diagnostics: () => request<Record<string, unknown>>("GET", "/diagnostics"),
  // graph
  graphStats: () =>
    request<{ graph_name: string; node_count: number; edge_count: number; nodes_by_label: Record<string, number>; edges_by_type: Record<string, number>; dataset: Record<string, unknown> }>(
      "GET",
      "/graph/stats",
    ),
  graphSchema: () => request<Record<string, unknown>>("GET", "/graph/schema"),
  search: (q: string) => request<GraphNode[]>("GET", "/graph/search", { query: { q } }),
  entity: (id: string) => request<EntityDetail>("GET", `/entities/${encodeURIComponent(id)}`),
  neighbors: (id: string, depth: number, includeHistorical: boolean, maxNodes = 60) =>
    request<GraphPayload>("GET", `/entities/${encodeURIComponent(id)}/neighbors`, {
      query: { depth, include_historical: includeHistorical, max_nodes: maxNodes },
    }),
  // alerts
  alerts: (query: Query) => request<Page<GraphNode>>("GET", "/alerts", { query }),
  alert: (id: string) => request<AlertDetail>("GET", `/alerts/${encodeURIComponent(id)}`),
  // investigations
  startInvestigation: (question: string, targetId?: string) =>
    request<InvestigationResult>("POST", "/investigations", {
      body: { question, ...(targetId ? { target_id: targetId } : {}) },
    }),
  investigations: (query: Query) => request<Page<InvestigationSummary>>("GET", "/investigations", { query }),
  investigation: (id: string) => request<InvestigationResult>("GET", `/investigations/${encodeURIComponent(id)}`),
  trace: (id: string) => request<InvestigationTrace>("GET", `/investigations/${encodeURIComponent(id)}/trace`),
  // actions
  actions: (query: Query) => request<Page<RecommendedAction>>("GET", "/actions", { query }),
  approve: (a: RecommendedAction, comment: string, key: string) =>
    request<RecommendedAction>("POST", `/actions/${encodeURIComponent(a.id)}/approve`, {
      body: { investigation_id: a.investigation_id, policy_version: a.policy_version, confirm: true, comment: comment || null },
      headers: { "Idempotency-Key": key },
    }),
  reject: (a: RecommendedAction, reason: string, key: string) =>
    request<RecommendedAction>("POST", `/actions/${encodeURIComponent(a.id)}/reject`, {
      body: { investigation_id: a.investigation_id, policy_version: a.policy_version, reason },
      headers: { "Idempotency-Key": key },
    }),
  // audit
  audit: (query: Query) => request<Page<AuditEvent>>("GET", "/audit/events", { query }),
  verifyAudit: () => request<{ valid: boolean; checked: number; head_hash: string | null; note: string }>("GET", "/audit/verify"),
};
