import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";

import { AuthProvider } from "./hooks/useAuth";
import type { GraphPayload, Me, RecommendedAction } from "./types/api";

export function renderWithProviders(ui: ReactNode, me: Me | null = null) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(["me"], me);
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthProvider>{ui}</AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

export const ME_APPROVER: Me = {
  id: "demo:bob", name: "Bob Approver", role: "approver", tenant: "acme", auth_method: "demo",
  permissions: ["actions:approve", "actions:reject", "actions:read", "investigations:read"],
};
export const ME_VIEWER: Me = { ...ME_APPROVER, id: "demo:vera", name: "Vera", role: "viewer", permissions: ["actions:read"] };

export const PAYLOAD: GraphPayload = {
  nodes: [
    { id: "ALT-1001", label: "SecurityAlert", labels: ["SecurityAlert"], display_name: "Anomalous VPN login", properties: { severity: "high" } },
    { id: "ip-203-0-113-45", label: "IP", labels: ["IP"], display_name: "203.0.113.45", properties: { scope: "external" } },
    { id: "dev-wks-0142", label: "Device", labels: ["Device"], display_name: "WKS-0142", properties: {} },
    { id: "dev-wks-0077", label: "Device", labels: ["Device"], display_name: "WKS-0077", properties: { status: "retired" } },
  ],
  edges: [
    { id: "ip-203-0-113-45|TRIGGERED|ALT-1001", type: "TRIGGERED", source: "ip-203-0-113-45", target: "ALT-1001", properties: { role: "source_ip" }, temporal_status: "current" },
    { id: "ip-203-0-113-45|CONNECTED_TO|dev-wks-0142", type: "CONNECTED_TO", source: "ip-203-0-113-45", target: "dev-wks-0142", properties: {}, temporal_status: "current" },
    { id: "ip-203-0-113-45|ASSIGNED_TO|dev-wks-0077", type: "ASSIGNED_TO", source: "ip-203-0-113-45", target: "dev-wks-0077", properties: { valid_to: "2025-06-01T00:00:00Z" }, temporal_status: "historical" },
  ],
  paths: [
    {
      id: "path-aaaaaaaaaaaa", node_ids: ["ALT-1001", "ip-203-0-113-45", "dev-wks-0142"],
      edge_ids: ["ip-203-0-113-45|TRIGGERED|ALT-1001", "ip-203-0-113-45|CONNECTED_TO|dev-wks-0142"], hops: 2,
      start_id: "ALT-1001", end_id: "dev-wks-0142", end_label: "Device", description: "d", contains_historical: false,
    },
  ],
  highlighted_path_ids: ["path-aaaaaaaaaaaa"],
  evidence_refs: [],
  truncation: { truncated: false, reason: null, max_nodes: 150, max_depth: 5 },
};

export function action(overrides: Partial<RecommendedAction> = {}): RecommendedAction {
  return {
    id: "ACT-1", investigation_id: "INV-1", action_type: "isolate_endpoint", title: "Isolate", target_id: "dev-wks-0142",
    target_label: "Device", status: "pending_approval", consequential: true, requires_approval: true,
    policy_version: "policy-2026.10.1", policy_rule: "P-ISOLATE", justification: "Endpoint telemetry supports compromise.",
    evidence_refs: [{ type: "evidence", id: "EV-1002" }], risk_score_at_proposal: 65, proposed_by: "agent:graphsentinel",
    proposed_at: "2026-10-01T12:00:00Z", expires_at: "2026-10-02T12:00:00Z", decided_by: null, decided_at: null,
    decision_comment: null, executed_at: null, execution_result: null, simulated: true, version: 1, ...overrides,
  };
}
