// Typed mirrors of the backend's Pydantic contracts (app/schemas/*). Keep in sync.

export type Severity = "low" | "medium" | "high" | "critical";
export type RiskBand = Severity;
export type Verdict = "likely_malicious" | "suspicious" | "likely_benign" | "inconclusive";
export type InvestigationStatus = "queued" | "running" | "completed" | "inconclusive" | "failed";
export type ActionStatus =
  | "proposed"
  | "pending_approval"
  | "approved"
  | "executed_simulation"
  | "rejected"
  | "expired"
  | "failed"
  | "cancelled";

export type PropertyValue = string | number | boolean | null | PropertyValue[];

export interface GraphNode {
  id: string;
  label: string;
  labels: string[];
  display_name: string;
  properties: Record<string, PropertyValue>;
}

export interface GraphEdge {
  id: string;
  type: string;
  source: string;
  target: string;
  properties: Record<string, PropertyValue>;
  temporal_status: "current" | "historical";
}

export interface GraphPath {
  id: string;
  node_ids: string[];
  edge_ids: string[];
  hops: number;
  start_id: string;
  end_id: string;
  end_label: string;
  description: string;
  contains_historical: boolean;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
  paths: GraphPath[];
  highlighted_path_ids: string[];
  evidence_refs: string[];
  truncation: { truncated: boolean; reason: string | null; max_nodes: number | null; max_depth: number | null };
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Ref {
  type: "node" | "edge" | "evidence" | "path" | "tool_call" | "calculation";
  id: string;
}

export interface EvidenceItem {
  id: string;
  kind: string;
  source_system: string;
  source_ref: string;
  observed_at: string | null;
  summary: string;
  claim: string | null;
  confidence: number;
  stance: "supports" | "contradicts";
  target_id: string;
  target_label: string;
  freshness: number | null;
  suspected_prompt_injection: boolean;
  injection_signals: string[];
  excluded_from_scoring: boolean;
  exclusion_reason: string | null;
}

export interface RiskFactor {
  key: string;
  label: string;
  weight: number;
  value: number;
  contribution: number;
  explanation: string;
  refs: Ref[];
}

export interface RiskAssessment {
  method: string;
  weights_version: string;
  calibrated: boolean;
  as_of: string;
  raw_score: number;
  contradiction_strength: number;
  contradiction_penalty: number;
  score: number;
  band: RiskBand;
  factors: RiskFactor[];
  confidence: number;
  confidence_band: "low" | "medium" | "high";
  uncertainty_notes: string[];
  verdict: Verdict;
  verdict_reason: string;
}

export interface RecommendedAction {
  id: string;
  investigation_id: string;
  action_type: string;
  title: string;
  target_id: string;
  target_label: string;
  status: ActionStatus;
  consequential: boolean;
  requires_approval: boolean;
  policy_version: string;
  policy_rule: string;
  justification: string;
  evidence_refs: Ref[];
  risk_score_at_proposal: number;
  proposed_by: string;
  proposed_at: string;
  expires_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_comment: string | null;
  executed_at: string | null;
  execution_result: Record<string, unknown> | null;
  simulated: true;
  version: number;
}

export interface Finding {
  id: string;
  kind: "observed_fact" | "inference" | "hypothesis";
  statement: string;
  refs: Ref[];
  origin: "graph" | "deterministic_analysis" | "model";
  confidence: number | null;
}

export interface ToolCallRecord {
  id: string;
  seq: number;
  tool: string;
  arguments: Record<string, unknown>;
  status: "ok" | "error" | "rejected";
  error: string | null;
  summary: string;
  origin: "llm" | "orchestrator_baseline";
  rationale: string | null;
  executed_in: string | null;
  duration_ms: number;
  result_hash: string | null;
  node_ids: string[];
  path_ids: string[];
  evidence_ids: string[];
}

export interface ProviderInfo {
  name: string;
  model: string;
  is_mock: boolean;
  api: string | null;
}

export interface InvestigationResult {
  id: string;
  tenant: string;
  status: InvestigationStatus;
  question: string;
  target_id: string;
  target_label: string | null;
  requested_by: string;
  created_at: string;
  completed_at: string | null;
  provider: ProviderInfo;
  verdict: Verdict | null;
  risk: RiskAssessment | null;
  findings: Finding[];
  unsupported_claims: { statement: string; reason: string }[];
  supporting_evidence: EvidenceItem[];
  contradicting_evidence: EvidenceItem[];
  narrative: { deterministic: string; model_summary: string | null } | null;
  recommended_actions: RecommendedAction[];
  graph: GraphPayload;
  tool_calls: ToolCallRecord[];
  missing_information: string[];
  prior_investigations: {
    investigation_id: string;
    verdict: string | null;
    risk_score: number | null;
    completed_at: string | null;
    target_id: string;
    shared_entities: string[];
  }[];
  stats: {
    steps: number;
    tool_calls: number;
    rejected_tool_calls: number;
    llm_calls: number;
    input_tokens: number;
    output_tokens: number;
    duration_ms: number;
    limits_hit: string[];
  };
  error: string | null;
  trace_head_hash: string | null;
  synthetic_data: boolean;
}

export interface InvestigationSummary {
  id: string;
  status: InvestigationStatus;
  question: string;
  target_id: string;
  requested_by: string;
  created_at: string;
  completed_at: string | null;
  verdict: Verdict | null;
  risk_score: number | null;
  risk_band: RiskBand | null;
  provider_name: string;
  provider_is_mock: boolean;
}

export interface TraceEvent {
  id: string;
  investigation_id: string;
  seq: number;
  ts: string;
  kind: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface InvestigationTrace {
  investigation_id: string;
  events: TraceEvent[];
  integrity: { valid: boolean; checked_events: number; head_hash: string | null; reason: string | null };
}

export interface AuditEvent {
  id: string;
  seq: number;
  ts: string;
  actor: string;
  actor_role: string | null;
  tenant: string;
  event_type: string;
  resource_type: string;
  resource_id: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface Me {
  id: string;
  name: string;
  role: "viewer" | "investigator" | "approver" | "admin";
  tenant: string;
  auth_method: string;
  permissions: string[];
}

export interface SystemStatus {
  app_env: string;
  demo_mode: boolean;
  auth_mode: string;
  llm_provider: "azure" | "groq" | "mock" | "unavailable";
  llm_model: string | null;
  groq_configured: boolean;
  llm_is_mock: boolean;
  azure_configured: boolean;
  falkordb: { reachable: boolean; graph: string };
  metadata_db: { reachable: boolean };
  simulation_only: boolean;
  policy_version: string;
  risk_weights_version: string;
  synthetic_data: boolean;
}

export interface DashboardSummary {
  alerts: { total: number; by_severity: Record<string, number>; by_status: Record<string, number> };
  investigations: {
    total: number;
    running: number;
    completed: number;
    inconclusive: number;
    failed: number;
    high_risk: number;
  };
  pending_approvals: number;
  recent_investigations: InvestigationSummary[];
  graph: { node_count: number; edge_count: number; nodes_by_label: Record<string, number>; dataset: Record<string, unknown> };
}

export interface AlertDetail {
  alert: GraphNode;
  relationships: { edge: GraphEdge; neighbor: GraphNode }[];
  evidence: EvidenceItem[];
  investigations: InvestigationSummary[];
}

export interface EntityDetail {
  entity: GraphNode;
  relationships: { edge: GraphEdge; neighbor: GraphNode }[];
}

export interface DemoUser {
  id: string;
  name: string;
  role: string;
  description: string;
}

export interface ApiErrorBody {
  error: { code: string; message: string; request_id: string | null; details: Record<string, unknown> };
}
