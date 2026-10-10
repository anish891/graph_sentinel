import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, FlaskConical, X } from "lucide-react";
import { useRef, useState } from "react";

import { ActionStatusBadge, Badge, Button, ConfirmDialog, ErrorState, Mono } from "../components/ui";
import { useAuth } from "../hooks/useAuth";
import { api, newIdempotencyKey } from "../lib/api";
import { fmtTime, humanize } from "../lib/format";
import type { RecommendedAction, Ref } from "../types/api";
import { RefChips } from "./RefChips";

export function ActionCard({ action, onRef, requesterId }: { action: RecommendedAction; onRef?: (r: Ref) => void; requesterId?: string }) {
  const { can, me } = useAuth();
  const qc = useQueryClient();
  const [mode, setMode] = useState<"approve" | "reject" | null>(null);
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  // One idempotency key per dialog opening: double-clicks and retries cannot execute twice.
  const keyRef = useRef<string>(newIdempotencyKey());

  const decide = useMutation({
    mutationFn: () =>
      mode === "approve" ? api.approve(action, comment, keyRef.current) : api.reject(action, comment, keyRef.current),
    onSuccess: async () => {
      setMode(null);
      await qc.invalidateQueries({ queryKey: ["actions"] });
      await qc.invalidateQueries({ queryKey: ["investigation", action.investigation_id] });
      await qc.invalidateQueries({ queryKey: ["audit"] });
    },
  });

  const open = (m: "approve" | "reject") => {
    keyRef.current = newIdempotencyKey();
    setComment("");
    setAck(false);
    decide.reset();
    setMode(m);
  };

  const pending = action.status === "pending_approval";
  const isRequester = !!requesterId && me?.id === requesterId;
  const canDecide = pending && can("actions:approve") && !isRequester;

  return (
    <li className="rounded-xl border border-line bg-panel-2 p-3 text-[13px]" data-testid={`action-${action.action_type}`}>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-medium">{humanize(action.action_type)}</span>
        <span className="text-faint">→</span>
        <Mono>{action.target_id}</Mono>
        <ActionStatusBadge status={action.status} />
        <Badge tone="violet">
          <FlaskConical className="size-3" aria-hidden /> simulated
        </Badge>
        {action.consequential && <Badge tone="warn">consequential</Badge>}
      </div>
      <p className="mt-1.5 text-muted">{action.justification}</p>
      {action.evidence_refs.length > 0 && <RefChips refs={action.evidence_refs} onRef={onRef} />}
      <p className="mt-1.5 text-[11px] text-faint">
        Rule <Mono>{action.policy_rule}</Mono> · {action.policy_version} · risk at proposal {action.risk_score_at_proposal} · proposed by{" "}
        {action.proposed_by} · expires {fmtTime(action.expires_at)}
      </p>
      {action.decided_by && (
        <p className="mt-1 text-[11px] text-faint">
          Decided by <span className="text-ink">{action.decided_by}</span> at {fmtTime(action.decided_at)}
          {action.decision_comment ? ` — “${action.decision_comment}”` : ""}
        </p>
      )}
      {action.execution_result && (
        <p className="mt-1 rounded bg-emerald-500/10 px-2 py-1 text-[12px] text-emerald-200">
          {String(action.execution_result.description ?? "Simulated execution recorded")} — no external system contacted.
        </p>
      )}
      {pending && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Button size="sm" variant="success" disabled={!canDecide} onClick={() => open("approve")}>
            <Check className="size-3.5" aria-hidden /> Approve…
          </Button>
          <Button size="sm" variant="secondary" disabled={!canDecide} onClick={() => open("reject")}>
            <X className="size-3.5" aria-hidden /> Reject…
          </Button>
          {!can("actions:approve") && <span className="text-[11px] text-faint">Requires approver role</span>}
          {can("actions:approve") && isRequester && <span className="text-[11px] text-faint">Four-eyes: you requested this investigation</span>}
        </div>
      )}
      <ConfirmDialog
        open={mode !== null}
        onOpenChange={(o) => !o && setMode(null)}
        title={mode === "approve" ? "Approve simulated action" : "Reject action"}
        description={
          <>
            {humanize(action.action_type)} on <Mono>{action.target_id}</Mono> for investigation <Mono>{action.investigation_id}</Mono> under{" "}
            <Mono>{action.policy_version}</Mono>.
          </>
        }
        confirmLabel={mode === "approve" ? "Approve & run simulation" : "Reject action"}
        confirmVariant={mode === "approve" ? "success" : "danger"}
        busy={decide.isPending}
        confirmDisabled={mode === "approve" ? !ack : comment.trim().length < 3}
        onConfirm={() => decide.mutate()}
      >
        <div className="space-y-3 text-[13px]">
          <p className="rounded-lg bg-violet-500/10 p-2 text-violet-200">
            Execution is simulated. No account, device, firewall or external system will be changed.
          </p>
          <label className="block">
            <span className="text-muted">{mode === "approve" ? "Comment (optional)" : "Reason (required)"}</span>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              maxLength={1000}
              rows={2}
              className="mt-1 w-full rounded-lg border border-line-strong bg-bg p-2 text-ink outline-none focus:border-sky-400"
            />
          </label>
          {mode === "approve" && (
            <label className="flex items-start gap-2">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5 accent-sky-400" />
              <span>I reviewed the evidence, risk rationale and policy justification for this action.</span>
            </label>
          )}
          {decide.isError && <ErrorState error={decide.error} />}
        </div>
      </ConfirmDialog>
    </li>
  );
}
