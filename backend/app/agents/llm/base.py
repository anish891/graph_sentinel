"""Provider-agnostic LLM contract. Tool execution, graph access and policy never live here."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

FINISH_TOOL_NAME = "finish_investigation"


class ToolSpec(BaseModel):
    name: str
    description: str
    parameters: dict[str, Any]


class StepRecord(BaseModel):
    """One prior tool step, as shown back to the model (outputs are compact and data-only)."""

    call_id: str
    tool: str
    arguments: dict[str, Any]
    status: Literal["ok", "error", "rejected"]
    output: dict[str, Any]


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: str = Field(min_length=3, max_length=600)
    kind: Literal["observed_fact", "inference", "hypothesis"]
    refs: list[str] = Field(
        default_factory=list, max_length=12, description="ids of nodes, paths, evidence or tool calls from tool outputs"
    )


class FinishPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=10, max_length=2500)
    claims: list[Claim] = Field(default_factory=list, max_length=25)
    missing_information: list[str] = Field(default_factory=list, max_length=10)
    # Claims the model sent that did not match the Claim shape (set by our parser, not by the model).
    malformed_claims: list[str] = Field(default_factory=list, max_length=25)

    @classmethod
    def lenient(cls, args: dict[str, Any]) -> FinishPayload:
        """Parse model output without letting one bad claim discard the whole finish.

        Strings are trimmed to the limits, each claim is validated individually, and malformed claims
        are kept (as text) so they can be reported as rejected rather than silently lost.
        """
        summary = str(args.get("summary") or "").strip()[:2500]
        if len(summary) < 10:
            raise ValueError("summary missing or too short")
        claims: list[Claim] = []
        malformed: list[str] = []
        claims_arg = args.get("claims")
        raw_claims: list[Any] = claims_arg if isinstance(claims_arg, list) else []
        for raw in raw_claims[:25]:
            if not isinstance(raw, dict):
                malformed.append(str(raw)[:300])
                continue
            refs = raw.get("refs")
            try:
                claims.append(
                    Claim(
                        statement=str(raw.get("statement", "")).strip()[:600],
                        kind=raw.get("kind"),
                        refs=[str(r) for r in refs][:12] if isinstance(refs, list) else [],
                    )
                )
            except ValidationError:
                malformed.append(str(raw.get("statement") or raw)[:300])
        missing_raw = args.get("missing_information")
        missing = [str(m)[:300] for m in missing_raw][:10] if isinstance(missing_raw, list) else []
        return cls(summary=summary, claims=claims, missing_information=missing, malformed_claims=malformed)


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class AgentDecision(BaseModel):
    kind: Literal["tool_call", "finish"]
    call_id: str
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str | None = None
    finish: FinishPayload | None = None
    usage: Usage = Field(default_factory=Usage)


class DecisionRequest(BaseModel):
    investigation_id: str
    question: str
    target_id: str
    tools: list[ToolSpec]
    history: list[StepRecord]
    remaining_tool_calls: int
    remaining_steps: int


class LLMProvider(ABC):
    name: str
    model: str
    is_mock: bool
    api: str | None = None

    @abstractmethod
    async def decide(self, request: DecisionRequest) -> AgentDecision: ...

    async def aclose(self) -> None:
        return None


def finish_tool_spec() -> ToolSpec:
    # Deliberately relaxed (no length/item limits, extra fields allowed): some providers validate tool
    # arguments server-side and reject the *whole* call on one bad claim. Limits are enforced by
    # FinishPayload.lenient, claim by claim.
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "Concise conclusion (a few sentences)."},
            "claims": {
                "type": "array",
                "description": "At most 25 claims.",
                "items": {
                    "type": "object",
                    "properties": {
                        "statement": {"type": "string", "description": "One sentence."},
                        "kind": {"type": "string", "enum": ["observed_fact", "inference", "hypothesis"]},
                        "refs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "ids from tool outputs (path-…, EV-…, node ids)",
                        },
                    },
                    "required": ["statement", "kind", "refs"],
                },
            },
            "missing_information": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["summary", "claims"],
    }
    return ToolSpec(
        name=FINISH_TOOL_NAME,
        description=(
            "Finish the investigation. Provide a concise summary and claims. Every claim MUST cite ids "
            "(path ids, evidence ids, node ids) that appeared in tool outputs; uncited claims are "
            "discarded. Do not provide a risk score: it is computed deterministically."
        ),
        parameters=schema,
    )
