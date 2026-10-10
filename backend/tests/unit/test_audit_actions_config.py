from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.audit.chain import GENESIS_HASH, chain_hash
from app.auth.permissions import Permission, permissions_for
from app.auth.tokens import DEMO_USERS, TokenService
from app.core.config import Settings
from app.core.errors import AuthenticationRequiredError
from app.persistence.db import Database
from app.schemas.actions import ActionStatus
from app.services.actions import can_transition
from app.services.audit import AuditService


def test_state_machine() -> None:
    S = ActionStatus
    assert can_transition(S.PENDING_APPROVAL, S.APPROVED)
    assert can_transition(S.APPROVED, S.EXECUTED_SIMULATION)
    assert not can_transition(S.PENDING_APPROVAL, S.EXECUTED_SIMULATION)  # no skipping approval
    assert not can_transition(S.EXECUTED_SIMULATION, S.APPROVED)
    assert not can_transition(S.REJECTED, S.APPROVED)
    assert not can_transition(S.EXPIRED, S.APPROVED)


def test_rbac_matrix() -> None:
    assert Permission.APPROVE_ACTION not in permissions_for("investigator")
    assert Permission.CREATE_INVESTIGATION not in permissions_for("approver")
    assert Permission.CREATE_INVESTIGATION not in permissions_for("viewer")
    assert Permission.READ_METRICS in permissions_for("admin")
    assert permissions_for("nonexistent") == frozenset()


async def test_audit_chain_detects_tampering(tmp_path) -> None:
    db = Database(str(tmp_path / "a.db"))
    await db.connect()
    audit = AuditService(db)
    for i in range(5):
        await audit.record(
            actor="t",
            actor_role=None,
            tenant="acme",
            event_type="test.event",
            resource_type="x",
            resource_id=str(i),
            details={"i": i},
        )
    assert (await audit.verify_chain()).valid
    with pytest.raises(Exception, match="append-only"):
        await db.conn.execute("UPDATE audit_events SET actor = 'evil' WHERE seq = 2")
    # An attacker with raw DB access who bypasses the trigger is detected by the chain.
    await db.conn.execute("DROP TRIGGER audit_no_update")
    await db.conn.execute("UPDATE audit_events SET details_json = '{\"i\": 99}' WHERE seq = 3")
    result = await audit.verify_chain()
    assert not result.valid and result.first_invalid_seq == 3
    await db.close()


def test_chain_hash_deterministic() -> None:
    a = chain_hash(GENESIS_HASH, {"b": 1, "a": [1, 2]})
    assert a == chain_hash(GENESIS_HASH, {"a": [1, 2], "b": 1}) and len(a) == 64


def test_production_rejects_demo_settings() -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="production", demo_mode=True, auth_mode="demo", _env_file=None)
    with pytest.raises(ValidationError):
        Settings(simulation_only=False, _env_file=None)


def test_provider_selection_without_azure() -> None:
    s = Settings(
        _env_file=None,
        demo_mode=True,
        azure_openai_api_key=None,
        azure_openai_endpoint=None,
        azure_openai_deployment=None,
    )
    assert s.effective_llm_provider == "mock"
    s2 = Settings(
        _env_file=None,
        demo_mode=False,
        app_env="development",
        azure_openai_api_key=None,
        azure_openai_endpoint=None,
        azure_openai_deployment=None,
    )
    assert s2.effective_llm_provider == "unavailable"
    issues = s2.config_issues()
    assert any(i.severity == "error" for i in issues)
    assert all("sk-" not in i.message for i in issues)


def test_secrets_not_in_repr() -> None:
    s = Settings(_env_file=None, azure_openai_api_key="super-secret-value", falkordb_password="pw-value")
    assert "super-secret-value" not in repr(s) and "pw-value" not in repr(s)


def test_demo_tokens() -> None:
    svc = TokenService(Settings(_env_file=None, auth_secret_key="k" * 48))
    token, csrf, _ = svc.issue_demo(DEMO_USERS["bob"])
    p, c = svc.verify_demo(token)
    assert p.role == "approver" and p.tenant == "acme" and c == csrf
    other = TokenService(Settings(_env_file=None, auth_secret_key="z" * 48))
    with pytest.raises(AuthenticationRequiredError):
        other.verify_demo(token)
    with pytest.raises(AuthenticationRequiredError):
        svc.verify_demo(token[:-3] + "abc")


async def test_reset_all_in_place_visible_to_open_connections(tmp_path) -> None:
    path = str(tmp_path / "r.db")
    server, cli = Database(path), Database(path)
    await server.connect()
    await AuditService(server).record(
        actor="a", actor_role=None, tenant="acme", event_type="x", resource_type="y", resource_id=None
    )
    await cli.connect()
    await cli.reset_all()
    await cli.close()
    # The long-lived "server" connection keeps working against the same file after the reset.
    await AuditService(server).record(
        actor="b", actor_role=None, tenant="acme", event_type="x", resource_type="y", resource_id=None
    )
    reopened = Database(path)
    await reopened.connect()
    events, total = await AuditService(reopened).list_page("acme", offset=0, limit=10)
    assert total == 1 and events[0].actor == "b"
    assert (await AuditService(reopened).verify_chain()).valid
    await reopened.close()
    await server.close()
