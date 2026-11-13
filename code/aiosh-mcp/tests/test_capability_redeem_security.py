"""PoR I-2: capability tokens are redeemed PEP grants, not any non-empty string (T-03429 F1).

Before T-03429 these state-changing MCP tools only checked ``capability_token.strip()``. Every test here would have
let a forged token through."""

import datetime as dt
import json
import sqlite3
from contextlib import closing

import pytest

from agent_loop_grants import mint_grant, revoke_grant
from aiosh_mcp import capability_redeem as cr
from aiosh_mcp.mcp_server_core_recovery import MCPRECV_ERR_UNAUTHORIZED, recover_mcp_store

FORGED = ["forged", "valid-token", "x" * 64, "token:admin", " grant "]


@pytest.fixture
def db(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("AIOSH_HOME", str(home))
    return str(home / "audit.db")


def corrupt_store(tmp_path):
    f = tmp_path / "store.json"
    f.write_text('{"broken": [1,', encoding="utf-8")
    return f


def redeem_rows(db):
    with closing(sqlite3.connect(db)) as c:
        return c.execute("SELECT count(*) FROM audit_ring WHERE tool = 'pep.capability.redeem'").fetchone()[0]


def served():
    from aiosh_mcp.server import mcp
    return {t.name: t for t in mcp._tool_manager.list_tools()}


# ---- the shared gate --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("token", FORGED + ["", "   ", None, 42, "a\x00b", "g" * (cr.MAX_TOKEN_CHARS + 1)])
def test_forged_or_malformed_tokens_are_refused(db, token):
    assert cr.redeem_capability(token, tool="aios.mcp.recovery.repair") is not None


def test_real_grant_redeems_once_and_writes_an_audit_row(db):
    mint_grant(db, "g-1", tools=["aios.mcp.recovery.repair"])
    assert cr.redeem_capability("g-1", tool="aios.mcp.recovery.repair") is None
    assert redeem_rows(db) == 1
    assert "already redeemed" in cr.redeem_capability("g-1", tool="aios.mcp.recovery.repair")
    assert redeem_rows(db) == 1


def test_scope_revocation_and_expiry_are_enforced(db):
    mint_grant(db, "other-tool", tools=["aios.fs.read"])
    assert cr.redeem_capability("other-tool", tool="aios.mcp.recovery.repair") is not None
    mint_grant(db, "revoked", tools=["aios.mcp.recovery.repair"])
    revoke_grant(db, "revoked")
    assert cr.redeem_capability("revoked", tool="aios.mcp.recovery.repair") is not None
    mint_grant(db, "expired", tools=["aios.mcp.recovery.repair"], expires_in=dt.timedelta(seconds=-5))
    assert cr.redeem_capability("expired", tool="aios.mcp.recovery.repair") is not None
    assert redeem_rows(db) == 0


def test_unavailable_db_fails_closed(db, monkeypatch):
    mint_grant(db, "g-db", tools=["aios.mcp.recovery.repair"])

    def broken(*a, **k):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(cr.audit_client, "open_db", broken)
    assert "unavailable" in cr.redeem_capability("g-db", tool="aios.mcp.recovery.repair")


def test_refusal_reason_is_masked_and_bounded(db):
    secret = "sk-" + "A" * 40
    reason = cr.redeem_capability(secret, tool="aios.mcp.recovery.repair")
    assert secret not in reason and len(reason) <= 300


# ---- every former non-empty-only tool ---------------------------------------------------------------------------

@pytest.mark.parametrize("token", FORGED)
def test_mcp_store_recovery_refuses_a_forged_token_and_changes_nothing(db, tmp_path, token):
    f = corrupt_store(tmp_path)
    with pytest.raises(PermissionError, match=MCPRECV_ERR_UNAUTHORIZED):
        recover_mcp_store(str(f), capability_token=token)
    assert f.read_text(encoding="utf-8") == '{"broken": [1,' and list(tmp_path.glob("store.json.bak*")) == []


def test_mcp_store_recovery_with_a_real_grant(db, tmp_path):
    f = corrupt_store(tmp_path)
    mint_grant(db, "repair-1", tools=["aios.mcp.recovery.repair"])
    assert recover_mcp_store(str(f), capability_token="repair-1").ok is True
    with pytest.raises(PermissionError):                                  # single use: no second repair
        recover_mcp_store(str(corrupt_store(tmp_path)), capability_token="repair-1")


def test_model_config_recovery_refuses_a_forged_token(db, tmp_path):
    from aiosh_mcp.model_backend_adapters_recovery import MODRECV_ERR_UNAUTHORIZED, get_global_recovery_engine
    f = tmp_path / "models.json"
    f.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match=MODRECV_ERR_UNAUTHORIZED):
        get_global_recovery_engine().recover_config_file(str(f), capability_token="forged")
    assert f.read_text(encoding="utf-8") == "{not json"


@pytest.mark.parametrize("tool,tool_scope", [("aios_model_endpoint_register", "aios.model.endpoint.register"),
                                             ("model_backend_register", "model_backend.register")])
def test_endpoint_registration_needs_a_real_grant(db, tool, tool_scope):
    from aiosh_mcp.model_backend_adapters_data_model import _GLOBAL_MODEL_REGISTRY as reg
    fn = served()[tool].fn
    kwargs = dict(backend_id=f"t03429-{tool}", provider="ollama", model_name="m")
    out = fn(**kwargs, capability_token="forged")
    assert "UNAUTHORIZED" in json.dumps(out)
    assert f"t03429-{tool}" not in {e.backend_id for e in reg.list_endpoints()}
    mint_grant(db, f"reg-{tool}", tools=[tool_scope])
    assert "UNAUTHORIZED" not in json.dumps(fn(**kwargs, capability_token=f"reg-{tool}"))


@pytest.mark.anyio
async def test_model_completion_refuses_a_forged_token_before_any_backend_call(db, monkeypatch):
    from aiosh_mcp import model_backend_adapters_service as svc
    called = []

    async def spy(*a, **k):
        called.append(1)
        raise AssertionError("backend reached")
    monkeypatch.setattr(svc._GLOBAL_MODEL_SERVICE, "complete", spy)
    out = await served()["aios_model_complete"].fn(model_id="m", messages=[{"role": "user", "content": "hi"}],
                                                    capability_token="forged")
    assert out["ok"] is False and "UNAUTHORIZED" in out["error"] and called == []
