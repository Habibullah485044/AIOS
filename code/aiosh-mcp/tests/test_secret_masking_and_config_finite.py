"""Regression tests for security audit findings #6 and #7 (2026-11-05)."""

import json

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import agent_loop_config as alc
from aiosh_mcp.agent_loop_data_model import LoopConfig, mask_secrets
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService

SECRETS = {
    "github_fine_grained": "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    "github_oauth": "gho_abcdefghijklmnopqrstuvwxyz0123",
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "slack": "xoxb-1234567890-abcdefghijkl",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
}


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_token_shapes_masked(name):
    out = mask_secrets(f"prefix {SECRETS[name]} suffix")
    assert SECRETS[name] not in out and "[REDACTED_SECRET]" in out
    assert out.startswith("prefix ")


@pytest.mark.parametrize("text,leak", [
    ("{'password': 'hunter2'}", "hunter2"),
    ('{"api_key": "abc123def"}', "abc123def"),
    ("db?user=x&passwd=s3cret&x=1", "s3cret"),
    ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("{'client_secret': 'cs-998877'}", "cs-998877"),
])
def test_credential_named_values_masked(text, leak):
    assert leak not in mask_secrets(text)


def test_non_secret_fields_untouched():
    text = "{'path': 'README.md', 'tokens_consumed': 80, 'max_total_tokens': 32768}"
    assert mask_secrets(text) == text


def test_secrets_never_reach_the_audit_ring(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_mask", tools=["aios.agent_loop.start", "aios.fs.read"])
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-mask-01"), capability_token="gr_mask")
    svc.advance_turn("loop-mask-01", "x", tool_name="aios.fs.read",
                     tool_args={"password": "hunter2", "aws": SECRETS["aws_access_key"]},
                     capability_token="gr_mask")
    import sqlite3
    raw = "\n".join(r[0] for r in sqlite3.connect(db).execute("SELECT args_json FROM audit_ring"))
    assert "hunter2" not in raw and SECRETS["aws_access_key"] not in raw
    snap = json.dumps(svc.get_snapshot("loop-mask-01").to_dict())
    assert "hunter2" not in snap


@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "-inf", float("nan"), float("inf")])
def test_non_finite_config_rejected(monkeypatch, value):
    r = alc.resolve(overrides={"mcp_call_timeout_s": value, "registry_capacity": value})
    assert r["config"] == alc.default_config()
    assert all("finite" in e for e in r["errors"])
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", str(value))
    r = alc.resolve()  # must not raise (AGENTLOOPCONF-INV1)
    assert r["config"]["registry_capacity"] == 256
    assert r["source"]["registry_capacity"] == "env_invalid"


def test_nan_literal_in_config_file_rejected(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text('{"mcp_call_timeout_s": NaN}', encoding="utf-8")
    r = alc.resolve(arg_config=str(p))
    assert r["source"]["_file"] == "config_invalid"
    assert r["config"]["mcp_call_timeout_s"] == 15.0
