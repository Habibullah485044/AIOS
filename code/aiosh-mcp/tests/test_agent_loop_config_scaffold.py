"""Scaffold tests for Agent Loop Hardening configuration (T-03305)."""

from aiosh_mcp import agent_loop_config as alc
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_data_model import MAX_REGISTRY_CAPACITY
from aiosh_mcp.agent_loop_mcp import DEFAULT_STEPS_TAIL, MAX_RESPONSE_BYTES, TOOL_CALL_TIMEOUT_S
from aiosh_mcp.agent_loop_gate import BUSY_TIMEOUT_MS


def test_field_table_matches_spec_and_current_constants():
    """Defaults equal today's hard-coded values, so adopting config changes nothing by default."""
    lc = LoopConfig(loop_id="loop-config-scaffold")
    expected = {
        "default_max_iterations": lc.max_iterations,
        "default_max_total_tokens": lc.max_total_tokens,
        "default_timeout_ms_per_step": lc.timeout_ms_per_step,
        "default_total_timeout_ms": lc.total_timeout_ms,
        "default_consecutive_failure_limit": lc.consecutive_failure_limit,
        "registry_capacity": MAX_REGISTRY_CAPACITY,
        "mcp_call_timeout_s": TOOL_CALL_TIMEOUT_S,
        "history_page_bytes": MAX_RESPONSE_BYTES,
        "snapshot_steps_tail": DEFAULT_STEPS_TAIL,
        "db_busy_timeout_ms": BUSY_TIMEOUT_MS,
    }
    assert {k: f.default for k, f in alc.FIELDS.items()} == expected
    for key, f in alc.FIELDS.items():
        assert f.lo <= f.default <= f.hi, key
        assert f.env == "AIOSH_AGENT_LOOP_" + key.removeprefix("default_").upper(), key


def test_loop_config_bounds_agree_with_validate_bounds():
    """Clamp bounds never admit a value LoopConfig.validate_bounds would reject."""
    names = {"default_max_iterations": "max_iterations", "default_max_total_tokens": "max_total_tokens",
             "default_timeout_ms_per_step": "timeout_ms_per_step", "default_total_timeout_ms": "total_timeout_ms",
             "default_consecutive_failure_limit": "consecutive_failure_limit"}
    for key, field in names.items():
        for edge in (alc.FIELDS[key].lo, alc.FIELDS[key].hi):
            LoopConfig(loop_id="loop-config-scaffold", **{field: alc.FIELDS[key].kind(edge)}).validate_bounds()


def test_locked_keys_are_not_tunable():
    assert not set(alc.LOCKED_KEYS) & set(alc.FIELDS)
    assert {"require_grant", "audit_mutations", "max_args_bytes"} <= set(alc.LOCKED_KEYS)


def test_stubs_fail_loudly():
    import pytest
    for call in (alc.default_config, lambda: alc.hygiene_ok("x"), lambda: alc.validate({}),
                 alc.resolve, lambda: alc.loop_config_for("loop-config-scaffold")):
        with pytest.raises(NotImplementedError):
            call()
