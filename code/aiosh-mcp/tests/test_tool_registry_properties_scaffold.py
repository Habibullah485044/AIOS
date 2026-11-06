"""Scaffold tests for the tool registry property tests (T-03415; spec T-03414)."""

import pytest

import tool_registry_model as M


def test_env_knobs(monkeypatch):
    monkeypatch.delenv("AIOSH_TOOLREG_FUZZ_SEEDS", raising=False)
    monkeypatch.delenv("AIOSH_TOOLREG_FUZZ_N", raising=False)
    assert M.seeds() == [1, 2, 3] and M.n_cases() == 300
    monkeypatch.setenv("AIOSH_TOOLREG_FUZZ_SEEDS", "7, 9")
    monkeypatch.setenv("AIOSH_TOOLREG_FUZZ_N", "10")
    assert M.seeds() == [7, 9] and M.n_cases() == 10


def test_oracles_are_declared():
    for name in ("gen_kwargs", "entry_should_be_valid", "gen_name_set", "catalog_should_collide", "legacy_floor",
                 "caution", "gen_config_sources", "expected_config"):
        assert callable(getattr(M, name)), name


def test_stubs_fail_loudly():
    with pytest.raises(NotImplementedError, match="T-03416"):
        M.legacy_floor("x")
