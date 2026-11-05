"""Scaffold tests for the tool registry core service (T-03375; spec T-03374)."""

import dataclasses

import pytest

from aiosh_mcp import tool_registry_service as svc


def test_constants_match_spec():
    assert svc.MODES == ("shadow", "strict") and svc.DEFAULT_MODE == "shadow"
    assert svc.DISAGREEMENT_KINDS == ("unregistered", "grant", "irreversible", "scope")
    assert svc.ENV_MODE == "AIOSH_TOOL_REGISTRY_MODE" and svc.TOOLSVC_ERR_MODE == "TOOLSVC_ERR_MODE"


def test_decision_is_frozen_with_spec_fields():
    assert [f.name for f in dataclasses.fields(svc.ToolDecision)] == [
        "canonical", "registered", "requires_grant", "irreversible", "scope_kinds", "disagreements", "mode"]
    assert svc.ToolDecision.__dataclass_params__.frozen


def test_stubs_fail_loudly():
    for call in (svc.ToolRegistryService, svc.service):
        with pytest.raises(NotImplementedError, match="T-03376"):
            call()


def test_error_carries_code():
    err = svc.ToolServiceError(svc.TOOLSVC_ERR_MODE, "bad")
    assert err.code == "TOOLSVC_ERR_MODE" and isinstance(err, ValueError)
