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


def test_scaffold_stubs_are_implemented():
    """The T-03375 stubs raised NotImplementedError; T-03376 implemented them."""
    assert svc.ToolRegistryService(mode="shadow").mode == "shadow"
    assert isinstance(svc.service(), svc.ToolRegistryService)


def test_error_carries_code():
    err = svc.ToolServiceError(svc.TOOLSVC_ERR_MODE, "bad")
    assert err.code == "TOOLSVC_ERR_MODE" and isinstance(err, ValueError)
