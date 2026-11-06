"""Regression tests for the tool registry API surface security review (T-03399).

Each test fails on the pre-T-03399 code (see docs/tasks/evidence/T-03399-security.md).
"""

import pytest
from mcp.types import ToolAnnotations

from aiosh_mcp import tool_registry_api as api
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.server import mcp as server_app

TOOLS = {t.name: t for t in server_app._tool_manager.list_tools()}
GRANT_OR_PATH = ("grant_id", "caller_grant_id", "capability_token", "token", "path", "anchors_path", "config_path")


# F1: tools that can redeem a caller-supplied grant must not look auto-approvable.
@pytest.mark.parametrize("name", ["aios_restraint_prove", "aios_restraint_verify"])
def test_grant_redeeming_tools_are_not_read_only(name):
    assert TOOLS[name].annotations.readOnlyHint is False


# F1 + F4, generalised: no read-only-advertised tool takes a grant, token or path argument.
def test_no_read_only_tool_takes_grants_tokens_or_paths():
    offenders = [n for n, t in TOOLS.items() if t.annotations.readOnlyHint
                 and set(t.parameters.get("properties", {})) & set(GRANT_OR_PATH)]
    assert offenders == []


# F4: the file-oracle tools are not advertised read-only.
@pytest.mark.parametrize("name", ["aios_mcp_recovery_check", "aios_model_validate_config"])
def test_path_taking_tools_are_not_read_only(name):
    assert TOOLS[name].annotations.readOnlyHint is False


def test_parameter_rule():
    assert api.unsafe_for_read_only_hint({"properties": {"caller_grant_id": {}}})
    assert api.unsafe_for_read_only_hint({"properties": {"anchors_path": {}}})
    assert not api.unsafe_for_read_only_hint({"properties": {"limit": {}, "query": {}}})


# F2: an annotation that claims destructive/non-idempotent effects is never turned into read-only.
@pytest.mark.parametrize("existing", [ToolAnnotations(destructiveHint=True), ToolAnnotations(idempotentHint=False)])
def test_effect_claims_block_read_only(existing):
    merged = api.more_cautious(existing, ToolAnnotations(readOnlyHint=True, openWorldHint=False), True)
    assert merged.readOnlyHint is not True


# F3 / S1: decide cannot pollute or probe the server's dispatch telemetry.
def test_decide_does_not_touch_dispatch_telemetry():
    before = trs.service().stats()
    for i in range(60):
        TOOLS[api.DECIDE_TOOL].fn(name=f"aios.junk.n{i}")
    assert trs.service().stats() == before
