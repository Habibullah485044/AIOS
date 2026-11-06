"""Scaffold tests for the tool registry API surface (T-03395; spec T-03394)."""

import pytest

from aiosh_mcp import tool_registry_api as api
from aiosh_mcp.tool_registry_data_model import Category


def test_constants_match_spec():
    assert (api.DECIDE_TOOL, api.STATS_TOOL) == ("aios_tool_registry_decide", "aios_tool_registry_stats")
    assert set(api.READ_ONLY_HINT_CATEGORIES) <= {c.value for c in Category}


def test_stubs_fail_loudly():
    for call in (lambda: api.more_cautious(None, None, False), lambda: api.apply_catalog_annotations(None),
                 lambda: api.register_tool_registry_api_tools(None)):
        with pytest.raises(NotImplementedError, match="T-03396"):
            call()
