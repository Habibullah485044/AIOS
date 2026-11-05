"""Scaffold tests for the Agent Loop Hardening MCP/API surface (T-03295)."""

from mcp.server.fastmcp import FastMCP

from aiosh_mcp.agent_loop_mcp import (
    READ_ONLY,
    TOOL_ANNOTATIONS,
    LoopIdArg,
    TokensArg,
)


def test_annotation_table_covers_nine_tools():
    assert len(TOOL_ANNOTATIONS) == 9  # +aios_agent_loop_config (T-03308), +aios_agent_loop_metrics (T-03338)
    read_only = {n for n, a in TOOL_ANNOTATIONS.items() if a.readOnlyHint}
    assert read_only == {"aios_agent_loop_snapshot", "aios_agent_loop_list", "aios_agent_loop_history",
                         "aios_agent_loop_config", "aios_agent_loop_metrics"}
    destructive = {n for n, a in TOOL_ANNOTATIONS.items() if a.destructiveHint}
    assert destructive == {"aios_agent_loop_abort", "aios_agent_loop_complete"}


def test_annotated_constraints_reach_input_schema():
    """Confirms T-03293 assumption A2 on the installed SDK: Field constraints are published."""
    app = FastMCP("scaffold-probe")

    @app.tool(annotations=READ_ONLY)
    def probe(loop_id: LoopIdArg, tokens: TokensArg = 0) -> dict:
        return {}

    tool = app._tool_manager.get_tool("probe")
    props = tool.parameters["properties"]
    assert props["loop_id"]["pattern"] == r"^[a-zA-Z0-9_\-]{8,64}$"
    assert (props["tokens"]["minimum"], props["tokens"]["maximum"]) == (0, 1_000_000)
    assert tool.annotations.readOnlyHint is True
