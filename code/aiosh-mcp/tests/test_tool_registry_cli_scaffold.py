"""Scaffold tests for the tool registry CLI (T-03385; spec T-03384)."""

import argparse

import pytest

from aiosh_mcp import tool_registry_cli as cli


def test_constants_match_spec():
    assert (cli.EXIT_SUCCESS, cli.EXIT_FAILURE, cli.EXIT_USAGE) == (0, 1, 2)
    assert cli.SUBCOMMANDS == ("list", "get", "decide", "export", "check")
    codes = sorted(v for k, v in vars(cli).items() if k.startswith("TOOLCLI_ERR_"))
    assert codes == ["TOOLCLI_ERR_IO", "TOOLCLI_ERR_UNAVAILABLE", "TOOLCLI_ERR_USAGE"]


def test_parser_has_the_spec_subcommands_and_never_exits():
    parser = cli._build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert tuple(sub.choices) == cli.SUBCOMMANDS
    with pytest.raises(cli._UsageError):
        parser.parse_args(["list", "--category", "nope"])          # raises instead of sys.exit (TOOLCLI-INV2)


def test_result_envelope():
    r = cli.CliResult(0, "list", data={"count": 0})
    assert r.to_dict() == {"ok": True, "subcommand": "list", "data": {"count": 0}, "error_code": None, "error": None}


def test_scaffold_stubs_are_implemented():
    """The T-03385 stubs raised NotImplementedError; T-03386 implemented them."""
    assert cli.dispatch_cli(["list"]).exit_code == 0
