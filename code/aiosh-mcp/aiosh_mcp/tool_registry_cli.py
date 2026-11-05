"""Tool Registry & Taxonomy operator CLI (T-03385 scaffold).

Spec: docs/tasks/evidence/T-03384-spec.md. Read-only inspection of the trusted tool catalog:
``list``, ``get``, ``decide``, ``export``, ``check`` (TOOLCLI-INV1..TOOLCLI-INV4).

    aiosh-tool-registry get aios_pentest_nmap --json
    python -m aiosh_mcp.tool_registry_cli check aios.fs.read pentest.nmap
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from aiosh_mcp.tool_registry_data_model import Category

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

TOOLCLI_ERR_USAGE = "TOOLCLI_ERR_USAGE"
TOOLCLI_ERR_IO = "TOOLCLI_ERR_IO"
TOOLCLI_ERR_UNAVAILABLE = "TOOLCLI_ERR_UNAVAILABLE"

SUBCOMMANDS = ("list", "get", "decide", "export", "check")
MAX_NAMES = 256
MAX_NAME_CHARS = 256
MAX_SHOWN_CHARS = 80


@dataclass
class CliResult:
    """Standard CLI result (spec §1): exit code plus the --json payload."""

    exit_code: int
    subcommand: str
    data: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.exit_code == EXIT_SUCCESS, "subcommand": self.subcommand, "data": self.data,
                "error_code": self.error_code, "error": self.error}


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """argparse that raises instead of printing and exiting (TOOLCLI-INV2)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message)


def _build_parser() -> _Parser:
    parser = _Parser(prog="aiosh-tool-registry", add_help=False)
    sub = parser.add_subparsers(dest="subcommand", parser_class=_Parser)
    ls = sub.add_parser("list", add_help=False)
    ls.add_argument("--category", choices=[c.value for c in Category])
    ls.add_argument("--json", action="store_true")
    gt = sub.add_parser("get", add_help=False)
    gt.add_argument("name")
    gt.add_argument("--json", action="store_true")
    dc = sub.add_parser("decide", add_help=False)
    dc.add_argument("name")
    dc.add_argument("--target")
    dc.add_argument("--require-grant", action="store_true")
    dc.add_argument("--mode", choices=["shadow", "strict"], default="shadow")
    dc.add_argument("--json", action="store_true")
    ex = sub.add_parser("export", add_help=False)
    ex.add_argument("--out")
    ex.add_argument("--json", action="store_true")
    ck = sub.add_parser("check", add_help=False)
    ck.add_argument("names", nargs="+")
    ck.add_argument("--json", action="store_true")
    return parser


def dispatch_cli(argv: List[str]) -> CliResult:
    """Pure CLI core: argv in, CliResult out (spec §1)."""
    raise NotImplementedError("T-03386: dispatch_cli")


def main(argv: Optional[List[str]] = None) -> int:
    """Console entry point; returns the process exit code."""
    raise NotImplementedError("T-03386: main")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
