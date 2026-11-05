"""Scaffold tests for the agent-loop generated reference (T-03345)."""

import re
from pathlib import Path

import pytest

from aiosh_mcp import agent_loop_doc as doc

PKG = Path(__file__).resolve().parents[1] / "aiosh_mcp"


def defined_codes():
    out = set()
    for f in PKG.glob("agent_loop_*.py"):
        out |= set(re.findall(r"^([A-Z]+_ERR_[A-Z_]+)\s*=", f.read_text(encoding="utf-8"), re.M))
    return out


def test_error_meanings_cover_every_code_both_ways():
    assert set(doc.ERROR_MEANINGS) == defined_codes()
    assert all(isinstance(v, str) and v for v in doc.ERROR_MEANINGS.values())


def test_sections_and_stub():
    assert doc.SECTIONS == ("tools", "errors", "config", "cli", "policy")
    with pytest.raises(NotImplementedError):
        doc.reference()
