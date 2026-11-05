"""Hardening tests for the agent-loop generated reference (T-03350)."""

import json

import pytest

from aiosh_mcp import agent_loop_doc as doc


@pytest.fixture
def broken_cli(monkeypatch):
    def boom():
        raise ImportError("parser moved in a refactor: /secret/path/x.py")
    monkeypatch.setitem(doc._BUILDERS, "cli", boom)
    doc._built.cache_clear()
    yield
    doc._built.cache_clear()


def test_one_broken_section_degrades_not_fails(broken_cli):
    r = doc.reference()
    assert r["_unavailable"] == {"cli": "ImportError"}
    assert set(r) == set(doc.SECTIONS) - {"cli"} | {"_unavailable"}
    assert "/secret/path" not in json.dumps(r)            # only the exception type is reported


def test_failures_are_not_cached(broken_cli, monkeypatch):
    with pytest.raises(ImportError):
        doc.reference("cli")
    monkeypatch.setitem(doc._BUILDERS, "cli", lambda: [{"subcommand": "run", "flags": []}])
    assert doc.reference("cli") == {"cli": [{"subcommand": "run", "flags": []}]}


def test_reference_is_json_serialisable_and_bounded():
    doc._built.cache_clear()
    text = json.dumps(doc.reference())
    assert len(text) < 256 * 1024
