"""Security tests for the agent-loop generated reference (T-03349)."""

import json
import os
import re
import time

from aiosh_mcp import agent_loop_doc as doc
from aiosh_mcp.agent_loop_service import _GLOBAL_AGENT_LOOP_SERVICE


def test_repeated_calls_are_cheap(monkeypatch):
    doc.reference()                                   # warm the per-process cache
    t = time.perf_counter()
    for _ in range(50):
        doc.reference()
    assert (time.perf_counter() - t) / 50 < 0.01       # ~0.12 s per warm call before caching, ~0.6 ms after


def test_callers_cannot_poison_the_cache():
    r = doc.reference("errors")
    r["errors"][0]["meaning"] = "ATTACKER TEXT"
    r["errors"].clear()
    fresh = doc.reference("errors")["errors"]
    assert len(fresh) == len(doc.ERROR_MEANINGS) and "ATTACKER TEXT" not in json.dumps(fresh)


def test_reference_has_no_side_effects_or_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path / "home-sentinel"))
    before = len(_GLOBAL_AGENT_LOOP_SERVICE._loops)
    text = json.dumps(doc.reference())
    assert len(_GLOBAL_AGENT_LOOP_SERVICE._loops) == before
    assert not (tmp_path / "home-sentinel").exists()                  # no audit DB created
    assert "home-sentinel" not in text and not re.search(r"gr_[A-Za-z0-9_]{6,}", text)
    assert os.environ.get("USERPROFILE", "~~none~~") not in text
