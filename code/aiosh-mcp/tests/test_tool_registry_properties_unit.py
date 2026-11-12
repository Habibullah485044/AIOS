"""Unit tests for the tool registry property-test oracles and generators (T-03417).

An oracle that is wrong in the same way as the code would let both pass. These tests pin each oracle to
hand-worked examples taken from the operator doc, and check that the generators are deterministic and
actually reach every rule.
"""

import random

import pytest

import tool_registry_model as M

GOOD = {"canonical": "aios.x.read", "mcp_names": ("aios_x_read",), "title": "Read x", "category": "fs.read",
        "effect": "read_only", "irreversible": False, "scope_kind": "path", "open_world": False,
        "requires_grant": False, "idempotent": False}


# ---- P1 oracle: one hand-worked case per doc rule -----------------------------------------------------------

@pytest.mark.parametrize("change,valid", [
    ({}, True),
    ({"effect": "read_only", "idempotent": True}, False),                                       # rule 1
    ({"effect": "additive", "irreversible": True, "requires_grant": False}, False),             # rule 2
    ({"effect": "read_only", "irreversible": True, "requires_grant": True}, False),             # rules 1 and 2
    ({"scope_kind": "network", "open_world": False}, False),                                    # rule 3
    ({"category": "pentest", "effect": "additive", "irreversible": True, "requires_grant": True,
      "scope_kind": "none"}, False),                                                            # rule 4
    ({"category": "pentest", "effect": "additive", "irreversible": True, "requires_grant": True,
      "scope_kind": "path"}, True),                                                             # rule 4, offline tool
    ({"category": "system", "effect": "additive"}, False),                                      # rule 5
    ({"category": "network", "scope_kind": "path"}, False),                                     # rule 6
    ({"canonical": "shell.exec", "effect": "additive", "category": "process"}, False),         # rule 7
    ({"canonical": "pentest", "category": "admin", "effect": "additive"}, False),               # rule 7, bare name
    ({"canonical": "Aios.x"}, False), ({"canonical": "x" * 65}, False), ({"canonical": "a..b"}, False),
    ({"mcp_names": ("a b",)}, False), ({"mcp_names": ("a",) * 9}, False), ({"mcp_names": ["a"]}, False),
    ({"title": ""}, False), ({"title": "t" * 65}, False), ({"title": "a‮b"}, False),
    ({"irreversible": 0}, False),
])
def test_entry_oracle_matches_doc_examples(change, valid):
    assert M.entry_should_be_valid({**GOOD, **change}) is valid


# ---- P2 oracle -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("names,collide", [
    ([("aios.fs.read", ("aios_fs_read",))], False),                    # alias folds onto its own canonical
    ([("aios.a", ("x_y", "x-y"))], True),                              # two aliases of one entry
    ([("aios.a", ()), ("aios.b", ("AIOS-A",))], True),                # alias of another entry, case + separator
    ([("aios.a", ()), ("aios.b", ())], False),
])
def test_collision_oracle(names, collide):
    assert M.catalog_should_collide(names) is collide


def test_fold_examples():
    assert M.fold("AIOS_Fs-read") == M.fold("aios.fs.read") == M.fold("ａｉｏｓ.fs.read") == "aios.fs.read"
    assert M.fold("a__b") == "a.b"


# ---- P3 / P4 / P5 oracles -------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,floor", [("pentest.nmap", (True, True)), ("fs.write", (True, True)),
                                        ("process.kill", (False, True)), ("PENTEST.x", (False, True)),
                                        ("shell", (False, True)), ("process", (False, True)),
                                        ("aios.backup.create", (False, True)), ("session.create.x", (False, True)),
                                        ("system.reboot", (True, True)), ("aios.x", (False, False)),
                                        (None, (False, False))])
def test_legacy_floor_examples(name, floor):
    assert M.legacy_floor(name) == floor


def test_caution_defaults_follow_mcp():
    from mcp.types import ToolAnnotations
    assert M.caution(None) == (False, True, False, True)
    assert M.caution(ToolAnnotations()) == (False, True, False, True)
    assert M.caution(ToolAnnotations(readOnlyHint=True, destructiveHint=True)) == (True, None, None, True)


@pytest.mark.parametrize("raw,vote", [(None, None), ("", None), ("  ", None), ("strict", "strict"),
                                      ("SHADOW ", "shadow"), ("ｓｔｒｉｃｔ", "strict"), ("strct", "strict"),
                                      (1, "strict")])
def test_mode_vote_examples(raw, vote):
    assert M.mode_vote(raw) == vote


def test_expected_config_examples():
    base = {"arg_mode": None, "env_mode": None, "file": None, "path_kind": "none",
            "env_nums": {"report_max_lines": None, "unregistered_samples": None}}
    assert M.expected_config(base) == {"mode": "shadow", "report_max_lines": 32, "unregistered_samples": 50}
    assert M.expected_config({**base, "path_kind": "missing"})["mode"] == "strict"
    assert M.expected_config({**base, "path_kind": "env", "file": b'{"mode": "shadow"}', "env_mode": "strict"})[
        "mode"] == "strict"
    assert M.expected_config({**base, "path_kind": "env", "file": b'{"report_max_lines": 9}',
                              "env_nums": {"report_max_lines": " 12 ", "unregistered_samples": "999"}}) == {
        "mode": "shadow", "report_max_lines": 12, "unregistered_samples": 200}
    assert M.expected_config({**base, "path_kind": "env", "file": b'{"catalog": []}'})["mode"] == "strict"


# ---- generators: deterministic and reaching every rule ----------------------------------------------------------

def test_generators_are_deterministic():
    a, b = random.Random(42), random.Random(42)
    assert [M.gen_kwargs(a) for _ in range(50)] == [M.gen_kwargs(b) for _ in range(50)]


RULES = {
    1: lambda kw: not (kw["effect"] == "read_only" and (kw["irreversible"] or kw["idempotent"])),
    2: lambda kw: not kw["irreversible"] or (kw["requires_grant"] and kw["effect"] != "read_only"),
    3: lambda kw: kw["scope_kind"] != "network" or kw["open_world"],
    4: lambda kw: kw["category"] != "pentest" or (kw["irreversible"] and kw["scope_kind"] != "none"),
    5: lambda kw: kw["category"] not in ("fs.write", "system") or kw["irreversible"],
    6: lambda kw: kw["category"] != "network" or kw["scope_kind"] == "network",
    7: lambda kw: not M.irreversible_by_name(kw["canonical"]) or (kw["irreversible"] and kw["requires_grant"]),
}


def _well_typed(kw):
    return (type(kw["canonical"]) is str and M.CANONICAL.fullmatch(kw["canonical"]) and len(kw["canonical"]) <= 64
            and type(kw["mcp_names"]) is tuple and len(kw["mcp_names"]) <= 8
            and all(type(a) is str and 1 <= len(a) <= 64 and M.MCP_NAME.fullmatch(a) for a in kw["mcp_names"])
            and type(kw["title"]) is str and 1 <= len(kw["title"]) <= 64 and kw["title"].isprintable()
            and all(type(kw[k]) is bool for k in ("irreversible", "open_world", "requires_grant", "idempotent")))


def test_generator_breaks_every_rule_alone():
    """T-03419: each rule must be the *only* broken rule in some case, or deleting it could pass P1 unnoticed."""
    for seed in M.seeds():
        rng = random.Random(seed)
        alone = set()
        for _ in range(M.n_cases()):
            kw = M.gen_kwargs(rng)
            if not _well_typed(kw):
                continue
            broken = [r for r, ok in RULES.items() if not ok(kw)]
            if len(broken) == 1:
                alone.add(broken[0])
        assert alone == set(RULES), f"seed={seed}: rules never broken alone: {sorted(set(RULES) - alone)}"


def test_valid_generator_is_always_valid():
    rng = random.Random(7)
    assert all(M.entry_should_be_valid(M.gen_valid_kwargs(rng)) for _ in range(2000))


@pytest.mark.parametrize("var,value", [("AIOSH_TOOLREG_FUZZ_SEEDS", ","), ("AIOSH_TOOLREG_FUZZ_SEEDS", ""),
                                       ("AIOSH_TOOLREG_FUZZ_N", "0")])
def test_empty_knobs_are_errors_not_skips(var, value, monkeypatch):
    monkeypatch.setenv(var, value)
    with pytest.raises(ValueError):
        M.seeds() if "SEEDS" in var else M.n_cases()
