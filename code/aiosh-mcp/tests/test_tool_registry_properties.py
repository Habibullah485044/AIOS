"""Seeded property tests for the tool registry (T-03416; spec T-03414 §2).

Each property runs ``tool_registry_model.n_cases()`` generated cases per seed in ``seeds()``. A failure names the
seed, property and case index and shows the input, so ``random.Random(seed)`` replays it exactly (AUTOTEST-INV1).
"""

import json
import os
import random

import pytest

import tool_registry_model as M
from aiosh_mcp import tool_registry_api as api
from aiosh_mcp import tool_registry_config as conf
from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.tool_registry_data_model import Category, Effect, ScopeKind, ToolCatalog, ToolEntry, ToolRegistryError
from aiosh_mcp.tool_registry_service import ToolRegistryService

#: The entry fields of the operator doc §2 table.
DOC_FIELDS = {"canonical", "mcp_names", "title", "category", "effect", "irreversible", "scope_kind", "open_world",
              "requires_grant", "idempotent"}
SEEDS = M.seeds()


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """No host config can influence a property (T-03419 hygiene)."""
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path / "home"))
    monkeypatch.delenv(conf.ENV_CONFIG, raising=False)
    monkeypatch.delenv(conf.ENV_MODE, raising=False)
    conf.reset_process_config()
N = M.n_cases()


def build(kw):
    args = dict(kw)
    for key, enum in (("category", Category), ("effect", Effect), ("scope_kind", ScopeKind)):
        args[key] = enum(args[key])
    return ToolEntry(**args)


@pytest.mark.parametrize("seed", SEEDS)
def test_p1_entry_validity_matches_the_doc(seed):
    rng = random.Random(seed)
    accepted = 0
    for case in range(N):
        kw = M.gen_kwargs(rng)
        expected = M.entry_should_be_valid(kw)
        try:
            build(kw)
            actual = True
        except ToolRegistryError:
            actual = False
        assert actual == expected, f"seed={seed} property=P1 case={case} expected_valid={expected} input={kw!r}"
        accepted += actual
    assert N * 0.2 <= accepted <= N * 0.8 or N < 50, f"seed={seed}: generator too one-sided ({accepted}/{N} valid)"


@pytest.mark.parametrize("seed", SEEDS)
def test_p2_collisions_match_the_fold_rule(seed):
    rng = random.Random(seed)
    collided = 0
    for case in range(N):
        names = M.gen_name_set(rng)
        entries = [ToolEntry(canonical=c, mcp_names=a,
                             title="t", category=Category.SERVICE, effect=Effect.ADDITIVE, irreversible=False,
                             scope_kind=ScopeKind.NONE, open_world=False, requires_grant=True)
                   for c, a in names if M.CANONICAL.fullmatch(c)]
        names = [(e.canonical, e.mcp_names) for e in entries]
        expected = M.catalog_should_collide(names)
        try:
            ToolCatalog(entries)
            actual = False
        except ToolRegistryError as exc:
            assert exc.code == "TOOLREG_ERR_DUPLICATE", f"seed={seed} P2 case={case} {exc}"
            actual = True
        assert actual == expected, f"seed={seed} property=P2 case={case} expected_collision={expected} input={names!r}"
        collided += actual
    assert 0 < collided < N, f"seed={seed}: generator too one-sided ({collided}/{N} collisions)"


@pytest.mark.parametrize("seed", SEEDS)
def test_p3_profiles_and_decisions_are_never_weaker(seed):
    rng = random.Random(seed)
    catalog = reg.default_catalog()
    svc = ToolRegistryService(catalog, mode="shadow")
    registered = list(catalog.names())
    for case in range(N):
        name = M.gen_query_name(rng, registered)
        grant, irrev = M.legacy_floor(name)
        p = catalog.profile(name)
        caller_grant, c3 = rng.random() < 0.3, rng.random() < 0.3
        d = svc.decide(name, "t", classification={"c_flags": {"c3": c3}}, require_grant=caller_grant)
        where = f"seed={seed} property=P3 case={case} name={name!r} require_grant={caller_grant} c3={c3}"
        assert d.requires_grant or not caller_grant, where                # the caller's flag is never dropped
        assert d.irreversible or not c3, where                            # classifier C-3 is never dropped
        assert p.requires_grant >= grant and p.irreversible >= irrev, where
        assert d.requires_grant >= grant and d.irreversible >= irrev, where
        assert d.requires_grant >= p.requires_grant and d.irreversible >= p.irreversible, where   # stricter of both
        if catalog.resolve(name) is None:
            assert p.requires_grant and p.irreversible, where            # unknown = fail closed


@pytest.mark.parametrize("seed", SEEDS)
def test_p4_annotation_merge_never_relaxes(seed):
    rng = random.Random(seed)
    for case in range(N):
        existing, derived, allow = M.gen_annotation(rng), None, rng.random() < 0.5
        while derived is None:                                         # the catalog always derives one
            derived = M.gen_annotation(rng)
        merged = api.more_cautious(existing, derived, allow)
        old, new, cat = M.caution(existing), M.caution(merged), M.caution(derived)
        where = f"seed={seed} property=P4 case={case} existing={existing!r} derived={derived!r} allow={allow}"
        if new[0]:
            assert allow and derived.readOnlyHint is True and not M.contrary_claim(existing), where
        else:
            # doc §6d: destructive and open world stay true if *either* side says so; idempotent only if both do
            if not old[0]:
                assert new[1] or not old[1], where
            if not cat[0]:
                assert new[1] or not cat[1], where
            assert not new[2] or (bool(old[2]) and bool(cat[2])), where
        assert new[3] or not old[3], where                                # open world sticky, both sides
        assert new[3] or not cat[3], where


@pytest.mark.parametrize("seed", SEEDS)
def test_p5_configuration_follows_the_doc(seed, tmp_path, monkeypatch):
    rng = random.Random(seed)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("AIOSH_HOME", str(home))
    monkeypatch.chdir(tmp_path)
    default_file = home / "tool_registry_config.json"
    env_file = tmp_path / "c.json"
    for case in range(min(N, 200)):
        src = M.gen_config_sources(rng)
        for var in (conf.ENV_CONFIG, conf.ENV_MODE, *M.ENV_NUM.values()):
            monkeypatch.delenv(var, raising=False)
        for f in (default_file, env_file):
            if f.exists():
                f.unlink()
        kind = src["path_kind"]
        if kind == "env":
            monkeypatch.setenv(conf.ENV_CONFIG, str(env_file))
            if src["file"] is not None:
                env_file.write_bytes(src["file"])
        elif kind == "default" and src["file"] is not None:
            default_file.write_bytes(src["file"])
        elif kind == "missing":
            monkeypatch.setenv(conf.ENV_CONFIG, str(tmp_path / "absent.json"))
        elif kind == "bad":
            monkeypatch.setenv(conf.ENV_CONFIG, rng.choice(["CON", "../x.json", "\\??\\C:\\x.json"]))
        if src["env_mode"] is not None:
            monkeypatch.setenv(conf.ENV_MODE, src["env_mode"])
        for key, value in src["env_nums"].items():
            if value is not None:
                monkeypatch.setenv(M.ENV_NUM[key], value)
        resolved = conf.resolve(arg_mode=src["arg_mode"])
        assert resolved["config"] == M.expected_config(src), f"seed={seed} property=P5 case={case} input={src!r}"
        if kind == "bad":                                              # refused before any open (T-03419)
            assert any("path hygiene" in e for e in resolved["errors"]), f"seed={seed} P5 case={case}"


@pytest.mark.parametrize("seed", SEEDS)
def test_p6_export_round_trips(seed):
    rng = random.Random(seed)
    sizes = []
    for case in range(max(1, N // 10)):
        kws = [M.gen_valid_kwargs(rng) for _ in range(rng.randint(1, 40))]
        entries, seen = [], set()
        for kw in kws:
            keys = {M.fold(n) for n in (kw["canonical"], *kw["mcp_names"])}
            if not keys & seen and not M.catalog_should_collide([(kw["canonical"], kw["mcp_names"])]):                                            # keep one valid catalog
                seen |= keys
                entries.append(build(kw))
        sizes.append(len(entries))
        exported = ToolCatalog(entries).export_json()
        doc = json.loads(exported)
        assert doc["schema_version"] == 1
        for e in doc["entries"]:
            assert set(e) == DOC_FIELDS, f"seed={seed} property=P6 case={case} fields={sorted(e)}"
        rebuilt = ToolCatalog(build({**e, "mcp_names": tuple(e["mcp_names"])}) for e in doc["entries"])
        where = f"seed={seed} property=P6 case={case}"
        assert list(rebuilt.entries()) == sorted(entries, key=lambda e: e.canonical), where   # every field survives
        assert rebuilt.export_json() == exported, where
    assert max(sizes) >= 10 and sum(sizes) / len(sizes) >= 3, f"seed={seed}: catalogs too small {sizes}"
