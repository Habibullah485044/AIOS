# T-03415 Evidence: Tool Registry & Taxonomy — automated tests Scaffold

- Date: 2026-11-06
- Spec: [T-03414-spec.md](T-03414-spec.md)
- New `code/aiosh-mcp/tests/tool_registry_model.py`:
  - working env knobs `seeds()` (`AIOSH_TOOLREG_FUZZ_SEEDS`, default `1,2,3`) and `n_cases()` (`AIOSH_TOOLREG_FUZZ_N`, default 300);
  - the spec's oracle and generator signatures (`gen_kwargs`, `entry_should_be_valid`, `gen_name_set`, `catalog_should_collide`,
    `legacy_floor`, `caution`, `gen_config_sources`, `expected_config`), stubbed with `NotImplementedError("T-03416: ...")`.
- New `tests/test_tool_registry_properties_scaffold.py` (3): env defaults and overrides, every oracle declared, stubs fail loudly.
- Stdlib only, no new dependency. CI suite #35 picks it up through `-k tool_registry`.
```
$ python -m pytest tests/test_tool_registry_properties_scaffold.py -q
3 passed in 1.91s
```
