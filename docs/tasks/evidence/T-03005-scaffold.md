# Evidence: T-03005 Incident Response Runbooks configuration Scaffold

## Summary
- **Task ID**: T-03005
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Area**: Incident Response Runbooks / configuration
- **Type**: Scaffold

## Implemented Scaffolding
1. **Rust Core Substrate**:
   - Created `code/aiosh-rust/aiosh-core/src/runbook_config.rs`:
     - Defined configuration structures: `RunbookConfig`, `RunbookEntryConfig`, `RunbookStepConfig`, `ParameterConfig`.
     - Defined configuration resolution source enumeration: `RunbookConfigSource` (`BuiltinDefault`, `SystemDefault`, `WorkspaceExplicit`, `CliOverride`).
     - Defined limits and constants: `MAX_RUNBOOK_CONFIG_FILE_BYTES` (64 KiB), `MAX_RUNBOOKS_IN_CONFIG` (64), `MAX_STEPS_PER_RUNBOOK_CONFIG` (32).
     - Implemented path validation helper: `validate_runbook_config_path`.
     - Defined resolution function signature: `resolve_runbook_config(...) -> Result<RunbookConfig, RunbookConfigError>` which fails loudly with `unimplemented!("T-03006: Incident Response Runbooks configuration implementation")`.
   - Re-exported module in `code/aiosh-rust/aiosh-core/src/lib.rs` under `pub mod runbook_config;`.
   - Created Rust test harness `code/aiosh-rust/aiosh-core/tests/test_runbook_config_scaffold.rs` verifying constants, path validation, and loud scaffold panics on unimplemented resolution.

2. **Python MCP Substrate**:
   - Created `code/aiosh-mcp/aiosh_mcp/runbook_config.py`:
     - Defined dataclasses and enums matching Rust: `RunbookConfig`, `RunbookEntryConfig`, `RunbookStepConfig`, `ParameterConfig`, `RunbookConfigSource`.
     - Defined limits: `MAX_RUNBOOK_CONFIG_FILE_BYTES`, `MAX_RUNBOOKS_IN_CONFIG`, `MAX_STEPS_PER_RUNBOOK_CONFIG`.
     - Implemented `validate_runbook_config_path`.
     - Defined `resolve_runbook_config(...) -> RunbookConfig` raising `NotImplementedError("T-03006: Incident Response Runbooks configuration implementation")`.
   - Created Python test harness `code/aiosh-mcp/tests/test_runbook_config_scaffold.py` verifying types, path validation, and loud scaffold exceptions.

## Verification Results
- **Rust Scaffold Test**:
  ```
  cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-core --test test_runbook_config_scaffold
  test test_constants_and_default_config ... ok
  test test_validate_config_path ... ok
  test test_resolve_scaffold_panics_unimplemented - should panic ... ok
  test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
  ```
- **Python Scaffold Test**:
  ```
  python -m pytest code/aiosh-mcp/tests/test_runbook_config_scaffold.py -v
  3 passed
  ```
