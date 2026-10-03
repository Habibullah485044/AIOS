# Hardening Evidence: Threat Model Maintenance Configuration (T-02748)

## Overview
This document provides evidence and validation of the hardening measures applied to the Threat Model Configuration subsystem (`ThreatModelConfig`), adhering to ADR-0035 A F-2 failure semantics, resource limits, and bounds enforcement.

## 1. Hardening Measures Implemented

### 1.1 Atomic Persistence & Zero-Leak Temp File Cleanup
- **Collision-Resistant Unique Temp Paths**: Atomic file writes use PID and nanosecond epoch timestamps (`tmp.<pid>.<nanos>`) to prevent race conditions during concurrent config updates.
- **Guaranteed Cleanup on Error**: If file write or file rename encounters any I/O failure, the temporary file is explicitly unlinked (`std::fs::remove_file`) before returning an error envelope, ensuring no temporary files leak into the filesystem.
- **Pre-Validation Guarantee**: Invariant verification is executed *prior* to touching disk. If configuration parameters violate bounds, `save_to_path` terminates immediately without touching storage or leaving dirty state.

### 1.2 Bounded Sizes and Denial of Service Mitigation
- **Config File Size Limit**: Strict 64 KiB cap (`MAX_CONFIG_FILE_BYTES = 65_536`). Files exceeding this size are rejected with `THREATCONF_ERR_BOUNDS` to eliminate memory exhaustion / JSON decompression attacks.
- **Store File Size Limit**: Runtime bound clamped between 4 KiB and 16 MiB (`MIN_MAX_STORE_FILE_BYTES..=MAX_MAX_STORE_FILE_BYTES`).
- **Threat Capacity Bounds**: Hard cap clamped between 1 and 4096 threats (`MIN_MAX_THREAT_CAPACITY..=MAX_MAX_THREAT_CAPACITY`).
- **Path Length & Character Restrictions**: Store paths and config paths are restricted to $\le 1024$ bytes and forbidden from containing control characters or path traversal substrings (`..`).

### 1.3 Symlink Rejection (TOCTOU / Privilege Escalation Prevention)
- `load_from_path` interrogates `std::fs::symlink_metadata(p)`.
- If the target path is a symbolic link, load is immediately aborted with `THREATCONF_ERR_VALIDATION`, preventing arbitrary file disclosure or symlink redirection attacks.

### 1.4 Audit Envelope & Fail-Open Logging
- All MCP interactions invoking `aios.threat.config` are piped through `dispatch::recorded_call`.
- Every failure mode (bad argument, invalid JSON, bounds violations, traversal detection) outputs an explicit, typed error (`ERR_THREAT_*` / `THREATCONF_ERR_*`) and generates an immutable row in SQLite `audit_ring` (ADR-0035 A F-2 compliance).

## 2. Test Verification

```text
running 6 tests
test test_threat_model_config_defaults ... ok
test test_threat_model_config_bounds_validation ... ok
test test_threat_model_config_env_overrides ... ok
test test_threat_model_config_hardening ... ok
test test_threat_model_config_rejections ... ok
test test_threat_model_config_save_and_load ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
```

All hardening tests pass with zero warnings, zero leaks, and verified atomicity.
