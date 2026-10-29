# Specification: AI Control Plane Model Backend Adapters Recovery & Validation

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-RECOVERY  
**Lifecycle Target**: T-03253..T-03262 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / recovery & validation)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, PoR Invariant I-2  
**Status**: APPROVED / ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters Recovery & Validation Subsystem** guarantees that model configuration files, fallback cascade graphs, and provider descriptors stored on disk or passed into AIOS remain syntactically sound, structurally valid, and resilient against process crashes, disk corruption, and traversal attacks.

When corrupted or unparseable configurations are detected, the subsystem atomically quarantines the defective file to `<path>.corrupt.<timestamp>` and synthesizes an authoritative default fallback configuration containing safe offline/mock endpoints.

---

## 2. Invariants & Certified Contracts

| Invariant | Target | Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODRECV-INV1`** | Structural Integrity | Record Conservation | `total_models == valid_models + invalid_models`. All parsed model definitions are strictly accounted for. |
| **`MODRECV-INV2`** | Health State | Health Consistency | `is_healthy == (len(issues) == 0 and invalid_models == 0)`. An environment is healthy if and only if zero issues and zero invalid models exist. |
| **`MODRECV-INV3`** | Path Security | Traversal & Injection Immunity | Config path must be validated via `validate_model_store_path()`: rejects `..`, NUL bytes (`\0`), alternate data streams (`:`), length > 1024, and reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`). |
| **`MODRECV-INV4`** | PoR (Invariant I-2) | Token Gating & Accountability | Config validation (`aios_model_validate_config`) is a pure read consuming 0 tokens. Recovery (`aios_model_recover_config`) mutates disk state and requires a valid capability token. |
| **`MODRECV-INV5`** | Recovery Safety | Atomic Quarantine & Backup | Corrupted files are preserved to `<path>.corrupt.<iso_timestamp>` before replacement, ensuring forensic traceability. |

---

## 3. Data Models & Interface Contracts

### 3.1 `ModelValidationIssue`
```python
@dataclass(frozen=True)
class ModelValidationIssue:
    severity: str    # "error" | "warning"
    code: str        # e.g., "ERR_MISSING_PROVIDER", "ERR_INVALID_URL", "ERR_MAX_TOKENS"
    message: str
    model_name: str

    def to_dict(self) -> Dict[str, Any]: ...
```

### 3.2 `ModelConfigValidationReport`
```python
@dataclass
class ModelConfigValidationReport:
    store_path: str
    is_healthy: bool
    total_models: int
    valid_models: int
    invalid_models: int
    issues: List[ModelValidationIssue] = field(default_factory=list)
    validated_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate_invariants(self) -> None:
        """Enforces MODRECV-INV1 and MODRECV-INV2."""
        if self.total_models != (self.valid_models + self.invalid_models):
            raise AssertionError("MODRECV-INV1 violated: total != valid + invalid")
        expected_healthy = (len(self.issues) == 0 and self.invalid_models == 0)
        if self.is_healthy != expected_healthy:
            raise AssertionError("MODRECV-INV2 violated: health state inconsistent")

    def to_dict(self) -> Dict[str, Any]: ...
```

### 3.3 `ModelRecoveryResult`
```python
@dataclass
class ModelRecoveryResult:
    ok: bool
    action_taken: str
    quarantine_path: Optional[str]
    backup_path: Optional[str]
    error: Optional[str] = None
    recovered_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]: ...
```

---

## 4. MCP Wire Tools

### 4.1 `aios_model_validate_config`
- **Parameters**: `config_path: str`
- **PoR Requirement**: 0 tokens.
- **Returns**: ADR-0035 envelope containing `ModelConfigValidationReport`.

### 4.2 `aios_model_recover_config`
- **Parameters**: `config_path: str`, `capability_token: str`, `create_backup: bool = True`
- **PoR Requirement**: Valid capability token redemption (Invariant I-2).
- **Returns**: ADR-0035 envelope containing `ModelRecoveryResult`.

---

## 5. Usage Examples

### 5.1 Programmatic Python Invocation
```python
from aiosh_mcp.model_backend_adapters_recovery import get_global_recovery_engine

engine = get_global_recovery_engine()

# 1. Validate configuration file (pure read, 0 tokens)
report = engine.validate_config_file("config/models.json")
if not report.is_healthy:
    print(f"Config unhealthy! Issues found: {len(report.issues)}")
    # 2. Recover defective configuration (requires capability token)
    result = engine.recover_config_file(
        path="config/models.json",
        capability_token="cap_operator_recovery_token",
        create_backup=True,
    )
    print(f"Recovery status: {result.action_taken}, quarantine: {result.quarantine_path}")
```

### 5.2 FastMCP Tool Call
```json
// Validate config
{
  "name": "aios_model_validate_config",
  "arguments": {
    "config_path": "config/models.json"
  }
}

// Recover config
{
  "name": "aios_model_recover_config",
  "arguments": {
    "config_path": "config/models.json",
    "capability_token": "cap_sample_valid_token_12345",
    "create_backup": true
  }
}
```

---

## 6. Constraints & Known Limitations

1. **Maximum File Size**: Config files exceeding `MAX_CONFIG_FILE_BYTES` (10 MiB) fail validation immediately.
2. **Maximum Model Definitions**: Config files cannot declare more than `MAX_CONFIG_MODELS_CAP` (128) model items.
3. **Capability Token Requirement**: `aios_model_recover_config` strictly rejects invocations with missing or whitespace-only tokens.
4. **Path Traversal Restrictions**: Target paths cannot contain `..`, Windows reserved names (`CON`, `NUL`), or alternate data streams (`:`).
5. **Offline Fallback Guarantee**: The synthesized default configuration points strictly to a safe offline `mock` endpoint (`http://localhost:8080/mock`) to avoid accidental external credential requirements upon disaster recovery.

---

## 7. Traceability & Task Evidence Links

- `T-03253`: Recovery Research — [`docs/tasks/evidence/T-03253-recovery-validation-research.md`](file:///docs/tasks/evidence/T-03253-recovery-validation-research.md)
- `T-03254`: Recovery Specification — [`docs/tasks/evidence/T-03254-recovery-validation-specification.md`](file:///docs/tasks/evidence/T-03254-recovery-validation-specification.md)
- `T-03255`: Recovery Scaffold — [`docs/tasks/evidence/T-03255-recovery-validation-scaffold.md`](file:///docs/tasks/evidence/T-03255-recovery-validation-scaffold.md)
- `T-03256`: Recovery Implementation — [`docs/tasks/evidence/T-03256-recovery-validation-implementation.md`](file:///docs/tasks/evidence/T-03256-recovery-validation-implementation.md)
- `T-03257`: Recovery Unit Test — [`docs/tasks/evidence/T-03257-recovery-validation-unit-test.md`](file:///docs/tasks/evidence/T-03257-recovery-validation-unit-test.md)
- `T-03258`: Recovery Integration — [`docs/tasks/evidence/T-03258-recovery-validation-integration.md`](file:///docs/tasks/evidence/T-03258-recovery-validation-integration.md)
- `T-03259`: Recovery Security Review — [`docs/tasks/evidence/T-03259-recovery-validation-security-review.md`](file:///docs/tasks/evidence/T-03259-recovery-validation-security-review.md)
- `T-03260`: Recovery Hardening — [`docs/tasks/evidence/T-03260-recovery-validation-hardening.md`](file:///docs/tasks/evidence/T-03260-recovery-validation-hardening.md)
- `T-03261`: Recovery Documentation — [`docs/tasks/evidence/T-03261-recovery-validation-documentation.md`](file:///docs/tasks/evidence/T-03261-recovery-validation-documentation.md)
