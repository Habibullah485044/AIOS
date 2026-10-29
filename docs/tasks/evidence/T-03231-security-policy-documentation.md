# Documentation Evidence: AI Control Plane Model Backend Adapters Security Policy (T-03231)

**Task ID**: T-03231 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / security policy: Documentation)  
**Contract Reference**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-SECURITY-POLICY.md`, ADR-0035 §AF-2, PoR Invariant I-2  
**Date**: 2026-10-29  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Documentation completed with runnable Python code examples, invariant definitions, parameter bounds, limitations honestly stated, and lifecycle evidence links.

---

## 1. Documentation Updates Delivered

1. **Updated Specification (`docs/SPEC-MODEL-BACKEND-ADAPTERS-SECURITY-POLICY.md`)**:
   - Complete technical reference for `ModelSecurityPolicy` and `PolicyVerdict`.
   - Invariant matrix (`MODSEC-INV1` through `MODSEC-INV5`).
   - Copy-pasteable Python examples for read evaluation, unauthorized mutation, and authorized mutation.
   - Comprehensive enumeration of boundaries and constraints (1 MiB payloads, 512-char tokens, 64-char action names).
   - Cross-links to all evidence files from `T-03223` through `T-03231`.

2. **Codebase Module Docstrings Synchronized**:
   - `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_security_policy.py`.

---

## 2. Copy-Pasteable Verification Example

```python
from aiosh_mcp.model_backend_adapters_security_policy import ModelSecurityPolicy

policy = ModelSecurityPolicy()
# 1. Read operations: zero tokens consumed
read_verdict = policy.evaluate("list")
assert read_verdict.allowed is True

# 2. Mutating operations: mandatory token gate
unauth_verdict = policy.evaluate("complete", token=None)
assert unauth_verdict.allowed is False
assert "Missing mandatory capability token" in unauth_verdict.reason

auth_verdict = policy.evaluate("complete", token="grant_tok_123")
assert auth_verdict.allowed is True
```
