# Documentation Evidence: AI Control Plane Model Backend Adapters CLI Surface (T-03191)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / CLI surface
- **Artifact**: `docs/tasks/evidence/T-03191-cli-surface-documentation.md`
- **Specification Document**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-CLI.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Documentation Overview

Task `T-03191` updates and solidifies the operator-facing and developer documentation for the Model Backend Adapters CLI surface (`aiosh model ...`):

1. **Subcommand Reference & Grammar**:
   - Comprehensive grammar diagram for `list`, `show`, `health`, `complete`, and `register`.
   - Detailed flag descriptions, default values, and boundary constraints.

2. **Proof-of-Restraint Invariant I-2 Guidelines**:
   - Explicit operational instructions for read-only vs. state-mutating actions.
   - Explains zero-token queries (`list`, `show`, `health`) and `--token` requirements for `complete` and `register`.

3. **Standardized Exit Code Taxonomy**:
   - Details `EXIT_SUCCESS=0`, `EXIT_FAILURE=1`, `EXIT_USAGE=2`, `EXIT_UNAUTHORIZED=3`, and `EXIT_TIMEOUT=4`.
   - Documents the structured JSON envelope format for scripting and programmatic orchestration.

4. **Hardened Boundary Constraints**:
   - Documents identifier length limits (64 chars), directory traversal defenses, temperature bounds `[0.0, 2.0]`, timeout bounds `[1000, 300000] ms`, and fallback depth limits (5).

---

## 2. Verification

- Documentation updated in `docs/SPEC-MODEL-BACKEND-ADAPTERS-CLI.md`.
- All dual-substrate test batteries pass (30 Python tests, 5 Rust tests).
- Validated with `tools/check_evidence.py`.
