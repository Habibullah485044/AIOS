# Specification Evidence: Threat Model Maintenance Automated Tests (T-02752)

## Overview
Defines the formal testing contract and verification vectors for the automated tests suite of Threat Model Maintenance (`T-02751`..`T-02760`).

## Formal Test Vectors Contract
- `AUTOTHREAT1`: Full Threat Lifecycle & Invariant Transitions
- `AUTOTHREAT2`: STRIDE Taxonomy & Severity Matrix
- `AUTOTHREAT3`: Secret & Private Key Scrubbing Invariant
- `AUTOTHREAT4`: Path Traversal & Symlink Defense
- `AUTOTHREAT5`: Multi-Threaded Concurrency Safety
- `AUTOTHREAT6`: Risk Monotonicity & Composite Scoring
- `AUTOTHREAT7`: Capacity Ceiling & DoS Resistance
- `AUTOTHREAT8`: Serialization Roundtrip & Invariant Preservation
- `AUTOTHREAT9`: Atomic Persistence & Zero-Leak File Handling
- `AUTOTHREAT10`: Canonical Baseline Reset & Idempotent Init

## Interfaces Reused
- `aiosh_core::threat_model_data_model::*`: Reused for enum models, state machines, and entry serialization.
- `aiosh_core::threat_model_service::*`: Reused for business logic, catalog persistence, and risk calculations.
- `aiosh_core::threat_model_config::*`: Reused for configuration boundaries and path validations.

## Artifact References
- Master Spec: `docs/SPEC-THREAT-MODEL-AUTOMATED-TESTS.md`
- Target Test File: `code/aiosh-rust/aiosh-core/tests/test_threat_model_automated.rs`
