# Specification Evidence: Threat Model Security Policy (T-02762)

## Overview
Defines the formal contract, policy schema, data models, invariant rulesets (`THREATPOL1`..`THREATPOL7`), and evaluation APIs for Threat Model Maintenance Security Policy.

## Master Document
See master specification in [`docs/SPEC-THREAT-MODEL-POLICY.md`](../../SPEC-THREAT-MODEL-POLICY.md).

## Reused vs. New Interfaces
- **Reused Interfaces**:
  - `aiosh_core::threat_model_data_model::{ThreatEntry, ThreatCategory, ThreatSeverity, ThreatStatus}`
  - `aiosh_core::threat_model_service::ThreatRiskAssessment`
- **New Interfaces**:
  - `ThreatPolicyMode`: Enum (`Enforcing`, `Permissive`, `Disabled`)
  - `ThreatPolicyVerdict`: Enum (`Permit`, `PermitWithWarning`, `Deny`)
  - `ThreatModelSecurityPolicy`: Struct with evaluation methods
  - MCP Tool: `aios.threat.policy`

## Error Constants
- `THREATPOL_ERR_VALIDATION`: Structural invalidity in policy.
- `THREATPOL_ERR_DENIED`: Operation denied under policy.
- `THREATPOL_ERR_CWE_REQUIRED`: Missing CWE mapping on registered threat.
- `THREATPOL_ERR_CRITICAL_UNMITIGATED`: Attempt to accept/resolve critical threat without mitigations.
- `THREATPOL_ERR_CATEGORY_PROHIBITED`: Prohibited threat category.
- `THREATPOL_ERR_CAPACITY_EXCEEDED`: Exceeded catalog or critical count density.
- `THREATPOL_ERR_IO`: I/O error reading or writing policy.
- `THREATPOL_ERR_PARSE`: Deserialization error.
