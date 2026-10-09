# T-02904 — Compliance Mapping / Configuration: Specification

**Status**: COMPLETE (2026-10-08)
**Full evidence**: [T-02904-spec.md](T-02904-spec.md)

Normative contract for Compliance Mapping **configuration**: reused-vs-new interface inventory
(every existing interface cited file:line, every proposal marked ⟦AIOS⟧), the `ComplianceConfig`
model and 4-level precedence ladder (argument → env → file → defaults) identical across both
substrates, full input/output/error/persistence tables with exact error codes, the CWE-15 env
hygiene predicate, the 64 KiB config cap independent of the 1 MiB store cap, the PEP-gated
`config-init` / read-only `config-show` surface, resolution of all nine T-02903 decisions
(D-1…D-9), ten testable assertions, and honest limitations.
