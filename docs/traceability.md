# Traceability

Every MVP requirement maps to an implementation task and at least one deterministic acceptance surface. Test module names are stable contracts for the implementation run.

| Requirement | Task | Acceptance surface |
|---|---|---|
| GOV-001 | T09, T10 | `test_blueprint_contract.py`, skill fixtures |
| GOV-002 | T01, T07 | `test_workflow_profiles.py` |
| GOV-003 | T03 | `test_candidate_identity.py` |
| GOV-004 | T02, T04, T05 | `test_gate_evidence.py` |
| GOV-005 | T06 | `test_reviewer_isolation.py` |
| GOV-006 | T06, T09 | `test_reviewer_isolation.py`, CI static checks |
| GOV-007 | T02, T06 | `test_reviewer_isolation.py`, schema fixtures |
| GOV-008 | T01, T05, T07 | `test_disposition_policy.py`, `test_gate_evidence.py` |
| GOV-009 | T03, T05, T06 | `test_candidate_identity.py`, `test_disposition_policy.py` |
| GOV-010 | T08 | `test_stop_hook.py` |
| GOV-011 | T09 | `test_governance_integrity.py`, workflow validation |
| GOV-012 | T01, T07 | `test_disposition_policy.py` |
| GOV-013 | T09 | `test_governance_integrity.py` |
| GOV-014 | T05, T07 | `test_workflow_profiles.py`, `test_gate_evidence.py` |
| GOV-015 | T07 | `test_workflow_profiles.py` |
| GOV-016 | T06 | `test_reviewer_isolation.py` |
| GOV-017 | T01, T07 | `test_disposition_policy.py` |
| GOV-018 | T01, T07 | `test_disposition_policy.py` |
| GOV-019 | T03, T05, T09 | `test_candidate_identity.py`, CI static checks |
| GOV-020 | T06 | `test_reviewer_isolation.py` |
| GOV-021 | T04, T06, T09 | `test_reviewer_isolation.py`, `test_governance_integrity.py` |
| GOV-022 | T01-T10 | Blueprint clean-environment gate |
| GOV-023 | T02, T04, T07 | `test_disposition_policy.py`, schema/example checks |
| GOV-024 | T09, T10 | Governance mutation corpus |
| GOV-025 | T06, T08 | `test_reviewer_isolation.py`, `test_stop_hook.py` |
| GOV-026 | T01, T05 | `test_gate_evidence.py` |
| GOV-027 | T05, T06 | `test_gate_evidence.py`, `test_reviewer_isolation.py` |
| GOV-028 | T03, T04 | `test_candidate_identity.py`, artifact-store security tests |
| GOV-029 | T03, T07 | `test_candidate_identity.py`, configuration tests |
| GOV-030 | T01, T07, T09 | `test_disposition_policy.py`, capability-boundary tests |

## Coverage rules

- `scripts/validate_blueprint.py` MUST fail if a requirement lacks a task or acceptance surface.
- New requirements MUST update this table, the implementation plan, and an executable test before being considered design-ready.
- Renaming a test does not remove the requirement; traceability must be updated in the same governance change.
- A mapped test that is skipped, expected-failed, non-discovered, or not executed provides no acceptance evidence.
