"""Deterministic quality-profile validation."""

from collections.abc import Mapping
from typing import Any


def validate_task_contract(contract: Mapping[str, Any]) -> list[str]:
    """Return deterministic requirement violations for the selected profile."""
    violations: list[str] = []
    profile = contract.get("profile")
    gates = contract.get("required_gate_ids")
    specialists = contract.get("specialist_reviews")
    if profile not in {"code", "specification", "mixed", "governance"}:
        violations.append("profile must be code, specification, mixed, or governance")
        return violations
    if not isinstance(gates, list) or not gates or not all(
        isinstance(gate, str) and gate for gate in gates
    ):
        violations.append("required gate IDs must be a non-empty string list")
        gates = []
    if len(gates) != len(set(gates)):
        violations.append("required gate IDs must be unique")
    if not isinstance(specialists, list):
        violations.append("specialist reviews must be a list")
        specialists = []

    code_profiles = {"code", "mixed", "governance"}
    if profile in code_profiles:
        executable_tokens = (
            "test", "acceptance", "build", "lint", "type", "security",
            "mutation", "adversarial", "quality",
        )
        if not any(any(token in gate.lower() for token in executable_tokens) for gate in gates):
            violations.append("code profile requires at least one executable gate")
    if profile in {"specification", "mixed", "governance"}:
        for specialist in ("business", "engineering", "qa", "rst"):
            if specialist not in specialists:
                violations.append(
                    f"specification profile requires {specialist} specialist review"
                )
    requested = contract.get("governance_change_requested")
    if profile == "governance" and requested is not True:
        violations.append("governance profile must declare the governance change request")
    if profile != "governance" and requested is True:
        violations.append("a governance change request requires the governance profile")
    risk_profile = contract.get("risk_profile")
    rapid = contract.get("rapid_review")
    if risk_profile not in {"low", "standard", "elevated"}:
        violations.append("task contract requires a low, standard, or elevated risk profile")
    if not isinstance(rapid, Mapping):
        violations.append("task contract requires rapid-review policy")
    else:
        minimum = rapid.get("minimum_charters")
        required = rapid.get("required")
        rationale = rapid.get("skip_rationale")
        if risk_profile == "low":
            if required is not False or minimum != 0:
                violations.append("low risk requires an explicit zero-charter rapid-review skip")
            if not isinstance(rationale, str) or not rationale.strip():
                violations.append("low-risk rapid-review skip requires a recorded rationale")
        elif risk_profile == "standard" and (required is not True or minimum != 1):
            violations.append("standard risk requires at least one rapid-review charter")
        elif risk_profile == "elevated" and (
            required is not True or not isinstance(minimum, int) or minimum < 2
        ):
            violations.append("elevated risk requires multiple rapid-review charters")
    return sorted(violations)
