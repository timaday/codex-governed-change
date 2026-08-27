"""Protected policy loading and observable precedence resolution."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codex_governance.canonical import canonical_json_bytes, normalize_repo_path, sha256_bytes
from codex_governance.schema import load_and_validate


def load_effective_policy(*, policy_path: Path, schema_path: Path) -> dict[str, Any]:
    policy = load_and_validate(policy_path, schema_path)
    if not isinstance(policy, dict):
        raise ValueError("effective policy must be an object")
    normalize_repo_path(policy["evidence_root"])
    gate_ids: set[str] = set()
    for gate in policy["gates"]:
        gate_id = gate["gate_id"]
        if gate_id in gate_ids:
            raise ValueError(f"duplicate protected gate ID: {gate_id}")
        gate_ids.add(gate_id)
        if gate["shell"] and not gate["risk_label"].strip():
            raise ValueError(f"shell gate {gate_id} lacks a risk label")
        if not gate["shell"] and gate["risk_label"]:
            raise ValueError(f"non-shell gate {gate_id} cannot carry shell risk")
    return policy


def resolve_effective_configuration(
    *,
    policy: Mapping[str, Any],
    task_contract: Mapping[str, Any] | None = None,
    evidence_root_override: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Resolve only documented policy/task/CLI fields and return its digest."""
    evidence_root = normalize_repo_path(
        evidence_root_override or str(policy["evidence_root"])
    )
    available = {gate["gate_id"]: dict(gate) for gate in policy["gates"]}
    required: list[str]
    profile: str | None
    risk_profile: str | None
    rapid_review: Mapping[str, Any] | None
    if task_contract is None:
        required = sorted(available)
        profile = None
        risk_profile = None
        rapid_review = None
    else:
        profile = task_contract.get("profile")
        required = list(task_contract.get("required_gate_ids", ()))
        if len(required) != len(set(required)) or any(item not in available for item in required):
            raise ValueError("task contract requests an unavailable protected gate")
        if any(profile not in available[item]["profiles"] for item in required):
            raise ValueError("task profile is not permitted for a required protected gate")
        risk_profile = task_contract.get("risk_profile")
        rapid_review = task_contract.get("rapid_review")
    effective = {
        "schema_version": "1.0.0",
        "repository_id": policy["repository_id"],
        "policy_id": policy["policy_id"],
        "lkg_governance_commit": policy["lkg_governance_commit"],
        "evidence_root": evidence_root,
        "profile": profile,
        "risk_profile": risk_profile,
        "rapid_review": dict(rapid_review) if isinstance(rapid_review, Mapping) else None,
        "required_gate_ids": required,
        "gates": [available[item] for item in required],
        "reviewer": dict(policy["reviewer"]),
        "decision_source": dict(policy["decision_source"]),
        "protected_minimums": [dict(item) for item in policy["protected_minimums"]],
        "sandbox": dict(policy["sandbox"]),
        "context": dict(policy["context"]),
        "mutation": dict(policy["mutation"]),
        "producer_version": policy["producer_version"],
        "precedence": [
            "built-in-safe-defaults",
            "protected-policy",
            "task-contract-allowlist",
            "cli-evidence-root",
        ],
    }
    encoded = canonical_json_bytes(effective)
    return effective, sha256_bytes(encoded)
