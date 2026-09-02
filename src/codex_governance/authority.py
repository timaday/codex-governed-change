"""Pure authenticated-decision, obligation-floor, and LKG policies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from datetime import datetime
from typing import Any

from codex_governance.domain.model import DispositionState
from codex_governance.canonical import verify_content_address
from codex_governance.lifecycle import parse_rfc3339


_RISK_RANK = {"low": 0, "standard": 1, "elevated": 2}


def decision_applies(
    *,
    decision: Mapping[str, Any],
    repository_id: str,
    candidate_id: str,
    task_contract_sha256: str,
    policy_sha256: str,
    required_type: str,
    required_scope: Sequence[str],
    now: datetime,
    source_verified: bool,
) -> bool:
    if not source_verified or now.tzinfo is None:
        return False
    if not verify_content_address(decision, "decision_id"):
        return False
    issuer = decision.get("issuer")
    if not isinstance(issuer, Mapping):
        return False
    authenticated = (
        isinstance(issuer.get("authentication_method"), str)
        and bool(issuer["authentication_method"])
        and isinstance(issuer.get("assertion_sha256"), str)
        and str(issuer["assertion_sha256"]).startswith("sha256:")
    )
    protected = isinstance(issuer.get("protected_source"), str) and bool(
        issuer["protected_source"]
    )
    if not authenticated or not protected:
        return False
    expected = {
        "repository_id": repository_id,
        "candidate_id": candidate_id,
        "task_contract_sha256": task_contract_sha256,
        "effective_policy_sha256": policy_sha256,
        "decision_type": required_type,
    }
    if any(decision.get(key) != value for key, value in expected.items()):
        return False
    scope = decision.get("scope")
    if not isinstance(scope, Sequence) or isinstance(scope, (str, bytes)):
        return False
    if not set(required_scope).issubset(set(scope)):
        return False
    try:
        issued = parse_rfc3339(str(decision["issued_at"]))
        expires = parse_rfc3339(str(decision["expires_at"]))
    except (KeyError, ValueError):
        return False
    return issued <= now <= expires and issued < expires


def authorize_governance_change(
    *,
    repository_id: str,
    candidate_id: str,
    task_contract_sha256: str,
    policy_sha256: str,
    changed_paths: Sequence[str],
    governance_paths: Sequence[str] | None = None,
    decisions: Sequence[Mapping[str, Any]],
    verified_decision_ids: Set[str],
    governance_change_authorized: bool,
    approver: str,
    now: datetime,
) -> DispositionState | None:
    del governance_change_authorized, approver
    from codex_governance.governance import is_governance_path

    governed = [
        path
        for path in changed_paths
        if (
            is_governance_path(path)
            if governance_paths is None
            else is_governance_path(path, governance_paths=governance_paths)
        )
    ]
    if not governed:
        return None
    for decision in decisions:
        if decision_applies(
            decision=decision,
            repository_id=repository_id,
            candidate_id=candidate_id,
            task_contract_sha256=task_contract_sha256,
            policy_sha256=policy_sha256,
            required_type="governance_authorization",
            required_scope=["schemas/" if path.startswith("schemas/") else path for path in governed],
            now=now,
            source_verified=decision.get("decision_id") in verified_decision_ids,
        ):
            return None
    return DispositionState.BLOCK


def resolve_protected_obligations(
    *,
    changed_paths: Sequence[str],
    affected_surfaces: Sequence[str],
    protected_rules: Sequence[Mapping[str, Any]],
    requested_risk: str,
    requested_gates: Sequence[str],
    reduction_decisions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    del reduction_decisions
    if requested_risk not in _RISK_RANK:
        raise ValueError("unknown requested risk profile")
    risk = requested_risk
    gates = set(requested_gates)
    protected_surfaces = tuple(dict.fromkeys([*changed_paths, *affected_surfaces]))
    for rule in protected_rules:
        prefix = rule.get("path_prefix")
        if isinstance(prefix, str) and any(
            isinstance(path, str) and path.startswith(prefix)
            for path in protected_surfaces
        ):
            protected_risk = rule.get("risk_profile")
            if protected_risk not in _RISK_RANK:
                raise ValueError("protected rule has an unknown risk profile")
            if _RISK_RANK[protected_risk] > _RISK_RANK[risk]:
                risk = protected_risk
            gates.update(str(item) for item in rule.get("gate_ids", ()))
    return {"risk_profile": risk, "gate_ids": sorted(gates)}


def evaluate_lkg_promotion(
    *,
    repository_id: str,
    candidate_id: str,
    task_contract_sha256: str,
    evaluating_policy_sha256: str,
    previous_lkg_policy_sha256: str,
    proposed_policy_sha256: str,
    promotion_decision: Mapping[str, Any] | None,
    rollback_evidence: Mapping[str, Any] | None,
    now: datetime,
    verified_decision_ids: Set[str],
) -> DispositionState:
    if evaluating_policy_sha256 != previous_lkg_policy_sha256:
        return DispositionState.BLOCK
    if proposed_policy_sha256 == previous_lkg_policy_sha256:
        return DispositionState.UNKNOWN
    if not isinstance(promotion_decision, Mapping) or not isinstance(rollback_evidence, Mapping):
        return DispositionState.UNKNOWN
    rollback_exact = (
        verify_content_address(rollback_evidence, "rollback_evidence_id")
        and rollback_evidence.get("repository_id") == repository_id
        and rollback_evidence.get("task_contract_sha256") == task_contract_sha256
        and rollback_evidence.get("candidate_id") == candidate_id
        and rollback_evidence.get("previous_lkg_policy_sha256")
        == previous_lkg_policy_sha256
        and rollback_evidence.get("proposed_policy_sha256") == proposed_policy_sha256
        and rollback_evidence.get("status") == "PASS"
    )
    if not rollback_exact:
        return DispositionState.BLOCK
    if not decision_applies(
        decision=promotion_decision,
        repository_id=repository_id,
        candidate_id=candidate_id,
        task_contract_sha256=task_contract_sha256,
        policy_sha256=previous_lkg_policy_sha256,
        required_type="lkg_promotion",
        required_scope=[
            f"promote:{proposed_policy_sha256}",
            f"rollback:{rollback_evidence['rollback_evidence_id']}",
        ],
        now=now,
        source_verified=promotion_decision.get("decision_id") in verified_decision_ids,
    ):
        return DispositionState.BLOCK
    return DispositionState.READY_FOR_HUMAN
