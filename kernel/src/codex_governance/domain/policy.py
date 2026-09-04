"""Pure fail-closed governance policies."""

from collections.abc import Mapping, Sequence, Set
from datetime import datetime, timezone
from typing import Any

from codex_governance.domain.model import DispositionState
from codex_governance.authority import decision_applies
from codex_governance.canonical import verify_content_address
from codex_governance.lifecycle import parse_rfc3339


def evaluate_disposition(
    *,
    candidate_id: str,
    required_gate_ids: Sequence[str],
    gate_results: Mapping[str, Mapping[str, Any]],
    reviewer_result: Mapping[str, Any] | None,
    governance_integrity: bool,
) -> DispositionState:
    """Evaluate evidence without performing I/O.

    Confirmed authority violations and failures block.  Incomplete or stale
    observations remain UNKNOWN.  READY_FOR_HUMAN is possible only when every
    mandatory prerequisite is exact and affirmative.
    """
    if not governance_integrity:
        return DispositionState.BLOCK

    required = tuple(required_gate_ids)
    if not candidate_id or not required or len(required) != len(set(required)):
        return DispositionState.UNKNOWN

    # A confirmed failure is useful evidence even if another prerequisite is
    # absent.  Malformed or stale results are never treated as confirmed.
    for gate_id in required:
        result = gate_results.get(gate_id)
        if not isinstance(result, Mapping):
            continue
        if result.get("candidate_id") == candidate_id and result.get("status") == "FAIL":
            return DispositionState.BLOCK

    for gate_id in required:
        result = gate_results.get(gate_id)
        if not isinstance(result, Mapping):
            return DispositionState.UNKNOWN
        if result.get("candidate_id") != candidate_id:
            return DispositionState.UNKNOWN
        if result.get("status") not in {"PASS", "FAIL", "UNKNOWN"}:
            return DispositionState.UNKNOWN
        if result.get("status") == "UNKNOWN":
            return DispositionState.UNKNOWN

    if not isinstance(reviewer_result, Mapping):
        return DispositionState.UNKNOWN
    if reviewer_result.get("candidate_id") != candidate_id:
        return DispositionState.UNKNOWN
    verdict = reviewer_result.get("verdict")
    if verdict == "BLOCK":
        return DispositionState.BLOCK
    if verdict != "NO_BLOCKING_FINDING_OBSERVED":
        return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN


def waiver_applies(
    *,
    waiver: Mapping[str, Any],
    repository_id: str,
    candidate_id: str,
    task_contract_sha256: str,
    policy_sha256: str,
    requirement_id: str,
    decisions: Sequence[Mapping[str, Any]],
    verified_decision_ids: Set[str],
    now: datetime,
) -> bool:
    """Return whether a protected human waiver applies to one exact fact.

    Both issuance and one-time consumption are authenticated exact-candidate
    decisions. Free text and an approver string are never authority.
    """
    if now.tzinfo is None:
        return False
    if (
        not verify_content_address(waiver, "waiver_id")
        or waiver.get("repository_id") != repository_id
        or waiver.get("candidate_id") != candidate_id
        or waiver.get("task_contract_sha256") != task_contract_sha256
        or waiver.get("effective_policy_sha256") != policy_sha256
        or waiver.get("single_use") is not True
    ):
        return False
    if requirement_id not in waiver.get("requirement_ids", ()):
        return False
    try:
        expires = parse_rfc3339(str(waiver["expires_at"]))
        created = parse_rfc3339(str(waiver["created_at"]))
    except (KeyError, TypeError, ValueError):
        return False
    if created >= expires:
        return False
    normalized_now = now.astimezone(timezone.utc)
    if not created <= normalized_now < expires:
        return False
    by_id = {
        item.get("decision_id"): item
        for item in decisions
        if isinstance(item, Mapping)
    }
    issuance = by_id.get(waiver.get("issuance_decision_id"))
    consumption = by_id.get(waiver.get("consumption_decision_id"))
    if not isinstance(issuance, Mapping) or not isinstance(consumption, Mapping):
        return False
    common = {
        "repository_id": repository_id,
        "candidate_id": candidate_id,
        "task_contract_sha256": task_contract_sha256,
        "policy_sha256": policy_sha256,
        "required_scope": [requirement_id],
        "now": normalized_now,
    }
    return bool(
        issuance.get("single_use") is True
        and consumption.get("single_use") is True
        and consumption.get("consumption_id") == issuance.get("decision_id")
        and decision_applies(
            decision=issuance,
            required_type="waiver_issuance",
            source_verified=issuance.get("decision_id") in verified_decision_ids,
            **common,
        )
        and decision_applies(
            decision=consumption,
            required_type="waiver_consumption",
            source_verified=consumption.get("decision_id") in verified_decision_ids,
            **common,
        )
    )
