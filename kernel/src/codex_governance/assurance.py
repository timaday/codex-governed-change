"""Pure fixed-rule assurance claim policies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from codex_governance.domain.model import DispositionState


SATISFIED_CLASSIFICATIONS = frozenset(
    {"DIRECTLY_OBSERVED", "VERIFIED_WITHIN_SCOPE"}
)

ASSURANCE_ARGUMENT_RULES = {
    "scope_authorized": "RULE_SCOPE_AUTH",
    "candidate_current": "RULE_CANDIDATE_CURRENT",
    "gates_complete": "RULE_GATES_COMPLETE",
    "governance_integrity": "RULE_GOVERNANCE_LKG",
    "rst_complete": "RULE_RST_COMPLETE",
    "mutation_complete": "RULE_MUTATION_COMPLETE",
    "fresh_review_complete": "RULE_FRESH_REVIEW",
    "residual_risk_visible": "RULE_RISK_VISIBLE",
    "context_complete": "RULE_CONTEXT_COMPLETE",
}


def assurance_claim_set_is_fixed(claims: Any) -> bool:
    """Require exactly one protected claim-to-argument-rule pair."""
    if not isinstance(claims, (list, tuple)) or len(claims) != len(
        ASSURANCE_ARGUMENT_RULES
    ):
        return False
    observed: set[str] = set()
    for claim in claims:
        if not isinstance(claim, Mapping):
            return False
        claim_id = claim.get("claim_id")
        if (
            not isinstance(claim_id, str)
            or claim_id in observed
            or claim.get("argument_rule") != ASSURANCE_ARGUMENT_RULES.get(claim_id)
        ):
            return False
        observed.add(claim_id)
    return observed == set(ASSURANCE_ARGUMENT_RULES)


def evaluate_assurance_claim(claim: Mapping[str, Any]) -> DispositionState:
    classification = claim.get("classification")
    refuting = claim.get("refuting_evidence")
    supporting = claim.get("supporting_evidence")
    defeaters = claim.get("unresolved_defeaters")
    if classification == "REFUTED" or (
        isinstance(refuting, (list, tuple)) and bool(refuting)
    ):
        return DispositionState.BLOCK
    if (
        classification not in SATISFIED_CLASSIFICATIONS
        or not isinstance(supporting, (list, tuple))
        or not supporting
        or not isinstance(defeaters, (list, tuple))
        or bool(defeaters)
    ):
        return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN


_DEGRADATIONS = frozenset(
    {
        "add_failure",
        "add_unknown",
        "remove_required_evidence",
        "make_stale",
        "change_repository",
        "change_candidate",
        "change_policy",
        "change_source_identity",
        "change_execution_identity",
    }
)


def disposition_cannot_improve(degradation: str) -> bool:
    """Declare the finite degradation operators used by exhaustive meta-tests."""
    return degradation in _DEGRADATIONS
