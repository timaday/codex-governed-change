"""Pure fixed-rule assurance claim policies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from codex_governance.domain.model import DispositionState


SATISFIED_CLASSIFICATIONS = frozenset(
    {"DIRECTLY_OBSERVED", "VERIFIED_WITHIN_SCOPE"}
)


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
