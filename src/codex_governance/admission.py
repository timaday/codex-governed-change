"""The sole pure deterministic readiness reference monitor."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from codex_governance.domain.model import DispositionState


_SATISFIED = frozenset({"DIRECTLY_OBSERVED", "VERIFIED_WITHIN_SCOPE"})


def evaluate_ci_prerequisites(
    required_jobs: Sequence[str], observed_results: Mapping[str, str]
) -> DispositionState:
    """Classify the always-running CI boundary before artifact reconstruction."""
    if (
        not required_jobs
        or len(required_jobs) != len(set(required_jobs))
        or set(observed_results) != set(required_jobs)
    ):
        return DispositionState.UNKNOWN
    outcomes = tuple(observed_results.values())
    if "failure" in outcomes:
        return DispositionState.BLOCK
    if any(item != "success" for item in outcomes):
        return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN


def evaluate_admission(
    *,
    repository_id: str,
    candidate_id: str,
    upstream_results: Mapping[str, str],
    claims: Mapping[str, Mapping[str, Any]],
    required_claim_ids: Sequence[str],
) -> DispositionState:
    if not repository_id.startswith("repo:") or not candidate_id.startswith("sha256:"):
        return DispositionState.UNKNOWN
    if not upstream_results or not required_claim_ids or len(required_claim_ids) != len(set(required_claim_ids)):
        return DispositionState.UNKNOWN
    outcomes = tuple(upstream_results.values())
    if "failure" in outcomes:
        return DispositionState.BLOCK
    if any(outcome != "success" for outcome in outcomes):
        return DispositionState.UNKNOWN
    for claim_id in required_claim_ids:
        claim = claims.get(claim_id)
        if not isinstance(claim, Mapping):
            return DispositionState.UNKNOWN
        if claim.get("classification") == "REFUTED":
            return DispositionState.BLOCK
        if claim.get("classification") not in _SATISFIED:
            return DispositionState.UNKNOWN
        defeaters = claim.get("defeaters")
        if not isinstance(defeaters, (list, tuple)) or defeaters:
            return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN


class AdmissionKernel:
    """Names the protected capability-free policy boundary."""

    evaluate = staticmethod(evaluate_admission)
