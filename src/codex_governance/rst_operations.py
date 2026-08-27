"""Pure operational RST lineage and feedback policies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from codex_governance.domain.model import DispositionState


REQUIRED_RST_KINDS = frozenset(
    {"risk_register", "oracle_reference", "charter", "session", "coverage_note", "debrief", "follow_up"}
)


def validate_rst_lineage(
    repository_id: str,
    task_contract_sha256: str,
    candidate_id: str,
    artifacts: Sequence[Mapping[str, Any]],
) -> DispositionState:
    kinds: set[str] = set()
    for artifact in artifacts:
        if (
            artifact.get("repository_id") != repository_id
            or artifact.get("task_contract_sha256") != task_contract_sha256
            or artifact.get("candidate_id") != candidate_id
        ):
            return DispositionState.UNKNOWN
        kind = artifact.get("kind")
        if not isinstance(kind, str) or kind in kinds:
            return DispositionState.UNKNOWN
        kinds.add(kind)
    return (
        DispositionState.READY_FOR_HUMAN
        if REQUIRED_RST_KINDS.issubset(kinds)
        else DispositionState.UNKNOWN
    )


def derive_follow_ups(
    *,
    observations: Sequence[Mapping[str, Any]],
    mutants: Sequence[Mapping[str, Any]],
    reviewer_findings: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in observations:
        if item.get("surprise"):
            result.append({"source_kind": "observation", "source_id": item.get("id"), "required": False})
    for item in mutants:
        if item.get("outcome") == "SURVIVED":
            result.append({"source_kind": "mutant", "source_id": item.get("id"), "required": True})
    for item in reviewer_findings:
        if item.get("severity") in {"critical", "high", "medium", "low"}:
            result.append({"source_kind": "reviewer_finding", "source_id": item.get("id"), "required": item.get("severity") in {"critical", "high"}})
    return result


def evaluate_operational_rst(
    *,
    artifacts_complete: bool,
    direct_observations: Sequence[Any],
    fallible_oracles: Sequence[Any],
    coverage_notes: Sequence[Any],
    unresolved_follow_ups: Sequence[Any],
) -> DispositionState:
    if unresolved_follow_ups:
        return DispositionState.BLOCK
    if not artifacts_complete or not direct_observations or not fallible_oracles or not coverage_notes:
        return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN
