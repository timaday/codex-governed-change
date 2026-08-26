"""Fail-closed disposition policy skeleton."""

from collections.abc import Mapping, Sequence
from typing import Any

from codex_governance.domain.model import DispositionState


def evaluate_disposition(
    *,
    candidate_id: str,
    required_gate_ids: Sequence[str],
    gate_results: Mapping[str, Mapping[str, Any]],
    reviewer_result: Mapping[str, Any] | None,
    governance_integrity: bool,
) -> DispositionState:
    """Evaluate evidence without performing I/O."""
    del candidate_id, required_gate_ids, gate_results, reviewer_result, governance_integrity
    raise NotImplementedError("T01: implement fail-closed disposition policy")
