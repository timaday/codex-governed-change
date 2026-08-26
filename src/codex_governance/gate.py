"""Deterministic gate observation policy skeleton."""

from codex_governance.domain.model import GateStatus


def classify_gate_result(
    *,
    termination_kind: str,
    exit_code: int | None,
    observation_complete: bool,
    required_output_truncated: bool,
    candidate_before: str,
    candidate_after: str,
) -> GateStatus:
    """Classify a gate without confusing failure and observation uncertainty."""
    del termination_kind, exit_code, observation_complete
    del required_output_truncated, candidate_before, candidate_after
    raise NotImplementedError("T05: implement gate observation classification")
