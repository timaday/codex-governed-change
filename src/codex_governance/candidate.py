"""Candidate identity application boundary skeleton."""

from collections.abc import Mapping, Sequence
from typing import Any


def candidate_id_from_components(
    *,
    mode: str,
    base_commit: str,
    head_commit: str | None,
    tracked_diff_sha256: str,
    untracked_entries: Sequence[Mapping[str, Any]],
    submodules: Sequence[Mapping[str, Any]],
    effective_policy_sha256: str,
) -> str:
    """Return a canonical sha256-prefixed candidate identity."""
    del mode, base_commit, head_commit, tracked_diff_sha256
    del untracked_entries, submodules, effective_policy_sha256
    raise NotImplementedError("T03: implement canonical candidate identity")
