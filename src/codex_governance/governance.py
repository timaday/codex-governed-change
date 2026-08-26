"""Governance asset integrity skeleton."""

from collections.abc import Sequence

from codex_governance.domain.model import DispositionState


def classify_governance_change(
    *,
    changed_paths: Sequence[str],
    task_profile: str,
    governance_change_authorized: bool,
) -> DispositionState | None:
    """Block an ordinary candidate from changing its own acceptance authority."""
    del changed_paths, task_profile, governance_change_authorized
    raise NotImplementedError("T09: implement governance integrity policy")
