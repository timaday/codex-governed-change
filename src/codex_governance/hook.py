"""Codex Stop-hook decision skeleton."""

from collections.abc import Mapping
from typing import Any


def decide_stop(
    *,
    event: Mapping[str, Any],
    current_candidate_id: str,
    disposition: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return one bounded continuation or a visible stop."""
    del event, current_candidate_id, disposition
    raise NotImplementedError("T08: implement bounded Stop-hook policy")
