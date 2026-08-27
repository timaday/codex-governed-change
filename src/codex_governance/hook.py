"""Bounded Codex Stop-hook decision policy."""

from collections.abc import Mapping
from typing import Any


def decide_stop(
    *,
    event: Mapping[str, Any],
    current_candidate_id: str,
    disposition: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return one bounded continuation or a visible stop."""
    if not isinstance(event.get("stop_hook_active"), bool):
        return {"continue": False, "stopReason": "UNKNOWN: malformed Stop event"}
    valid = (
        isinstance(disposition, Mapping)
        and disposition.get("state") == "READY_FOR_HUMAN"
        and disposition.get("candidate_id") == current_candidate_id
    )
    if valid:
        return {"continue": True}
    stale = isinstance(disposition, Mapping) and disposition.get("candidate_id") != current_candidate_id
    reason = (
        "UNKNOWN: disposition is stale; run codex-governance evaluate for the current candidate"
        if stale
        else "UNKNOWN: required governed-change evidence is missing or incomplete; run codex-governance status"
    )
    if event["stop_hook_active"]:
        return {"continue": False, "stopReason": reason}
    return {"decision": "block", "reason": reason}
