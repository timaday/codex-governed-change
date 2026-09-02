"""Schema-version and RFC 3339 lifecycle policy."""

from __future__ import annotations

import re
from datetime import datetime


RFC3339_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60)"
    r"(?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)


def parse_rfc3339(value: str) -> datetime:
    """Parse the supported complete RFC 3339 profile and reject invalid dates."""
    if not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None:
        raise ValueError("timestamp must be a complete RFC 3339 value")
    if value[17:19] == "60":
        raise ValueError("leap seconds are not supported by the Python adapter")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp is not a real calendar instant") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires an explicit offset")
    return parsed


def validate_time_order(start: str, end: str) -> bool:
    try:
        return parse_rfc3339(start) <= parse_rfc3339(end)
    except ValueError:
        return False


def migration_policy(kind: str, from_version: str, to_version: str) -> str:
    """Return the protected migration policy for a public representation."""
    if kind in {
        "effective-policy",
        "evidence-manifest",
        "reviewer-qualification",
        "reviewer-qualification-cases",
        "reviewer-qualification-corpus",
        "reviewer-result",
    } and (
        from_version,
        to_version,
    ) == ("1.0.0", "2.0.0"):
        return "explicit_required"
    if kind == "reviewer-execution" and (
        from_version,
        to_version,
    ) in {("1.0.0", "2.0.0"), ("2.0.0", "3.0.0")}:
        return "explicit_required"
    if kind == "reviewer-qualification-cases" and (
        from_version,
        to_version,
    ) == ("2.0.0", "3.0.0"):
        return "explicit_required"
    if kind in {"evidence-manifest", "reviewer-result"} and (
        from_version,
        to_version,
    ) == ("2.0.0", "3.0.0"):
        return "explicit_required"
    if kind == "rollback-evidence" and (
        from_version,
        to_version,
    ) == ("1.0.0", "2.0.0"):
        return "explicit_required"
    if from_version == to_version and from_version in {"1.0.0", "2.0.0", "3.0.0"}:
        return "identity"
    return "unsupported"
