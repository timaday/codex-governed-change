"""Schema-version and RFC 3339 lifecycle policy."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any


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


def _legacy_document(
    document: Mapping[str, Any], *, identity_field: str
) -> dict[str, Any]:
    from codex_governance.canonical import verify_content_address

    if document.get("schema_version") != "1.0.0":
        raise ValueError("migration input must use schema version 1.0.0")
    if not verify_content_address(document, identity_field):
        raise ValueError("migration input content address does not reconstruct")
    return dict(document)


def migrate_context_receipt_v1_to_v2(
    document: Mapping[str, Any], *,
    context_qualification_id: str,
    source_bundle_sha256: str,
) -> dict[str, Any]:
    """Migrate a legacy receipt using separately protected context bindings."""
    from codex_governance.canonical import content_address, require_sha256

    migrated = _legacy_document(document, identity_field="receipt_id")
    if "context_qualification_id" in migrated or "source_bundle_sha256" in migrated:
        raise ValueError("legacy context receipt already contains v2 fields")
    migrated["schema_version"] = "2.0.0"
    migrated["context_qualification_id"] = require_sha256(
        context_qualification_id, name="context_qualification_id"
    )
    migrated["source_bundle_sha256"] = require_sha256(
        source_bundle_sha256, name="source_bundle_sha256"
    )
    return content_address(migrated, "receipt_id")


def migrate_sandbox_capability_v1_to_v2(
    document: Mapping[str, Any], *, image: str, command: Sequence[str]
) -> dict[str, Any]:
    """Migrate a legacy capability with protected image and command identity."""
    from codex_governance.canonical import content_address
    from codex_governance.sandbox import sandbox_execution_identity

    migrated = _legacy_document(document, identity_field="capability_id")
    if "image" in migrated or "command" in migrated:
        raise ValueError("legacy sandbox capability already contains v2 fields")
    if (
        not isinstance(image, str)
        or not image
        or not isinstance(command, Sequence)
        or isinstance(command, (str, bytes))
        or not command
        or any(not isinstance(item, str) or not item for item in command)
    ):
        raise ValueError("protected sandbox image and command are required")
    migrated["schema_version"] = "2.0.0"
    migrated["image"] = image
    migrated["command"] = list(command)
    migrated["execution_identity"] = sandbox_execution_identity(
        provider=migrated["provider"],
        provider_version=migrated["provider_version"],
        image=image,
        command=command,
        process_limit=migrated["process_limit"],
        memory_bytes=migrated["memory_bytes"],
        cpu_seconds=migrated["cpu_seconds"],
        timeout_seconds=migrated["timeout_seconds"],
        output_bytes=migrated["output_bytes"],
    )
    return content_address(migrated, "capability_id")


def migrate_provenance_statement_v1_to_v2(
    document: Mapping[str, Any], *, cpu_seconds: int
) -> dict[str, Any]:
    """Migrate legacy provenance with an explicitly supplied CPU bound."""
    from codex_governance.canonical import content_address

    migrated = _legacy_document(document, identity_field="statement_id")
    if not isinstance(cpu_seconds, int) or isinstance(cpu_seconds, bool) or cpu_seconds < 1:
        raise ValueError("positive protected cpu_seconds is required")
    predicate = migrated.get("predicate")
    if not isinstance(predicate, Mapping):
        raise ValueError("legacy provenance predicate is unavailable")
    limits = predicate.get("limits")
    if not isinstance(limits, Mapping) or "cpu_seconds" in limits:
        raise ValueError("legacy provenance limits are not a v1 migration input")
    migrated["schema_version"] = "2.0.0"
    migrated["predicate"] = dict(predicate)
    migrated["predicate"]["limits"] = {**limits, "cpu_seconds": cpu_seconds}
    return content_address(migrated, "statement_id")


def migration_policy(kind: str, from_version: str, to_version: str) -> str:
    """Return the protected migration policy for a public representation."""
    if kind in {
        "effective-policy",
        "evidence-manifest",
        "reviewer-qualification",
        "reviewer-qualification-cases",
        "reviewer-qualification-corpus",
        "reviewer-result",
        "context-receipt",
        "sandbox-capability",
        "provenance-statement",
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
