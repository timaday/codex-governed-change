"""Pure reviewer and context-variant qualification policy."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from codex_governance.domain.model import DispositionState
from codex_governance.canonical import verify_content_address


REVIEWER_IDENTITY_FIELDS = (
    "prompt_sha256",
    "schema_sha256",
    "launcher_sha256",
    "codex_cli_version",
    "model",
    "reasoning_effort",
)


def reviewer_qualification_state(
    identity: Mapping[str, Any],
    record: Mapping[str, Any],
    *,
    protected_qualification_id: str | None,
) -> DispositionState:
    if not verify_content_address(record, "qualification_id"):
        return DispositionState.UNKNOWN
    if not protected_qualification_id or record.get("qualification_id") != protected_qualification_id:
        return DispositionState.UNKNOWN
    if any(identity.get(field) != record.get(field) for field in REVIEWER_IDENTITY_FIELDS):
        return DispositionState.UNKNOWN
    if record.get("human_labelled") is not True or record.get("qualified") is not True:
        return DispositionState.UNKNOWN
    critical = record.get("critical_cases")
    detected = record.get("critical_detected")
    if not isinstance(critical, int) or critical < 1 or detected != critical:
        return DispositionState.BLOCK
    if record.get("false_passes") != 0:
        return DispositionState.BLOCK
    return DispositionState.READY_FOR_HUMAN


def reconcile_review_lanes(
    *,
    risk: str,
    outcomes: Sequence[str],
    specialist_required: bool,
    specialist_present: bool,
) -> DispositionState:
    if not outcomes or len(set(outcomes)) != 1:
        return DispositionState.UNKNOWN
    if specialist_required and not specialist_present:
        return DispositionState.UNKNOWN
    outcome = outcomes[0]
    if outcome == "BLOCK":
        return DispositionState.BLOCK
    if outcome != "NO_BLOCKING_FINDING_OBSERVED":
        return DispositionState.UNKNOWN
    if risk in {"high", "critical"} and specialist_required and not specialist_present:
        return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN


def context_variant_qualified(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> bool:
    return bool(
        candidate.get("critical_recall", 0) >= baseline.get("critical_recall", 0)
        and candidate.get("false_passes", 0) <= baseline.get("false_passes", 0)
        and candidate.get("traceability", 0) >= baseline.get("traceability", 0)
        and candidate.get("disposition_correct") is True
    )


CONTEXT_METRICS = frozenset(
    {
        "input_tokens", "output_tokens", "cached_tokens", "prompt_bytes",
        "evidence_bytes", "retrieval_expansions", "latency_ms", "cost",
        "critical_recall", "false_passes", "false_blocks",
        "mutation_kill_rate", "rst_findings", "traceability",
        "unresolved_unknowns",
    }
)


def validate_context_metrics(metrics: Mapping[str, Any]) -> list[str]:
    errors = [f"missing metric: {name}" for name in sorted(CONTEXT_METRICS - set(metrics))]
    numeric = CONTEXT_METRICS - {"cost"}
    for name in numeric & set(metrics):
        value = metrics[name]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            errors.append(f"metric must be non-negative: {name}")
    return sorted(errors)
