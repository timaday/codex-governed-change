"""Deterministic risk-aware model-context compiler."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from codex_governance.candidate import verify_candidate_identity
from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    normalize_repo_path,
    require_sha256,
    sha256_canonical,
)
from codex_governance.domain.model import DispositionState
from codex_governance.lifecycle import parse_rfc3339


CONTEXT_PROFILES = ("COMPACT", "STANDARD", "DEEP")
FORBIDDEN_SOURCE_KEYS = frozenset(
    {"author_conversation", "author_hidden_reasoning", "persisted_reasoning", "author_transcript"}
)
DEEP_PATH_PREFIXES = (
    "AGENTS.md",
    ".agents/",
    ".codex/",
    ".github/",
    "schemas/",
    "docs/architecture",
    "docs/threat-model",
    "src/codex_governance/admission",
    "src/codex_governance/authority",
    "src/codex_governance/assurance",
    "src/codex_governance/attestation",
    "src/codex_governance/context",
    "src/codex_governance/evidence",
    "src/codex_governance/governance",
    "src/codex_governance/reviewer",
)
KERNEL_FIELDS = (
    "task_authority",
    "policy",
    "repository_id",
    "candidate_id",
    "repository_inventory",
    "changed_files",
    "affected_closure",
    "gate_results",
    "risks",
    "failures",
    "conflicts",
    "survivors",
    "limitations",
    "unknowns",
    "rubric",
    "disposition_contract",
)


def select_context_profile(
    *,
    requested_profile: str,
    changed_paths: Sequence[str],
    gate_failed: bool = False,
    gate_missing: bool = False,
    surviving_mutant: bool = False,
    conflicting_oracle: bool = False,
    prompt_injection_risk: bool = False,
    authority_incomplete: bool = False,
    provenance_incomplete: bool = False,
    reviewer_uncertain: bool = False,
    selector_uncertain: bool = False,
) -> str:
    if requested_profile not in CONTEXT_PROFILES:
        raise ValueError("unknown context profile")
    deep_signal = any(
        (
            gate_failed,
            gate_missing,
            surviving_mutant,
            conflicting_oracle,
            prompt_injection_risk,
            authority_incomplete,
            provenance_incomplete,
            reviewer_uncertain,
            selector_uncertain,
            any(path == prefix or path.startswith(prefix) for path in changed_paths for prefix in DEEP_PATH_PREFIXES),
        )
    )
    return "DEEP" if deep_signal else requested_profile


def _source_reference(kind: str, reference: str, value: Any) -> dict[str, str]:
    digest = value.get("sha256") if isinstance(value, Mapping) else None
    if not isinstance(digest, str):
        digest = sha256_canonical(value)
    return {"kind": kind, "reference": reference, "sha256": digest}


def compile_context(
    *,
    sources: Mapping[str, Any],
    candidate: Mapping[str, Any],
    requested_profile: str,
    token_budget: int,
    changed_paths: Sequence[str],
    affected_closure: Sequence[str],
    model: str,
    reasoning_effort: str,
    gate_failed: bool = False,
    gate_missing: bool = False,
    surviving_mutant: bool = False,
    conflicting_oracle: bool = False,
    prompt_injection_risk: bool = False,
    authority_incomplete: bool = False,
    provenance_incomplete: bool = False,
    reviewer_uncertain: bool = False,
    selector_uncertain: bool = False,
) -> dict[str, Any]:
    if (
        not verify_candidate_identity(candidate)
        or candidate.get("repository_id") != sources.get("repository_id")
        or candidate.get("candidate_id") != sources.get("candidate_id")
    ):
        raise ValueError("context candidate identity is not verified and exact")
    candidate_paths = list(candidate.get("changed_paths", ()))
    if list(changed_paths) != candidate_paths:
        raise ValueError("context selector paths must exactly match the verified candidate")
    if sources.get("changed_files") != candidate_paths:
        raise ValueError("context changed files must exactly match the verified candidate")
    forbidden = FORBIDDEN_SOURCE_KEYS & set(sources)
    if forbidden:
        raise ValueError("author session state is forbidden context input: " + ", ".join(sorted(forbidden)))
    missing = [field for field in KERNEL_FIELDS if field not in sources]
    if missing:
        raise ValueError("mandatory context sources missing: " + ", ".join(missing))
    try:
        derived_closure = [normalize_repo_path(path) for path in affected_closure]
    except (TypeError, ValueError) as exc:
        raise ValueError("affected closure must be a canonical repository path list") from exc
    if (
        not derived_closure
        or derived_closure != sorted(set(derived_closure))
        or sources.get("affected_closure") != derived_closure
        or not set(candidate_paths).issubset(derived_closure)
    ):
        raise ValueError(
            "context affected closure must exactly match the protected repository derivation"
        )
    if not isinstance(token_budget, int) or token_budget < 1:
        token_budget = 0
    created_at = sources.get("created_at")
    try:
        parse_rfc3339(created_at)
    except (TypeError, ValueError) as exc:
        raise ValueError("context sources require an explicit RFC 3339 created_at") from exc
    profile = select_context_profile(
        requested_profile=requested_profile,
        changed_paths=candidate_paths,
        gate_failed=gate_failed,
        gate_missing=gate_missing,
        surviving_mutant=surviving_mutant,
        conflicting_oracle=conflicting_oracle,
        prompt_injection_risk=prompt_injection_risk,
        authority_incomplete=authority_incomplete,
        provenance_incomplete=provenance_incomplete,
        reviewer_uncertain=reviewer_uncertain,
        selector_uncertain=selector_uncertain,
    )
    kernel = {field: sources[field] for field in KERNEL_FIELDS}
    kernel_bytes = canonical_json_bytes(kernel)
    artifacts = sources.get("artifacts", ())
    included_artifacts: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    retrieval_index: dict[str, str] = {}
    seen_digests: set[str] = set()
    for raw in artifacts:
        if not isinstance(raw, Mapping):
            raise ValueError("context artifact must be an object")
        reference = raw.get("reference")
        digest = raw.get("sha256")
        if not isinstance(reference, str) or not isinstance(digest, str):
            raise ValueError("context artifact requires reference and digest")
        require_sha256(digest, name="context artifact digest")
        retrieval_index[reference] = digest
        if digest in seen_digests:
            excluded.append(
                {"reference": reference, "sha256": digest, "reason": "duplicate"}
            )
            continue
        seen_digests.add(digest)
        if raw.get("relevant") is True:
            projected: dict[str, Any] = {"reference": reference, "sha256": digest}
            if profile in {"STANDARD", "DEEP"} and raw.get("summary") is not None:
                projected["typed_summary"] = raw["summary"]
            if profile == "DEEP" and raw.get("excerpt") is not None:
                projected["relevant_excerpt"] = raw["excerpt"]
            included_artifacts.append(projected)
        else:
            excluded.append(
                {"reference": reference, "sha256": digest, "reason": "available_by_retrieval"}
            )

    projection = {
        "projection_version": "1.0.0",
        "profile": profile,
        "stable_prefix": {
            "policy": sources["policy"],
            "rubric": sources["rubric"],
            "disposition_contract": sources["disposition_contract"],
        },
        "assurance_kernel": kernel,
        "evidence_index": sorted(included_artifacts, key=lambda item: item["reference"]),
        "progressive_disclosure": ["manifest", "typed_summary", "relevant_excerpt", "complete_artifact"],
    }
    projection_bytes = canonical_json_bytes(projection)
    estimated_tokens = (len(projection_bytes) + 3) // 4
    insufficient = estimated_tokens > token_budget
    if insufficient and profile != "DEEP":
        profile = "DEEP"
        projection["profile"] = profile
        projection_bytes = canonical_json_bytes(projection)
        estimated_tokens = (len(projection_bytes) + 3) // 4
    source_sha256 = sha256_canonical(sources)
    projection_sha256 = sha256_canonical(projection)
    included = [
        _source_reference("authority", "task_authority", sources["task_authority"]),
        _source_reference("policy", "policy", sources["policy"]),
        _source_reference("inventory", "repository_inventory", sources["repository_inventory"]),
        _source_reference("change", "changed_files", sources["changed_files"]),
        _source_reference("closure", "affected_closure", sources["affected_closure"]),
        _source_reference("gate", "gate_results", sources["gate_results"]),
        _source_reference("risk", "risks", sources["risks"]),
        _source_reference("gate", "failures", sources["failures"]),
        _source_reference("unknown", "conflicts", sources["conflicts"]),
        _source_reference("mutation", "survivors", sources["survivors"]),
        _source_reference("limitation", "limitations", sources["limitations"]),
        _source_reference("unknown", "unknowns", sources["unknowns"]),
        _source_reference("rubric", "rubric", sources["rubric"]),
        _source_reference("rubric", "disposition_contract", sources["disposition_contract"]),
    ]
    receipt: dict[str, Any] = {
        "schema_version": "1.0.0",
        "repository_id": sources["repository_id"],
        "candidate_id": sources["candidate_id"],
        "projection_version": "1.0.0",
        "profile": profile,
        "source_sha256": source_sha256,
        "projection_sha256": projection_sha256,
        "included_sources": included,
        "excluded_sources": sorted(excluded, key=lambda item: item["reference"]),
        "estimated_input_tokens": estimated_tokens,
        "actual_input_tokens": 0,
        "actual_output_tokens": 0,
        "cached_input_tokens": 0,
        "prompt_bytes": len(canonical_json_bytes(projection["stable_prefix"])),
        "evidence_bytes": len(kernel_bytes),
        "retrieval_expansions": [],
        "truncation_status": "CONTEXT_BUDGET_INSUFFICIENT" if insufficient else "NONE",
        "model": model,
        "reasoning_effort": reasoning_effort,
        "latency_ms": 0,
        "cost": "unavailable",
        "quality_metrics": {
            "critical_defect_recall": "not-yet-qualified",
            "false_passes": 0,
            "false_blocks": 0,
            "mutation_kill_rate": "not-yet-measured",
            "evidence_traceability": "projection-complete",
            "unresolved_unknowns": len(sources["unknowns"]),
        },
        "created_at": str(created_at),
    }
    receipt = content_address(receipt, "receipt_id")
    return {
        "projection": projection,
        "receipt": receipt,
        "retrieval_index": dict(sorted(retrieval_index.items())),
        "state": DispositionState.UNKNOWN if insufficient else DispositionState.READY_FOR_HUMAN,
    }


def record_retrieval_expansion(
    *,
    receipt: Mapping[str, Any],
    retrieval_index: Mapping[str, str],
    reference: str,
    level: str,
    reason: str,
) -> dict[str, Any]:
    """Return a new content-addressed receipt for one verified disclosure step."""
    if level not in {"typed_summary", "relevant_excerpt", "complete_artifact"}:
        raise ValueError("unsupported retrieval expansion level")
    if not isinstance(reason, str) or not reason.strip() or reference not in retrieval_index:
        raise ValueError("retrieval expansion must name an indexed source and reason")
    require_sha256(retrieval_index[reference], name="retrieval expansion digest")
    updated = dict(receipt)
    expansions = [dict(item) for item in receipt.get("retrieval_expansions", ())]
    expansion = {
        "reference": reference,
        "sha256": retrieval_index[reference],
        "level": level,
        "reason": reason,
    }
    if expansion not in expansions:
        expansions.append(expansion)
    updated["retrieval_expansions"] = sorted(
        expansions,
        key=lambda item: (item["reference"], item["level"], item["reason"]),
    )
    return content_address(updated, "receipt_id")


def finalize_context_receipt(
    receipt: Mapping[str, Any],
    *,
    review_mode: str,
    reviewer_output_sha256: str,
    retrieval_expansions: Sequence[Mapping[str, Any]],
    usage_observed: bool,
    actual_input_tokens: int,
    actual_output_tokens: int,
    cached_input_tokens: int,
    reasoning_output_tokens: int,
    latency_ms: int,
    cost: str,
    created_at: str,
    limitations: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a post-run receipt without mutating the prepared input receipt."""
    if review_mode not in {"conformance", "rapid_review"}:
        raise ValueError("unknown review mode")
    metrics = (
        actual_input_tokens,
        actual_output_tokens,
        cached_input_tokens,
        reasoning_output_tokens,
        latency_ms,
    )
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in metrics):
        raise ValueError("context usage metrics must be non-negative integers")
    if not isinstance(usage_observed, bool) or not isinstance(cost, str):
        raise ValueError("context usage observation and cost are required")
    parse_rfc3339(created_at)
    expansions = [dict(item) for item in retrieval_expansions]
    for expansion in expansions:
        if (
            set(expansion) != {"reference", "sha256", "level", "reason"}
            or expansion["level"] not in {
                "typed_summary", "relevant_excerpt", "complete_artifact"
            }
            or not isinstance(expansion["reference"], str)
            or not isinstance(expansion["reason"], str)
        ):
            raise ValueError("invalid retrieval expansion")
        require_sha256(expansion["sha256"], name="retrieval expansion digest")
    prepared_sha256 = sha256_canonical(receipt)
    document = {
        "schema_version": "1.0.0",
        "repository_id": receipt.get("repository_id"),
        "candidate_id": receipt.get("candidate_id"),
        "input_context_receipt_sha256": prepared_sha256,
        "projection_sha256": require_sha256(receipt.get("projection_sha256")),
        "review_mode": review_mode,
        "reviewer_output_sha256": require_sha256(reviewer_output_sha256),
        "model": receipt.get("model"),
        "reasoning_effort": receipt.get("reasoning_effort"),
        "retrieval_expansions": sorted(
            expansions,
            key=lambda item: (item["reference"], item["level"], item["reason"]),
        ),
        "usage_observed": usage_observed,
        "input_tokens": actual_input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": actual_output_tokens,
        "reasoning_output_tokens": reasoning_output_tokens,
        "latency_ms": latency_ms,
        "cost": cost,
        "created_at": created_at,
        "limitations": list(limitations),
    }
    return content_address(document, "execution_receipt_id")
