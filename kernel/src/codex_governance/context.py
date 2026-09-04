"""Deterministic risk-aware model-context compiler."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_governance.artifacts import ArtifactSafetyError, read_bounded_repository_file
from codex_governance.candidate import verify_candidate_identity
from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    normalize_repo_path,
    require_sha256,
    sha256_bytes,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.qualification import context_variant_qualified


CONTEXT_PROFILES = ("COMPACT", "STANDARD", "DEEP")
CONTEXT_PROJECTION_VERSION = "1.0.0"
MANDATORY_REVIEWER_CLAIMS = (
    {"claim_id": "candidate_identity", "claim": "The exact candidate identity and diff were reviewed."},
    {"claim_id": "required_gates", "claim": "Every protected mandatory gate is reconstructed and successful."},
    {"claim_id": "affected_closure", "claim": "The complete protected affected closure was reviewed."},
    {"claim_id": "governance_integrity", "claim": "Governance authority and protected controls were not bypassed."},
    {"claim_id": "evidence_reconstruction", "claim": "Every relied-on evidence reference is resolved and digest-bound."},
)
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
    "mandatory_claims",
    "risks",
    "failures",
    "conflicts",
    "survivors",
    "limitations",
    "unknowns",
    "rubric",
    "disposition_contract",
)
REVIEW_RUBRIC = {
    "required_surfaces": [
        "exact_diff",
        "affected_closure",
        "governance_and_evidence",
    ],
    "finding_rule": "Every finding cites a requirement or oracle and a concrete repository location.",
    "success_rule": "No blocking finding is observed only within the exact reviewed closure.",
}
DISPOSITION_CONTRACT = {
    "ready": "Every fixed mandatory claim is supported and no unresolved defeater remains.",
    "block": "A confirmed failure, blocking finding, or unauthorized governance change blocks.",
    "unknown": "Missing, stale, conflicting, malformed, truncated, or unavailable evidence blocks.",
}


def build_repository_inventory(
    repository: Path,
    *,
    affected_closure: Sequence[str],
    changed_paths: Sequence[str],
) -> list[dict[str, str]]:
    """Hash the complete protected closure without following repository links."""
    changed = set(changed_paths)
    inventory: list[dict[str, str]] = []
    for raw_path in affected_closure:
        path = normalize_repo_path(raw_path)
        try:
            data = read_bounded_repository_file(repository, path, max_bytes=8_000_000)
        except ArtifactSafetyError as exc:
            absolute = repository.joinpath(*path.split("/"))
            try:
                absolute.lstat()
            except FileNotFoundError:
                if path not in changed:
                    raise ValueError(
                        "unchanged affected-closure file is unavailable"
                    ) from exc
                inventory.append({"path": path, "state": "absent"})
                continue
            raise ValueError(
                "affected-closure inventory requires bounded regular files"
            ) from exc
        inventory.append({"path": path, "state": "present", "sha256": sha256_bytes(data)})
    if [item["path"] for item in inventory] != sorted(
        set(item["path"] for item in inventory)
    ):
        raise ValueError("repository inventory must be a sorted unique closure")
    return inventory


def build_protected_context_sources(
    *,
    candidate: Mapping[str, Any],
    task: Mapping[str, Any],
    policy: Mapping[str, Any],
    repository_inventory: Sequence[Mapping[str, Any]],
    affected_closure: Sequence[str],
    gate_results: Sequence[Mapping[str, Any]],
    mutation_records: Sequence[Mapping[str, Any]],
    created_at: str,
    artifacts: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Construct the only admissible context source set from protected inputs."""
    repository_id = candidate.get("repository_id")
    if (
        not verify_candidate_identity(candidate)
        or task.get("repository_id") != repository_id
        or policy.get("repository_id") != repository_id
        or candidate.get("effective_policy_sha256") != sha256_canonical(policy)
    ):
        raise ValueError("protected context authority binding mismatch")
    parse_rfc3339(created_at)
    closure = [normalize_repo_path(path) for path in affected_closure]
    if closure != sorted(set(closure)) or not set(candidate.get("changed_paths", ())).issubset(closure):
        raise ValueError("protected context closure is incomplete")
    inventory = [dict(item) for item in repository_inventory]
    if [item.get("path") for item in inventory] != closure:
        raise ValueError("protected context inventory does not exactly cover the closure")
    gates = [dict(item) for item in gate_results]
    records = [dict(item) for item in mutation_records]
    failures = [item for item in gates if item.get("status") == "FAIL"]
    unknowns: list[Any] = list(task.get("unknowns", ()))
    unknowns.extend(
        item for item in gates if item.get("status") not in {"PASS", "FAIL"}
    )
    survivors = [item for item in records if item.get("outcome") == "SURVIVED"]
    unknowns.extend(
        item
        for item in records
        if item.get("outcome") not in {"KILLED", "SURVIVED"}
    )
    gate_ids = [item.get("gate_id") for item in gates]
    conflicts = (
        [{"kind": "duplicate_gate_id", "gate_id": gate_id}]
        if (gate_id := next(
            (item for item in gate_ids if gate_ids.count(item) > 1), None
        )) is not None
        else []
    )
    limitations = [
        {"kind": "gate", "gate_id": item.get("gate_id"), "values": item["limitations"]}
        for item in gates
        if item.get("limitations")
    ] + [
        {"kind": "mutation", "mutant_id": item.get("mutant_id"), "values": item["limitations"]}
        for item in records
        if item.get("limitations")
    ]
    return {
        "repository_id": repository_id,
        "candidate_id": candidate["candidate_id"],
        "created_at": created_at,
        "task_authority": dict(task),
        "policy": dict(policy),
        "repository_inventory": inventory,
        "changed_files": list(candidate.get("changed_paths", ())),
        "affected_closure": closure,
        "gate_results": gates,
        "mandatory_claims": [dict(item) for item in MANDATORY_REVIEWER_CLAIMS],
        "risks": list(task.get("risks", ())),
        "failures": failures,
        "conflicts": conflicts,
        "survivors": survivors,
        "limitations": limitations,
        "unknowns": unknowns,
        "rubric": REVIEW_RUBRIC,
        "disposition_contract": DISPOSITION_CONTRACT,
        "artifacts": [dict(item) for item in artifacts],
    }


def derive_context_signals(sources: Mapping[str, Any]) -> dict[str, bool]:
    """Derive profile escalation only from the complete protected source set."""
    gates = sources.get("gate_results", ())
    statuses = {
        item.get("status")
        for item in gates
        if isinstance(item, Mapping)
    }
    searchable = " ".join(
        str(value).lower()
        for key in ("risks", "conflicts", "limitations", "unknowns")
        for value in sources.get(key, ())
    )
    return {
        "gate_failed": "FAIL" in statuses or bool(sources.get("failures")),
        "gate_missing": not gates or "UNKNOWN" in statuses,
        "surviving_mutant": bool(sources.get("survivors")),
        "conflicting_oracle": bool(sources.get("conflicts")),
        "prompt_injection_risk": "prompt injection" in searchable,
        "authority_incomplete": "authority" in searchable,
        "provenance_incomplete": "provenance" in searchable,
        "reviewer_uncertain": bool(sources.get("unknowns")),
        "selector_uncertain": False,
    }


def context_qualification_valid(
    record: Mapping[str, Any], *, profile: str, protected_id: str
) -> bool:
    """Recompute one protected projection-profile qualification decision."""
    try:
        return bool(
            verify_content_address(record, "qualification_id")
            and record.get("qualification_id") == require_sha256(protected_id)
            and record.get("projection_version") == CONTEXT_PROJECTION_VERSION
            and record.get("profile") == profile
            and record.get("qualified") is True
            and context_variant_qualified(record["baseline"], record["candidate"])
        )
    except (KeyError, TypeError, ValueError):
        return False


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
    return {"kind": kind, "reference": reference, "sha256": sha256_canonical(value)}


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
    context_qualification: Mapping[str, Any],
    protected_qualification_ids: Mapping[str, str],
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
    mandatory_claims = [dict(item) for item in MANDATORY_REVIEWER_CLAIMS]
    if (
        "mandatory_claims" in sources
        and sources.get("mandatory_claims") != mandatory_claims
    ):
        raise ValueError("mandatory reviewer claims do not match protected policy")
    sources = dict(sources)
    sources["mandatory_claims"] = mandatory_claims
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
    risk_signals = derive_context_signals(sources)
    profile = select_context_profile(
        requested_profile=requested_profile,
        changed_paths=candidate_paths,
        **risk_signals,
    )
    kernel = {field: sources[field] for field in KERNEL_FIELDS}
    kernel_bytes = canonical_json_bytes(kernel)
    if profile != "DEEP" and (len(kernel_bytes) + 3) // 4 > token_budget:
        profile = "DEEP"
    protected_qualification_id = protected_qualification_ids.get(profile)
    if not isinstance(protected_qualification_id, str) or not context_qualification_valid(
        context_qualification,
        profile=profile,
        protected_id=protected_qualification_id,
    ):
        raise ValueError("context profile/version qualification is unavailable")
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

    source_bundle = content_address(
        {
            "schema_version": "1.0.0",
            "repository_id": sources["repository_id"],
            "candidate_id": sources["candidate_id"],
            "effective_policy_sha256": candidate["effective_policy_sha256"],
            "requested_profile": requested_profile,
            "token_budget": token_budget,
            "model": model,
            "reasoning_effort": reasoning_effort,
            "sources": dict(sources),
            "risk_signals": risk_signals,
            "created_at": str(created_at),
        },
        "source_bundle_id",
    )
    projection = content_address({
        "schema_version": "1.0.0",
        "source_bundle_id": source_bundle["source_bundle_id"],
        "repository_id": sources["repository_id"],
        "candidate_id": sources["candidate_id"],
        "projection_version": CONTEXT_PROJECTION_VERSION,
        "profile": profile,
        "context_qualification_id": context_qualification["qualification_id"],
        "stable_prefix": {
            "policy": sources["policy"],
            "rubric": sources["rubric"],
            "disposition_contract": sources["disposition_contract"],
        },
        "assurance_kernel": kernel,
        "evidence_index": sorted(included_artifacts, key=lambda item: item["reference"]),
        "progressive_disclosure": ["manifest", "typed_summary", "relevant_excerpt", "complete_artifact"],
    }, "projection_id")
    projection_bytes = canonical_json_bytes(projection)
    estimated_tokens = (len(projection_bytes) + 3) // 4
    insufficient = estimated_tokens > token_budget
    source_sha256 = sha256_canonical(source_bundle)
    projection_sha256 = sha256_canonical(projection)
    included = [
        _source_reference("authority", "task_authority", sources["task_authority"]),
        _source_reference("policy", "policy", sources["policy"]),
        _source_reference("inventory", "repository_inventory", sources["repository_inventory"]),
        _source_reference("change", "changed_files", sources["changed_files"]),
        _source_reference("closure", "affected_closure", sources["affected_closure"]),
        _source_reference("gate", "gate_results", sources["gate_results"]),
        _source_reference("rubric", "mandatory_claims", sources["mandatory_claims"]),
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
        "schema_version": "2.0.0",
        "repository_id": sources["repository_id"],
        "candidate_id": sources["candidate_id"],
        "projection_version": "1.0.0",
        "profile": profile,
        "context_qualification_id": context_qualification["qualification_id"],
        "source_bundle_sha256": source_sha256,
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
        "source_bundle": source_bundle,
        "projection": projection,
        "receipt": receipt,
        "retrieval_index": dict(sorted(retrieval_index.items())),
        "state": "UNKNOWN" if insufficient else "CONTEXT_READY",
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


def validate_retrieval_expansions(
    *,
    retrieval_expansions: Sequence[Mapping[str, Any]],
    retrieval_index: Mapping[str, str],
    artifact_reader: Any | None,
) -> list[dict[str, Any]]:
    """Resolve every reported disclosure through the protected retrieval index."""
    expansions = [dict(item) for item in retrieval_expansions]
    seen_expansions: set[tuple[str, str]] = set()
    for expansion in expansions:
        if (
            set(expansion) != {"reference", "sha256", "level", "reason"}
            or expansion["level"] not in {
                "typed_summary", "relevant_excerpt", "complete_artifact"
            }
            or not isinstance(expansion["reference"], str)
            or not isinstance(expansion["reason"], str)
            or not expansion["reason"].strip()
        ):
            raise ValueError("invalid retrieval expansion")
        digest = require_sha256(
            expansion["sha256"], name="retrieval expansion digest"
        )
        reference = expansion["reference"]
        key = (reference, expansion["level"])
        if (
            key in seen_expansions
            or retrieval_index.get(reference) != digest
            or not callable(artifact_reader)
        ):
            raise ValueError("retrieval expansion is not in the protected index")
        observed = artifact_reader(reference)
        if not isinstance(observed, bytes) or sha256_bytes(observed) != digest:
            raise ValueError("retrieval expansion artifact is unavailable or changed")
        seen_expansions.add(key)
    return expansions


def finalize_context_receipt(
    receipt: Mapping[str, Any],
    *,
    review_mode: str,
    reviewer_output_sha256: str,
    retrieval_expansions: Sequence[Mapping[str, Any]],
    retrieval_index: Mapping[str, str],
    artifact_reader: Any | None,
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
    expansions = validate_retrieval_expansions(
        retrieval_expansions=retrieval_expansions,
        retrieval_index=retrieval_index,
        artifact_reader=artifact_reader,
    )
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
