"""Pure operational RST lineage and feedback policies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from codex_governance.canonical import require_sha256, verify_content_address
from codex_governance.domain.model import DispositionState


REQUIRED_RST_KINDS = frozenset(
    {"risk_register", "oracle_reference", "charter", "session", "coverage_note", "debrief", "follow_up"}
)


def validate_rst_lineage(
    repository_id: str,
    task_contract_sha256: str,
    candidate_id: str,
    artifacts: Sequence[Mapping[str, Any]] | None = None,
    *,
    risk_assessment: Mapping[str, Any] | None = None,
    risk_register: Mapping[str, Any] | None = None,
    oracle_references: Sequence[Mapping[str, Any]] = (),
    charters: Sequence[Mapping[str, Any]] = (),
    sessions: Sequence[Mapping[str, Any]] = (),
    coverage_notes: Sequence[Mapping[str, Any]] = (),
    debrief: Mapping[str, Any] | None = None,
    follow_ups: Sequence[Mapping[str, Any]] = (),
    risk_disposition: Mapping[str, Any] | None = None,
    evidence_index: Mapping[str, str] | None = None,
    requirement_sources: Sequence[str] = (),
    change_sources: Sequence[str] = (),
    charter_digests: Mapping[str, str] | None = None,
    debrief_digest: str | None = None,
    mutation_records: Sequence[Mapping[str, Any]] = (),
    reviewer_findings: Sequence[Mapping[str, Any]] = (),
) -> DispositionState:
    """Resolve the complete protected RST relationship graph."""
    if artifacts is not None:
        # Artifact-kind presence is intentionally never sufficient evidence.
        return DispositionState.UNKNOWN
    documents = [
        risk_assessment,
        risk_register,
        *oracle_references,
        *charters,
        *sessions,
        *coverage_notes,
        debrief,
        *follow_ups,
        risk_disposition,
    ]
    if any(
        not isinstance(item, Mapping)
        or item.get("repository_id") != repository_id
        or item.get("task_contract_sha256") != task_contract_sha256
        or item.get("candidate_id") != candidate_id
        for item in documents
    ):
        return DispositionState.UNKNOWN
    if not all(
        isinstance(values, Sequence) and not isinstance(values, (str, bytes))
        for values in (oracle_references, charters, sessions, coverage_notes, follow_ups)
    ):
        return DispositionState.UNKNOWN
    if not oracle_references or not charters or not sessions or not coverage_notes:
        return DispositionState.UNKNOWN
    try:
        index = {
            str(reference): require_sha256(digest)
            for reference, digest in (evidence_index or {}).items()
        }
        charter_digest_by_id = {
            str(charter_id): require_sha256(digest)
            for charter_id, digest in (charter_digests or {}).items()
        }
        expected_debrief_digest = require_sha256(debrief_digest)
        protected_requirement_sources = {
            str(identity) for identity in requirement_sources
        }
        protected_change_sources = {str(identity) for identity in change_sources}
    except (TypeError, ValueError):
        return DispositionState.UNKNOWN

    def unique_by(values: Sequence[Mapping[str, Any]], field: str) -> dict[str, Mapping[str, Any]] | None:
        result: dict[str, Mapping[str, Any]] = {}
        for value in values:
            identity = value.get(field) if isinstance(value, Mapping) else None
            if not isinstance(identity, str) or not identity or identity in result:
                return None
            result[identity] = value
        return result

    def refs_resolve(values: Any) -> bool:
        if (
            not isinstance(values, Sequence)
            or isinstance(values, (str, bytes))
            or not values
            or not all(isinstance(value, str) for value in values)
        ):
            return False
        return len(values) == len(set(values)) and all(
            value in index for value in values
        )

    assessment_id = risk_assessment.get("assessment_id")
    if not isinstance(assessment_id, str) or not assessment_id:
        return DispositionState.UNKNOWN
    charter_by_id = unique_by(charters, "charter_id")
    session_by_id = unique_by(sessions, "session_id")
    oracle_by_id = unique_by(oracle_references, "oracle_id")
    coverage_by_id = unique_by(coverage_notes, "coverage_note_id")
    follow_up_by_id = unique_by(follow_ups, "follow_up_id")
    if any(
        value is None
        for value in (
            charter_by_id,
            session_by_id,
            oracle_by_id,
            coverage_by_id,
            follow_up_by_id,
        )
    ):
        return DispositionState.UNKNOWN
    assert charter_by_id is not None
    assert session_by_id is not None
    assert oracle_by_id is not None
    assert coverage_by_id is not None
    assert follow_up_by_id is not None
    if set(charter_digest_by_id) != set(charter_by_id):
        return DispositionState.UNKNOWN
    for charter_id, charter in charter_by_id.items():
        if (
            charter.get("risk_assessment_sha256") != assessment_id
            or charter_digest_by_id.get(charter_id) is None
        ):
            return DispositionState.UNKNOWN

    experiment_ids: set[str] = set()
    finding_ids: set[str] = set()
    residual_ids: set[str] = set()
    for session in sessions:
        charter_id = session.get("charter_id")
        if (
            charter_id not in charter_by_id
            or session.get("charter_sha256") != charter_digest_by_id.get(charter_id)
        ):
            return DispositionState.UNKNOWN
        for collection, field, identities in (
            (session.get("experiments"), "id", experiment_ids),
            (session.get("findings", ()), "finding_id", finding_ids),
            (session.get("residual_risks"), "risk_id", residual_ids),
        ):
            if not isinstance(collection, Sequence) or isinstance(collection, (str, bytes)):
                return DispositionState.UNKNOWN
            for item in collection:
                identity = item.get(field) if isinstance(item, Mapping) else None
                if (
                    not isinstance(identity, str)
                    or not identity
                    or identity in identities
                    or not refs_resolve(item.get("evidence_refs"))
                ):
                    return DispositionState.UNKNOWN
                identities.add(identity)
        for expansion in session.get("retrieval_expansions", ()):
            if (
                not isinstance(expansion, Mapping)
                or index.get(expansion.get("reference")) != expansion.get("sha256")
            ):
                return DispositionState.UNKNOWN

    for oracle_id, oracle in oracle_by_id.items():
        if (
            not verify_content_address(oracle, "oracle_id")
            or oracle_id != oracle.get("oracle_id")
            or index.get(oracle.get("source")) != oracle.get("source_sha256")
        ):
            return DispositionState.UNKNOWN
    coverage_session_sequence: list[str] = []
    coverage_oracle_sequence: list[str] = []
    for coverage_id, note in coverage_by_id.items():
        oracle_refs = note.get("oracle_refs")
        if (
            not verify_content_address(note, "coverage_note_id")
            or coverage_id != note.get("coverage_note_id")
            or note.get("session_id") not in session_by_id
            or not isinstance(oracle_refs, Sequence)
            or isinstance(oracle_refs, (str, bytes))
            or not oracle_refs
            or len(oracle_refs) != len(set(oracle_refs))
            or not set(oracle_refs).issubset(oracle_by_id)
        ):
            return DispositionState.UNKNOWN
        coverage_session_sequence.append(str(note["session_id"]))
        coverage_oracle_sequence.extend(str(reference) for reference in oracle_refs)
    if (
        len(coverage_session_sequence) != len(set(coverage_session_sequence))
        or set(coverage_session_sequence) != set(session_by_id)
        or len(coverage_oracle_sequence) != len(set(coverage_oracle_sequence))
        or set(coverage_oracle_sequence) != set(oracle_by_id)
    ):
        return DispositionState.UNKNOWN

    risk_ids: set[str] = set()
    for risk in risk_register.get("risks", ()):
        risk_id = risk.get("risk_id") if isinstance(risk, Mapping) else None
        charter_refs = risk.get("charter_refs") if isinstance(risk, Mapping) else None
        if (
            not isinstance(risk_id, str)
            or not risk_id
            or risk_id in risk_ids
            or not refs_resolve(risk.get("source_refs"))
            or not isinstance(charter_refs, Sequence)
            or isinstance(charter_refs, (str, bytes))
            or not charter_refs
            or any(not isinstance(reference, str) for reference in charter_refs)
            or len(charter_refs) != len(set(charter_refs))
            or not set(charter_refs).issubset(charter_by_id)
        ):
            return DispositionState.UNKNOWN
        risk_ids.add(risk_id)
    if not risk_ids or not verify_content_address(risk_register, "risk_register_id"):
        return DispositionState.UNKNOWN

    mutant_ids = {
        str(record.get("mutant_id"))
        for record in mutation_records
        if isinstance(record, Mapping) and isinstance(record.get("mutant_id"), str)
    }
    reviewer_finding_ids = {
        str(finding.get("finding_id"))
        for finding in reviewer_findings
        if isinstance(finding, Mapping)
        and isinstance(finding.get("finding_id"), str)
    }
    if len(mutant_ids) != len(mutation_records) or len(reviewer_finding_ids) != len(
        reviewer_findings
    ) or reviewer_finding_ids & finding_ids:
        return DispositionState.UNKNOWN
    typed_sources: dict[str, set[str]] = {
        "session": set(session_by_id),
        "observation": experiment_ids,
        "mutant": set(mutant_ids),
        "reviewer_finding": set(reviewer_finding_ids) | finding_ids,
        "debrief": {str(debrief.get("debrief_id"))},
        "requirement": protected_requirement_sources,
        "change": protected_change_sources,
    }
    updated_from = risk_register.get("updated_from", ())
    if (
        not isinstance(updated_from, Sequence)
        or isinstance(updated_from, (str, bytes))
        or not updated_from
        or len(updated_from) != len(set(updated_from))
    ):
        return DispositionState.UNKNOWN
    for reference in updated_from:
        if not isinstance(reference, str) or ":" not in reference:
            return DispositionState.UNKNOWN
        kind, identity = reference.split(":", 1)
        if identity not in typed_sources.get(kind, set()):
            return DispositionState.UNKNOWN
    expected_updates = {
        *(f"requirement:{identity}" for identity in protected_requirement_sources),
        *(f"change:{identity}" for identity in protected_change_sources),
        *(f"observation:{identity}" for identity in experiment_ids),
        *(
            f"mutant:{record['mutant_id']}"
            for record in mutation_records
            if record.get("outcome") == "SURVIVED"
        ),
        *(
            f"reviewer_finding:{identity}"
            for identity in reviewer_finding_ids | finding_ids
        ),
    }
    if set(updated_from) != expected_updates:
        return DispositionState.UNKNOWN

    session_refs = debrief.get("session_refs", ())
    actionable_findings = debrief.get("actionable_findings", ())
    residual_risks = debrief.get("residual_risks", ())
    if any(
        not isinstance(values, Sequence)
        or isinstance(values, (str, bytes))
        or len(values) != len(set(values))
        for values in (session_refs, actionable_findings, residual_risks)
    ):
        return DispositionState.UNKNOWN
    if set(session_refs) != set(session_by_id):
        return DispositionState.UNKNOWN
    for field in ("product_story", "testing_story", "quality_of_testing_story"):
        story = debrief.get(field)
        if not isinstance(story, Mapping) or not refs_resolve(story.get("evidence_refs")):
            return DispositionState.UNKNOWN
    if set(actionable_findings) != finding_ids:
        return DispositionState.UNKNOWN
    if set(residual_risks) != residual_ids:
        return DispositionState.UNKNOWN

    for follow_up_id, follow_up in follow_up_by_id.items():
        if (
            not verify_content_address(follow_up, "follow_up_id")
            or follow_up_id != follow_up.get("follow_up_id")
            or follow_up.get("source_id")
            not in typed_sources.get(str(follow_up.get("source_kind")), set())
        ):
            return DispositionState.UNKNOWN

    observations = [
        experiment
        for session in sessions
        for experiment in session.get("experiments", ())
        if isinstance(experiment, Mapping)
    ]
    expected_feedback = derive_follow_ups(
        observations=observations,
        mutants=mutation_records,
        reviewer_findings=[
            *reviewer_findings,
            *(
                finding
                for session in sessions
                for finding in session.get("findings", ())
                if isinstance(finding, Mapping)
            ),
        ],
    )
    expected_edges = {
        (item["source_kind"], item["source_id"], item["required"])
        for item in expected_feedback
    }
    observed_edge_list = [
        (
            item.get("source_kind"),
            item.get("source_id"),
            item.get("required"),
        )
        for item in follow_ups
    ]
    if (
        len(observed_edge_list) != len(set(observed_edge_list))
        or set(observed_edge_list) != expected_edges
    ):
        return DispositionState.UNKNOWN

    if risk_disposition.get("debrief_sha256") != expected_debrief_digest:
        return DispositionState.UNKNOWN
    expected_item_ids = finding_ids | residual_ids
    items = risk_disposition.get("items")
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        return DispositionState.UNKNOWN
    observed_item_ids: set[str] = set()
    for item in items:
        item_id = item.get("item_id") if isinstance(item, Mapping) else None
        if (
            not isinstance(item_id, str)
            or item_id in observed_item_ids
            or not refs_resolve(item.get("evidence_refs"))
        ):
            return DispositionState.UNKNOWN
        observed_item_ids.add(item_id)
    if observed_item_ids != expected_item_ids:
        return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN


def derive_follow_ups(
    *,
    observations: Sequence[Mapping[str, Any]],
    mutants: Sequence[Mapping[str, Any]],
    reviewer_findings: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in observations:
        if item.get("surprise"):
            result.append({"source_kind": "observation", "source_id": item.get("id"), "required": False})
    for item in mutants:
        if item.get("outcome") == "SURVIVED":
            result.append({"source_kind": "mutant", "source_id": item.get("mutant_id", item.get("id")), "required": True})
    for item in reviewer_findings:
        if item.get("severity") in {"critical", "high", "medium", "low"}:
            result.append({"source_kind": "reviewer_finding", "source_id": item.get("finding_id", item.get("id")), "required": item.get("severity") in {"critical", "high"}})
    return result


def evaluate_operational_rst(
    *,
    artifacts_complete: bool,
    direct_observations: Sequence[Any],
    fallible_oracles: Sequence[Any],
    coverage_notes: Sequence[Any],
    unresolved_follow_ups: Sequence[Any],
) -> DispositionState:
    if unresolved_follow_ups:
        return DispositionState.BLOCK
    if not artifacts_complete or not direct_observations or not fallible_oracles or not coverage_notes:
        return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN
