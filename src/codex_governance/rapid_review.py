"""Pure policy for candidate-bound RST-inspired rapid review."""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from datetime import datetime
from typing import Any

from codex_governance.domain.model import DispositionState
from codex_governance.authority import decision_applies


RISK_PROFILES = frozenset({"low", "standard", "elevated"})
HAZARDOUS_CLASSES = frozenset(
    {
        "security",
        "authorization",
        "destructive_operations",
        "migration",
        "concurrency",
        "data_integrity",
        "public_api",
        "governance_boundary",
    }
)


def select_risk_profile(
    requested_profile: str,
    hazard_classes: Sequence[str],
    skip_rationale: str,
) -> tuple[str, int, bool]:
    """Resolve effective profile, minimum charters, and review requirement."""
    if requested_profile not in RISK_PROFILES:
        raise ValueError("risk profile must be low, standard, or elevated")
    hazards = set(hazard_classes)
    unknown = hazards - HAZARDOUS_CLASSES
    if unknown:
        raise ValueError("unknown hazard classes: " + ", ".join(sorted(unknown)))
    effective = "elevated" if hazards else requested_profile
    if effective == "low":
        if not isinstance(skip_rationale, str) or not skip_rationale.strip():
            raise ValueError("low-risk rapid-review skip requires a recorded rationale")
        return effective, 0, False
    if effective == "standard":
        return effective, 1, True
    return effective, 2, True


def _nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
    )


def _valid_story(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and isinstance(value.get("summary"), str)
        and bool(value["summary"].strip())
        and _nonempty_strings(value.get("evidence_refs"))
        and _nonempty_strings(value.get("limitations"))
    )


def evaluate_rapid_review(
    *,
    candidate_id: str,
    risk_assessment: Mapping[str, Any] | None,
    charters: Sequence[Mapping[str, Any]],
    sessions: Sequence[Mapping[str, Any]],
    debrief: Mapping[str, Any] | None,
    risk_disposition: Mapping[str, Any] | None,
    authorized_humans: Set[str],
    authenticated_decisions: Mapping[str, Mapping[str, Any]] | None = None,
    verified_decision_ids: Set[str] = frozenset(),
    repository_id: str | None = None,
    task_contract_sha256: str | None = None,
    policy_sha256: str | None = None,
    now: datetime | None = None,
) -> DispositionState:
    """Evaluate rapid-review facts without treating investigation as proof."""
    del authorized_humans
    if not isinstance(risk_assessment, Mapping):
        return DispositionState.UNKNOWN
    if risk_assessment.get("candidate_id") != candidate_id:
        return DispositionState.UNKNOWN
    if risk_assessment.get("change_kind") not in {
        "specification", "code", "mixed", "governance"
    }:
        return DispositionState.UNKNOWN
    hazards = risk_assessment.get("hazard_classes")
    if not isinstance(hazards, Sequence) or isinstance(hazards, (str, bytes)):
        return DispositionState.UNKNOWN
    try:
        profile, minimum_charters, required = select_risk_profile(
            str(risk_assessment.get("risk_profile")),
            hazards,
            str(risk_assessment.get("skip_rationale", "")),
        )
    except ValueError:
        return DispositionState.UNKNOWN
    if profile != risk_assessment.get("risk_profile"):
        return DispositionState.BLOCK
    if (
        risk_assessment.get("mandatory_charter_count") != minimum_charters
        or risk_assessment.get("rapid_review_required") is not required
    ):
        return DispositionState.BLOCK
    if not required and not charters and not sessions:
        return DispositionState.READY_FOR_HUMAN

    if len(charters) < minimum_charters:
        return DispositionState.UNKNOWN
    assessment_id = risk_assessment.get("assessment_id")
    charter_by_id: dict[str, Mapping[str, Any]] = {}
    for charter in charters:
        if not isinstance(charter, Mapping):
            return DispositionState.UNKNOWN
        charter_id = charter.get("charter_id")
        if (
            not isinstance(charter_id, str)
            or not charter_id
            or charter_id in charter_by_id
            or charter.get("candidate_id") != candidate_id
            or charter.get("risk_assessment_sha256") != assessment_id
            or not isinstance(charter.get("mission"), str)
            or not charter["mission"].strip()
            or not _nonempty_strings(charter.get("oracle_heuristics"))
            or not _nonempty_strings(charter.get("required_evidence"))
        ):
            return DispositionState.UNKNOWN
        charter_by_id[charter_id] = charter

    session_by_charter: dict[str, Mapping[str, Any]] = {}
    finding_severity: dict[str, str] = {}
    residual_material: dict[str, bool] = {}
    for session in sessions:
        if not isinstance(session, Mapping):
            return DispositionState.UNKNOWN
        charter_id = session.get("charter_id")
        if (
            session.get("candidate_id") != candidate_id
            or charter_id not in charter_by_id
            or charter_id in session_by_charter
        ):
            return DispositionState.UNKNOWN
        if session.get("status") in {"blocked", "inconclusive"}:
            return DispositionState.UNKNOWN
        if session.get("status") != "completed":
            return DispositionState.UNKNOWN
        experiments = session.get("experiments")
        if not isinstance(experiments, Sequence) or isinstance(experiments, (str, bytes)) or not experiments:
            return DispositionState.UNKNOWN
        investigation_observed = False
        for experiment in experiments:
            if not isinstance(experiment, Mapping):
                return DispositionState.UNKNOWN
            if experiment.get("activity_kind") == "investigation":
                investigation_observed = True
            if (
                experiment.get("activity_kind") not in {"checking", "investigation"}
                or not isinstance(experiment.get("observation"), str)
                or not experiment["observation"].strip()
                or not isinstance(experiment.get("oracle"), str)
                or not experiment["oracle"].strip()
                or not _nonempty_strings(experiment.get("evidence_refs"))
            ):
                return DispositionState.UNKNOWN
        if not investigation_observed:
            return DispositionState.UNKNOWN
        for field in (
            "counter_hypotheses", "coverage_achieved", "omitted_areas",
            "obstacles", "residual_risks",
        ):
            if not session.get(field):
                return DispositionState.UNKNOWN
        for finding in session.get("findings", ()):
            if not isinstance(finding, Mapping):
                return DispositionState.UNKNOWN
            finding_id = finding.get("finding_id")
            severity = finding.get("severity")
            if (
                not isinstance(finding_id, str)
                or not finding_id
                or finding_id in finding_severity
                or severity not in {"critical", "high", "medium", "low"}
                or finding.get("confidence") not in {"high", "medium", "low"}
                or not isinstance(finding.get("impact"), str)
                or not finding["impact"].strip()
                or not isinstance(finding.get("oracle"), str)
                or not finding["oracle"].strip()
                or not _nonempty_strings(finding.get("evidence_refs"))
                or not isinstance(finding.get("threatened_value"), str)
                or not finding["threatened_value"].strip()
            ):
                return DispositionState.UNKNOWN
            finding_severity[finding_id] = severity
        for residual in session["residual_risks"]:
            if not isinstance(residual, Mapping):
                return DispositionState.UNKNOWN
            risk_id = residual.get("risk_id")
            if (
                not isinstance(risk_id, str)
                or not risk_id
                or risk_id in residual_material
                or not isinstance(residual.get("material"), bool)
                or not _nonempty_strings(residual.get("evidence_refs"))
            ):
                return DispositionState.UNKNOWN
            residual_material[risk_id] = residual["material"]
        session_by_charter[charter_id] = session

    if set(session_by_charter) != set(charter_by_id):
        return DispositionState.UNKNOWN
    if not isinstance(debrief, Mapping) or debrief.get("candidate_id") != candidate_id:
        return DispositionState.UNKNOWN
    if set(debrief.get("session_refs", ())) != {
        session.get("session_id") for session in sessions
    }:
        return DispositionState.UNKNOWN
    if not all(
        _valid_story(debrief.get(field))
        for field in ("product_story", "testing_story", "quality_of_testing_story")
    ) or not _nonempty_strings(debrief.get("residual_risks")):
        return DispositionState.UNKNOWN

    if not isinstance(risk_disposition, Mapping) or risk_disposition.get("candidate_id") != candidate_id:
        return DispositionState.UNKNOWN
    disposition_by_id: dict[str, Mapping[str, Any]] = {}
    for item in risk_disposition.get("items", ()):
        if not isinstance(item, Mapping):
            return DispositionState.UNKNOWN
        item_id = item.get("item_id")
        if not isinstance(item_id, str) or not item_id or item_id in disposition_by_id:
            return DispositionState.UNKNOWN
        if not _nonempty_strings(item.get("evidence_refs")):
            return DispositionState.UNKNOWN
        disposition_by_id[item_id] = item
    expected_ids = set(finding_severity) | set(residual_material)
    if set(disposition_by_id) != expected_ids:
        return DispositionState.UNKNOWN

    for item_id, item in disposition_by_id.items():
        disposition = item.get("disposition")
        accepted = disposition == "accepted"
        if accepted:
            decision_ref = item.get("decision_ref")
            decision = (
                authenticated_decisions.get(decision_ref)
                if isinstance(authenticated_decisions, Mapping)
                and isinstance(decision_ref, str)
                else None
            )
            if (
                not isinstance(decision, Mapping)
                or not isinstance(repository_id, str)
                or not isinstance(task_contract_sha256, str)
                or not isinstance(policy_sha256, str)
                or not isinstance(now, datetime)
                or not decision_applies(
                    decision=decision,
                    repository_id=repository_id,
                    candidate_id=candidate_id,
                    task_contract_sha256=task_contract_sha256,
                    policy_sha256=policy_sha256,
                    required_type="risk_reduction",
                    required_scope=[item_id],
                    now=now,
                    source_verified=decision.get("decision_id") in verified_decision_ids,
                )
            ):
                return DispositionState.BLOCK
        severe = finding_severity.get(item_id) in {"critical", "high"}
        material = residual_material.get(item_id) is True
        if (severe or material) and disposition not in {"remediated", "accepted"}:
            return DispositionState.BLOCK
        if disposition == "unknown":
            return DispositionState.UNKNOWN
        if disposition not in {"remediated", "accepted", "deferred"}:
            return DispositionState.UNKNOWN
    return DispositionState.READY_FOR_HUMAN
