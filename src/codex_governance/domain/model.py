"""Immutable domain vocabulary.

This module deliberately contains no filesystem, Git, subprocess, clock, JSON, or
Codex dependencies.  Adapters translate external representations into these
values at the application boundary.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class GateStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ReviewerVerdict(StrEnum):
    NO_BLOCKING_FINDING_OBSERVED = "NO_BLOCKING_FINDING_OBSERVED"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class DispositionState(StrEnum):
    READY_FOR_HUMAN = "READY_FOR_HUMAN"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class ClaimClassification(StrEnum):
    DIRECTLY_OBSERVED = "DIRECTLY_OBSERVED"
    VERIFIED_WITHIN_SCOPE = "VERIFIED_WITHIN_SCOPE"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"


class CandidateMode(StrEnum):
    COMMIT = "commit"
    WORKING_TREE = "working_tree"


class RiskProfile(StrEnum):
    LOW = "low"
    STANDARD = "standard"
    ELEVATED = "elevated"


class RapidReviewSessionStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class TaskContract:
    task_id: str
    profile: str
    base_commit: str
    required_gate_ids: tuple[str, ...]
    governance_change_requested: bool
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    candidate_id: str
    mode: CandidateMode
    base_commit: str
    head_commit: str | None
    tracked_diff_sha256: str
    changed_paths: tuple[str, ...]
    effective_policy_sha256: str
    dirty: bool


@dataclass(frozen=True, slots=True)
class GateDefinition:
    gate_id: str
    profile: str
    command: tuple[str, ...]
    timeout_seconds: float
    max_output_bytes: int
    shell: bool = False
    risk_label: str | None = None


@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    candidate_before: str
    candidate_after: str
    status: GateStatus
    termination_kind: str
    exit_code: int | None
    observation_complete: bool
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReviewerResult:
    candidate_id: str
    verdict: ReviewerVerdict
    findings: tuple[dict[str, Any], ...] = ()
    missing_evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    manifest_id: str
    candidate_id: str
    task_contract: EvidenceReference
    effective_policy: EvidenceReference
    required_gate_ids: tuple[str, ...]
    gate_results: tuple[EvidenceReference, ...]
    reviewer_result: EvidenceReference


@dataclass(frozen=True, slots=True)
class Waiver:
    waiver_id: str
    candidate_id: str
    requirement_ids: tuple[str, ...]
    approver: str
    expires_at: str
    single_use: bool


@dataclass(frozen=True, slots=True)
class Disposition:
    candidate_id: str
    state: DispositionState
    reasons: tuple[str, ...]
    human_action_required: bool = True
    approved: bool = False


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    assessment_id: str
    candidate_id: str
    change_kind: str
    risk_profile: RiskProfile
    hazard_classes: tuple[str, ...]
    mandatory_charter_count: int


@dataclass(frozen=True, slots=True)
class ReviewCharter:
    charter_id: str
    candidate_id: str
    mission: str
    timebox_minutes: int


@dataclass(frozen=True, slots=True)
class RapidReviewSession:
    session_id: str
    candidate_id: str
    charter_id: str
    status: RapidReviewSessionStatus


@dataclass(frozen=True, slots=True)
class RapidReviewDebrief:
    debrief_id: str
    candidate_id: str
    product_story: str
    testing_story: str
    quality_of_testing_story: str


@dataclass(frozen=True, slots=True)
class RiskDisposition:
    risk_disposition_id: str
    candidate_id: str
    state: DispositionState
    human_owned: bool = True
    approved: bool = False


@dataclass(frozen=True, slots=True)
class AuthenticatedDecision:
    decision_id: str
    repository_id: str
    decision_type: str
    task_contract_sha256: str
    candidate_id: str | None
    effective_policy_sha256: str
    scope: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AssuranceClaim:
    claim_id: str
    argument_rule: str
    classification: ClaimClassification
    supporting_evidence: tuple[str, ...]
    refuting_evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    unresolved_defeaters: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceLocator:
    locator_id: str
    repository_id: str
    task_contract_sha256: str
    candidate_id: str
    kind: str
    path: str
    artifact_sha256: str


@dataclass(frozen=True, slots=True)
class ContextReceipt:
    receipt_id: str
    repository_id: str
    candidate_id: str
    profile: str
    source_sha256: str
    projection_sha256: str
    truncation_status: str
