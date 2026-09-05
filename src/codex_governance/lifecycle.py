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


def migrate_context_qualification_v1_to_v2(
    document: Mapping[str, Any], *, evidence_class: str
) -> dict[str, Any]:
    """Add a separately protected empirical or bootstrap evidence class."""
    from codex_governance.canonical import content_address

    migrated = _legacy_document(document, identity_field="qualification_id")
    if "evidence_class" in migrated or evidence_class not in {
        "empirical",
        "synthetic_bootstrap",
    }:
        raise ValueError("protected context qualification evidence class is required")
    migrated["schema_version"] = "2.0.0"
    migrated["evidence_class"] = evidence_class
    if evidence_class == "synthetic_bootstrap":
        migrated["qualified"] = False
        limitations = list(migrated.get("limitations", ()))
        limitation = (
            "Synthetic bootstrap context is not empirical qualification evidence."
        )
        if limitation not in limitations:
            limitations.append(limitation)
        migrated["limitations"] = limitations
    return content_address(migrated, "qualification_id")


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


def _migration_document(
    document: Mapping[str, Any], *, from_version: str, identity_field: str | None
) -> dict[str, Any]:
    from codex_governance.canonical import verify_content_address

    if document.get("schema_version") != from_version:
        raise ValueError(f"migration input must use schema version {from_version}")
    if identity_field is not None and not verify_content_address(
        document, identity_field
    ):
        raise ValueError("migration input content address does not reconstruct")
    return dict(document)


def _finish_migration(
    document: Mapping[str, Any], *, to_version: str, identity_field: str | None
) -> dict[str, Any]:
    from codex_governance.canonical import content_address

    migrated = dict(document)
    migrated["schema_version"] = to_version
    return (
        content_address(migrated, identity_field)
        if identity_field is not None
        else migrated
    )


def _reference(value: Mapping[str, Any], *, name: str) -> dict[str, str]:
    from codex_governance.canonical import normalize_repo_path, require_sha256

    if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
        raise ValueError(f"protected {name} reference is required")
    return {
        "path": normalize_repo_path(value["path"]),
        "sha256": require_sha256(value["sha256"], name=f"{name} sha256"),
    }


def migrate_effective_policy_v1_to_v2(
    document: Mapping[str, Any], *, context_qualification_ids: Mapping[str, str],
    reviewer_qualification_corpus_sha256: str,
    reviewer_qualification_label_decision_id: str,
) -> dict[str, Any]:
    """Add protected context and reviewer qualification authority to policy v1."""
    from codex_governance.canonical import require_sha256

    migrated = _migration_document(
        document, from_version="1.0.0", identity_field=None
    )
    context = migrated.get("context")
    reviewer = migrated.get("reviewer")
    if not isinstance(context, Mapping) or not isinstance(reviewer, Mapping):
        raise ValueError("legacy effective policy sections are unavailable")
    if "qualification_ids" in context or any(
        key in reviewer
        for key in ("qualification_corpus_sha256", "qualification_label_decision_id")
    ):
        raise ValueError("legacy effective policy already contains v2 fields")
    if set(context_qualification_ids) != {"COMPACT", "STANDARD", "DEEP"}:
        raise ValueError("all protected context qualification IDs are required")
    migrated["context"] = {
        **context,
        "qualification_ids": {
            key: require_sha256(value, name=f"{key} qualification")
            for key, value in context_qualification_ids.items()
        },
    }
    migrated["reviewer"] = {
        **reviewer,
        "qualification_corpus_sha256": require_sha256(
            reviewer_qualification_corpus_sha256,
            name="reviewer qualification corpus",
        ),
        "qualification_label_decision_id": require_sha256(
            reviewer_qualification_label_decision_id,
            name="reviewer qualification label decision",
        ),
    }
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field=None
    )


def migrate_effective_policy_v2_to_v3(
    document: Mapping[str, Any], *, mutation_corpus_sha256: str
) -> dict[str, Any]:
    """Bind policy v3 to the exact previous-LKG mutation corpus bytes."""
    from codex_governance.canonical import require_sha256

    migrated = _migration_document(
        document, from_version="2.0.0", identity_field=None
    )
    mutation = migrated.get("mutation")
    if not isinstance(mutation, Mapping) or "corpus_sha256" in mutation:
        raise ValueError("legacy mutation policy is not a v2 migration input")
    migrated["mutation"] = {
        **mutation,
        "corpus_sha256": require_sha256(
            mutation_corpus_sha256, name="mutation corpus"
        ),
    }
    return _finish_migration(
        migrated, to_version="3.0.0", identity_field=None
    )


def migrate_evidence_manifest_v1_to_v2(
    document: Mapping[str, Any], *, protected_references: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Add the seven protected qualification/context references introduced by v2."""
    required = {
        "reviewer_qualification_cases",
        "rapid_review_qualification_cases",
        "reviewer_qualification_corpus",
        "reviewer_qualification_label_decision",
        "context_sources",
        "context_projection",
        "context_qualification",
    }
    if set(protected_references) != required:
        raise ValueError("complete v2 evidence-manifest references are required")
    migrated = _migration_document(
        document, from_version="1.0.0", identity_field="manifest_id"
    )
    if required & set(migrated):
        raise ValueError("legacy evidence manifest already contains v2 fields")
    migrated.update(
        {
            name: _reference(protected_references[name], name=name)
            for name in sorted(required)
        }
    )
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field="manifest_id"
    )


def migrate_evidence_manifest_v2_to_v3(
    document: Mapping[str, Any], *, lkg_policy_decision: Mapping[str, Any],
    proposed_policy: Mapping[str, Any] | None = None,
    lkg_promotion_decision: Mapping[str, Any] | None = None,
    rollback_evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Add authenticated previous-LKG authority and optional promotion evidence."""
    migrated = _migration_document(
        document, from_version="2.0.0", identity_field="manifest_id"
    )
    additions = {
        "lkg_policy_decision": _reference(
            lkg_policy_decision, name="lkg policy decision"
        )
    }
    optional = (proposed_policy, lkg_promotion_decision, rollback_evidence)
    if any(item is not None for item in optional):
        if not all(item is not None for item in optional):
            raise ValueError("complete governance promotion references are required")
        additions.update(
            proposed_policy=_reference(proposed_policy, name="proposed policy"),
            lkg_promotion_decision=_reference(
                lkg_promotion_decision, name="LKG promotion decision"
            ),
            rollback_evidence=_reference(
                rollback_evidence, name="rollback evidence"
            ),
        )
    if set(additions) & set(migrated):
        raise ValueError("legacy evidence manifest already contains v3 fields")
    migrated.update(additions)
    return _finish_migration(
        migrated, to_version="3.0.0", identity_field="manifest_id"
    )


def migrate_evidence_manifest_v3_to_v4(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Move a valid previous-LKG v3 manifest to the dual-mode v4 contract."""
    migrated = _migration_document(
        document, from_version="3.0.0", identity_field="manifest_id"
    )
    if "lkg_policy_decision" not in migrated or {
        "initial_bootstrap_decision",
        "initial_bootstrap_verification",
    } & set(migrated):
        raise ValueError("legacy evidence manifest is not a previous-LKG v3 input")
    return _finish_migration(
        migrated, to_version="4.0.0", identity_field="manifest_id"
    )


def migrate_reviewer_qualification_v1_to_v2(
    document: Mapping[str, Any], *, label_decision_id: str,
    case_evidence_sha256: str,
) -> dict[str, Any]:
    from codex_governance.canonical import require_sha256

    migrated = _migration_document(
        document, from_version="1.0.0", identity_field="qualification_id"
    )
    if "label_decision_id" in migrated or "case_evidence_sha256" in migrated:
        raise ValueError("legacy reviewer qualification already contains v2 fields")
    migrated["label_decision_id"] = require_sha256(label_decision_id)
    migrated["case_evidence_sha256"] = require_sha256(case_evidence_sha256)
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field="qualification_id"
    )


def migrate_reviewer_qualification_v2_to_v3(
    document: Mapping[str, Any], *, authentication: str
) -> dict[str, Any]:
    """Bind a legacy reviewer qualification to protected ChatGPT authentication."""
    migrated = _migration_document(
        document, from_version="2.0.0", identity_field="qualification_id"
    )
    if "authentication" in migrated or authentication != "chatgpt":
        raise ValueError("protected ChatGPT authentication is required")
    migrated["authentication"] = authentication
    return _finish_migration(
        migrated, to_version="3.0.0", identity_field="qualification_id"
    )


def migrate_reviewer_qualification_cases_v1_to_v2(
    document: Mapping[str, Any]
) -> dict[str, Any]:
    migrated = _migration_document(
        document, from_version="1.0.0", identity_field="case_evidence_id"
    )
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field="case_evidence_id"
    )


def migrate_reviewer_qualification_cases_v2_to_v3(
    document: Mapping[str, Any], *, context_references: Mapping[str, Mapping[str, Mapping[str, Any]]]
) -> dict[str, Any]:
    required = {
        "context_sources",
        "context_projection",
        "context_qualification",
        "context_receipt",
        "context_execution_receipt",
    }
    migrated = _migration_document(
        document, from_version="2.0.0", identity_field="case_evidence_id"
    )
    observations = migrated.get("observations")
    if not isinstance(observations, Sequence) or isinstance(observations, (str, bytes)):
        raise ValueError("legacy reviewer case observations are unavailable")
    rebuilt = []
    for raw in observations:
        if not isinstance(raw, Mapping):
            raise ValueError("legacy reviewer case observation is invalid")
        case_id = raw.get("case_id")
        supplied = context_references.get(str(case_id))
        if not isinstance(supplied, Mapping) or set(supplied) != required:
            raise ValueError("complete protected case context references are required")
        if required & set(raw):
            raise ValueError("legacy reviewer case already contains v3 fields")
        rebuilt.append(
            {
                **raw,
                **{
                    name: _reference(supplied[name], name=f"{case_id} {name}")
                    for name in sorted(required)
                },
            }
        )
    if set(context_references) != {str(item.get("case_id")) for item in observations}:
        raise ValueError("case context reference set does not match observations")
    migrated["observations"] = rebuilt
    return _finish_migration(
        migrated, to_version="3.0.0", identity_field="case_evidence_id"
    )


def migrate_reviewer_qualification_cases_v3_to_v4(
    document: Mapping[str, Any],
    *,
    evidence_references: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    """Add protected invocation-material references absent from v3 cases."""
    migrated = _migration_document(
        document, from_version="3.0.0", identity_field="case_evidence_id"
    )
    observations = migrated.get("observations")
    if not isinstance(observations, Sequence) or isinstance(
        observations, (str, bytes)
    ):
        raise ValueError("legacy reviewer case observations are unavailable")
    required = {"permitted_inputs"}
    if migrated.get("mode") == "rapid_review":
        required.update(("risk_assessment", "review_charter"))
    rebuilt = []
    for raw in observations:
        if not isinstance(raw, Mapping):
            raise ValueError("legacy reviewer case observation is invalid")
        case_id = str(raw.get("case_id"))
        supplied = evidence_references.get(case_id)
        if not isinstance(supplied, Mapping) or set(supplied) != required:
            raise ValueError(
                "complete protected case invocation references are required"
            )
        if required & set(raw):
            raise ValueError("legacy reviewer case already contains v4 fields")
        rebuilt.append(
            {
                **raw,
                **{
                    name: _reference(supplied[name], name=f"{case_id} {name}")
                    for name in sorted(required)
                },
            }
        )
    if set(evidence_references) != {
        str(item.get("case_id")) for item in observations
    }:
        raise ValueError("case invocation reference set does not match observations")
    migrated["observations"] = rebuilt
    return _finish_migration(
        migrated, to_version="4.0.0", identity_field="case_evidence_id"
    )


def migrate_reviewer_qualification_cases_v4_to_v5(
    document: Mapping[str, Any], *, authentication: str
) -> dict[str, Any]:
    """Bind qualification case evidence to protected ChatGPT authentication."""
    migrated = _migration_document(
        document, from_version="4.0.0", identity_field="case_evidence_id"
    )
    identity = migrated.get("identity")
    if (
        not isinstance(identity, Mapping)
        or "authentication" in identity
        or authentication != "chatgpt"
    ):
        raise ValueError("protected ChatGPT authentication is required")
    migrated["identity"] = {**identity, "authentication": authentication}
    return _finish_migration(
        migrated, to_version="5.0.0", identity_field="case_evidence_id"
    )


def migrate_reviewer_qualification_corpus_v1_to_v2(
    document: Mapping[str, Any], *, case_classes: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    allowed = {"seeded_defect", "prompt_injection", "clean_control"}
    migrated = _migration_document(
        document, from_version="1.0.0", identity_field="corpus_id"
    )
    cases = migrated.get("cases")
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes)):
        raise ValueError("legacy reviewer corpus cases are unavailable")
    rebuilt = []
    for raw in cases:
        if not isinstance(raw, Mapping) or "case_classes" in raw:
            raise ValueError("legacy reviewer corpus case is invalid")
        case_id = str(raw.get("case_id"))
        values = case_classes.get(case_id)
        if (
            not isinstance(values, Sequence)
            or isinstance(values, (str, bytes))
            or not values
            or len(values) != len(set(values))
            or any(value not in allowed for value in values)
        ):
            raise ValueError("protected case classes are incomplete")
        rebuilt.append({**raw, "case_classes": list(values)})
    if set(case_classes) != {str(item.get("case_id")) for item in cases}:
        raise ValueError("case class set does not match the corpus")
    migrated["cases"] = rebuilt
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field="corpus_id"
    )


def migrate_reviewer_qualification_corpus_v2_to_v3(
    document: Mapping[str, Any], *, expected_findings: Mapping[str, Mapping[str, Any] | None]
) -> dict[str, Any]:
    migrated = _migration_document(
        document, from_version="2.0.0", identity_field="corpus_id"
    )
    cases = migrated.get("cases")
    if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes)):
        raise ValueError("legacy reviewer corpus cases are unavailable")
    rebuilt = []
    case_ids = {str(item.get("case_id")) for item in cases if isinstance(item, Mapping)}
    if set(expected_findings) != case_ids:
        raise ValueError("expected finding set does not match the corpus")
    for raw in cases:
        if not isinstance(raw, Mapping) or "expected_finding" in raw:
            raise ValueError("legacy reviewer corpus case is invalid")
        case_id = str(raw.get("case_id"))
        expected = expected_findings[case_id]
        if raw.get("severity") == "critical":
            if not isinstance(expected, Mapping) or set(expected) != {
                "defect_id",
                "path",
                "line",
            }:
                raise ValueError("protected critical expected finding is incomplete")
            value: Mapping[str, Any] | None = dict(expected)
        elif raw.get("severity") == "control" and expected is None:
            value = None
        else:
            raise ValueError("protected expected finding conflicts with case severity")
        rebuilt.append({**raw, "expected_finding": value})
    migrated["cases"] = rebuilt
    return _finish_migration(
        migrated, to_version="3.0.0", identity_field="corpus_id"
    )


def migrate_reviewer_result_v1_to_v2(
    document: Mapping[str, Any]
) -> dict[str, Any]:
    migrated = _migration_document(
        document, from_version="1.0.0", identity_field=None
    )
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field=None
    )


def migrate_rapid_review_session_v1_to_v2(
    document: Mapping[str, Any], *,
    finding_targets: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Add protected path/line targets to legacy rapid-review findings."""
    from codex_governance.canonical import normalize_repo_path

    migrated = _migration_document(
        document, from_version="1.0.0", identity_field=None
    )
    findings = migrated.get("findings")
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        raise ValueError("legacy rapid-review findings are unavailable")
    rebuilt = []
    finding_ids = {
        str(item.get("finding_id"))
        for item in findings
        if isinstance(item, Mapping)
    }
    if len(finding_ids) != len(findings) or set(finding_targets) != finding_ids:
        raise ValueError("rapid-review finding target set does not match")
    for raw in findings:
        if not isinstance(raw, Mapping) or {"path", "line"} & set(raw):
            raise ValueError("legacy rapid-review finding is invalid")
        finding_id = str(raw.get("finding_id"))
        target = finding_targets.get(finding_id)
        if not isinstance(target, Mapping) or set(target) != {"path", "line"}:
            raise ValueError("protected rapid-review finding target is incomplete")
        line = target.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise ValueError("protected rapid-review finding line is invalid")
        rebuilt.append(
            {
                **raw,
                "path": normalize_repo_path(target["path"]),
                "line": line,
            }
        )
    migrated["findings"] = rebuilt
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field=None
    )


def migrate_reviewer_result_v2_to_v3(
    document: Mapping[str, Any], *, claim_ids: Sequence[str]
) -> dict[str, Any]:
    from codex_governance.context import MANDATORY_REVIEWER_CLAIMS

    required_claim_ids = {
        item["claim_id"] for item in MANDATORY_REVIEWER_CLAIMS
    }
    migrated = _migration_document(
        document, from_version="2.0.0", identity_field=None
    )
    claims = migrated.get("claims")
    if (
        not isinstance(claims, Sequence)
        or isinstance(claims, (str, bytes))
        or len(claims) != len(claim_ids)
        or set(claim_ids) != required_claim_ids
    ):
        raise ValueError("the exact protected reviewer claim IDs are required")
    rebuilt = []
    for claim, claim_id in zip(claims, claim_ids, strict=True):
        if (
            not isinstance(claim, Mapping)
            or "claim_id" in claim
            or not claim.get("evidence_refs")
        ):
            raise ValueError("legacy reviewer claim cannot satisfy v3")
        rebuilt.append({"claim_id": claim_id, **claim})
    migrated["claims"] = rebuilt
    return _finish_migration(
        migrated, to_version="3.0.0", identity_field=None
    )


def migrate_reviewer_execution_v1_to_v2(
    document: Mapping[str, Any], *, observation_complete: bool,
    capture_threads_completed: bool, process_cleanup_complete: bool,
    execution_valid: bool,
) -> dict[str, Any]:
    migrated = _migration_document(
        document, from_version="1.0.0", identity_field="execution_id"
    )
    additions = {
        "observation_complete": observation_complete,
        "capture_threads_completed": capture_threads_completed,
        "process_cleanup_complete": process_cleanup_complete,
        "execution_valid": execution_valid,
    }
    if any(not isinstance(value, bool) for value in additions.values()):
        raise ValueError("protected reviewer execution observations must be booleans")
    if set(additions) & set(migrated):
        raise ValueError("legacy reviewer execution already contains v2 fields")
    migrated.update(additions)
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field="execution_id"
    )


def migrate_reviewer_execution_v2_to_v3(
    document: Mapping[str, Any], *, observation: Mapping[str, Any],
    stdin_delivery_complete: bool, stdout: Mapping[str, Any],
    stderr: Mapping[str, Any],
) -> dict[str, Any]:
    migrated = _migration_document(
        document, from_version="2.0.0", identity_field="execution_id"
    )
    if not isinstance(observation, Mapping) or not isinstance(
        stdin_delivery_complete, bool
    ):
        raise ValueError("protected primitive reviewer observations are required")
    additions = {
        "observation": dict(observation),
        "stdin_delivery_complete": stdin_delivery_complete,
        "stdout": _reference(stdout, name="reviewer stdout"),
        "stderr": _reference(stderr, name="reviewer stderr"),
    }
    if set(additions) & set(migrated):
        raise ValueError("legacy reviewer execution already contains v3 fields")
    migrated.update(additions)
    return _finish_migration(
        migrated, to_version="3.0.0", identity_field="execution_id"
    )


def migrate_reviewer_execution_v3_to_v4(
    document: Mapping[str, Any], *, executed_argv_sha256: str
) -> dict[str, Any]:
    from codex_governance.canonical import require_sha256

    migrated = _migration_document(
        document, from_version="3.0.0", identity_field="execution_id"
    )
    exact = require_sha256(
        executed_argv_sha256, name="protected exact reviewer argv"
    )
    if "executed_argv_sha256" in migrated:
        raise ValueError("legacy reviewer execution already contains v4 field")
    observation = migrated.get("observation")
    if not isinstance(observation, Mapping) or not isinstance(
        observation.get("supervisor"), Mapping
    ):
        raise ValueError("legacy reviewer supervisor observation is required")
    rebuilt_observation = dict(observation)
    rebuilt_supervisor = dict(observation["supervisor"])
    if "executed_argv_sha256" in rebuilt_supervisor:
        raise ValueError("legacy reviewer supervisor already contains v4 field")
    rebuilt_supervisor["executed_argv_sha256"] = exact
    rebuilt_observation["supervisor"] = rebuilt_supervisor
    migrated["observation"] = rebuilt_observation
    migrated["executed_argv_sha256"] = exact
    return _finish_migration(
        migrated, to_version="4.0.0", identity_field="execution_id"
    )


def migrate_reviewer_execution_v4_to_v5(
    document: Mapping[str, Any], *, authentication: str
) -> dict[str, Any]:
    """Bind a reviewer execution statement to protected ChatGPT authentication."""
    migrated = _migration_document(
        document, from_version="4.0.0", identity_field="execution_id"
    )
    if "authentication" in migrated or authentication != "chatgpt":
        raise ValueError("protected ChatGPT authentication is required")
    migrated["authentication"] = authentication
    return _finish_migration(
        migrated, to_version="5.0.0", identity_field="execution_id"
    )


def migrate_rollback_evidence_v1_to_v2(
    document: Mapping[str, Any], *, gate_result: Mapping[str, Any],
    sandbox_capability: Mapping[str, Any], provenance_statement: Mapping[str, Any],
) -> dict[str, Any]:
    migrated = _migration_document(
        document, from_version="1.0.0", identity_field="rollback_evidence_id"
    )
    replacements = {
        "gate_result": ("gate_result_sha256", gate_result),
        "sandbox_capability": (
            "sandbox_capability_sha256",
            sandbox_capability,
        ),
        "provenance_statement": (
            "provenance_statement_sha256",
            provenance_statement,
        ),
    }
    for target, (legacy_digest, reference) in replacements.items():
        resolved = _reference(reference, name=target)
        if migrated.get(legacy_digest) != resolved["sha256"]:
            raise ValueError("typed rollback reference does not match legacy digest")
        migrated.pop(legacy_digest)
        migrated[target] = resolved
    return _finish_migration(
        migrated, to_version="2.0.0", identity_field="rollback_evidence_id"
    )


EXECUTABLE_MIGRATIONS = {
    ("effective-policy", "1.0.0", "2.0.0"): migrate_effective_policy_v1_to_v2,
    ("effective-policy", "2.0.0", "3.0.0"): migrate_effective_policy_v2_to_v3,
    ("evidence-manifest", "1.0.0", "2.0.0"): migrate_evidence_manifest_v1_to_v2,
    ("evidence-manifest", "2.0.0", "3.0.0"): migrate_evidence_manifest_v2_to_v3,
    ("evidence-manifest", "3.0.0", "4.0.0"): migrate_evidence_manifest_v3_to_v4,
    ("reviewer-qualification", "1.0.0", "2.0.0"): migrate_reviewer_qualification_v1_to_v2,
    ("reviewer-qualification", "2.0.0", "3.0.0"): migrate_reviewer_qualification_v2_to_v3,
    ("reviewer-qualification-cases", "1.0.0", "2.0.0"): migrate_reviewer_qualification_cases_v1_to_v2,
    ("reviewer-qualification-cases", "2.0.0", "3.0.0"): migrate_reviewer_qualification_cases_v2_to_v3,
    ("reviewer-qualification-cases", "3.0.0", "4.0.0"): migrate_reviewer_qualification_cases_v3_to_v4,
    ("reviewer-qualification-cases", "4.0.0", "5.0.0"): migrate_reviewer_qualification_cases_v4_to_v5,
    ("reviewer-qualification-corpus", "1.0.0", "2.0.0"): migrate_reviewer_qualification_corpus_v1_to_v2,
    ("reviewer-qualification-corpus", "2.0.0", "3.0.0"): migrate_reviewer_qualification_corpus_v2_to_v3,
    ("rapid-review-session", "1.0.0", "2.0.0"): migrate_rapid_review_session_v1_to_v2,
    ("reviewer-result", "1.0.0", "2.0.0"): migrate_reviewer_result_v1_to_v2,
    ("reviewer-result", "2.0.0", "3.0.0"): migrate_reviewer_result_v2_to_v3,
    ("reviewer-execution", "1.0.0", "2.0.0"): migrate_reviewer_execution_v1_to_v2,
    ("reviewer-execution", "2.0.0", "3.0.0"): migrate_reviewer_execution_v2_to_v3,
    ("reviewer-execution", "3.0.0", "4.0.0"): migrate_reviewer_execution_v3_to_v4,
    ("reviewer-execution", "4.0.0", "5.0.0"): migrate_reviewer_execution_v4_to_v5,
    ("rollback-evidence", "1.0.0", "2.0.0"): migrate_rollback_evidence_v1_to_v2,
    ("context-qualification", "1.0.0", "2.0.0"): migrate_context_qualification_v1_to_v2,
    ("context-receipt", "1.0.0", "2.0.0"): migrate_context_receipt_v1_to_v2,
    ("sandbox-capability", "1.0.0", "2.0.0"): migrate_sandbox_capability_v1_to_v2,
    ("provenance-statement", "1.0.0", "2.0.0"): migrate_provenance_statement_v1_to_v2,
}


def migration_policy(kind: str, from_version: str, to_version: str) -> str:
    """Return the protected migration policy for a public representation."""
    if (kind, from_version, to_version) in EXECUTABLE_MIGRATIONS:
        return "explicit_required"
    if from_version == to_version and from_version in {
        "1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"
    }:
        return "identity"
    return "unsupported"
