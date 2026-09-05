"""Pure, non-authorizing T24 paired-comparison reconstruction."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from datetime import timezone
from pathlib import PurePosixPath
from typing import Any

from common import canonical_bytes, content_address, require_digest, sha256_bytes
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.portability import stream_contains_shaped_value
from codex_governance.qualification import qualification_case_classes_complete
from codex_governance.reviewer import parse_codex_jsonl_evidence


DISPOSITIONS = frozenset({"BLOCK", "NO_BLOCKING_FINDING_OBSERVED", "UNKNOWN"})
TOKEN_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)


def _artifact_reference(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
        raise ValueError("comparison artifact reference is malformed")
    path = value.get("path")
    if not isinstance(path, str) or not path.startswith("comparison/"):
        raise ValueError("comparison artifact path is outside its package")
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != path
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise ValueError("comparison artifact path is unsafe")
    return {"path": path, "sha256": require_digest(value.get("sha256"), "artifact")}


def _json_object(data: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("comparison JSON contains duplicate keys")
            result[key] = value
        return result

    value = json.loads(data, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("comparison artifact is not a JSON object")
    return value


def validate_comparison_inputs(
    corpus: Mapping[str, Any],
    decision: Mapping[str, Any],
    *,
    actor: str,
    authority_repository: str,
    authority_ref: str,
    evaluated_at: str,
) -> None:
    """Require an exact protected corpus and runtime-authenticated label approval."""
    if content_address(dict(corpus), "corpus_id") != dict(corpus):
        raise ValueError("comparison corpus identity does not reconstruct")
    cases = corpus.get("cases")
    if (
        corpus.get("human_labelled") is not True
        or not isinstance(cases, list)
        or len(cases) < 4
        or not qualification_case_classes_complete(cases)
    ):
        raise ValueError("comparison corpus coverage is incomplete")
    case_ids: list[str] = []
    labels: dict[str, str] = {}
    defects = controls = 0
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValueError("comparison case is malformed")
        case_id = case.get("case_id")
        expected = case.get("expected_disposition")
        expected_finding = case.get("expected_finding")
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in labels
            or expected not in DISPOSITIONS - {"UNKNOWN"}
        ):
            raise ValueError("comparison case identity or label is invalid")
        if expected == "BLOCK":
            defects += 1
            if (
                not isinstance(expected_finding, Mapping)
                or not isinstance(expected_finding.get("path"), str)
                or not isinstance(expected_finding.get("line"), int)
                or isinstance(expected_finding.get("line"), bool)
                or expected_finding["line"] < 1
            ):
                raise ValueError("comparison defect target is incomplete")
        else:
            controls += 1
            if expected_finding is not None:
                raise ValueError("comparison clean control cannot name a defect")
        case_ids.append(case_id)
        labels[case_id] = expected
    if defects < 2 or controls < 2:
        raise ValueError("comparison needs at least two defects and two controls")

    if content_address(dict(decision), "decision_id") != dict(decision):
        raise ValueError("comparison label decision identity does not reconstruct")
    issuer = {
        "subject": "github:" + actor,
        "authentication_method": "github-actions-workflow-dispatch",
        "protected_source": authority_repository + "@" + authority_ref,
    }
    now = parse_rfc3339(evaluated_at).astimezone(timezone.utc)
    if (
        decision.get("repository_id") != "repo:timaday/codex-governed-change"
        or decision.get("decision_type") != "paired_comparison_labels"
        or decision.get("approved_corpus_id") != corpus.get("corpus_id")
        or decision.get("approved_case_ids") != case_ids
        or decision.get("approved_labels") != labels
        or decision.get("approved_arms") != ["governed", "ordinary"]
        or decision.get("issuer")
        != issuer | {"assertion_sha256": sha256_bytes(canonical_bytes(issuer))}
        or not (
            parse_rfc3339(str(decision.get("issued_at"))).astimezone(timezone.utc)
            <= now
            < parse_rfc3339(str(decision.get("expires_at"))).astimezone(timezone.utc)
        )
    ):
        raise ValueError("comparison label decision does not exactly approve the corpus")


def score_task(
    *,
    arm: str,
    case: Mapping[str, Any],
    observed_disposition: str,
    findings: Sequence[Mapping[str, Any]],
    usage: Mapping[str, Any],
    usage_complete: bool,
    elapsed_ms: int,
    artifacts: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    """Score one arm without exposing protected labels to the model prompt."""
    if arm not in {"governed", "ordinary"} or observed_disposition not in DISPOSITIONS:
        raise ValueError("comparison arm or disposition is invalid")
    if not isinstance(usage_complete, bool):
        raise ValueError("comparison token-observation state is invalid")
    if not isinstance(elapsed_ms, int) or isinstance(elapsed_ms, bool) or elapsed_ms < 0:
        raise ValueError("comparison elapsed time is invalid")
    observed_usage: dict[str, int] = {}
    for name in TOKEN_FIELDS:
        value = usage.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("comparison token usage is unavailable")
        observed_usage[name] = value
    if observed_usage["cached_input_tokens"] > observed_usage["input_tokens"]:
        raise ValueError("comparison cached input exceeds input usage")
    if observed_usage["reasoning_output_tokens"] > observed_usage["output_tokens"]:
        raise ValueError("comparison reasoning output exceeds output usage")
    if isinstance(findings, (str, bytes)) or any(
        not isinstance(item, Mapping) for item in findings
    ):
        raise ValueError("comparison findings are malformed")
    normalized_artifacts = {
        name: _artifact_reference(reference)
        for name, reference in artifacts.items()
        if isinstance(name, str) and name
    }
    if set(normalized_artifacts) != {"result", "execution", "stdout", "stderr"}:
        raise ValueError("comparison artifact inventory is incomplete")
    expected = case.get("expected_disposition")
    expected_finding = case.get("expected_finding")
    finding_match = expected_finding is None and not findings
    if isinstance(expected_finding, Mapping):
        finding_match = any(
            isinstance(item, Mapping)
            and item.get("requirement_id") == case.get("requirement_id")
            and item.get("path") == expected_finding.get("path")
            and item.get("line") == expected_finding.get("line")
            for item in findings
        )
    correct = bool(observed_disposition == expected and finding_match)
    return {
        "case_id": case["case_id"],
        "arm": arm,
        "expected_disposition": expected,
        "observed_disposition": observed_disposition,
        "expected_finding_matched": finding_match,
        "accepted_defect": bool(
            expected == "BLOCK"
            and observed_disposition == "NO_BLOCKING_FINDING_OBSERVED"
        ),
        "correct_completion": correct,
        "false_block": bool(
            expected == "NO_BLOCKING_FINDING_OBSERVED"
            and observed_disposition == "BLOCK"
        ),
        "unknown": observed_disposition == "UNKNOWN",
        "token_usage_complete": usage_complete,
        **observed_usage,
        "total_tokens": (
            observed_usage["input_tokens"]
            + observed_usage["output_tokens"]
        ),
        "elapsed_ms": elapsed_ms,
        "artifacts": normalized_artifacts,
    }


def reconstruct_task(
    *,
    arm: str,
    case: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, str]],
    artifact_reader: Callable[[Mapping[str, str]], bytes],
) -> dict[str, Any]:
    """Derive a task score from its retained result, execution and streams."""
    references = {
        name: _artifact_reference(reference)
        for name, reference in artifacts.items()
        if isinstance(name, str) and name
    }
    if set(references) != {"result", "execution", "stdout", "stderr"}:
        raise ValueError("comparison artifact inventory is incomplete")
    observed: dict[str, bytes] = {}
    for name, reference in references.items():
        data = artifact_reader(reference)
        if sha256_bytes(data) != reference["sha256"]:
            raise ValueError("comparison artifact digest does not reconstruct")
        if stream_contains_shaped_value(data):
            raise ValueError("comparison artifact retains a shaped machine value")
        observed[name] = data

    result = _json_object(observed["result"])
    execution = _json_object(observed["execution"])
    if content_address(execution, "execution_id") != execution:
        raise ValueError("comparison execution identity does not reconstruct")
    if (
        execution.get("case_id") != case.get("case_id")
        or execution.get("case_sha256") != sha256_bytes(canonical_bytes(dict(case)))
        or execution.get("arm") != arm
        or execution.get("result_sha256") != references["result"]["sha256"]
        or execution.get("stdout_sha256") != references["stdout"]["sha256"]
        or execution.get("stderr_sha256") != references["stderr"]["sha256"]
    ):
        raise ValueError("comparison execution bindings differ")
    parsed_stream = parse_codex_jsonl_evidence(observed["stdout"])
    usage = {name: execution.get(name) for name in TOKEN_FIELDS}
    primitive = execution.get("primitive")
    if not isinstance(primitive, Mapping):
        raise ValueError("comparison primitive execution facts are absent")
    if arm == "governed":
        source = primitive.get("reviewer_execution")
        if (
            not isinstance(source, Mapping)
            or content_address(dict(source), "execution_id") != dict(source)
            or source.get("reviewer_output_sha256") != references["result"]["sha256"]
            or source.get("stdout_sha256") != references["stdout"]["sha256"]
            or source.get("stderr_sha256") != references["stderr"]["sha256"]
            or source.get("latency_ms") != execution.get("elapsed_ms")
            or any(source.get(name) != usage[name] for name in TOKEN_FIELDS)
        ):
            raise ValueError("governed primitive execution does not reconstruct")
        primitive_valid = source.get("execution_valid") is True
    else:
        primitive_valid = bool(
            set(primitive)
            == {
                "return_code",
                "timed_out",
                "stdin_complete",
                "output_present",
                "output_valid",
                "stdout_complete",
                "stderr_complete",
                "process_cleanup_complete",
                "output_truncated",
                "ambiguous_redaction",
                "candidate_unchanged",
            }
            and primitive.get("return_code") == 0
            and primitive.get("timed_out") is False
            and primitive.get("stdin_complete") is True
            and primitive.get("output_present") is True
            and primitive.get("output_valid") is True
            and primitive.get("stdout_complete") is True
            and primitive.get("stderr_complete") is True
            and primitive.get("process_cleanup_complete") is True
            and primitive.get("output_truncated") is False
            and primitive.get("ambiguous_redaction") is False
            and primitive.get("candidate_unchanged") is True
        )
    if execution.get("execution_valid") is not primitive_valid:
        raise ValueError("comparison execution summary differs from primitive facts")
    if (
        not primitive_valid
        or execution.get("usage_observed") is not True
        or parsed_stream.get("jsonl_valid") is not True
        or parsed_stream.get("usage_observed") is not True
        or any(parsed_stream.get(name) != usage[name] for name in TOKEN_FIELDS)
    ):
        observed_disposition = "UNKNOWN"
    else:
        field = "verdict" if arm == "governed" else "disposition"
        observed_disposition = result.get(field)
        if observed_disposition not in DISPOSITIONS:
            observed_disposition = "UNKNOWN"
    try:
        final_result = json.loads(str(parsed_stream.get("final_message")))
    except (TypeError, ValueError, json.JSONDecodeError):
        final_result = None
    if final_result != result:
        observed_disposition = "UNKNOWN"
    findings = result.get("findings")
    if not isinstance(findings, list):
        findings = []
        observed_disposition = "UNKNOWN"
    return score_task(
        arm=arm,
        case=case,
        observed_disposition=observed_disposition,
        findings=findings,
        usage=usage,
        usage_complete=execution.get("usage_observed") is True,
        elapsed_ms=execution.get("elapsed_ms"),
        artifacts=references,
    )


def aggregate_tasks(
    tasks: Sequence[Mapping[str, Any]], *, expected_case_ids: Sequence[str]
) -> dict[str, int]:
    """Recompute one arm only after its exact ordered task set is complete."""
    if [item.get("case_id") for item in tasks] != list(expected_case_ids):
        raise ValueError("comparison arm task inventory is incomplete or reordered")
    if len(set(expected_case_ids)) != len(expected_case_ids):
        raise ValueError("comparison case IDs are duplicated")
    totals = {
        "tasks": len(tasks),
        "accepted_defects": 0,
        "correct_completions": 0,
        "false_blocks": 0,
        "unknowns": 0,
        "token_usage_incomplete": 0,
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
        "total_tokens": 0,
        "elapsed_ms": 0,
    }
    mappings = {
        "accepted_defects": "accepted_defect",
        "correct_completions": "correct_completion",
        "false_blocks": "false_block",
        "unknowns": "unknown",
        "token_usage_incomplete": "token_usage_complete",
    }
    for task in tasks:
        for total, field in mappings.items():
            value = task.get(field) is True
            totals[total] += int(not value if total == "token_usage_incomplete" else value)
        for field in (*TOKEN_FIELDS, "total_tokens", "elapsed_ms"):
            value = task.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("comparison aggregate input is invalid")
            totals[field] += value
    return totals


def build_comparison_document(
    *,
    corpus: Mapping[str, Any],
    decision: Mapping[str, Any],
    identity: Mapping[str, Any],
    governed_tasks: Sequence[Mapping[str, Any]],
    ordinary_tasks: Sequence[Mapping[str, Any]],
    created_at: str,
) -> dict[str, Any]:
    """Build the descriptive machine result; it is never an admission input."""
    parse_rfc3339(created_at)
    case_ids = [str(item["case_id"]) for item in corpus["cases"]]
    document = {
        "schema_version": "1.0.0",
        "corpus_id": corpus["corpus_id"],
        "label_decision_id": decision["decision_id"],
        "identity": dict(identity),
        "arms": {
            "governed": {
                "tasks": [dict(item) for item in governed_tasks],
                "aggregate": aggregate_tasks(
                    governed_tasks, expected_case_ids=case_ids
                ),
            },
            "ordinary": {
                "tasks": [dict(item) for item in ordinary_tasks],
                "aggregate": aggregate_tasks(
                    ordinary_tasks, expected_case_ids=case_ids
                ),
            },
        },
        "human_effort_status": "PENDING_HUMAN_RECORD",
        "admission_authority": False,
        "confidence": "small_corpus_descriptive_only",
        "created_at": created_at,
        "limitations": [
            "A small synthetic held-out corpus cannot establish causal or general performance benefit.",
            "The tasks measure bounded defect triage, not end-to-end code authoring or deployment.",
            "The fixed governed-then-ordinary arm order may confound service load, caching and latency.",
            "Human review and operation minutes require a separate human-supplied record.",
            "Total tokens equal input plus output tokens; reasoning output is retained separately as a subset of output and is not double-counted.",
            "Token totals are measurements only for tasks whose token usage is complete.",
            "The comparison cannot substitute for deterministic admission, operational qualification, or release approval.",
        ],
    }
    return content_address(document, "comparison_id")


def human_effort_record_valid(
    record: Mapping[str, Any], *, comparison: Mapping[str, Any], actor: str
) -> bool:
    """Validate separate human-supplied effort without granting it authority."""
    try:
        issuer = {
            "subject": "github:" + actor,
            "authentication_method": "github-actions-workflow-dispatch",
            "protected_source": (
                "timaday/codex-governed-change@refs/heads/governance-authority"
            ),
        }
        if (
            content_address(dict(record), "effort_id") != dict(record)
            or record.get("comparison_id") != comparison.get("comparison_id")
            or record.get("recorded_by") != "github:" + actor
            or record.get("issuer")
            != issuer | {"assertion_sha256": sha256_bytes(canonical_bytes(issuer))}
            or record.get("measurement_method") != "human_self_report"
            or record.get("admission_authority") is not False
            or parse_rfc3339(str(record.get("recorded_at")))
            < parse_rfc3339(str(comparison.get("created_at")))
        ):
            return False
        for arm in ("governed", "ordinary"):
            effort = record.get(arm)
            if not isinstance(effort, Mapping) or set(effort) != {
                "review_minutes",
                "operation_minutes",
            }:
                return False
            if any(
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or value < 0
                for value in effort.values()
            ):
                return False
        limitations = record.get("limitations")
        return isinstance(limitations, list) and all(
            isinstance(item, str) and item for item in limitations
        )
    except (TypeError, ValueError):
        return False


def comparison_document_valid(
    document: Mapping[str, Any],
    *,
    corpus: Mapping[str, Any],
    decision: Mapping[str, Any],
    expected_identity: Mapping[str, Any],
    artifact_reader: Callable[[Mapping[str, str]], bytes],
) -> bool:
    """Reconstruct metrics and reject unsafe retained comparison artifacts."""
    try:
        if (
            content_address(dict(document), "comparison_id") != dict(document)
            or document.get("corpus_id") != corpus.get("corpus_id")
            or document.get("label_decision_id") != decision.get("decision_id")
            or document.get("identity") != dict(expected_identity)
            or document.get("admission_authority") is not False
            or document.get("human_effort_status") != "PENDING_HUMAN_RECORD"
            or document.get("confidence") != "small_corpus_descriptive_only"
            or not document.get("limitations")
        ):
            return False
        case_ids = [str(item["case_id"]) for item in corpus["cases"]]
        arms = document["arms"]
        if set(arms) != {"governed", "ordinary"}:
            return False
        for arm_name, arm in arms.items():
            tasks = arm["tasks"]
            reconstructed = [
                reconstruct_task(
                    arm=arm_name,
                    case=case,
                    artifacts=task["artifacts"],
                    artifact_reader=artifact_reader,
                )
                for case, task in zip(corpus["cases"], tasks, strict=True)
            ]
            if tasks != reconstructed:
                return False
            if arm["aggregate"] != aggregate_tasks(
                reconstructed, expected_case_ids=case_ids
            ):
                return False
        return True
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False
