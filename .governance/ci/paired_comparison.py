"""Pure, non-authorizing T24 paired-comparison reconstruction."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import timezone
from pathlib import Path, PurePosixPath
from typing import Any

from common import (
    canonical_bytes,
    content_address,
    load_json,
    read_bytes_once,
    require_digest,
    sha256_bytes,
)
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.portability import stream_contains_shaped_value
from codex_governance.qualification import (
    bootstrap_qualification_record,
    qualification_candidate_document,
    qualification_case_classes_complete,
    qualification_conformance_output_valid,
    qualification_context_documents,
    qualification_gate_documents,
    qualification_policy_document,
    qualification_task_document,
)
from codex_governance.reviewer import (
    REVIEWER_ENVIRONMENT_ALLOWLIST,
    build_reviewer_stdin,
    parse_codex_jsonl_evidence,
    reviewer_argv_sha256,
    reviewer_input_keys,
    reviewer_launcher_sha256,
    reviewer_observation_facts,
    reviewer_stream_is_portable,
    sanitized_invocation_descriptor,
)
from codex_governance.schema import validate_instance


DISPOSITIONS = frozenset({"BLOCK", "NO_BLOCKING_FINDING_OBSERVED", "UNKNOWN"})
TOKEN_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
REVIEWER_EXECUTION_SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "kernel"
    / "schemas"
    / "reviewer-execution.schema.json"
)
REVIEWER_RESULT_SCHEMA = REVIEWER_EXECUTION_SCHEMA.with_name(
    "reviewer-result.schema.json"
)
AUTHORITY_ROOT = Path(__file__).resolve().parents[2]
REVIEWER_PROMPT = (
    AUTHORITY_ROOT / "kernel" / ".codex" / "review" / "reviewer.prompt.md"
)
ORDINARY_RESULT_SCHEMA = (
    AUTHORITY_ROOT / ".governance" / "schemas" / "paired-comparison-result.schema.json"
)
EVALUATION_REPOSITORY_ID = "repo:timaday/codex-governed-change-qualification"
BASE_ARTIFACTS = frozenset({"result", "execution", "stdout", "stderr"})
GOVERNED_CONTEXT_ARTIFACTS = frozenset(
    {
        "context_sources",
        "context_projection",
        "context_qualification",
        "context_receipt",
        "context_execution_receipt",
        "permitted_inputs",
    }
)


def _expected_environment_keys(expected_identity: Mapping[str, Any]) -> list[str]:
    """Return the one sorted, protected key-only environment identity."""
    keys = expected_identity.get("environment_keys")
    if (
        not isinstance(keys, list)
        or any(
            not isinstance(name, str)
            or not name
            or name not in REVIEWER_ENVIRONMENT_ALLOWLIST
            for name in keys
        )
        or keys != sorted(set(keys))
    ):
        raise ValueError("comparison environment identity is invalid")
    return keys


def _elapsed_milliseconds(
    started_at: Any, ended_at: Any, timeout_seconds: Any
) -> int:
    """Derive elapsed milliseconds by flooring the exact RFC3339 interval."""
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        raise ValueError("comparison timing limit is invalid")
    started = parse_rfc3339(str(started_at))
    ended = parse_rfc3339(str(ended_at))
    interval = ended - started
    elapsed_microseconds = (
        (interval.days * 86_400 + interval.seconds) * 1_000_000
        + interval.microseconds
    )
    if elapsed_microseconds < 0:
        raise ValueError("comparison timing interval is negative")
    if elapsed_microseconds > timeout_seconds * 1_000_000:
        raise ValueError("comparison timing exceeds its protected deadline")
    return elapsed_microseconds // 1_000


def _required_artifacts(arm: str) -> frozenset[str]:
    if arm == "governed":
        return BASE_ARTIFACTS | GOVERNED_CONTEXT_ARTIFACTS
    if arm == "ordinary":
        return BASE_ARTIFACTS
    raise ValueError("comparison arm is invalid")


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


def ordinary_candidate_id(case: Mapping[str, Any]) -> str:
    """Bind the ordinary arm to only the same protected candidate file bytes."""
    files = case.get("files")
    if not isinstance(files, Mapping) or any(
        not isinstance(path, str) or not isinstance(body, str)
        for path, body in files.items()
    ):
        raise ValueError("comparison candidate files are malformed")
    return sha256_bytes(canonical_bytes({"files": dict(files)}))


def ordinary_prompt(case: Mapping[str, Any], candidate_id: str | None = None) -> str:
    """Build the label-blind ordinary prompt from protected case fields."""
    return (
        "Review this bounded synthetic repository read-only. Determine whether the "
        "implementation violates the named mandatory requirement. Inspect the exact "
        "repository files and report only concrete findings for that requirement. "
        "A finding must use a repository-relative path and its exact one-based line. "
        "If evidence is unavailable, return UNKNOWN. Do not expose environment, host, "
        "credential, or endpoint values.\n\n"
        f"CASE_ID: {case['case_id']}\n"
        f"CANDIDATE_ID: {candidate_id or ordinary_candidate_id(case)}\n"
        f"REQUIREMENT_ID: {case['requirement_id']}\n"
        "OBJECTIVE: Review the bounded synthetic candidate against its sole mandatory "
        "requirement.\n"
        "SCOPE: " + ", ".join(sorted(case["files"])) + "\n"
    )


def _governed_primitive_valid(
    *,
    case: Mapping[str, Any],
    corpus: Mapping[str, Any],
    decision: Mapping[str, Any],
    source: Mapping[str, Any],
    result: Mapping[str, Any],
    references: Mapping[str, Mapping[str, str]],
    observed: Mapping[str, bytes],
    parsed_stream: Mapping[str, Any],
    usage: Mapping[str, Any],
    expected_identity: Mapping[str, Any],
) -> bool:
    """Reconstruct governed execution validity instead of trusting its summary."""
    execution_schema = load_json(REVIEWER_EXECUTION_SCHEMA)
    result_schema = load_json(REVIEWER_RESULT_SCHEMA)
    observation = source.get("observation")
    if (
        not isinstance(execution_schema, dict)
        or not isinstance(result_schema, dict)
        or validate_instance(dict(source), execution_schema)
        or validate_instance(dict(result), result_schema)
        or not isinstance(observation, Mapping)
    ):
        return False
    derived = reviewer_observation_facts(observation)
    stdout_ref = source.get("stdout")
    stderr_ref = source.get("stderr")
    supervisor = observation.get("supervisor")
    output = observation.get("output")
    if not all(
        isinstance(value, Mapping)
        for value in (stdout_ref, stderr_ref, supervisor, output)
    ):
        return False
    summary_fields = {
        "return_code": observation.get("return_code"),
        "timed_out": observation.get("timed_out"),
        **derived,
    }
    try:
        prompt_bytes = read_bytes_once(REVIEWER_PROMPT)
        governed_schema_bytes = read_bytes_once(REVIEWER_RESULT_SCHEMA)
        corpus_sha256 = sha256_bytes(canonical_bytes(dict(corpus)))
        identity = {
            "prompt_sha256": expected_identity["governed_prompt_sha256"],
            "schema_sha256": expected_identity["governed_schema_sha256"],
            "launcher_sha256": expected_identity["governed_launcher_sha256"],
            "codex_cli_version": expected_identity["codex_cli_version"],
            "authentication": expected_identity["authentication"],
            "model": expected_identity["model"],
            "reasoning_effort": expected_identity["reasoning_effort"],
            "timeout_seconds": expected_identity["timeout_seconds"],
            "max_output_bytes": expected_identity["max_output_bytes"],
        }
        if (
            identity["prompt_sha256"] != sha256_bytes(prompt_bytes)
            or identity["schema_sha256"] != sha256_bytes(governed_schema_bytes)
            or identity["launcher_sha256"] != reviewer_launcher_sha256()
            or expected_identity.get("governed_profile") != "STANDARD"
        ):
            return False
        bootstrap = bootstrap_qualification_record(
            identity=identity,
            corpus_sha256=corpus_sha256,
            label_decision_id=str(decision["decision_id"]),
        )
        task = qualification_task_document(
            repository_id=EVALUATION_REPOSITORY_ID,
            case=case,
        )
        task_sha256 = sha256_bytes(canonical_bytes(task))
        policy = qualification_policy_document(
            repository_id=EVALUATION_REPOSITORY_ID,
            case=case,
            corpus_sha256=corpus_sha256,
            bootstrap_qualification_id=bootstrap["qualification_id"],
            model=str(identity["model"]),
            reasoning_effort=str(identity["reasoning_effort"]),
        )
        policy_sha256 = sha256_bytes(canonical_bytes(policy))
        expected_candidate = qualification_candidate_document(
            repository_id=EVALUATION_REPOSITORY_ID,
            case=case,
            effective_policy_sha256=policy_sha256,
        )
        candidate_id = expected_candidate["candidate_id"]
        parsed_context = {
            name: _json_object(observed[name])
            for name in GOVERNED_CONTEXT_ARTIFACTS
            if name != "permitted_inputs"
        }
        permitted_inputs = _json_object(observed["permitted_inputs"])
        if any(
            canonical_bytes(document) != observed[name]
            for name, document in parsed_context.items()
        ) or canonical_bytes(permitted_inputs) != observed["permitted_inputs"]:
            return False
        expected_context = qualification_context_documents(
            mode="conformance",
            case=case,
            task=task,
            policy=policy,
            candidate=expected_candidate,
            reviewer_output_sha256=references["result"]["sha256"],
            execution=source,
            requested_profile="STANDARD",
        )
        if parsed_context != expected_context:
            return False
        _gate, gate_manifest = qualification_gate_documents(
            repository_id=EVALUATION_REPOSITORY_ID,
            task_contract_sha256=task_sha256,
            candidate_id=candidate_id,
        )
        prefix = f"qualification/STANDARD/conformance/{case['case_id']}"
        expected_permitted_inputs = {
            "task_contract_path": prefix + "/task-contract.json",
            "task_contract_sha256": task_sha256,
            "repository_id": EVALUATION_REPOSITORY_ID,
            "candidate_id": candidate_id,
            "candidate_path": "candidate",
            "effective_policy_path": prefix + "/effective-policy.json",
            "effective_policy_sha256": policy_sha256,
            "gate_manifest_path": prefix + "/gate-manifest.json",
            "gate_manifest_sha256": sha256_bytes(canonical_bytes(gate_manifest)),
            "context_receipt_path": prefix + "/context-receipt.json",
            "context_receipt_sha256": references["context_receipt"]["sha256"],
            "context_sources_path": prefix + "/context-sources.json",
            "context_sources_sha256": references["context_sources"]["sha256"],
            "context_projection_path": prefix + "/context-projection.json",
            "context_projection_sha256": references["context_projection"]["sha256"],
            "context_qualification_path": prefix + "/context-qualification.json",
            "context_qualification_sha256": references["context_qualification"]["sha256"],
            "context_qualification_id": expected_context["context_qualification"]["qualification_id"],
            "reviewer_qualification_path": prefix + "/reviewer-qualification.json",
            "reviewer_qualification_sha256": sha256_bytes(canonical_bytes(bootstrap)),
            "reviewer_qualification_id": bootstrap["qualification_id"],
            "evidence_root": "qualification",
            "reviewer_prompt_sha256": identity["prompt_sha256"],
            "review_mode": "conformance",
        }
        expected_materials = [
            {"name": "task-contract", "sha256": task_sha256},
            {"name": "effective-policy", "sha256": policy_sha256},
            {"name": "candidate", "sha256": candidate_id},
            {"name": "reviewer-prompt", "sha256": identity["prompt_sha256"]},
            {"name": "permitted-inputs", "sha256": references["permitted_inputs"]["sha256"]},
            {"name": "output-schema", "sha256": identity["schema_sha256"]},
            {"name": "launcher", "sha256": identity["launcher_sha256"]},
            {"name": "qualification", "sha256": bootstrap["qualification_id"]},
            {"name": "context-source-bundle", "sha256": references["context_sources"]["sha256"]},
            {"name": "context-projection", "sha256": references["context_projection"]["sha256"]},
            {"name": "context-qualification", "sha256": expected_context["context_qualification"]["qualification_id"]},
            {"name": "prepared-context", "sha256": references["context_receipt"]["sha256"]},
            {"name": "post-run-context", "sha256": references["context_execution_receipt"]["sha256"]},
        ]
        output_bindings = {
            "repository_id": EVALUATION_REPOSITORY_ID,
            "task_contract_sha256": task_sha256,
            "effective_policy_sha256": policy_sha256,
            "candidate_id": candidate_id,
            "reviewer_prompt_sha256": identity["prompt_sha256"],
            "qualification_id": bootstrap["qualification_id"],
            "model": identity["model"],
            "context_receipt_sha256": references["context_receipt"]["sha256"],
        }
        expected_stdin_sha256 = sha256_bytes(
            build_reviewer_stdin(
                fixed_prompt=prompt_bytes.decode("utf-8"),
                permitted_inputs=permitted_inputs,
            ).encode("utf-8")
        )
        environment_keys = _expected_environment_keys(expected_identity)
        elapsed_ms = _elapsed_milliseconds(
            source.get("started_at"),
            source.get("ended_at"),
            expected_identity.get("timeout_seconds"),
        )
    except (KeyError, OSError, TypeError, UnicodeError, ValueError):
        return False
    return bool(
        source.get("repository_id") == EVALUATION_REPOSITORY_ID
        and source.get("task_contract_sha256") == task_sha256
        and source.get("effective_policy_sha256") == policy_sha256
        and source.get("candidate_id") == candidate_id
        and source.get("prompt_sha256") == identity["prompt_sha256"]
        and source.get("output_schema_sha256") == identity["schema_sha256"]
        and source.get("launcher_sha256") == identity["launcher_sha256"]
        and source.get("qualification_id") == bootstrap["qualification_id"]
        and source.get("model") == identity["model"]
        and source.get("reasoning_effort") == identity["reasoning_effort"]
        and source.get("authentication") == identity["authentication"]
        and source.get("tools")
        == [{"name": "codex-cli", "version": identity["codex_cli_version"]}]
        and source.get("workflow")
        == {
            "system": "github-actions-qualification",
            "run_id": expected_identity.get("workflow_run_id"),
            "attempt": expected_identity.get("workflow_attempt"),
        }
        and source.get("limits")
        == {
            "timeout_seconds": expected_identity.get("timeout_seconds"),
            "max_output_bytes": expected_identity.get("max_output_bytes"),
        }
        and source.get("environment_keys") == environment_keys
        and source.get("latency_ms") == elapsed_ms
        and source.get("invocation")
        == sanitized_invocation_descriptor(
            model=str(identity["model"]),
            reasoning_effort=str(identity["reasoning_effort"]),
            prompt_sha256=str(identity["prompt_sha256"]),
        )
        and source.get("argv_sha256")
        == reviewer_argv_sha256(
            model=str(identity["model"]),
            reasoning_effort=str(identity["reasoning_effort"]),
        )
        and source.get("stdin_sha256") == expected_stdin_sha256
        and all(source.get(name) == value for name, value in summary_fields.items())
        and all(result.get(name) == value for name, value in output_bindings.items())
        and source.get("materials") == expected_materials
        and permitted_inputs == expected_permitted_inputs
        and set(permitted_inputs) == reviewer_input_keys("conformance")
        and source.get("review_mode") == "conformance"
        and source.get("candidate_id")
        == source.get("candidate_before")
        == source.get("candidate_after")
        and source.get("reviewer_output_sha256")
        == references["result"]["sha256"]
        and source.get("stdout_sha256") == references["stdout"]["sha256"]
        and source.get("stderr_sha256") == references["stderr"]["sha256"]
        and stdout_ref.get("sha256") == references["stdout"]["sha256"]
        and stderr_ref.get("sha256") == references["stderr"]["sha256"]
        and source.get("input_context_receipt_sha256")
        == references["context_receipt"]["sha256"]
        and source.get("context_execution_receipt_sha256")
        == references["context_execution_receipt"]["sha256"]
        and qualification_conformance_output_valid(
            result=result,
            repository_id=EVALUATION_REPOSITORY_ID,
            task_contract_sha256=task_sha256,
            candidate=expected_candidate,
            expected_context=expected_context,
            case=case,
        )
        and output.get("bytes") == len(observed["result"])
        and observation.get("stdout", {}).get("bytes_normalized")
        == len(observed["stdout"])
        and observation.get("stderr", {}).get("bytes_normalized")
        == len(observed["stderr"])
        and source.get("executed_argv_sha256")
        == supervisor.get("executed_argv_sha256")
        and source.get("codex_thread_id") == parsed_stream.get("thread_id")
        and source.get("usage_observed") is True
        and all(source.get(name) == usage[name] for name in TOKEN_FIELDS)
        and source.get("limitations") == []
        and reviewer_stream_is_portable(observed["stdout"])
        and reviewer_stream_is_portable(observed["stderr"])
        and derived["execution_valid"] is True
    )


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
    if set(normalized_artifacts) != _required_artifacts(arm):
        raise ValueError("comparison artifact inventory is incomplete")
    expected = case.get("expected_disposition")
    expected_finding = case.get("expected_finding")
    finding_match = expected_finding is None and not findings
    if isinstance(expected_finding, Mapping):
        finding_match = any(
            isinstance(item, Mapping)
            and (
                (
                    arm == "ordinary"
                    and item.get("requirement_id") == case.get("requirement_id")
                )
                or (
                    arm == "governed"
                    and isinstance(item.get("violated_oracle"), str)
                    and str(case.get("requirement_id"))
                    in re.findall(r"[A-Za-z0-9_-]+", str(item.get("violated_oracle")))
                )
            )
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


def _ordinary_primitive_valid(
    *,
    case: Mapping[str, Any],
    execution: Mapping[str, Any],
    control: Mapping[str, Any],
    observation: Mapping[str, Any],
    result: Mapping[str, Any],
    references: Mapping[str, Mapping[str, str]],
    observed: Mapping[str, bytes],
    parsed_stream: Mapping[str, Any],
    usage: Mapping[str, Any],
    expected_identity: Mapping[str, Any],
) -> bool:
    """Reconstruct the ordinary invocation from protected inputs and raw facts."""
    try:
        schema = load_json(ORDINARY_RESULT_SCHEMA)
        prompt = ordinary_prompt(case)
        environment_keys = _expected_environment_keys(expected_identity)
        elapsed_ms = _elapsed_milliseconds(
            control.get("started_at"),
            control.get("ended_at"),
            expected_identity.get("timeout_seconds"),
        )
        derived = reviewer_observation_facts(observation)
    except (KeyError, OSError, TypeError, ValueError):
        return False
    supervisor = observation.get("supervisor")
    output = observation.get("output")
    candidate_id = ordinary_candidate_id(case)
    return bool(
        isinstance(schema, dict)
        and not validate_instance(dict(result), schema)
        and isinstance(supervisor, Mapping)
        and isinstance(output, Mapping)
        and set(control)
        == {
            "schema_version",
            "candidate_before",
            "candidate_after",
            "model",
            "reasoning_effort",
            "authentication",
            "codex_cli_version",
            "prompt_sha256",
            "output_schema_sha256",
            "launcher_sha256",
            "invocation",
            "argv_sha256",
            "executed_argv_sha256",
            "stdin_sha256",
            "workflow",
            "limits",
            "environment_keys",
            "started_at",
            "ended_at",
            "latency_ms",
            "output_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "limitations",
        }
        and control.get("schema_version") == "1.0.0"
        and control.get("candidate_before")
        == control.get("candidate_after")
        == candidate_id
        and control.get("model") == expected_identity.get("model")
        and control.get("reasoning_effort")
        == expected_identity.get("reasoning_effort")
        and control.get("authentication") == expected_identity.get("authentication")
        and control.get("codex_cli_version")
        == expected_identity.get("codex_cli_version")
        and control.get("prompt_sha256") == sha256_bytes(prompt.encode("utf-8"))
        and control.get("output_schema_sha256")
        == expected_identity.get("ordinary_schema_sha256")
        == sha256_bytes(read_bytes_once(ORDINARY_RESULT_SCHEMA))
        and control.get("launcher_sha256")
        == expected_identity.get("governed_launcher_sha256")
        == reviewer_launcher_sha256()
        and control.get("invocation")
        == sanitized_invocation_descriptor(
            model=str(expected_identity.get("model")),
            reasoning_effort=str(expected_identity.get("reasoning_effort")),
            prompt_sha256=str(control.get("prompt_sha256")),
        )
        and control.get("argv_sha256")
        == reviewer_argv_sha256(
            model=str(expected_identity.get("model")),
            reasoning_effort=str(expected_identity.get("reasoning_effort")),
        )
        and control.get("executed_argv_sha256")
        == supervisor.get("executed_argv_sha256")
        and control.get("stdin_sha256") == sha256_bytes(prompt.encode("utf-8"))
        and control.get("workflow")
        == {
            "system": "github-actions-comparison",
            "run_id": expected_identity.get("workflow_run_id"),
            "attempt": expected_identity.get("workflow_attempt"),
        }
        and control.get("limits")
        == {
            "timeout_seconds": expected_identity.get("timeout_seconds"),
            "max_output_bytes": expected_identity.get("max_output_bytes"),
        }
        and control.get("environment_keys") == environment_keys
        and control.get("latency_ms") == elapsed_ms == execution.get("elapsed_ms")
        and control.get("output_sha256") == references["result"]["sha256"]
        and control.get("stdout_sha256") == references["stdout"]["sha256"]
        and control.get("stderr_sha256") == references["stderr"]["sha256"]
        and output.get("bytes") == len(observed["result"])
        and observation.get("stdout", {}).get("bytes_normalized")
        == len(observed["stdout"])
        and observation.get("stderr", {}).get("bytes_normalized")
        == len(observed["stderr"])
        and result.get("candidate_id") == candidate_id
        and control.get("limitations") == []
        and reviewer_stream_is_portable(observed["stdout"])
        and reviewer_stream_is_portable(observed["stderr"])
        and parsed_stream.get("thread_id")
        and all(parsed_stream.get(name) == usage[name] for name in TOKEN_FIELDS)
        and derived["execution_valid"] is True
    )


def reconstruct_task(
    *,
    arm: str,
    case: Mapping[str, Any],
    corpus: Mapping[str, Any],
    decision: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, str]],
    artifact_reader: Callable[[Mapping[str, str]], bytes],
    expected_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive a task score from its retained result, execution and streams."""
    references = {
        name: _artifact_reference(reference)
        for name, reference in artifacts.items()
        if isinstance(name, str) and name
    }
    if set(references) != _required_artifacts(arm):
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
        primitive_valid = _governed_primitive_valid(
            case=case,
            corpus=corpus,
            decision=decision,
            source=source,
            result=result,
            references=references,
            observed=observed,
            parsed_stream=parsed_stream,
            usage=usage,
            expected_identity=expected_identity,
        )
    else:
        ordinary_observation = primitive.get("reviewer_observation")
        ordinary_control = primitive.get("control")
        if (
            set(primitive) != {"reviewer_observation", "control"}
            or not isinstance(ordinary_observation, Mapping)
            or not isinstance(ordinary_control, Mapping)
        ):
            raise ValueError("ordinary primitive execution does not reconstruct")
        primitive_valid = _ordinary_primitive_valid(
            case=case,
            execution=execution,
            control=ordinary_control,
            observation=ordinary_observation,
            result=result,
            references=references,
            observed=observed,
            parsed_stream=parsed_stream,
            usage=usage,
            expected_identity=expected_identity,
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
            "Governed-arm context is explicitly unqualified synthetic_bootstrap context for evaluation-case construction, not empirical production qualification.",
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
        timeout_seconds = expected_identity.get("timeout_seconds")
        max_output_bytes = expected_identity.get("max_output_bytes")
        _expected_environment_keys(expected_identity)
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
            or not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or max_output_bytes < 1
            or content_address(dict(document), "comparison_id") != dict(document)
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
                    corpus=corpus,
                    decision=decision,
                    artifacts=task["artifacts"],
                    artifact_reader=artifact_reader,
                    expected_identity=expected_identity,
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
