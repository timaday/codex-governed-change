"""Candidate-bound evidence references, manifests, and reconstruction."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    normalize_repo_path,
    require_sha256,
    sha256_bytes,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.artifacts import read_bounded_repository_file
from codex_governance.candidate import GitCliRepositoryAdapter, verify_candidate_identity
from codex_governance.context import (
    build_protected_context_sources,
    build_repository_inventory,
    compile_context,
)
from codex_governance.domain.model import DispositionState
from codex_governance.admission import evaluate_admission
from codex_governance.assurance import evaluate_assurance_claim
from codex_governance.attestation import (
    gate_implementation_sha256,
    mutation_implementation_sha256,
    verify_provenance_statement,
)
from codex_governance.authority import (
    authorize_governance_change,
    decision_applies,
    resolve_protected_obligations,
)
from codex_governance.mutation import (
    REQUIRED_CURATED_MUTANTS,
    build_mutation_probe_command,
    evaluate_mutation_record,
    mutated_source_identity,
    parse_curated_corpus,
)
from codex_governance.qualification import (
    qualification_evidence_valid,
    reviewer_qualification_state,
)
from codex_governance.rapid_review import evaluate_rapid_review
from codex_governance.reviewer import (
    REVIEWER_ENVIRONMENT_ALLOWLIST,
    parse_codex_jsonl_evidence,
    reviewer_observation_facts,
    reviewer_stream_is_portable,
)
from codex_governance.rst_operations import evaluate_operational_rst
from codex_governance.sandbox import (
    sandbox_execution_identity,
    validate_sandbox_capability,
)
from codex_governance.schema import load_json, validate_instance, validate_semantics
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.locators import resolve_evidence_locator


PRODUCER_VERSION = "0.1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def candidate_prefix(candidate_id: str) -> str:
    digest = require_sha256(candidate_id, name="candidate_id").split(":", 1)[1]
    return f"candidates/{digest}"


def repository_reference(
    *, evidence_root: str, relative_path: str, sha256: str
) -> dict[str, str]:
    root = normalize_repo_path(evidence_root)
    relative = normalize_repo_path(relative_path)
    return {
        "path": normalize_repo_path(f"{root}/{relative}"),
        "sha256": require_sha256(sha256),
    }


def read_reference(
    *, repository: Path, reference: Mapping[str, Any], max_bytes: int = 8_000_000
) -> bytes:
    data = read_bounded_repository_file(
        repository, str(reference.get("path")), max_bytes=max_bytes
    )
    if sha256_bytes(data) != require_sha256(reference.get("sha256")):
        raise ValueError("evidence reference digest mismatch")
    return data


def load_referenced_json(
    *,
    repository: Path,
    reference: Mapping[str, Any],
    schema_path: Path,
) -> dict[str, Any]:
    data = read_reference(repository=repository, reference=reference)
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("referenced artifact is not valid UTF-8 JSON") from exc
    schema = load_json(schema_path)
    errors = validate_instance(document, schema)
    errors.extend(
        validate_semantics(
            document, schema_path.name.removesuffix(".schema.json")
        )
    )
    if errors or not isinstance(document, dict):
        raise ValueError("referenced artifact fails its protected schema")
    return document


def assemble_gate_manifest(
    *,
    repository_id: str,
    task_contract_sha256: str,
    candidate_id: str,
    required_gate_ids: Sequence[str],
    gate_references: Mapping[str, Mapping[str, str]],
    created_at: str | None = None,
) -> dict[str, Any]:
    if set(required_gate_ids) != set(gate_references):
        raise ValueError("gate manifest references must exactly match required gates")
    document = {
        "schema_version": "1.0.0",
        "repository_id": repository_id,
        "task_contract_sha256": require_sha256(task_contract_sha256),
        "candidate_id": require_sha256(candidate_id, name="candidate_id"),
        "required_gate_ids": list(required_gate_ids),
        "gate_results": [
            {"gate_id": gate_id, "reference": dict(gate_references[gate_id])}
            for gate_id in required_gate_ids
        ],
        "created_at": created_at or utc_now(),
        "producer_version": PRODUCER_VERSION,
    }
    return content_address(document, "gate_manifest_id")


def assemble_evidence_manifest(
    *,
    repository_id: str,
    candidate_id: str,
    task_contract: Mapping[str, str],
    effective_policy: Mapping[str, str],
    required_gate_ids: Sequence[str],
    gate_references: Mapping[str, Mapping[str, str]],
    gate_manifest: Mapping[str, str],
    authenticated_decisions: Sequence[Mapping[str, str]],
    evidence_locators: Sequence[Mapping[str, str]],
    sandbox_capabilities: Sequence[Mapping[str, str]],
    provenance_statements: Sequence[Mapping[str, str]],
    mutation_corpus: Mapping[str, str],
    mutation_baseline: Mapping[str, str],
    mutant_records: Sequence[Mapping[str, str]],
    reviewer_qualification: Mapping[str, str],
    rapid_review_qualification: Mapping[str, str],
    reviewer_qualification_cases: Mapping[str, str],
    rapid_review_qualification_cases: Mapping[str, str],
    reviewer_qualification_corpus: Mapping[str, str],
    reviewer_qualification_label_decision: Mapping[str, str],
    context_sources: Mapping[str, str],
    context_projection: Mapping[str, str],
    context_qualification: Mapping[str, str],
    context_receipt: Mapping[str, str],
    context_execution_receipt: Mapping[str, str],
    reviewer_result: Mapping[str, str],
    reviewer_execution: Mapping[str, str],
    rapid_review_executions: Sequence[Mapping[str, str]],
    rapid_review_context_execution_receipts: Sequence[Mapping[str, str]],
    risk_register: Mapping[str, str],
    oracle_references: Sequence[Mapping[str, str]],
    coverage_notes: Sequence[Mapping[str, str]],
    follow_ups: Sequence[Mapping[str, str]],
    assurance_case: Mapping[str, str],
    risk_assessment: Mapping[str, str] | None = None,
    rapid_review_charters: Sequence[Mapping[str, str]] = (),
    rapid_review_sessions: Sequence[Mapping[str, str]] = (),
    rapid_review_debrief: Mapping[str, str] | None = None,
    risk_disposition: Mapping[str, str] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "2.0.0",
        "repository_id": repository_id,
        "candidate_id": require_sha256(candidate_id, name="candidate_id"),
        "task_contract": dict(task_contract),
        "effective_policy": dict(effective_policy),
        "authenticated_decisions": [dict(item) for item in authenticated_decisions],
        "evidence_locators": [dict(item) for item in evidence_locators],
        "sandbox_capabilities": [dict(item) for item in sandbox_capabilities],
        "provenance_statements": [dict(item) for item in provenance_statements],
        "gate_manifest": dict(gate_manifest),
        "required_gate_ids": list(required_gate_ids),
        "gate_results": [
            {"gate_id": gate_id, "reference": dict(gate_references[gate_id])}
            for gate_id in required_gate_ids
        ],
        "mutation_corpus": dict(mutation_corpus),
        "mutation_baseline": dict(mutation_baseline),
        "reviewer_result": dict(reviewer_result),
        "mutant_records": [dict(item) for item in mutant_records],
        "reviewer_qualification": dict(reviewer_qualification),
        "rapid_review_qualification": dict(rapid_review_qualification),
        "reviewer_qualification_cases": dict(reviewer_qualification_cases),
        "rapid_review_qualification_cases": dict(rapid_review_qualification_cases),
        "reviewer_qualification_corpus": dict(reviewer_qualification_corpus),
        "reviewer_qualification_label_decision": dict(
            reviewer_qualification_label_decision
        ),
        "context_sources": dict(context_sources),
        "context_projection": dict(context_projection),
        "context_qualification": dict(context_qualification),
        "context_receipt": dict(context_receipt),
        "context_execution_receipt": dict(context_execution_receipt),
        "reviewer_execution": dict(reviewer_execution),
        "rapid_review_executions": [dict(item) for item in rapid_review_executions],
        "rapid_review_context_execution_receipts": [
            dict(item) for item in rapid_review_context_execution_receipts
        ],
        "risk_register": dict(risk_register),
        "oracle_references": [dict(item) for item in oracle_references],
        "coverage_notes": [dict(item) for item in coverage_notes],
        "follow_ups": [dict(item) for item in follow_ups],
        "assurance_case": dict(assurance_case),
        "created_at": created_at or utc_now(),
        "producer_version": PRODUCER_VERSION,
    }
    if risk_assessment is not None:
        document["risk_assessment"] = dict(risk_assessment)
    if rapid_review_charters:
        document["rapid_review_charters"] = [dict(item) for item in rapid_review_charters]
    if rapid_review_sessions:
        document["rapid_review_sessions"] = [dict(item) for item in rapid_review_sessions]
    if rapid_review_debrief is not None:
        document["rapid_review_debrief"] = dict(rapid_review_debrief)
    if risk_disposition is not None:
        document["risk_disposition"] = dict(risk_disposition)
    return content_address(document, "manifest_id")


def evaluate_manifest(
    *,
    repository: Path,
    manifest: Mapping[str, Any],
    schema_root: Path,
    current_candidate: Mapping[str, Any],
    evaluated_at: str,
    verified_decision_ids: frozenset[str] = frozenset(),
) -> tuple[DispositionState, list[str]]:
    """Reconstruct all fixed assurance claims from raw typed references."""
    repository_id = manifest.get("repository_id")
    if not verify_candidate_identity(current_candidate):
        return DispositionState.UNKNOWN, ["CURRENT_CANDIDATE_IDENTITY_INVALID"]
    current_candidate_id = current_candidate.get("candidate_id")
    if (
        not isinstance(repository_id, str)
        or current_candidate.get("repository_id") != repository_id
        or manifest.get("candidate_id") != current_candidate_id
        or not verify_content_address(manifest, "manifest_id")
    ):
        return DispositionState.UNKNOWN, ["MANIFEST_IDENTITY_INVALID"]
    try:
        now = parse_rfc3339(evaluated_at)
        manifest_created = parse_rfc3339(str(manifest.get("created_at")))
    except (TypeError, ValueError):
        return DispositionState.UNKNOWN, ["EVALUATION_TIME_INVALID"]
    if now < manifest_created:
        return DispositionState.UNKNOWN, ["EVALUATION_PRECEDES_MANIFEST"]

    upstream: dict[str, str] = {}
    defeaters: dict[str, list[str]] = {
        name: []
        for name in (
            "scope_authorized", "candidate_current", "gates_complete",
            "governance_integrity", "rst_complete", "mutation_complete",
            "fresh_review_complete", "residual_risk_visible", "context_complete",
        )
    }

    def load(reference: Mapping[str, Any], schema_name: str) -> dict[str, Any]:
        return load_referenced_json(
            repository=repository,
            reference=reference,
            schema_path=schema_root / f"{schema_name}.schema.json",
        )

    try:
        task = load(manifest["task_contract"], "task-contract")
        policy = load(manifest["effective_policy"], "effective-policy")
        task_sha = manifest["task_contract"]["sha256"]
        policy_sha = manifest["effective_policy"]["sha256"]
    except (KeyError, OSError, TypeError, ValueError):
        return DispositionState.UNKNOWN, ["AUTHORITY_REFERENCE_INVALID"]
    if (
        task.get("repository_id") != repository_id
        or policy.get("repository_id") != repository_id
        or current_candidate.get("effective_policy_sha256") != policy_sha
    ):
        return DispositionState.BLOCK, ["CROSS_REPOSITORY_AUTHORITY"]
    if current_candidate.get("base_commit") != task.get("base_commit"):
        return DispositionState.BLOCK, ["CANDIDATE_BASE_NOT_AUTHORIZED"]

    try:
        decisions = [load(reference, "authenticated-decision") for reference in manifest["authenticated_decisions"]]
    except (KeyError, OSError, TypeError, ValueError):
        decisions = []
    valid_decisions = [item for item in decisions if verify_content_address(item, "decision_id")]
    try:
        locators = [load(reference, "evidence-locator") for reference in manifest["evidence_locators"]]
        resolved_locators = {
            locator["locator_id"]: sha256_bytes(resolve_evidence_locator(repository, locator))
            for locator in locators
            if verify_content_address(locator, "locator_id")
            and locator.get("repository_id") == repository_id
            and locator.get("task_contract_sha256") == task_sha
            and locator.get("candidate_id") == current_candidate_id
        }
    except (KeyError, OSError, TypeError, ValueError):
        resolved_locators = {}

    def references_resolve(references: Sequence[Mapping[str, Any]]) -> bool:
        return all(
            isinstance(reference, Mapping)
            and resolved_locators.get(reference.get("locator_id")) == reference.get("sha256")
            for reference in references
        )

    def model_usage_reconciles(
        execution: Mapping[str, Any], context_execution: Mapping[str, Any]
    ) -> bool:
        keys = (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
            "latency_ms",
        )
        environment_keys = execution.get("environment_keys")
        expected_materials = [
            {"name": "task-contract", "sha256": task_sha},
            {"name": "effective-policy", "sha256": policy_sha},
            {"name": "candidate", "sha256": current_candidate_id},
            {"name": "reviewer-prompt", "sha256": execution.get("prompt_sha256")},
            {"name": "output-schema", "sha256": execution.get("output_schema_sha256")},
            {"name": "launcher", "sha256": execution.get("launcher_sha256")},
            {"name": "qualification", "sha256": execution.get("qualification_id")},
            {"name": "context-source-bundle", "sha256": manifest["context_sources"]["sha256"]},
            {"name": "context-projection", "sha256": manifest["context_projection"]["sha256"]},
            {"name": "context-qualification", "sha256": context_receipt.get("context_qualification_id")},
            {"name": "prepared-context", "sha256": execution.get("input_context_receipt_sha256")},
            {"name": "post-run-context", "sha256": execution.get("context_execution_receipt_sha256")},
        ]
        return bool(
            execution.get("usage_observed") is True
            and context_execution.get("usage_observed") is True
            and all(execution.get(key) == context_execution.get(key) for key in keys)
            and isinstance(execution.get("input_tokens"), int)
            and execution.get("input_tokens", 0) > 0
            and isinstance(execution.get("output_tokens"), int)
            and execution.get("output_tokens", 0) > 0
            and execution.get("cached_input_tokens", 0)
            <= execution.get("input_tokens", 0)
            and isinstance(environment_keys, list)
            and set(environment_keys) <= REVIEWER_ENVIRONMENT_ALLOWLIST
            and execution.get("codex_thread_id") not in {None, "", "unavailable"}
            and execution.get("limits")
            == {
                "timeout_seconds": policy.get("reviewer", {}).get("timeout_seconds"),
                "max_output_bytes": policy.get("reviewer", {}).get("max_output_bytes"),
            }
            and execution.get("tools")
            and len(execution["tools"]) == 1
            and execution["tools"][0].get("name") == "codex-cli"
            and isinstance(execution["tools"][0].get("version"), str)
            and execution["tools"][0]["version"].startswith("codex-cli ")
            and execution.get("materials") == expected_materials
        )

    def reviewer_execution_reconstructs(
        execution: Mapping[str, Any], output_reference: Mapping[str, Any]
    ) -> bool:
        try:
            stdout = read_reference(repository=repository, reference=execution["stdout"])
            stderr = read_reference(repository=repository, reference=execution["stderr"])
            output_bytes = read_reference(
                repository=repository, reference=output_reference
            )
            parsed_output = json.loads(output_bytes)
            parsed_stream = parse_codex_jsonl_evidence(stdout)
            final_message = json.loads(str(parsed_stream["final_message"]))
            primitive = execution["observation"]
            derived = reviewer_observation_facts(primitive)
        except (KeyError, OSError, TypeError, UnicodeError, ValueError):
            return False
        required_true = (
            "stdin_delivery_complete",
            "capture_threads_completed",
            "process_cleanup_complete",
            "observation_complete",
            "output_valid",
            "bindings_match",
            "execution_valid",
        )
        return bool(
            sha256_bytes(stdout) == execution.get("stdout_sha256")
            and sha256_bytes(stderr) == execution.get("stderr_sha256")
            and sha256_bytes(output_bytes) == execution.get("reviewer_output_sha256")
            and execution.get("stdout", {}).get("sha256")
            == execution.get("stdout_sha256")
            and execution.get("stderr", {}).get("sha256")
            == execution.get("stderr_sha256")
            and reviewer_stream_is_portable(stdout)
            and reviewer_stream_is_portable(stderr)
            and parsed_stream.get("jsonl_valid") is True
            and parsed_stream.get("usage_observed") is True
            and parsed_stream.get("thread_id") == execution.get("codex_thread_id")
            and final_message == parsed_output
            and isinstance(primitive, Mapping)
            and primitive.get("stdout", {}).get("bytes_normalized") == len(stdout)
            and primitive.get("stderr", {}).get("bytes_normalized") == len(stderr)
            and primitive.get("output", {}).get("bytes") == len(output_bytes)
            and all(execution.get(key) == value for key, value in derived.items())
            and all(derived[key] is True for key in required_true)
            and derived["output_truncated"] is False
            and execution.get("return_code") == primitive.get("return_code") == 0
            and execution.get("timed_out") == primitive.get("timed_out") is False
            and execution.get("usage_observed") is True
            and all(
                execution.get(key) == parsed_stream.get(key)
                for key in (
                    "input_tokens",
                    "cached_input_tokens",
                    "output_tokens",
                    "reasoning_output_tokens",
                )
            )
        )
    task_approved = any(
        decision_applies(
            decision=item, repository_id=repository_id,
            candidate_id=current_candidate_id, task_contract_sha256=task_sha,
            policy_sha256=policy_sha, required_type="task_approval",
            required_scope=task.get("scope", ()), now=now,
            source_verified=item.get("decision_id") in verified_decision_ids,
        )
        for item in valid_decisions
    )
    if not task_approved:
        defeaters["scope_authorized"].append("authenticated task approval missing or inapplicable")
        upstream["authority"] = "absent"
    else:
        upstream["authority"] = "success"

    affected_paths = [
        item.get("path", "") for item in task.get("affected_surfaces", ())
        if isinstance(item, Mapping)
    ]
    changed_paths = list(current_candidate.get("changed_paths", ()))
    scope_complete = all(
        any(
            changed == affected or changed.startswith(affected.rstrip("/") + "/")
            for affected in affected_paths
            if isinstance(affected, str) and affected
        )
        for changed in changed_paths
    )
    if not scope_complete:
        upstream["authority"] = "failure"
        defeaters["scope_authorized"].append(
            "task affected surfaces omit a candidate-bound changed path"
        )
    governance_state = authorize_governance_change(
        repository_id=repository_id, candidate_id=current_candidate_id,
        task_contract_sha256=task_sha, policy_sha256=policy_sha,
        changed_paths=changed_paths, decisions=valid_decisions,
        verified_decision_ids=verified_decision_ids,
        governance_change_authorized=False,
        approver="", now=now,
    )
    if governance_state is DispositionState.BLOCK:
        upstream["governance"] = "failure"
        defeaters["governance_integrity"].append("protected governance authorization is absent")
    else:
        upstream["governance"] = "success"

    try:
        obligations = resolve_protected_obligations(
            changed_paths=changed_paths,
            affected_surfaces=affected_paths,
            protected_rules=policy["protected_minimums"],
            requested_risk=task["risk_profile"],
            requested_gates=task["required_gate_ids"],
            reduction_decisions=valid_decisions,
        )
        gate_policy = {item["gate_id"]: item for item in policy["gates"]}
    except (KeyError, TypeError, ValueError):
        obligations = {"gate_ids": []}
        gate_policy = {}

    capability_by_sha: dict[str, Mapping[str, Any]] = {}
    provenance_by_sha: dict[str, Mapping[str, Any]] = {}
    capability_reference_by_sha: dict[str, Mapping[str, Any]] = {}
    provenance_reference_by_sha: dict[str, Mapping[str, Any]] = {}

    def execution_evidence_valid(
        result: Mapping[str, Any], *, source_identity: str,
        expected_command: Sequence[str], expected_gate_id: str,
        expected_gate_definition_sha256: str,
        expected_implementation_sha256: str,
        expected_timeout_seconds: int,
        expected_max_output_bytes: int,
        expected_shell: bool = False,
    ) -> bool:
        capability_sha = result.get("sandbox_capability_sha256")
        capability = capability_by_sha.get(str(capability_sha))
        statement_ref = result.get("provenance_statement")
        if not isinstance(statement_ref, Mapping):
            return False
        statement_sha = statement_ref.get("sha256")
        statement = provenance_by_sha.get(str(statement_sha))
        predicate = statement.get("predicate", {}) if isinstance(statement, Mapping) else {}
        environment = predicate.get("environment", {}) if isinstance(predicate, Mapping) else {}
        producer = predicate.get("producer", {}) if isinstance(predicate, Mapping) else {}
        sandbox_command = (
            ["sh", "-c", expected_command[0]]
            if expected_shell
            else list(expected_command)
        )
        try:
            expected_execution_identity = sandbox_execution_identity(
                provider=policy["sandbox"]["provider"],
                provider_version=capability["provider_version"],
                image=policy["sandbox"]["image"],
                command=sandbox_command,
                process_limit=int(policy["sandbox"]["process_limit"]),
                memory_bytes=int(policy["sandbox"]["memory_bytes"]),
                cpu_seconds=expected_timeout_seconds,
                timeout_seconds=expected_timeout_seconds,
                output_bytes=expected_max_output_bytes,
            )
        except (KeyError, TypeError, ValueError):
            return False
        try:
            chronology_valid = (
                parse_rfc3339(str(capability.get("verified_at")))
                <= parse_rfc3339(str(result.get("started_at")))
                <= parse_rfc3339(str(result.get("ended_at")))
                and predicate.get("started_at") == result.get("started_at")
                and predicate.get("ended_at") == result.get("ended_at")
            )
        except (AttributeError, TypeError, ValueError):
            chronology_valid = False
        artifacts = result.get("artifacts")
        if (
            not isinstance(artifacts, Sequence)
            or isinstance(artifacts, (str, bytes))
            or len(artifacts) != 2
        ):
            return False
        raw_streams: dict[str, str] = {}
        try:
            for artifact in artifacts:
                if not isinstance(artifact, Mapping):
                    return False
                stream = artifact.get("stream")
                declared_bytes = artifact.get("bytes")
                if (
                    stream not in {"stdout", "stderr"}
                    or stream in raw_streams
                    or artifact.get("truncated") is not False
                    or not isinstance(declared_bytes, int)
                    or isinstance(declared_bytes, bool)
                    or declared_bytes < 0
                    or declared_bytes > expected_max_output_bytes
                ):
                    return False
                data = read_reference(
                    repository=repository,
                    reference={
                        "path": artifact.get("path"),
                        "sha256": artifact.get("sha256"),
                    },
                    max_bytes=expected_max_output_bytes,
                )
                if len(data) != declared_bytes:
                    return False
                raw_streams[str(stream)] = sha256_bytes(data)
        except (OSError, TypeError, ValueError):
            return False
        if set(raw_streams) != {"stdout", "stderr"}:
            return False
        termination = result.get("termination")
        status = result.get("status")
        if not isinstance(termination, Mapping):
            return False
        exit_code = termination.get("exit_code")
        status_matches_termination = (
            result.get("observation_complete") is True
            and termination.get("kind") == "exited"
            and isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
            and (
                (status == "PASS" and exit_code == 0)
                or (status == "FAIL" and exit_code != 0)
            )
        )
        provenance_artifacts = [
            {"name": "stdout", "sha256": raw_streams["stdout"]},
            {"name": "stderr", "sha256": raw_streams["stderr"]},
            {"name": "sandbox-capability", "sha256": capability_sha},
        ]
        return bool(
            status_matches_termination
            and chronology_valid
            and predicate.get("artifacts") == provenance_artifacts
            and isinstance(capability, Mapping)
            and not validate_sandbox_capability(capability)
            and capability_reference_by_sha.get(str(capability_sha)) is not None
            and provenance_reference_by_sha.get(str(statement_sha)) == statement_ref
            and isinstance(statement, Mapping)
            and verify_provenance_statement(
                statement,
                repository_id,
                current_candidate_id,
                current_candidate_id,
            )
            and result.get("repository_id") == repository_id
            and result.get("task_contract_sha256") == task_sha
            and result.get("candidate_before") == current_candidate_id
            and result.get("candidate_after") == current_candidate_id
            and result.get("gate_id") == expected_gate_id
            and result.get("command") == list(expected_command)
            and result.get("source_identity") == source_identity
            and result.get("execution_identity") == capability.get("execution_identity")
            and capability.get("source_identity") == source_identity
            and capability.get("provider") == policy["sandbox"]["provider"]
            and capability.get("image") == policy["sandbox"]["image"]
            and capability.get("command") == sandbox_command
            and capability.get("process_limit") == policy["sandbox"]["process_limit"]
            and capability.get("memory_bytes") == policy["sandbox"]["memory_bytes"]
            and capability.get("cpu_seconds") == expected_timeout_seconds
            and capability.get("timeout_seconds") == expected_timeout_seconds
            and capability.get("output_bytes") == expected_max_output_bytes
            and capability.get("implementation_sha256")
            == expected_implementation_sha256
            and result.get("execution_identity") == expected_execution_identity
            and result.get("execution_identity") == environment.get("execution_identity")
            and source_identity == environment.get("source_identity")
            and capability_sha == environment.get("sandbox_capability_sha256")
            and predicate.get("task_contract_sha256") == task_sha
            and predicate.get("effective_policy_sha256") == policy_sha
            and predicate.get("gate_definition_sha256")
            == expected_gate_definition_sha256
            and predicate.get("result") == result.get("status")
            and predicate.get("limits")
            == {
                "timeout_seconds": expected_timeout_seconds,
                "max_output_bytes": expected_max_output_bytes,
                "process_limit": policy["sandbox"]["process_limit"],
                "memory_bytes": policy["sandbox"]["memory_bytes"],
                "cpu_seconds": expected_timeout_seconds,
            }
            and any(
                tool.get("name") == policy["sandbox"]["provider"]
                and tool.get("version") == capability.get("provider_version")
                for tool in predicate.get("tools", ())
                if isinstance(tool, Mapping)
            )
            and producer.get("builder_id") == "codex-governed-change"
            and producer.get("implementation_sha256")
            == expected_implementation_sha256
            and producer.get("version") == PRODUCER_VERSION
        )

    gate_documents: list[dict[str, Any]] = []
    try:
        capabilities = [load(reference, "sandbox-capability") for reference in manifest["sandbox_capabilities"]]
        capability_by_sha = {
            reference["sha256"]: document
            for reference, document in zip(manifest["sandbox_capabilities"], capabilities, strict=True)
        }
        provenance = [load(reference, "provenance-statement") for reference in manifest["provenance_statements"]]
        provenance_by_sha = {
            reference["sha256"]: document
            for reference, document in zip(manifest["provenance_statements"], provenance, strict=True)
        }
        capability_reference_by_sha = {
            reference["sha256"]: reference
            for reference in manifest["sandbox_capabilities"]
        }
        provenance_reference_by_sha = {
            reference["sha256"]: reference
            for reference in manifest["provenance_statements"]
        }

        gate_manifest = load(manifest["gate_manifest"], "gate-manifest")
        gate_manifest_ok = verify_content_address(gate_manifest, "gate_manifest_id")
        required_gate_ids = tuple(manifest["required_gate_ids"])
        gate_items = manifest["gate_results"]
        if (
            {item["gate_id"] for item in gate_items} != set(required_gate_ids)
            or set(required_gate_ids) != set(obligations["gate_ids"])
            or set(required_gate_ids) != set(task["required_gate_ids"])
        ):
            raise ValueError("gate set mismatch")
        gate_states: list[str] = []
        for item in gate_items:
            result = load(item["reference"], "gate-result")
            gate_documents.append(result)
            definition = gate_policy.get(item["gate_id"])
            if (
                not isinstance(definition, Mapping)
                or task["profile"] not in definition.get("profiles", ())
                or result.get("command") != definition.get("command")
                or result.get("profile") != task["profile"]
            ):
                gate_states.append("UNKNOWN")
                continue
            if not execution_evidence_valid(
                result,
                source_identity=current_candidate_id,
                expected_command=definition["command"],
                expected_gate_id=item["gate_id"],
                expected_gate_definition_sha256=sha256_canonical(definition),
                expected_implementation_sha256=gate_implementation_sha256(),
                expected_timeout_seconds=int(definition["timeout_seconds"]),
                expected_max_output_bytes=int(definition["max_output_bytes"]),
                expected_shell=bool(definition["shell"]),
            ):
                gate_states.append("UNKNOWN")
            else:
                gate_states.append(result["status"])
        gate_manifest_exact = (
            gate_manifest_ok
            and gate_manifest.get("repository_id") == repository_id
            and gate_manifest.get("task_contract_sha256") == task_sha
            and gate_manifest.get("candidate_id") == current_candidate_id
            and gate_manifest.get("required_gate_ids") == list(required_gate_ids)
            and gate_manifest.get("gate_results") == gate_items
            and parse_rfc3339(gate_manifest["created_at"])
            >= max(parse_rfc3339(result["ended_at"]) for result in gate_documents)
        )
    except (KeyError, OSError, TypeError, ValueError):
        gate_states = ["UNKNOWN"]
        gate_manifest_exact = False
    if "FAIL" in gate_states:
        upstream["gates"] = "failure"
        defeaters["gates_complete"].append("a mandatory deterministic gate failed")
    elif not gate_manifest_exact or not gate_states or any(item != "PASS" for item in gate_states):
        upstream["gates"] = "absent"
        defeaters["gates_complete"].append("gate evidence, sandbox, or provenance is incomplete")
    else:
        upstream["gates"] = "success"

    mutation_records: list[dict[str, Any]] = []
    try:
        corpus_reference = manifest["mutation_corpus"]
        expected_corpus_path = normalize_repo_path(policy["mutation"]["corpus_path"])
        if normalize_repo_path(corpus_reference["path"]) != expected_corpus_path:
            raise ValueError("mutation corpus path is not protected policy")
        corpus_bytes = read_reference(repository=repository, reference=corpus_reference)
        corpus_document = json.loads(corpus_bytes.decode("utf-8"))
        corpus = parse_curated_corpus(corpus_bytes)
        if corpus_document != corpus:
            raise ValueError("mutation corpus bytes changed during reconstruction")
        corpus_by_id = {item["mutant_id"]: item for item in corpus["mutants"]}
        mutation_max_output_bytes = max(
            int(item["max_output_bytes"]) for item in policy["gates"]
        )
        baseline = load(manifest["mutation_baseline"], "gate-result")
        baseline_command = ["/usr/bin/env", "PYTHONPATH=src", *corpus["baseline_command"]]
        baseline_ok = (
            baseline.get("status") == "PASS"
            and execution_evidence_valid(
                baseline,
                source_identity=current_candidate_id,
                expected_command=baseline_command,
                expected_gate_id="mutation-baseline",
                expected_gate_definition_sha256=sha256_canonical(
                    {"gate_id": "mutation-baseline", "command": baseline_command}
                ),
                expected_implementation_sha256=mutation_implementation_sha256(),
                expected_timeout_seconds=max(
                    int(item["timeout_seconds"]) for item in policy["gates"]
                ),
                expected_max_output_bytes=mutation_max_output_bytes,
            )
        )
        mutation_records = [load(reference, "mutant-record") for reference in manifest["mutant_records"]]
        observed_mutants = {str(item["mutant_id"]).lower().removeprefix("mutant-") for item in mutation_records}
        mutation_states: list[DispositionState] = []
        for record in mutation_records:
            corpus_key = str(record["mutant_id"]).lower().removeprefix("mutant-")
            definition = corpus_by_id.get(corpus_key)
            if not isinstance(definition, Mapping):
                mutation_states.append(DispositionState.UNKNOWN)
                continue
            expected_patch = sha256_canonical(
                {
                    "path": normalize_repo_path(definition["path"]),
                    "old": definition["old"],
                    "new": definition["new"],
                    "operator": definition["operator"],
                }
            )
            expected_source = mutated_source_identity(
                candidate_id=current_candidate_id,
                corpus_id=corpus["corpus_id"],
                mutant_id=definition["mutant_id"],
                patch_sha256=expected_patch,
            )
            execution = load(record["execution_result"], "gate-result")
            expected_command = build_mutation_probe_command(
                definition["path"], definition["selected_command"]
            )
            termination = execution.get("termination", {})
            killed_exact = (
                record.get("outcome") == "KILLED"
                and execution.get("status") == "FAIL"
                and termination.get("kind") == "exited"
                and termination.get("exit_code") not in {None, 120}
            )
            exact = (
                baseline_ok
                and record.get("repository_id") == repository_id
                and record.get("task_contract_sha256") == task_sha
                and record.get("effective_policy_sha256") == policy_sha
                and record.get("candidate_id") == current_candidate_id
                and record.get("corpus_id") == corpus["corpus_id"]
                and record.get("patch_sha256") == expected_patch
                and record.get("mutated_source_identity") == expected_source
                and record.get("selected_command") == definition["selected_command"]
                and record.get("operator") == definition["operator"]
                and record.get("requirement_id") == definition["requirement_id"]
                and record.get("execution_identity") == execution.get("execution_identity")
                and record.get("sandbox_capability")
                == capability_reference_by_sha.get(execution.get("sandbox_capability_sha256"))
                and record.get("provenance_statement") == execution.get("provenance_statement")
                and any(
                    reference.get("sha256") == record["execution_result"]["sha256"]
                    for reference in record.get("causal_evidence", ())
                    if isinstance(reference, Mapping)
                )
                and references_resolve(record.get("causal_evidence", ()))
                and execution_evidence_valid(
                    execution,
                    source_identity=expected_source,
                    expected_command=expected_command,
                    expected_gate_id=f"mutant-{definition['mutant_id']}",
                    expected_gate_definition_sha256=sha256_canonical(
                        {
                            "gate_id": f"mutant-{definition['mutant_id']}",
                            "command": expected_command,
                        }
                    ),
                    expected_implementation_sha256=mutation_implementation_sha256(),
                    expected_timeout_seconds=max(
                        int(item["timeout_seconds"]) for item in policy["gates"]
                    ),
                    expected_max_output_bytes=mutation_max_output_bytes,
                )
                and killed_exact
            )
            mutation_states.append(
                evaluate_mutation_record(record)
                if exact
                else (
                    DispositionState.BLOCK
                    if record.get("outcome") == "SURVIVED"
                    else DispositionState.UNKNOWN
                )
            )
        mutation_complete = (
            baseline_ok
            and REQUIRED_CURATED_MUTANTS == observed_mutants
            and len(mutation_records) == len(REQUIRED_CURATED_MUTANTS)
            and all(
            item is DispositionState.READY_FOR_HUMAN for item in mutation_states
            )
        )
    except (KeyError, OSError, TypeError, ValueError):
        mutation_complete = False
        mutation_states = []
    if any(item is DispositionState.BLOCK for item in mutation_states):
        upstream["mutation"] = "failure"
        defeaters["mutation_complete"].append("a mandatory mutant survived")
    elif not mutation_complete:
        upstream["mutation"] = "absent"
        defeaters["mutation_complete"].append("the curated semantic mutation corpus is incomplete")
    else:
        upstream["mutation"] = "success"

    try:
        context_sources = load(manifest["context_sources"], "context-source-bundle")
        context_projection = load(
            manifest["context_projection"], "context-projection"
        )
        context_qualification = load(
            manifest["context_qualification"], "context-qualification"
        )
        context_receipt = load(manifest["context_receipt"], "context-receipt")
        context_execution = load(
            manifest["context_execution_receipt"],
            "context-execution-receipt",
        )
        affected_closure = GitCliRepositoryAdapter(
            repository
        ).conservative_affected_closure(
            candidate=current_candidate,
            evidence_root=policy["evidence_root"],
        )
        repository_inventory = build_repository_inventory(
            repository,
            affected_closure=affected_closure,
            changed_paths=current_candidate["changed_paths"],
        )
        reconstructed_sources = build_protected_context_sources(
            candidate=current_candidate,
            task=task,
            policy=policy,
            repository_inventory=repository_inventory,
            affected_closure=affected_closure,
            gate_results=gate_documents,
            mutation_records=mutation_records,
            created_at=context_sources["created_at"],
        )
        reconstructed = compile_context(
            sources=reconstructed_sources,
            candidate=current_candidate,
            requested_profile=context_sources["requested_profile"],
            token_budget=context_sources["token_budget"],
            changed_paths=current_candidate["changed_paths"],
            affected_closure=affected_closure,
            model=context_sources["model"],
            reasoning_effort=context_sources["reasoning_effort"],
            context_qualification=context_qualification,
            protected_qualification_ids=policy["context"]["qualification_ids"],
        )
        context_ok = (
            verify_content_address(context_sources, "source_bundle_id")
            and verify_content_address(context_projection, "projection_id")
            and verify_content_address(context_qualification, "qualification_id")
            and verify_content_address(context_receipt, "receipt_id")
            and verify_content_address(context_execution, "execution_receipt_id")
            and context_sources == reconstructed["source_bundle"]
            and context_projection == reconstructed["projection"]
            and context_receipt == reconstructed["receipt"]
            and manifest["context_sources"]["sha256"]
            == context_receipt.get("source_bundle_sha256")
            and manifest["context_projection"]["sha256"]
            == context_receipt.get("projection_sha256")
            and context_qualification["qualification_id"]
            == context_receipt.get("context_qualification_id")
            and context_receipt.get("repository_id") == repository_id
            and context_receipt.get("candidate_id") == current_candidate_id
            and context_receipt.get("truncation_status") == "NONE"
            and context_receipt.get("quality_metrics", {}).get("unresolved_unknowns") == 0
            and context_execution.get("repository_id") == repository_id
            and context_execution.get("candidate_id") == current_candidate_id
            and context_execution.get("input_context_receipt_sha256")
            == manifest["context_receipt"]["sha256"]
            and context_execution.get("projection_sha256")
            == context_receipt.get("projection_sha256")
            and context_execution.get("review_mode") == "conformance"
            and context_execution.get("reviewer_output_sha256")
            == manifest["reviewer_result"]["sha256"]
            and context_execution.get("model") == policy.get("reviewer", {}).get("model")
            and context_execution.get("reasoning_effort")
            == policy.get("reviewer", {}).get("reasoning_effort")
            and context_execution.get("usage_observed") is True
        )
    except (KeyError, OSError, TypeError, ValueError):
        context_receipt, context_execution, context_ok = {}, {}, False
    upstream["context"] = "success" if context_ok else "absent"
    if not context_ok:
        defeaters["context_complete"].append("context receipt is stale, incomplete, or budget-insufficient")

    try:
        qualification = load(manifest["reviewer_qualification"], "reviewer-qualification")
        qualification_cases = load(
            manifest["reviewer_qualification_cases"],
            "reviewer-qualification-cases",
        )
        qualification_corpus = load(
            manifest["reviewer_qualification_corpus"],
            "reviewer-qualification-corpus",
        )
        qualification_label_decision = load(
            manifest["reviewer_qualification_label_decision"],
            "reviewer-qualification-label-decision",
        )
        identity = {
            field: qualification.get(field)
            for field in ("prompt_sha256", "schema_sha256", "launcher_sha256", "codex_cli_version", "model", "reasoning_effort")
        }
        qualification_ok = qualification_evidence_valid(
            mode="conformance",
            record=qualification,
            case_evidence=qualification_cases,
            corpus=qualification_corpus,
            label_decision=qualification_label_decision,
            artifact_reader=lambda reference: read_reference(
                repository=repository, reference=reference
            ),
            schema_root=schema_root,
            protected_repository_id=repository_id,
            verified_decision_ids=verified_decision_ids,
            evaluated_at=evaluated_at,
        ) and reviewer_qualification_state(
            identity,
            qualification,
            protected_qualification_id=policy.get("reviewer", {})
            .get("qualification_ids", {})
            .get("conformance"),
            protected_corpus_sha256=policy.get("reviewer", {}).get(
                "qualification_corpus_sha256"
            ),
            protected_label_decision_id=policy.get("reviewer", {}).get(
                "qualification_label_decision_id"
            ),
        ) is DispositionState.READY_FOR_HUMAN
        reviewer = load(manifest["reviewer_result"], "reviewer-result")
        reviewer_execution = load(
            manifest["reviewer_execution"], "reviewer-execution"
        )
        reviewer_exact = (
            reviewer.get("repository_id") == repository_id
            and reviewer.get("candidate_id") == current_candidate_id
            and reviewer.get("task_contract_sha256") == task_sha
            and reviewer.get("effective_policy_sha256") == policy_sha
            and reviewer.get("gate_manifest_sha256") == manifest["gate_manifest"]["sha256"]
            and reviewer.get("context_receipt_sha256") == manifest["context_receipt"]["sha256"]
            and reviewer.get("qualification_id") == qualification.get("qualification_id")
            and reviewer.get("reviewer_prompt_sha256") == qualification.get("prompt_sha256")
            and reviewer.get("model") == qualification.get("model")
            and reviewer.get("retrieval_expansions")
            == context_execution.get("retrieval_expansions")
            and {"exact_diff", "affected_closure", "governance_and_evidence"}
            <= set(reviewer.get("reviewed_surfaces", ()))
            and reviewer.get("affected_closure")
            == context_projection.get("assurance_kernel", {}).get(
                "affected_closure"
            )
            and set(current_candidate.get("changed_paths", ()))
            <= set(reviewer.get("affected_closure", ()))
            and reviewer_execution.get("repository_id") == repository_id
            and reviewer_execution.get("task_contract_sha256") == task_sha
            and reviewer_execution.get("effective_policy_sha256") == policy_sha
            and reviewer_execution.get("candidate_id") == current_candidate_id
            and reviewer_execution.get("review_mode") == "conformance"
            and reviewer_execution.get("prompt_sha256")
            == qualification.get("prompt_sha256")
            and reviewer_execution.get("output_schema_sha256")
            == qualification.get("schema_sha256")
            and reviewer_execution.get("launcher_sha256")
            == qualification.get("launcher_sha256")
            and reviewer_execution.get("qualification_id")
            == qualification.get("qualification_id")
            and reviewer_execution.get("model") == qualification.get("model")
            and reviewer_execution.get("reasoning_effort")
            == qualification.get("reasoning_effort")
            and reviewer_execution.get("tools")
            == [{"name": "codex-cli", "version": qualification.get("codex_cli_version")}]
            and reviewer_execution.get("input_context_receipt_sha256")
            == manifest["context_receipt"]["sha256"]
            and reviewer_execution.get("context_execution_receipt_sha256")
            == manifest["context_execution_receipt"]["sha256"]
            and reviewer_execution.get("reviewer_output_sha256")
            == manifest["reviewer_result"]["sha256"]
            and reviewer_execution.get("candidate_before") == current_candidate_id
            and reviewer_execution.get("candidate_after") == current_candidate_id
            and reviewer_execution.get("return_code") == 0
            and reviewer_execution.get("timed_out") is False
            and reviewer_execution.get("observation_complete") is True
            and reviewer_execution.get("capture_threads_completed") is True
            and reviewer_execution.get("process_cleanup_complete") is True
            and reviewer_execution.get("execution_valid") is True
            and reviewer_execution.get("output_valid") is True
            and reviewer_execution.get("bindings_match") is True
            and reviewer_execution.get("output_truncated") is False
            and model_usage_reconciles(reviewer_execution, context_execution)
            and reviewer_execution_reconstructs(
                reviewer_execution, manifest["reviewer_result"]
            )
        )
        reviewer_verdict = reviewer.get("verdict") if reviewer_exact and qualification_ok else "UNKNOWN"
        claims = reviewer.get("claims", ())
        if reviewer_verdict == "NO_BLOCKING_FINDING_OBSERVED" and (
            not claims
            or any(
                claim.get("classification") not in {
                    "DIRECTLY_OBSERVED",
                    "VERIFIED_WITHIN_SCOPE",
                }
                for claim in claims
                if isinstance(claim, Mapping)
            )
            or any(not isinstance(claim, Mapping) for claim in claims)
        ):
            reviewer_verdict = "UNKNOWN"
        if reviewer.get("missing_evidence") or reviewer.get("findings"):
            reviewer_verdict = "BLOCK" if reviewer.get("findings") else "UNKNOWN"
        reviewer_references = [
            reference
            for finding in reviewer.get("findings", ())
            for reference in finding.get("evidence_refs", ())
        ] + [
            reference
            for claim in reviewer.get("claims", ())
            for reference in claim.get("evidence_refs", ())
        ]
        if not references_resolve(reviewer_references):
            reviewer_verdict = "UNKNOWN"
    except (KeyError, OSError, TypeError, ValueError):
        reviewer_verdict = "UNKNOWN"
    if reviewer_verdict == "BLOCK":
        upstream["review"] = "failure"
        defeaters["fresh_review_complete"].append("fresh review reported findings")
    elif reviewer_verdict != "NO_BLOCKING_FINDING_OBSERVED":
        upstream["review"] = "absent"
        defeaters["fresh_review_complete"].append("qualified exact-candidate review is unavailable")
    else:
        upstream["review"] = "success"

    try:
        risk_register = load(manifest["risk_register"], "risk-register")
        oracles = [load(reference, "oracle-reference") for reference in manifest["oracle_references"]]
        coverage = [load(reference, "coverage-note") for reference in manifest["coverage_notes"]]
        follow_ups = [load(reference, "follow-up") for reference in manifest["follow_ups"]]
        lineage = [risk_register, *oracles, *coverage, *follow_ups]
        lineage_ok = all(
            item.get("repository_id") == repository_id
            and item.get("task_contract_sha256") == task_sha
            and item.get("candidate_id") == current_candidate_id
            for item in lineage
        )
        open_follow_ups = [item for item in follow_ups if item.get("required") and item.get("status") != "completed"]
        direct_observations: list[Any] = []
        rapid_state = DispositionState.UNKNOWN
        risk_ref = manifest.get("risk_assessment")
        if isinstance(risk_ref, Mapping):
            risk = load(risk_ref, "risk-assessment")
            risk_rank = {"low": 0, "standard": 1, "elevated": 2}
            protected_profile = obligations.get("risk_profile")
            task_rapid_review = task.get("rapid_review")
            profile_minimum_charters = {
                "low": 0,
                "standard": 1,
                "elevated": 2,
            }
            risk_floor_ok = bool(
                protected_profile in risk_rank
                and isinstance(task_rapid_review, Mapping)
                and risk.get("risk_profile") in risk_rank
                and risk_rank[str(risk.get("risk_profile"))]
                >= risk_rank[str(protected_profile)]
                and risk.get("mandatory_charter_count", -1)
                >= max(
                    profile_minimum_charters[str(protected_profile)],
                    int(task_rapid_review.get("minimum_charters", -1)),
                )
                and (
                    not (
                        protected_profile != "low"
                        or task_rapid_review.get("required") is True
                    )
                    or risk.get("rapid_review_required") is True
                )
            )
            charter_references = list(manifest.get("rapid_review_charters", ()))
            session_references = list(manifest.get("rapid_review_sessions", ()))
            charters = [load(reference, "review-charter") for reference in charter_references]
            sessions = [load(reference, "rapid-review-session") for reference in session_references]
            rapid_qualification = load(
                manifest["rapid_review_qualification"], "reviewer-qualification"
            )
            rapid_qualification_cases = load(
                manifest["rapid_review_qualification_cases"],
                "reviewer-qualification-cases",
            )
            rapid_identity = {
                field: rapid_qualification.get(field)
                for field in (
                    "prompt_sha256", "schema_sha256", "launcher_sha256",
                    "codex_cli_version", "model", "reasoning_effort",
                )
            }
            rapid_qualification_ok = qualification_evidence_valid(
                mode="rapid_review",
                record=rapid_qualification,
                case_evidence=rapid_qualification_cases,
                corpus=qualification_corpus,
                label_decision=qualification_label_decision,
                artifact_reader=lambda reference: read_reference(
                    repository=repository, reference=reference
                ),
                schema_root=schema_root,
                protected_repository_id=repository_id,
                verified_decision_ids=verified_decision_ids,
                evaluated_at=evaluated_at,
            ) and reviewer_qualification_state(
                rapid_identity,
                rapid_qualification,
                protected_qualification_id=policy.get("reviewer", {})
                .get("qualification_ids", {})
                .get("rapid_review"),
                protected_corpus_sha256=policy.get("reviewer", {}).get(
                    "qualification_corpus_sha256"
                ),
                protected_label_decision_id=policy.get("reviewer", {}).get(
                    "qualification_label_decision_id"
                ),
            ) is DispositionState.READY_FOR_HUMAN
            rapid_execution_references = list(
                manifest.get("rapid_review_executions", ())
            )
            rapid_context_references = list(
                manifest.get("rapid_review_context_execution_receipts", ())
            )
            rapid_executions = [
                load(reference, "reviewer-execution")
                for reference in rapid_execution_references
            ]
            rapid_contexts = [
                load(reference, "context-execution-receipt")
                for reference in rapid_context_references
            ]
            direct_observations = [experiment for session in sessions for experiment in session.get("experiments", ())]
            debrief = load(manifest["rapid_review_debrief"], "rapid-review-debrief") if isinstance(manifest.get("rapid_review_debrief"), Mapping) else None
            risk_disposition = load(manifest["risk_disposition"], "risk-disposition") if isinstance(manifest.get("risk_disposition"), Mapping) else None
            rapid_documents = [risk, *charters, *sessions]
            if isinstance(debrief, Mapping):
                rapid_documents.append(debrief)
            if isinstance(risk_disposition, Mapping):
                rapid_documents.append(risk_disposition)
            rapid_bindings = all(
                item.get("repository_id") == repository_id
                and item.get("task_contract_sha256") == task_sha
                and item.get("candidate_id") == current_candidate_id
                for item in rapid_documents
            )
            charter_sha_by_id = {
                charter["charter_id"]: reference["sha256"]
                for charter, reference in zip(charters, charter_references, strict=True)
            }
            rapid_bindings = rapid_bindings and all(
                session.get("charter_sha256")
                == charter_sha_by_id.get(session.get("charter_id"))
                for session in sessions
            )
            session_reference_by_sha = {
                reference["sha256"]: session
                for reference, session in zip(
                    session_references, sessions, strict=True
                )
            }
            session_artifact_reference_by_sha = {
                reference["sha256"]: reference
                for reference in session_references
            }
            context_reference_by_sha = {
                reference["sha256"]: document
                for reference, document in zip(
                    rapid_context_references, rapid_contexts, strict=True
                )
            }
            rapid_execution_ok = (
                rapid_qualification_ok
                and len(rapid_executions) == len(sessions)
                and len(rapid_contexts) == len(sessions)
                and all(
                    execution.get("repository_id") == repository_id
                    and execution.get("task_contract_sha256") == task_sha
                    and execution.get("effective_policy_sha256") == policy_sha
                    and execution.get("candidate_id") == current_candidate_id
                    and execution.get("review_mode") == "rapid_review"
                    and execution.get("prompt_sha256")
                    == rapid_qualification.get("prompt_sha256")
                    and execution.get("output_schema_sha256")
                    == rapid_qualification.get("schema_sha256")
                    and execution.get("launcher_sha256")
                    == rapid_qualification.get("launcher_sha256")
                    and execution.get("qualification_id")
                    == rapid_qualification.get("qualification_id")
                    and execution.get("model") == rapid_qualification.get("model")
                    and execution.get("reasoning_effort")
                    == rapid_qualification.get("reasoning_effort")
                    and execution.get("tools")
                    == [{"name": "codex-cli", "version": rapid_qualification.get("codex_cli_version")}]
                    and execution.get("input_context_receipt_sha256")
                    == manifest["context_receipt"]["sha256"]
                    and execution.get("candidate_before") == current_candidate_id
                    and execution.get("candidate_after") == current_candidate_id
                    and execution.get("return_code") == 0
                    and execution.get("timed_out") is False
                    and execution.get("observation_complete") is True
                    and execution.get("capture_threads_completed") is True
                    and execution.get("process_cleanup_complete") is True
                    and execution.get("execution_valid") is True
                    and execution.get("output_valid") is True
                    and execution.get("bindings_match") is True
                    and execution.get("output_truncated") is False
                    and execution.get("reviewer_output_sha256")
                    in session_reference_by_sha
                    and execution.get("context_execution_receipt_sha256")
                    in context_reference_by_sha
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("input_context_receipt_sha256")
                    == manifest["context_receipt"]["sha256"]
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("reviewer_output_sha256")
                    == execution.get("reviewer_output_sha256")
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("repository_id") == repository_id
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("candidate_id") == current_candidate_id
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("projection_sha256")
                    == context_receipt.get("projection_sha256")
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("review_mode") == "rapid_review"
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("model") == rapid_qualification.get("model")
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("reasoning_effort")
                    == rapid_qualification.get("reasoning_effort")
                    and context_reference_by_sha[
                        execution["context_execution_receipt_sha256"]
                    ].get("retrieval_expansions")
                    == session_reference_by_sha[
                        execution["reviewer_output_sha256"]
                    ].get("retrieval_expansions")
                    and model_usage_reconciles(
                        execution,
                        context_reference_by_sha[
                            execution["context_execution_receipt_sha256"]
                        ],
                    )
                    and reviewer_execution_reconstructs(
                        execution,
                        session_artifact_reference_by_sha[
                            execution["reviewer_output_sha256"]
                        ],
                    )
                    for execution in rapid_executions
                )
                and all(
                    session.get("reviewer_prompt_sha256")
                    == rapid_qualification.get("prompt_sha256")
                    and session.get("qualification_id")
                    == rapid_qualification.get("qualification_id")
                    and session.get("model") == rapid_qualification.get("model")
                    and any(
                        execution.get("reviewer_output_sha256")
                        == reference["sha256"]
                        for execution in rapid_executions
                    )
                    for session, reference in zip(
                        sessions, session_references, strict=True
                    )
                )
            )
            if isinstance(debrief, Mapping) and isinstance(risk_disposition, Mapping):
                rapid_bindings = rapid_bindings and (
                    risk_disposition.get("debrief_sha256")
                    == manifest["rapid_review_debrief"]["sha256"]
                )
            locator_ids: list[str] = []
            for session in sessions:
                for experiment in session.get("experiments", ()):
                    locator_ids.extend(experiment.get("evidence_refs", ()))
                for finding in session.get("findings", ()):
                    locator_ids.extend(finding.get("evidence_refs", ()))
                for residual in session.get("residual_risks", ()):
                    locator_ids.extend(residual.get("evidence_refs", ()))
            if isinstance(debrief, Mapping):
                for story_name in (
                    "product_story", "testing_story", "quality_of_testing_story"
                ):
                    story = debrief.get(story_name, {})
                    if isinstance(story, Mapping):
                        locator_ids.extend(story.get("evidence_refs", ()))
            if isinstance(risk_disposition, Mapping):
                for item in risk_disposition.get("items", ()):
                    locator_ids.extend(item.get("evidence_refs", ()))
            rapid_bindings = rapid_bindings and all(
                isinstance(locator_id, str) and locator_id in resolved_locators
                for locator_id in locator_ids
            )
            decision_map = {item["decision_id"]: item for item in valid_decisions}
            if not risk_floor_ok:
                rapid_state = DispositionState.BLOCK
            else:
                rapid_state = evaluate_rapid_review(
                    candidate_id=current_candidate_id, risk_assessment=risk,
                    charters=charters, sessions=sessions, debrief=debrief,
                    risk_disposition=risk_disposition, authorized_humans=set(),
                    authenticated_decisions=decision_map,
                    repository_id=repository_id,
                    task_contract_sha256=task_sha,
                    policy_sha256=policy_sha,
                    now=now,
                    verified_decision_ids=verified_decision_ids,
                )
                if not rapid_bindings or not rapid_execution_ok:
                    rapid_state = DispositionState.UNKNOWN
        operational_state = evaluate_operational_rst(
            artifacts_complete=lineage_ok,
            direct_observations=direct_observations,
            fallible_oracles=oracles,
            coverage_notes=coverage,
            unresolved_follow_ups=open_follow_ups,
        )
    except (KeyError, OSError, TypeError, ValueError):
        rapid_state = operational_state = DispositionState.UNKNOWN
    if DispositionState.BLOCK in {rapid_state, operational_state}:
        upstream["rst"] = "failure"
        defeaters["rst_complete"].append("rapid review has unresolved material work")
    elif rapid_state is not DispositionState.READY_FOR_HUMAN or operational_state is not DispositionState.READY_FOR_HUMAN:
        upstream["rst"] = "absent"
        defeaters["rst_complete"].append("operational RST evidence is incomplete")
    else:
        upstream["rst"] = "success"

    try:
        assurance_case = load(manifest["assurance_case"], "assurance-case")
        assurance_claims = assurance_case.get("claims", ())
        assurance_ok = (
            verify_content_address(assurance_case, "assurance_case_id")
            and assurance_case.get("repository_id") == repository_id
            and assurance_case.get("candidate_id") == current_candidate_id
            and assurance_case.get("task_contract_sha256") == task_sha
            and assurance_case.get("effective_policy_sha256") == policy_sha
            and assurance_case.get("state") == "READY_FOR_HUMAN"
            and not assurance_case.get("unresolved_defeaters")
            and all(
                references_resolve(item.get("supporting_evidence", ()))
                and references_resolve(item.get("refuting_evidence", ()))
                and evaluate_assurance_claim(item) is DispositionState.READY_FOR_HUMAN
                for item in assurance_claims
            )
        )
    except (KeyError, OSError, TypeError, ValueError):
        assurance_ok = False
    upstream["assurance"] = "success" if assurance_ok else "absent"

    claims = {
        claim_id: {
            "classification": (
                "VERIFIED_WITHIN_SCOPE" if not claim_defeaters else "UNKNOWN"
            ),
            "defeaters": claim_defeaters,
        }
        for claim_id, claim_defeaters in defeaters.items()
    }
    if upstream.get("gates") == "failure":
        claims["gates_complete"]["classification"] = "REFUTED"
    if upstream.get("governance") == "failure":
        claims["governance_integrity"]["classification"] = "REFUTED"
    if upstream.get("mutation") == "failure":
        claims["mutation_complete"]["classification"] = "REFUTED"
    if upstream.get("review") == "failure":
        claims["fresh_review_complete"]["classification"] = "REFUTED"
    if upstream.get("rst") == "failure":
        claims["rst_complete"]["classification"] = "REFUTED"
    claims["candidate_current"] = {"classification": "DIRECTLY_OBSERVED", "defeaters": []}
    state = evaluate_admission(
        repository_id=repository_id,
        candidate_id=current_candidate_id,
        upstream_results=upstream,
        claims=claims,
        required_claim_ids=tuple(defeaters),
    )
    reasons = sorted(
        {reason for claim in claims.values() for reason in claim.get("defeaters", ())}
    )
    if not assurance_ok:
        reasons.append("assurance case is missing, stale, unsupported, or inconsistent")
    if state is DispositionState.READY_FOR_HUMAN:
        reasons = ["all fixed assurance claims reconstruct for the exact candidate; human action remains required"]
    return state, reasons
