"""Fail-closed validation for the one authenticated initial-LKG bootstrap."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence, Set
from datetime import datetime
from pathlib import Path
from typing import Any

from codex_governance.attestation import (
    gate_implementation_sha256,
    verify_provenance_statement,
)
from codex_governance.authority import evaluate_lkg_promotion
from codex_governance.canonical import sha256_canonical, verify_content_address
from codex_governance.domain.model import DispositionState
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.profiles import validate_task_contract
from codex_governance.sandbox import validate_sandbox_capability

from common import (
    content_address,
    ensure_within,
    read_bytes_once,
    require_digest,
    require_sha,
    sha256_bytes,
    verify_candidate_identity,
)


def _timestamp(value: Any, name: str) -> datetime:
    try:
        return parse_rfc3339(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {name}") from exc


def _verified_decision(
    decision: Mapping[str, Any],
    *,
    decision_type: str,
    repository_id: str,
    candidate_id: str,
    task_contract_sha256: str,
    effective_policy_sha256: str,
    base_commit: str,
    exact_scope: Set[str],
    consumption_id: str,
    now: datetime,
    verified_decision_ids: Set[str],
) -> bool:
    issuer = decision.get("issuer")
    scope = decision.get("scope")
    if (
        not isinstance(scope, Sequence)
        or isinstance(scope, (str, bytes))
        or any(not isinstance(item, str) or not item for item in scope)
    ):
        return False
    try:
        issued_at = _timestamp(decision.get("issued_at"), "decision issued_at")
        expires_at = _timestamp(decision.get("expires_at"), "decision expires_at")
        assertion = require_digest(
            issuer.get("assertion_sha256") if isinstance(issuer, Mapping) else None,
            "decision assertion_sha256",
        )
    except ValueError:
        return False
    del assertion
    return bool(
        content_address(dict(decision), "decision_id") == dict(decision)
        and decision.get("decision_id") in verified_decision_ids
        and decision.get("decision_type") == decision_type
        and decision.get("repository_id") == repository_id
        and decision.get("candidate_id") == candidate_id
        and decision.get("task_contract_sha256") == task_contract_sha256
        and decision.get("effective_policy_sha256") == effective_policy_sha256
        and decision.get("base_commit") == base_commit
        and set(scope) == exact_scope
        and decision.get("single_use") is True
        and decision.get("consumption_id") == consumption_id
        and isinstance(issuer, Mapping)
        and isinstance(issuer.get("subject"), str)
        and bool(issuer.get("subject"))
        and isinstance(issuer.get("authentication_method"), str)
        and bool(issuer.get("authentication_method"))
        and isinstance(issuer.get("protected_source"), str)
        and bool(issuer.get("protected_source"))
        and issued_at < expires_at
        and issued_at <= now < expires_at
    )


def _raw_artifact(
    repository: Path,
    evidence: Path,
    item: Mapping[str, Any],
    *,
    expected_path: str,
    max_bytes: int,
) -> tuple[str, int]:
    if item.get("path") != expected_path or item.get("truncated") is not False:
        raise ValueError("rollback raw artifact path or truncation is invalid")
    path = ensure_within(repository, repository / expected_path)
    path.relative_to(evidence)
    data = read_bytes_once(path, max_bytes=max_bytes)
    if item.get("bytes") != len(data):
        raise ValueError("rollback raw artifact is unsafe or incorrectly sized")
    digest = sha256_bytes(data)
    if item.get("sha256") != digest:
        raise ValueError("rollback raw artifact digest mismatch")
    return digest, len(data)


def validate_initial_bootstrap(
    *,
    repository: Path,
    evidence: Path,
    candidate: Mapping[str, Any],
    bootstrap_policy: Mapping[str, Any],
    bootstrap_policy_sha256: str,
    task_contract_sha256: str,
    rollback_task: Mapping[str, Any],
    rollback_task_sha256: str,
    proposed_policy: Mapping[str, Any],
    proposed_policy_sha256: str,
    rollback_plan: Mapping[str, Any],
    rollback_plan_sha256: str,
    rollback_candidate: Mapping[str, Any],
    rollback_candidate_sha256: str,
    rollback: Mapping[str, Any],
    rollback_gate: Mapping[str, Any],
    rollback_gate_sha256: str,
    rollback_capability: Mapping[str, Any],
    rollback_capability_sha256: str,
    rollback_provenance: Mapping[str, Any],
    rollback_provenance_sha256: str,
    observation: Mapping[str, Any],
    decisions: Sequence[Mapping[str, Any]],
    verified_decision_ids: Set[str],
    evaluated_at: datetime,
) -> dict[str, Any]:
    """Reconstruct the explicit initial bootstrap and its rollback rehearsal."""
    repository = Path(os.path.abspath(os.fspath(repository)))
    evidence = ensure_within(repository, evidence)
    if evaluated_at.tzinfo is None:
        raise ValueError("bootstrap evaluation time must be timezone-aware")
    repository_id = str(candidate.get("repository_id"))
    candidate_id = require_digest(candidate.get("candidate_id"), "candidate_id")
    base_commit = require_sha(candidate.get("base_commit"), "base_commit")
    head_commit = require_sha(candidate.get("head_commit"), "head_commit")
    lkg_commit = require_sha(
        observation.get("lkg_governance_commit"), "lkg_governance_commit"
    )
    if (
        repository_id != "repo:timaday/codex-governed-change"
        or base_commit != "5393338571f8ed5de5192613dcdd6131044932dc"
        or head_commit != "b322d63d4327f0cccd10c24b48a5ee563da921d9"
        or lkg_commit != "a0a0b01a19e87f2591c7e97e892cd040ce9c6e58"
    ):
        raise ValueError("initial-LKG bootstrap is bound only to release v0.1.0")
    policy_sha = require_digest(bootstrap_policy_sha256, "bootstrap policy")
    proposed_sha = require_digest(proposed_policy_sha256, "proposed policy")
    task_sha = require_digest(task_contract_sha256, "task contract")
    rollback_task_sha = require_digest(rollback_task_sha256, "rollback task contract")
    rollback_candidate_sha256 = require_digest(
        rollback_candidate_sha256, "rollback candidate document"
    )
    authority_commit = require_sha(observation.get("authority_commit"), "authority_commit")
    authority_basis_commit = require_sha(
        observation.get("authority_basis_commit"), "authority_basis_commit"
    )
    if authority_basis_commit == authority_commit:
        raise ValueError("authority decision commit cannot be its own bootstrap basis")
    transition = observation.get("governance_transition")
    expected_transition = {
        "mode": "initial_lkg_bootstrap",
        "basis_commit": lkg_commit,
        "bootstrap_decision_type": "lkg_bootstrap",
        "promotion_decision_type": "lkg_promotion",
        "reusable": False,
    }
    if (
        transition != expected_transition
        or observation.get("kernel_source_commit") != head_commit
        or bootstrap_policy.get("repository_id") != repository_id
        or bootstrap_policy.get("lkg_governance_commit") != base_commit
        or proposed_policy.get("repository_id") != repository_id
        or proposed_policy.get("lkg_governance_commit") != head_commit
        or proposed_sha == policy_sha
    ):
        raise ValueError("initial-LKG transition and policies do not reconstruct")

    plan = dict(rollback_plan)
    gate_definition = plan.get("gate_definition")
    raw_paths = plan.get("raw_artifacts")
    expected_source = require_digest(
        plan.get("rollback_source_identity"), "rollback_source_identity"
    )
    if (
        set(plan)
        != {
            "schema_version",
            "rollback_plan_id",
            "repository_id",
            "task_contract_sha256",
            "rollback_task_contract_sha256",
            "bootstrap_policy_sha256",
            "current_candidate_id",
            "rollback_target_commit",
            "rollback_source_identity",
            "gate_definition",
            "gate_definition_sha256",
            "implementation_sha256",
            "reviewer_prompt_sha256",
            "raw_artifacts",
            "workflow_system",
            "producer_builder_id",
            "producer_version",
            "max_age_seconds",
            "limitations",
        }
        or plan.get("schema_version") != "1.0.0"
        or content_address(plan, "rollback_plan_id") != plan
        or rollback_plan_sha256
        != require_digest(observation.get("rollback_plan_sha256"), "rollback plan digest")
        or plan.get("rollback_plan_id") != observation.get("rollback_plan_id")
        or plan.get("repository_id") != repository_id
        or plan.get("task_contract_sha256") != task_sha
        or plan.get("rollback_task_contract_sha256") != rollback_task_sha
        or plan.get("bootstrap_policy_sha256") != policy_sha
        or plan.get("current_candidate_id") != candidate_id
        or plan.get("rollback_target_commit") != lkg_commit
        or not isinstance(gate_definition, Mapping)
        or set(gate_definition)
        != {
            "gate_id",
            "profiles",
            "command",
            "timeout_seconds",
            "max_output_bytes",
            "shell",
            "risk_label",
        }
        or rollback_task.get("profile") not in gate_definition.get("profiles", ())
        or gate_definition
        != next(
            (
                item
                for item in bootstrap_policy.get("gates", ())
                if item.get("gate_id") == gate_definition.get("gate_id")
            ),
            None,
        )
        or gate_definition.get("shell") is not False
        or gate_definition.get("risk_label") != ""
        or plan.get("gate_definition_sha256") != sha256_canonical(gate_definition)
        or plan.get("implementation_sha256") != gate_implementation_sha256()
        or not isinstance(raw_paths, Mapping)
        or set(raw_paths) != {"stdout", "stderr"}
        or raw_paths.get("stdout")
        != (evidence / "rollback/stdout.bin").relative_to(repository).as_posix()
        or raw_paths.get("stderr")
        != (evidence / "rollback/stderr.bin").relative_to(repository).as_posix()
        or not isinstance(plan.get("max_age_seconds"), int)
        or isinstance(plan.get("max_age_seconds"), bool)
        or int(plan["max_age_seconds"]) < 1
        or not isinstance(plan.get("limitations"), list)
        or not plan.get("limitations")
    ):
        raise ValueError("protected rollback plan does not reconstruct")
    if (
        validate_task_contract(rollback_task)
        or rollback_task.get("repository_id") != repository_id
        or rollback_task.get("base_commit") != lkg_commit
        or rollback_task.get("required_gate_ids")
        != [gate_definition.get("gate_id")]
        or not isinstance(rollback_task.get("authoritative_sources"), list)
        or not rollback_task.get("authoritative_sources")
    ):
        raise ValueError("protected rollback task contract does not reconstruct")
    prompt_path = (
        Path(__file__).resolve().parents[2]
        / "kernel/.codex/review/reviewer.prompt.md"
    )
    if sha256_bytes(read_bytes_once(prompt_path)) != plan.get("reviewer_prompt_sha256"):
        raise ValueError("rollback plan reviewer prompt does not match authority")

    if (
        not verify_candidate_identity(rollback_candidate)
        or rollback_candidate.get("repository_id") != repository_id
        or rollback_candidate.get("candidate_id") != expected_source
        or rollback_candidate.get("mode") != "commit"
        or rollback_candidate.get("dirty") is not False
        or rollback_candidate.get("base_commit") != lkg_commit
        or rollback_candidate.get("head_commit") != lkg_commit
        or rollback_candidate.get("changed_paths") != []
        or rollback_candidate.get("untracked_entries") != []
        or rollback_candidate.get("submodules") != []
        or rollback_candidate.get("effective_policy_sha256") != policy_sha
    ):
        raise ValueError("rollback candidate identity does not reconstruct")

    if (
        not verify_content_address(rollback, "rollback_evidence_id")
        or rollback.get("schema_version") != "2.0.0"
        or rollback.get("repository_id") != repository_id
        or rollback.get("task_contract_sha256") != task_sha
        or rollback.get("candidate_id") != candidate_id
        or rollback.get("previous_lkg_policy_sha256") != policy_sha
        or rollback.get("proposed_policy_sha256") != proposed_sha
        or rollback.get("rollback_target_commit") != lkg_commit
        or rollback.get("gate_result")
        != {
            "path": "artifacts/governance/completion/evidence/rollback/gate-result.json",
            "sha256": rollback_gate_sha256,
        }
        or rollback.get("sandbox_capability")
        != {
            "path": "artifacts/governance/completion/evidence/rollback/sandbox-capability.json",
            "sha256": rollback_capability_sha256,
        }
        or rollback.get("provenance_statement")
        != {
            "path": "artifacts/governance/completion/evidence/rollback/provenance-statement.json",
            "sha256": rollback_provenance_sha256,
        }
        or rollback.get("status") != "PASS"
        or rollback.get("limitations") != []
    ):
        raise ValueError("rollback summary does not reconstruct")

    max_output = int(gate_definition.get("max_output_bytes", 0))
    artifacts = rollback_gate.get("artifacts")
    if (
        not isinstance(artifacts, Sequence)
        or isinstance(artifacts, (str, bytes))
        or len(artifacts) != 2
    ):
        raise ValueError("rollback gate must bind exactly two raw streams")
    artifacts_by_stream = {
        item.get("stream"): item for item in artifacts if isinstance(item, Mapping)
    }
    if set(artifacts_by_stream) != {"stdout", "stderr"}:
        raise ValueError("rollback gate raw streams are missing or duplicated")
    stdout_sha, _ = _raw_artifact(
        repository,
        evidence,
        artifacts_by_stream["stdout"],
        expected_path=str(raw_paths["stdout"]),
        max_bytes=max_output,
    )
    stderr_sha, _ = _raw_artifact(
        repository,
        evidence,
        artifacts_by_stream["stderr"],
        expected_path=str(raw_paths["stderr"]),
        max_bytes=max_output,
    )

    if validate_sandbox_capability(rollback_capability):
        raise ValueError("rollback sandbox capability is invalid")
    if (
        not verify_content_address(rollback_capability, "capability_id")
        or rollback_capability.get("source_identity") != expected_source
        or rollback_capability.get("implementation_sha256")
        != plan.get("implementation_sha256")
        or rollback_capability.get("provider")
        != bootstrap_policy.get("sandbox", {}).get("provider")
        or rollback_capability.get("process_limit")
        != bootstrap_policy.get("sandbox", {}).get("process_limit")
        or rollback_capability.get("memory_bytes")
        != bootstrap_policy.get("sandbox", {}).get("memory_bytes")
        or rollback_capability.get("cpu_seconds") != gate_definition.get("timeout_seconds")
        or rollback_capability.get("timeout_seconds")
        != gate_definition.get("timeout_seconds")
        or rollback_capability.get("output_bytes") != max_output
        or rollback_capability.get("limitations")
        != ["unsigned local capability report"]
    ):
        raise ValueError("rollback sandbox identity or limits do not reconstruct")

    provenance_ref = rollback_gate.get("provenance_statement")
    expected_provenance_path = (
        evidence / "rollback/provenance-statement.json"
    ).relative_to(repository).as_posix()
    if (
        not isinstance(provenance_ref, Mapping)
        or provenance_ref.get("path") != expected_provenance_path
        or provenance_ref.get("sha256") != rollback_provenance_sha256
        or not verify_content_address(rollback_provenance, "statement_id")
        or not verify_provenance_statement(
            rollback_provenance, repository_id, expected_source, expected_source
        )
    ):
        raise ValueError("rollback provenance reference or identity is invalid")
    predicate = rollback_provenance.get("predicate")
    environment = predicate.get("environment") if isinstance(predicate, Mapping) else None
    producer = predicate.get("producer") if isinstance(predicate, Mapping) else None
    workflow = predicate.get("workflow") if isinstance(predicate, Mapping) else None
    tools = predicate.get("tools") if isinstance(predicate, Mapping) else None
    expected_materials = [
        {"name": "candidate", "sha256": expected_source},
        {"name": "task-contract", "sha256": rollback_task_sha},
        {"name": "effective-policy", "sha256": policy_sha},
    ]
    expected_provenance_artifacts = [
        {"name": "stdout", "sha256": stdout_sha},
        {"name": "stderr", "sha256": stderr_sha},
        {"name": "sandbox-capability", "sha256": rollback_capability_sha256},
    ]
    subject_hex = expected_source.split(":", 1)[1]
    expected_subject = [
        {"name": repository_id, "digest": {"sha256": subject_hex}},
        {"name": "candidate", "digest": {"sha256": subject_hex}},
    ]
    if (
        rollback_provenance.get("subject") != expected_subject
        or not isinstance(predicate, Mapping)
        or predicate.get("task_contract_sha256") != rollback_task_sha
        or predicate.get("effective_policy_sha256") != policy_sha
        or predicate.get("gate_definition_sha256")
        != plan.get("gate_definition_sha256")
        or predicate.get("reviewer_prompt_sha256")
        != plan.get("reviewer_prompt_sha256")
        or predicate.get("materials") != expected_materials
        or predicate.get("artifacts") != expected_provenance_artifacts
        or predicate.get("result") != "PASS"
        or predicate.get("limitations") != []
        or not isinstance(environment, Mapping)
        or environment.get("source_identity") != expected_source
        or environment.get("execution_identity")
        != rollback_capability.get("execution_identity")
        or environment.get("sandbox_capability_sha256")
        != rollback_capability_sha256
        or not isinstance(producer, Mapping)
        or producer.get("builder_id") != plan.get("producer_builder_id")
        or producer.get("implementation_sha256") != plan.get("implementation_sha256")
        or producer.get("version") != plan.get("producer_version")
        or not isinstance(workflow, Mapping)
        or workflow.get("system") != plan.get("workflow_system")
        or not isinstance(workflow.get("run_id"), str)
        or not workflow.get("run_id")
        or not isinstance(workflow.get("attempt"), int)
        or isinstance(workflow.get("attempt"), bool)
        or int(workflow["attempt"]) < 1
        or not isinstance(tools, Sequence)
        or isinstance(tools, (str, bytes))
        or len(tools) != 2
        or {item.get("name") for item in tools if isinstance(item, Mapping)}
        != {"python", rollback_capability.get("provider")}
        or any(
            not isinstance(item, Mapping)
            or not isinstance(item.get("version"), str)
            or not item.get("version")
            for item in tools
        )
        or not any(
            item.get("name") == rollback_capability.get("provider")
            and item.get("version") == rollback_capability.get("provider_version")
            for item in tools
            if isinstance(item, Mapping)
        )
    ):
        raise ValueError("rollback provenance bindings do not reconstruct")

    termination = rollback_gate.get("termination")
    if (
        rollback_gate.get("repository_id") != repository_id
        or rollback_gate.get("task_contract_sha256") != rollback_task_sha
        or rollback_gate.get("gate_id") != gate_definition.get("gate_id")
        or rollback_gate.get("profile") != rollback_task.get("profile")
        or rollback_gate.get("candidate_before") != expected_source
        or rollback_gate.get("candidate_after") != expected_source
        or rollback_gate.get("source_identity") != expected_source
        or rollback_gate.get("execution_identity")
        != rollback_capability.get("execution_identity")
        or rollback_gate.get("sandbox_capability_sha256")
        != rollback_capability_sha256
        or rollback_gate.get("command") != gate_definition.get("command")
        or rollback_gate.get("status") != "PASS"
        or rollback_gate.get("observation_complete") is not True
        or termination != {"kind": "exited", "exit_code": 0}
        or rollback_gate.get("limitations") != []
        or rollback_gate.get("producer_version") != plan.get("producer_version")
        or predicate.get("started_at") != rollback_gate.get("started_at")
        or predicate.get("ended_at") != rollback_gate.get("ended_at")
    ):
        raise ValueError("rollback gate execution does not reconstruct")

    started_at = _timestamp(rollback_gate.get("started_at"), "rollback started_at")
    ended_at = _timestamp(rollback_gate.get("ended_at"), "rollback ended_at")
    verified_at = _timestamp(
        rollback_capability.get("verified_at"), "sandbox verified_at"
    )
    rollback_created = _timestamp(rollback.get("created_at"), "rollback created_at")
    max_age = int(plan["max_age_seconds"])
    duration_ms = rollback_gate.get("duration_ms")
    if not (
        isinstance(duration_ms, int)
        and not isinstance(duration_ms, bool)
        and 0 <= duration_ms <= max_age * 1000
        and verified_at <= started_at <= ended_at <= rollback_created <= evaluated_at
        and (evaluated_at - rollback_created).total_seconds() <= max_age
        and (started_at - verified_at).total_seconds() <= max_age
        and duration_ms <= (ended_at - started_at).total_seconds() * 1000 + 1000
    ):
        raise ValueError("rollback evidence timing is stale or inconsistent")

    bootstrap_decisions = [
        item for item in decisions if item.get("decision_type") == "lkg_bootstrap"
    ]
    promotion_decisions = [
        item for item in decisions if item.get("decision_type") == "lkg_promotion"
    ]
    if len(bootstrap_decisions) != 1 or len(promotion_decisions) != 1:
        raise ValueError("exactly one bootstrap and one promotion decision are required")
    bootstrap_scope = {
        f"initial-lkg:{lkg_commit}",
        f"authority-basis:{authority_basis_commit}",
        f"kernel-source:{head_commit}",
        f"bootstrap-policy:{policy_sha}",
    }
    if not _verified_decision(
        bootstrap_decisions[0],
        decision_type="lkg_bootstrap",
        repository_id=repository_id,
        candidate_id=candidate_id,
        task_contract_sha256=task_sha,
        effective_policy_sha256=policy_sha,
        base_commit=base_commit,
        exact_scope=bootstrap_scope,
        consumption_id=f"initial-lkg-bootstrap:{candidate_id}",
        now=evaluated_at,
        verified_decision_ids=verified_decision_ids,
    ):
        raise ValueError("initial-LKG bootstrap decision does not reconstruct")
    promotion_scope = {
        f"promote:{proposed_sha}",
        f"rollback:{rollback['rollback_evidence_id']}",
    }
    if not _verified_decision(
        promotion_decisions[0],
        decision_type="lkg_promotion",
        repository_id=repository_id,
        candidate_id=candidate_id,
        task_contract_sha256=task_sha,
        effective_policy_sha256=policy_sha,
        base_commit=lkg_commit,
        exact_scope=promotion_scope,
        consumption_id=f"lkg-promotion:{candidate_id}",
        now=evaluated_at,
        verified_decision_ids=verified_decision_ids,
    ):
        raise ValueError("initial-LKG promotion decision does not reconstruct")
    state = evaluate_lkg_promotion(
        repository_id=repository_id,
        candidate_id=candidate_id,
        task_contract_sha256=task_sha,
        evaluating_policy_sha256=policy_sha,
        previous_lkg_policy_sha256=policy_sha,
        proposed_policy_sha256=proposed_sha,
        promotion_decision=promotion_decisions[0],
        rollback_evidence=rollback,
        expected_rollback_target_commit=lkg_commit,
        rollback_reconstructed=True,
        now=evaluated_at,
        verified_decision_ids=verified_decision_ids,
    )
    if state is not DispositionState.READY_FOR_HUMAN:
        raise ValueError("bootstrap-policy promotion evaluation did not reconstruct")

    authority_manifest = Path(__file__).resolve().parents[2] / "MANIFEST.json"
    return content_address(
        {
            "schema_version": "1.0.0",
            "repository_id": repository_id,
            "task_contract_sha256": task_sha,
            "candidate_id": candidate_id,
            "evaluation_mode": "initial_lkg_bootstrap",
            "bootstrap_basis_commit": lkg_commit,
            "authority_commit": authority_commit,
            "authority_basis_commit": authority_basis_commit,
            "authority_manifest_sha256": sha256_bytes(read_bytes_once(authority_manifest)),
            "bootstrap_policy_sha256": policy_sha,
            "proposed_policy_sha256": proposed_sha,
            "rollback_plan_id": plan["rollback_plan_id"],
            "rollback_plan_sha256": rollback_plan_sha256,
            "rollback_task_contract_sha256": rollback_task_sha,
            "rollback_candidate_sha256": rollback_candidate_sha256,
            "bootstrap_decision_id": bootstrap_decisions[0]["decision_id"],
            "promotion_decision_id": promotion_decisions[0]["decision_id"],
            "rollback_evidence_id": rollback["rollback_evidence_id"],
            "rollback_gate_result_sha256": rollback_gate_sha256,
            "rollback_sandbox_capability_sha256": rollback_capability_sha256,
            "rollback_provenance_statement_sha256": rollback_provenance_sha256,
            "rollback_stdout_sha256": stdout_sha,
            "rollback_stderr_sha256": stderr_sha,
            "state": "READY_FOR_HUMAN",
            "created_at": evaluated_at.isoformat().replace("+00:00", "Z"),
            "producer_version": "0.1.0-authority-bootstrap",
            "limitations": list(plan["limitations"]),
        },
        "bootstrap_verification_id",
    )
