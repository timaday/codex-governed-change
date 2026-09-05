#!/usr/bin/env python3
"""Run the protected reviewer calibration corpus through the exact launcher."""

from __future__ import annotations

import argparse
import json
import re
import stat
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from common import (
    canonical_bytes,
    content_address,
    load_and_validate_once,
    load_json,
    read_bytes_fresh,
    read_bytes_once,
    sha256_bytes,
    write_once,
)
from qualification_verifier import validate_qualification_bundle
from codex_governance.canonical import require_sha256, sha256_canonical
from codex_governance.context import (
    CONTEXT_PROFILES,
)
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.qualification import (
    bootstrap_qualification_record,
    qualification_case_classes_complete,
    qualification_candidate_document,
    qualification_charter_document,
    context_qualification_evidence_valid,
    qualification_context_documents,
    qualification_evidence_locators,
    qualification_expected_finding_detected,
    qualification_gate_documents,
    qualification_policy_document,
    qualification_task_document,
)
from codex_governance.reviewer import (
    build_reviewer_command,
    build_reviewer_execution_statement,
    build_reviewer_stdin,
    launch_reviewer,
    observe_codex_authentication,
    observe_codex_cli_version,
    reviewer_argv_sha256,
    reviewer_launcher_sha256,
)


ROOT = Path(__file__).resolve().parents[2]
MODEL = "gpt-5.6-sol"
REASONING_EFFORT = "xhigh"
EVALUATION_REPOSITORY_ID = "repo:timaday/codex-governed-change-qualification"
EXPECTED_DISPOSITIONS = {"BLOCK", "NO_BLOCKING_FINDING_OBSERVED"}
QUALIFICATION_ARTIFACT_PREFIX = "qualification"
CONTEXT_TOKEN_BUDGETS = {"COMPACT": 8000, "STANDARD": 24000, "DEEP": 64000}


def _safe_relative(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("qualification fixture path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", "..", ".git"} for part in path.parts):
        raise ValueError("qualification fixture path is unsafe")
    if path.as_posix() != value:
        raise ValueError("qualification fixture path is not canonical")
    return value


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            raise ValueError("qualification fixture contains a symlink")
        info = path.stat()
        path.chmod(0o555 if path.is_dir() or info.st_mode & stat.S_IXUSR else 0o444)
    root.chmod(0o555)


def _validate_corpus(
    corpus: Mapping[str, Any],
    decision: Mapping[str, Any],
    *,
    actor: str,
    authority_repository: str,
    authority_ref: str,
) -> None:
    if content_address(dict(corpus), "corpus_id") != dict(corpus):
        raise ValueError("qualification corpus identity does not reconstruct")
    cases = corpus.get("cases")
    if corpus.get("human_labelled") is not True or not isinstance(cases, list) or len(cases) != 8:
        raise ValueError("qualification corpus is not the eight-case human-labelled corpus")
    ids: list[str] = []
    labels: dict[str, str] = {}
    critical = 0
    for case in cases:
        if not isinstance(case, Mapping) or set(case) != {
            "case_id", "case_classes", "severity", "requirement_id",
            "expected_finding", "expected_disposition", "risk", "charter", "files",
        }:
            raise ValueError("qualification case has unexpected properties")
        case_id = case.get("case_id")
        label = case.get("expected_disposition")
        files = case.get("files")
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in labels
            or label not in EXPECTED_DISPOSITIONS
            or not isinstance(files, Mapping)
            or not files
            or any(not isinstance(body, str) for body in files.values())
        ):
            raise ValueError("qualification case is malformed")
        for path in files:
            _safe_relative(path)
        if case.get("severity") == "critical":
            critical += 1
        elif case.get("severity") != "control":
            raise ValueError("qualification case severity is invalid")
        ids.append(case_id)
        labels[case_id] = label
    if critical != 7 or not qualification_case_classes_complete(cases):
        raise ValueError("qualification corpus must contain seven critical cases")
    if content_address(dict(decision), "decision_id") != dict(decision):
        raise ValueError("human label decision identity does not reconstruct")
    issuer_assertion = {
        "subject": "github:" + actor,
        "authentication_method": "github-actions-workflow-dispatch",
        "protected_source": authority_repository + "@" + authority_ref,
    }
    now = datetime.now(timezone.utc)
    if (
        decision.get("repository_id") != "repo:timaday/codex-governed-change"
        or decision.get("decision_type") != "reviewer_qualification_labels"
        or decision.get("approved_corpus_id") != corpus.get("corpus_id")
        or decision.get("approved_case_ids") != ids
        or decision.get("approved_labels") != labels
        or decision.get("approved_modes") != ["conformance", "rapid_review"]
        or decision.get("issuer")
        != issuer_assertion
        | {"assertion_sha256": sha256_bytes(canonical_bytes(issuer_assertion))}
        or not (
            parse_rfc3339(decision["issued_at"])
            <= now
            < parse_rfc3339(decision["expires_at"])
        )
    ):
        raise ValueError("human label decision does not exactly approve the corpus")


def classify_observed_disposition(
    mode: str,
    result: Mapping[str, Any] | None,
    *,
    execution_valid: bool = True,
) -> str:
    """Map one exact-launch result to a fail-closed calibration disposition."""
    if not execution_valid or not isinstance(result, Mapping):
        return "UNKNOWN"
    if mode == "conformance":
        verdict = result.get("verdict")
        return verdict if verdict in EXPECTED_DISPOSITIONS else "UNKNOWN"
    if mode != "rapid_review":
        return "UNKNOWN"
    findings = result.get("findings")
    residual = result.get("residual_risks")
    if not isinstance(findings, list) or not isinstance(residual, list):
        return "UNKNOWN"
    if result.get("status") == "blocked":
        return "BLOCK"
    if any(
        isinstance(item, Mapping) and item.get("severity") in {"critical", "high"}
        for item in findings
    ):
        return "BLOCK"
    if any(isinstance(item, Mapping) and item.get("material") is True for item in residual):
        return "BLOCK"
    if result.get("status") == "completed":
        return "NO_BLOCKING_FINDING_OBSERVED"
    return "UNKNOWN"



def _prepare_case(
    *,
    root: Path,
    case: Mapping[str, Any],
    mode: str,
    prompt_path: Path,
    schema_path: Path,
    bootstrap: Mapping[str, Any],
    requested_profile: str | None,
) -> dict[str, Any]:
    candidate_root = root / "candidate"
    candidate_root.mkdir(parents=True)
    expected_files: dict[str, str] = {}
    for relative, body in case["files"].items():
        normalized = _safe_relative(relative)
        path = candidate_root.joinpath(*normalized.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        expected_files[normalized] = sha256_bytes(body.encode("utf-8"))

    prompt_sha = sha256_bytes(read_bytes_once(prompt_path))
    schema_sha = sha256_bytes(read_bytes_once(schema_path))
    corpus_sha = bootstrap["corpus_sha256"]
    task = qualification_task_document(
        repository_id=EVALUATION_REPOSITORY_ID, case=case
    )
    task_sha = sha256_bytes(canonical_bytes(task))
    policy = qualification_policy_document(
        repository_id=EVALUATION_REPOSITORY_ID,
        case=case,
        corpus_sha256=corpus_sha,
        bootstrap_qualification_id=bootstrap["qualification_id"],
        model=MODEL,
        reasoning_effort=REASONING_EFFORT,
    )
    policy_sha = sha256_bytes(canonical_bytes(policy))
    candidate = qualification_candidate_document(
        repository_id=EVALUATION_REPOSITORY_ID,
        case=case,
        effective_policy_sha256=policy_sha,
    )
    candidate_id = candidate["candidate_id"]
    _gate, gate_manifest = qualification_gate_documents(
        repository_id=EVALUATION_REPOSITORY_ID,
        task_contract_sha256=task_sha,
        candidate_id=candidate_id,
    )
    context_arguments = {
        "mode": mode,
        "case": case,
        "task": task,
        "policy": policy,
        "candidate": candidate,
        "reviewer_output_sha256": "sha256:" + "0" * 64,
        "execution": {
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "usage_observed": True,
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "output_tokens": 0,
            "reasoning_output_tokens": 0,
            "latency_ms": 0,
            "ended_at": "2026-08-26T10:00:00Z",
            "limitations": [],
        },
    }
    preliminary_context = qualification_context_documents(
        requested_profile=requested_profile, **context_arguments
    )
    risk = {"case_id": case["case_id"], "kind": "qualification-risk"}
    charter = qualification_charter_document(
        repository_id=EVALUATION_REPOSITORY_ID,
        candidate_id=candidate_id,
        case=case,
    )
    profile_prefix = "" if requested_profile is None else requested_profile + "/"
    prefix = f"qualification/{profile_prefix}{mode}/{case['case_id']}"
    evidence = root.joinpath(*prefix.split("/"))
    documents = {
        "task-contract.json": task,
        "effective-policy.json": policy,
        "gate-manifest.json": gate_manifest,
        "context-sources.json": preliminary_context["context_sources"],
        "context-projection.json": preliminary_context["context_projection"],
        "context-qualification.json": preliminary_context["context_qualification"],
        "context-receipt.json": preliminary_context["context_receipt"],
        "reviewer-qualification.json": dict(bootstrap),
    }
    if mode == "rapid_review":
        documents.update(
            {"risk-assessment.json": risk, "review-charter.json": charter}
        )
    references: dict[str, dict[str, str]] = {}
    for name, document in documents.items():
        _write_json(evidence / name, document)
        references[name] = {
            "path": f"{prefix}/{name}",
            "sha256": sha256_bytes(canonical_bytes(document)),
        }

    permitted = {
        "task_contract_path": references["task-contract.json"]["path"],
        "task_contract_sha256": task_sha,
        "repository_id": EVALUATION_REPOSITORY_ID,
        "candidate_id": candidate_id,
        "candidate_path": "candidate",
        "effective_policy_path": references["effective-policy.json"]["path"],
        "effective_policy_sha256": policy_sha,
        "gate_manifest_path": references["gate-manifest.json"]["path"],
        "gate_manifest_sha256": references["gate-manifest.json"]["sha256"],
        "context_receipt_path": references["context-receipt.json"]["path"],
        "context_receipt_sha256": references["context-receipt.json"]["sha256"],
        "context_sources_path": references["context-sources.json"]["path"],
        "context_sources_sha256": references["context-sources.json"]["sha256"],
        "context_projection_path": references["context-projection.json"]["path"],
        "context_projection_sha256": references["context-projection.json"]["sha256"],
        "context_qualification_path": references["context-qualification.json"]["path"],
        "context_qualification_sha256": references["context-qualification.json"]["sha256"],
        "context_qualification_id": preliminary_context["context_qualification"]["qualification_id"],
        "reviewer_qualification_path": references["reviewer-qualification.json"]["path"],
        "reviewer_qualification_sha256": references["reviewer-qualification.json"]["sha256"],
        "reviewer_qualification_id": bootstrap["qualification_id"],
        "evidence_root": "qualification",
        "reviewer_prompt_sha256": prompt_sha,
        "review_mode": mode,
    }
    if mode == "rapid_review":
        permitted.update(
            risk_assessment_path=references["risk-assessment.json"]["path"],
            risk_assessment_sha256=references["risk-assessment.json"]["sha256"],
            review_charter_path=references["review-charter.json"]["path"],
            review_charter_sha256=references["review-charter.json"]["sha256"],
        )
    permitted_bytes = canonical_bytes(permitted)
    (evidence / "permitted-inputs.json").write_bytes(permitted_bytes)

    expected = {
        "repository_id": EVALUATION_REPOSITORY_ID,
        "candidate_id": candidate_id,
        "task_contract_sha256": task_sha,
        "reviewer_prompt_sha256": prompt_sha,
        "qualification_id": bootstrap["qualification_id"],
        "model": MODEL,
    }
    if mode == "conformance":
        expected.update(
            effective_policy_sha256=policy_sha,
            gate_manifest_sha256=permitted["gate_manifest_sha256"],
            context_receipt_sha256=permitted["context_receipt_sha256"],
        )
    else:
        expected.update(
            charter_id=charter["charter_id"],
            charter_sha256=permitted["review_charter_sha256"],
        )
    _make_read_only(candidate_root)

    def current_candidate(unused_deadline: float) -> str:
        observed = sorted(
            path.relative_to(candidate_root).as_posix()
            for path in candidate_root.rglob("*")
            if path.is_file() or path.is_symlink()
        )
        if observed != sorted(expected_files):
            raise ValueError("qualification candidate file inventory changed")
        for relative, expected_digest in expected_files.items():
            path = candidate_root.joinpath(*relative.split("/"))
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise ValueError("qualification candidate file type changed")
            if sha256_bytes(read_bytes_fresh(path)) != expected_digest:
                raise ValueError("qualification candidate bytes changed")
        return candidate_id

    if (
        prompt_sha != sha256_bytes(read_bytes_once(prompt_path))
        or schema_sha != sha256_bytes(read_bytes_once(schema_path))
    ):
        raise ValueError("reviewer identity drifted while preparing qualification")
    return {
        "permitted": permitted,
        "permitted_bytes": permitted_bytes,
        "expected": expected,
        "supplier": current_candidate,
        "task": task,
        "policy": policy,
        "candidate": candidate,
        "preliminary_context": preliminary_context,
        "risk": risk,
        "charter": charter,
    }


def _run_mode(
    *,
    mode: str,
    corpus: Mapping[str, Any],
    label_decision: Mapping[str, Any],
    prompt_path: Path,
    schema_path: Path,
    codex: str,
    cli_version: str,
    authentication: str,
    timeout_seconds: float,
    max_output_bytes: int,
    workflow_run_id: str,
    workflow_attempt: int,
    output: Path,
    requested_profile: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    prompt_sha = sha256_bytes(read_bytes_once(prompt_path))
    schema_sha = sha256_bytes(read_bytes_once(schema_path))
    launcher_sha = reviewer_launcher_sha256()
    corpus_sha = sha256_bytes(canonical_bytes(corpus))
    identity = {
        "prompt_sha256": prompt_sha,
        "schema_sha256": schema_sha,
        "launcher_sha256": launcher_sha,
        "codex_cli_version": cli_version,
        "authentication": authentication,
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
    }
    bootstrap = bootstrap_qualification_record(
        identity=identity,
        corpus_sha256=corpus_sha,
        label_decision_id=label_decision["decision_id"],
    )
    observations: list[dict[str, Any]] = []
    execution_metrics: list[dict[str, int]] = []
    total_latency = 0
    for case in corpus["cases"]:
        with tempfile.TemporaryDirectory(prefix="governed-qualification-") as directory:
            root = Path(directory) / "harness"
            root.mkdir()
            prompt = root / "reviewer.prompt.md"
            schema = root / "reviewer-output.schema.json"
            prompt.write_bytes(read_bytes_once(prompt_path))
            schema.write_bytes(read_bytes_once(schema_path))
            prepared = _prepare_case(
                root=root,
                case=case,
                mode=mode,
                prompt_path=prompt,
                schema_path=schema,
                bootstrap=bootstrap,
                requested_profile=requested_profile,
            )
            permitted = prepared["permitted"]
            task = prepared["task"]
            policy = prepared["policy"]
            candidate = prepared["candidate"]
            result_path = root / "reviewer-result.json"
            command = build_reviewer_command(
                codex_executable=codex,
                model=MODEL,
                schema_path=schema,
                output_path=result_path,
                review_root=root,
                reasoning_effort=REASONING_EFFORT,
            )
            stdin_text = build_reviewer_stdin(
                fixed_prompt=read_bytes_once(prompt).decode("utf-8"),
                permitted_inputs=permitted,
            )
            if observe_codex_authentication(codex) != authentication:
                raise ValueError(
                    "Codex authentication changed before qualification invocation"
                )
            launched = launch_reviewer(
                command=command,
                stdin_text=stdin_text,
                schema_path=schema,
                output_path=result_path,
                expected_candidate_id=permitted["candidate_id"],
                candidate_supplier=prepared["supplier"],
                expected_bindings=prepared["expected"],
                review_mode=mode,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                model=MODEL,
                reasoning_effort=REASONING_EFFORT,
            )
            observed = classify_observed_disposition(
                mode,
                launched.get("result"),
                execution_valid=launched.get("execution_valid") is True,
            )
            reviewer_output = launched.get("output_bytes")
            if not isinstance(reviewer_output, bytes):
                raise ValueError("reviewer launcher did not return its exact output bytes")
            launched["reviewer_prompt_sha256"] = prompt_sha
            launched["model"] = MODEL
            launched["reasoning_effort"] = REASONING_EFFORT
            launched["argv_sha256"] = reviewer_argv_sha256(
                model=MODEL, reasoning_effort=REASONING_EFFORT
            )
            observed_usage: dict[str, int] = {}
            if launched.get("usage_observed") is not True:
                raise ValueError("qualification token usage was not observed")
            for name in (
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
                "reasoning_output_tokens",
            ):
                value = launched.get(name)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError("qualification token usage is unavailable")
                observed_usage[name] = value
            execution_metrics.append(observed_usage)
            context_arguments = {
                "mode": mode,
                "case": case,
                "task": task,
                "policy": policy,
                "candidate": candidate,
                "reviewer_output_sha256": launched["output_sha256"],
                "execution": launched,
            }
            context_documents = qualification_context_documents(
                requested_profile=requested_profile, **context_arguments
            )
            if (
                context_documents["context_receipt"]
                != prepared["preliminary_context"]["context_receipt"]
            ):
                raise ValueError("qualification prepared context drifted")
            artifact_parts = (
                (mode, str(case["case_id"]))
                if requested_profile is None
                else (requested_profile, mode, str(case["case_id"]))
            )
            artifact_directory = output.joinpath("raw", *artifact_parts)
            artifact_directory.mkdir(parents=True, exist_ok=True)

            def store(name: str, data: bytes) -> dict[str, str]:
                destination = artifact_directory / name
                destination.write_bytes(data)
                return {
                    "path": "/".join(
                        (QUALIFICATION_ARTIFACT_PREFIX, *artifact_parts, name)
                    ),
                    "sha256": sha256_bytes(data),
                }

            context_references = {
                name: store(
                    name.replace("_", "-") + ".json",
                    canonical_bytes(document),
                )
                for name, document in context_documents.items()
            }
            permitted_reference = store(
                "permitted-inputs.json", prepared["permitted_bytes"]
            )
            stdout_reference = store("stdout.bin", launched["stdout_bytes"])
            stderr_reference = store("stderr.bin", launched["stderr_bytes"])
            rapid_references: dict[str, dict[str, str]] = {}
            if mode == "rapid_review":
                rapid_references = {
                    "risk_assessment": store(
                        "risk-assessment.json", canonical_bytes(prepared["risk"])
                    ),
                    "review_charter": store(
                        "review-charter.json", canonical_bytes(prepared["charter"])
                    ),
                }
            execution = build_reviewer_execution_statement(
                repository_id=EVALUATION_REPOSITORY_ID,
                task_contract_sha256=sha256_bytes(canonical_bytes(task)),
                effective_policy_sha256=sha256_bytes(canonical_bytes(policy)),
                candidate_id=permitted["candidate_id"],
                review_mode=mode,
                output_schema_sha256=schema_sha,
                launcher_sha256=launcher_sha,
                qualification_id=bootstrap["qualification_id"],
                model=MODEL,
                reasoning_effort=REASONING_EFFORT,
                context_source_bundle_sha256=context_references[
                    "context_sources"
                ]["sha256"],
                context_projection_sha256=context_references[
                    "context_projection"
                ]["sha256"],
                context_qualification_id=context_documents[
                    "context_qualification"
                ]["qualification_id"],
                input_context_receipt_sha256=context_references[
                    "context_receipt"
                ]["sha256"],
                context_execution_receipt_sha256=context_references[
                    "context_execution_receipt"
                ]["sha256"],
                workflow_system="github-actions-qualification",
                run_id=workflow_run_id,
                attempt=workflow_attempt,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                codex_cli_version=cli_version,
                authentication=authentication,
                stdout_reference=stdout_reference,
                stderr_reference=stderr_reference,
                execution=launched,
                permitted_inputs_sha256=permitted_reference["sha256"],
                risk_assessment_sha256=(
                    rapid_references.get("risk_assessment", {}).get("sha256")
                ),
                review_charter_sha256=(
                    rapid_references.get("review_charter", {}).get("sha256")
                ),
            )
            expected_finding_detected = qualification_expected_finding_detected(
                mode=mode,
                result=(
                    launched["result"]
                    if isinstance(launched.get("result"), Mapping)
                    else {}
                ),
                case=case,
                candidate=candidate,
                repository_id=EVALUATION_REPOSITORY_ID,
                task_contract_sha256=sha256_bytes(canonical_bytes(task)),
            )
            total_latency += int(launched.get("latency_ms", 0))
            observations.append(
                {
                    "case_id": case["case_id"],
                    "severity": case["severity"],
                    "requirement_id": case["requirement_id"],
                    "expected_disposition": case["expected_disposition"],
                    "observed_disposition": observed,
                    "matched": (
                        observed == case["expected_disposition"]
                        and expected_finding_detected
                    ),
                    "task_contract_sha256": sha256_bytes(canonical_bytes(task)),
                    "effective_policy_sha256": sha256_bytes(
                        canonical_bytes(policy)
                    ),
                    "candidate": candidate,
                    **context_references,
                    **rapid_references,
                    "permitted_inputs": permitted_reference,
                    "reviewer_output": store("result.json", reviewer_output),
                    "reviewer_execution": store(
                        "execution.json", canonical_bytes(execution)
                    ),
                    "stdout": stdout_reference,
                    "stderr": stderr_reference,
                }
            )
    critical = [item for item in observations if item["severity"] == "critical"]
    controls = [item for item in observations if item["severity"] == "control"]
    critical_detected = sum(
        item["observed_disposition"] == "BLOCK" and item["matched"]
        for item in critical
    )
    false_passes = sum(
        item["expected_disposition"] == "BLOCK"
        and item["observed_disposition"] == "NO_BLOCKING_FINDING_OBSERVED"
        for item in observations
    )
    false_blocks = sum(item["observed_disposition"] == "BLOCK" for item in controls)
    unknowns = sum(item["observed_disposition"] == "UNKNOWN" for item in observations)
    qualified = bool(
        critical_detected == len(critical)
        and false_passes == 0
        and false_blocks == 0
        and unknowns == 0
        and all(item["matched"] for item in observations)
    )
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    case_evidence = content_address(
        {
            "schema_version": "5.0.0",
            "mode": mode,
            "evaluation_repository_id": EVALUATION_REPOSITORY_ID,
            "corpus_sha256": corpus_sha,
            "label_decision_id": label_decision["decision_id"],
            "identity": identity,
            "observations": observations,
        },
        "case_evidence_id",
    )
    record = content_address(
        {
            "schema_version": "3.0.0",
            **identity,
            "corpus_sha256": corpus_sha,
            "label_decision_id": label_decision["decision_id"],
            "case_evidence_sha256": sha256_bytes(canonical_bytes(case_evidence)),
            "human_labelled": True,
            "cases": len(observations),
            "critical_cases": len(critical),
            "critical_detected": critical_detected,
            "critical_defect_recall": f"{critical_detected}/{len(critical)}",
            "false_passes": false_passes,
            "false_blocks": false_blocks,
            "unknowns": unknowns,
            "latency_ms": total_latency,
            "cost": "unavailable",
            "qualified": qualified,
            "created_at": created_at,
            "limitations": (
                [] if qualified else ["One or more exact calibration cases did not match the human label"]
            ),
        },
        "qualification_id",
    )
    output.mkdir(parents=True, exist_ok=True)
    case_name = "conformance-cases.json" if mode == "conformance" else "rapid-review-cases.json"
    write_once(output / case_name, case_evidence)
    write_once(output / ("conformance.json" if mode == "conformance" else "rapid-review.json"), record)
    total_tokens = sum(
        int(item.get("input_tokens", 0))
        + int(item.get("output_tokens", 0))
        + int(item.get("reasoning_output_tokens", 0))
        for item in execution_metrics
    )
    return record, {
        "critical_cases": len(critical),
        "critical_detected": critical_detected,
        "false_passes": false_passes,
        "false_blocks": false_blocks,
        "unknowns": unknowns,
        "traceable_cases": critical_detected,
        "traceability_cases": len(critical),
        "tokens": total_tokens,
    }


def _combine_context_metrics(mode_metrics: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate both review modes without accepting missing or partial metrics."""
    if set(mode_metrics) != {"conformance", "rapid_review"}:
        raise ValueError("both context qualification modes are required")
    values = list(mode_metrics.values())
    critical_cases = sum(int(item["critical_cases"]) for item in values)
    critical_detected = sum(int(item["critical_detected"]) for item in values)
    cases = sum(int(item["traceability_cases"]) for item in values)
    traceable_cases = sum(int(item["traceable_cases"]) for item in values)
    if critical_cases < 1 or cases < 1:
        raise ValueError("context qualification metrics are empty")
    return {
        "critical_recall": critical_detected / critical_cases,
        "false_passes": sum(int(item["false_passes"]) for item in values),
        "traceability": traceable_cases / cases,
        "disposition_correct": bool(
            critical_detected == critical_cases
            and traceable_cases == cases
            and all(int(item["false_blocks"]) == 0 for item in values)
            and all(int(item["unknowns"]) == 0 for item in values)
        ),
        "tokens": sum(int(item["tokens"]) for item in values),
    }


def _context_qualification_record(
    *,
    profile: str,
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    created_at: str,
    corpus_sha256: str,
    label_decision_id: str,
    measurement_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Create an empirical profile record; assurance parity is mandatory."""
    if profile not in CONTEXT_PROFILES:
        raise ValueError("context qualification profile is invalid")
    baseline_value = dict(baseline)
    candidate_value = dict(candidate)
    assurance_parity = bool(
        baseline_value["disposition_correct"] is True
        and candidate_value["disposition_correct"] is True
        and candidate_value["critical_recall"] >= baseline_value["critical_recall"]
        and candidate_value["false_passes"] <= baseline_value["false_passes"]
        and candidate_value["traceability"] >= baseline_value["traceability"]
    )
    return content_address(
        {
            "schema_version": "3.0.0",
            "projection_version": "1.0.0",
            "profile": profile,
            "evidence_class": "empirical",
            "corpus_sha256": require_sha256(corpus_sha256),
            "label_decision_id": require_sha256(label_decision_id),
            "measurement_evidence": dict(measurement_evidence),
            "baseline": baseline_value,
            "candidate": candidate_value,
            "qualified": assurance_parity,
            "created_at": created_at,
            "limitations": [
                "Eight-case protected labelled corpus; comparative results do not establish causality."
            ],
        },
        "qualification_id",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--human-label-decision", type=Path, required=True)
    parser.add_argument("--prompt", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--expected-codex-version", required=True)
    parser.add_argument("--model", choices=[MODEL], required=True)
    parser.add_argument("--reasoning-effort", choices=[REASONING_EFFORT], required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--authority-repository", required=True)
    parser.add_argument(
        "--authority-ref",
        choices=["refs/heads/governance-authority"],
        required=True,
    )
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-attempt", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=900)
    parser.add_argument("--max-output-bytes", type=int, default=4_000_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.max_output_bytes < 1:
        raise ValueError("qualification execution limits are invalid")
    corpus = load_json(args.corpus)
    decision = load_json(args.human_label_decision)
    if not isinstance(corpus, Mapping) or not isinstance(decision, Mapping):
        raise ValueError("qualification inputs must be JSON objects")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", args.actor):
        raise ValueError("qualification actor is not a valid GitHub login")
    load_and_validate_once(
        args.corpus,
        args.schema_root / "reviewer-qualification-corpus.schema.json",
    )
    load_and_validate_once(
        args.human_label_decision,
        args.schema_root / "reviewer-qualification-label-decision.schema.json",
    )
    if args.workflow_attempt < 1:
        raise ValueError("qualification workflow attempt is invalid")
    _validate_corpus(
        corpus,
        decision,
        actor=args.actor,
        authority_repository=args.authority_repository,
        authority_ref=args.authority_ref,
    )
    authentication = observe_codex_authentication(args.codex)
    cli_version = observe_codex_cli_version(args.codex)
    if cli_version != args.expected_codex_version:
        raise ValueError("Codex CLI version is not the protected qualification identity")
    schemas = {
        "conformance": args.schema_root / "reviewer-result.schema.json",
        "rapid_review": args.schema_root / "rapid-review-session.schema.json",
    }
    records: dict[str, dict[str, Any]] = {}
    for mode, schema in schemas.items():
        records[mode], _unused_metrics = _run_mode(
            mode=mode,
            corpus=corpus,
            label_decision=decision,
            prompt_path=args.prompt,
            schema_path=schema,
            codex=args.codex,
            cli_version=cli_version,
            authentication=authentication,
            timeout_seconds=args.timeout_seconds,
            max_output_bytes=args.max_output_bytes,
            workflow_run_id=args.workflow_run_id,
            workflow_attempt=args.workflow_attempt,
            output=args.output,
            requested_profile=None,
        )
    validate_qualification_bundle(
        corpus_path=args.corpus,
        label_decision_path=args.human_label_decision,
        conformance_record_path=args.output / "conformance.json",
        conformance_cases_path=args.output / "conformance-cases.json",
        rapid_record_path=args.output / "rapid-review.json",
        rapid_cases_path=args.output / "rapid-review-cases.json",
        policy_path=None,
        authenticated_label_decision_id=decision["decision_id"],
        artifact_root=args.output / "raw",
    )
    profile_metrics: dict[str, dict[str, dict[str, Any]]] = {}
    records_by_profile: dict[str, dict[str, dict[str, Any]]] = {}
    cases_by_profile: dict[str, dict[str, dict[str, Any]]] = {}
    for profile in CONTEXT_PROFILES:
        profile_metrics[profile] = {}
        records_by_profile[profile] = {}
        cases_by_profile[profile] = {}
        profile_output = args.output / "context-variants" / profile
        for mode, schema in schemas.items():
            variant_record, metrics = _run_mode(
                mode=mode,
                corpus=corpus,
                label_decision=decision,
                prompt_path=args.prompt,
                schema_path=schema,
                codex=args.codex,
                cli_version=cli_version,
                authentication=authentication,
                timeout_seconds=args.timeout_seconds,
                max_output_bytes=args.max_output_bytes,
                workflow_run_id=args.workflow_run_id,
                workflow_attempt=args.workflow_attempt,
                output=profile_output,
                requested_profile=profile,
            )
            profile_metrics[profile][mode] = metrics
            records_by_profile[profile][mode] = variant_record
            cases_by_profile[profile][mode] = load_json(
                profile_output
                / (
                    "conformance-cases.json"
                    if mode == "conformance"
                    else "rapid-review-cases.json"
                )
            )
    combined_metrics = {
        profile: _combine_context_metrics(profile_metrics[profile])
        for profile in CONTEXT_PROFILES
    }
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    context_records = {
        profile: _context_qualification_record(
            profile=profile,
            baseline=combined_metrics["DEEP"],
            candidate=combined_metrics[profile],
            created_at=created_at,
            corpus_sha256=sha256_bytes(read_bytes_once(args.corpus)),
            label_decision_id=decision["decision_id"],
            measurement_evidence={
                "corpus": {
                    "path": ".governance/releases/v0.1.0/qualification/corpus.json",
                    "sha256": sha256_bytes(read_bytes_once(args.corpus)),
                },
                "label_decision": {
                    "path": ".governance/releases/v0.1.0/qualification/human-label-decision.json",
                    "sha256": sha256_bytes(
                        read_bytes_once(args.human_label_decision)
                    ),
                },
                "baseline": {
                    "profile": "DEEP",
                    "conformance": {
                        "record": {
                            "path": ".governance/releases/v0.1.0/qualification/evidence/context-variants/DEEP/conformance.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                records_by_profile["DEEP"]["conformance"]
                            )),
                        },
                        "cases": {
                            "path": ".governance/releases/v0.1.0/qualification/evidence/context-variants/DEEP/conformance-cases.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                cases_by_profile["DEEP"]["conformance"]
                            )),
                        },
                    },
                    "rapid_review": {
                        "record": {
                            "path": ".governance/releases/v0.1.0/qualification/evidence/context-variants/DEEP/rapid-review.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                records_by_profile["DEEP"]["rapid_review"]
                            )),
                        },
                        "cases": {
                            "path": ".governance/releases/v0.1.0/qualification/evidence/context-variants/DEEP/rapid-review-cases.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                cases_by_profile["DEEP"]["rapid_review"]
                            )),
                        },
                    },
                },
                "candidate": {
                    "profile": profile,
                    "conformance": {
                        "record": {
                            "path": f".governance/releases/v0.1.0/qualification/evidence/context-variants/{profile}/conformance.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                records_by_profile[profile]["conformance"]
                            )),
                        },
                        "cases": {
                            "path": f".governance/releases/v0.1.0/qualification/evidence/context-variants/{profile}/conformance-cases.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                cases_by_profile[profile]["conformance"]
                            )),
                        },
                    },
                    "rapid_review": {
                        "record": {
                            "path": f".governance/releases/v0.1.0/qualification/evidence/context-variants/{profile}/rapid-review.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                records_by_profile[profile]["rapid_review"]
                            )),
                        },
                        "cases": {
                            "path": f".governance/releases/v0.1.0/qualification/evidence/context-variants/{profile}/rapid-review-cases.json",
                            "sha256": sha256_bytes(canonical_bytes(
                                cases_by_profile[profile]["rapid_review"]
                            )),
                        },
                    },
                },
            },
        )
        for profile in CONTEXT_PROFILES
    }
    context_output = args.output / "context-qualifications"
    context_output.mkdir(parents=True, exist_ok=True)

    def context_artifact_reader(reference: Mapping[str, Any]) -> bytes:
        path = _safe_relative(reference.get("path"))
        expected = require_sha256(reference.get("sha256"))
        fixed = {
            ".governance/releases/v0.1.0/qualification/corpus.json": args.corpus,
            ".governance/releases/v0.1.0/qualification/human-label-decision.json": args.human_label_decision,
        }
        source = fixed.get(path)
        if source is None:
            prefix = ".governance/releases/v0.1.0/qualification/evidence/"
            if not path.startswith(prefix):
                raise ValueError("context measurement reference is outside its package")
            source = args.output.joinpath(*path[len(prefix):].split("/"))
        data = read_bytes_once(source)
        if sha256_bytes(data) != expected:
            raise ValueError("context measurement reference digest mismatch")
        return data

    for profile, record in context_records.items():
        write_once(context_output / f"{profile}.json", record)
        load_and_validate_once(
            context_output / f"{profile}.json",
            args.schema_root / "context-qualification.schema.json",
        )
        if not context_qualification_evidence_valid(
            record=record,
            artifact_reader=context_artifact_reader,
            schema_root=args.schema_root,
            protected_repository_id="repo:timaday/codex-governed-change",
            verified_decision_ids=frozenset({decision["decision_id"]}),
            evaluated_at=created_at,
            prompt_bytes=read_bytes_once(args.prompt),
        ):
            raise ValueError("context qualification evidence does not reconstruct")
    write_once(
        args.output / "summary.json",
        {
            "schema_version": "1.0.0",
            "corpus_id": corpus["corpus_id"],
            "human_label_decision_id": decision["decision_id"],
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "codex_cli_version": cli_version,
            "authentication": authentication,
            "conformance_qualification_id": records["conformance"]["qualification_id"],
            "rapid_review_qualification_id": records["rapid_review"]["qualification_id"],
            "context_qualification_ids": {
                profile: context_records[profile]["qualification_id"]
                for profile in CONTEXT_PROFILES
            },
            "qualified": bool(
                all(record["qualified"] for record in records.values())
                and all(record["qualified"] for record in context_records.values())
            ),
        },
    )
    if not (
        all(record["qualified"] for record in records.values())
        and all(record["qualified"] for record in context_records.values())
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
