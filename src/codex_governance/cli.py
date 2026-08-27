"""Standalone shell-free command-line orchestration boundary."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from codex_governance.artifacts import FilesystemArtifactStore
from codex_governance.attestation import (
    gate_implementation_sha256,
    mutation_implementation_sha256,
)
from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import (
    canonical_json_bytes,
    normalize_repo_path,
    sha256_bytes,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.configuration import load_effective_policy, resolve_effective_configuration
from codex_governance.context import compile_context, finalize_context_receipt
from codex_governance.domain.model import DispositionState
from codex_governance.evidence import (
    PRODUCER_VERSION,
    assemble_evidence_manifest,
    assemble_gate_manifest,
    candidate_prefix,
    evaluate_manifest,
    load_referenced_json,
    repository_reference,
)
from codex_governance.gate import run_gate
from codex_governance.hook import decide_stop
from codex_governance.locking import PipelineLock
from codex_governance.mutation_runner import run_governed_mutation_corpus
from codex_governance.profiles import validate_task_contract
from codex_governance.qualification import reviewer_qualification_state
from codex_governance.reviewer import (
    build_reviewer_command,
    build_reviewer_execution_statement,
    build_reviewer_stdin,
    launch_reviewer,
    observe_codex_cli_version,
    prepare_sanitized_harness,
    reviewer_launcher_sha256,
)
from codex_governance.sandbox import (
    build_container_invocation,
    iter_fresh_gate_copies,
    observe_container_provider,
)
from codex_governance.schema import (
    load_and_validate,
    load_json,
    validate_instance,
    validate_semantics,
)


EXIT_READY = 0
EXIT_BLOCK = 1
EXIT_UNKNOWN = 2
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")


def _write(path: Path, value: Any) -> None:
    data = canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("CLI output is not a regular file")
        if path.read_bytes() == data:
            return
        raise FileExistsError("write-once CLI output conflicts with existing content")
    temporary = path.parent / f".{path.name}.tmp-{secrets.token_hex(12)}"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            try:
                info = path.lstat()
                existing = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            except OSError:
                existing = None
            if existing != data:
                raise FileExistsError(
                    "write-once CLI output won a conflicting race"
                ) from exc
            return
        temporary.unlink()
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _document(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return value


def _validated(path: Path, schema_root: Path, name: str) -> dict[str, Any]:
    value = load_and_validate(path, schema_root / f"{name}.schema.json")
    if not isinstance(value, dict):
        raise ValueError("validated document must be an object")
    return value


def _state_exit(state: DispositionState | str) -> int:
    value = state.value if isinstance(state, DispositionState) else state
    return {"READY_FOR_HUMAN": 0, "BLOCK": 1, "UNKNOWN": 2}.get(value, 2)


def _scope(args: argparse.Namespace) -> int:
    task = _validated(args.task, args.schema_root, "task-contract")
    violations = validate_task_contract(task)
    policy = load_effective_policy(
        policy_path=args.policy,
        schema_path=args.schema_root / "effective-policy.schema.json",
    )
    if violations:
        _emit({"state": "BLOCK", "violations": violations})
        return EXIT_BLOCK
    resolved, digest = resolve_effective_configuration(
        policy=policy,
        task_contract=task,
        evidence_root_override=args.evidence_root,
    )
    result = {
        "state": "VALID",
        "effective_configuration_sha256": digest,
        "configuration": resolved,
    }
    if args.output:
        _write(args.output, result)
    _emit(result)
    return EXIT_READY


def _identify(args: argparse.Namespace) -> int:
    policy = _validated(args.policy, args.schema_root, "effective-policy")
    policy_sha = sha256_canonical(policy)
    candidate = GitCliRepositoryAdapter(args.repository).identify(
        repository_id=policy["repository_id"],
        mode=args.mode,
        base_commit=args.base,
        head_commit=args.head,
        effective_policy_sha256=policy_sha,
        evidence_root=policy["evidence_root"],
    )
    if args.output:
        _write(args.output, candidate)
    _emit(candidate)
    return EXIT_READY


def _run_gates(args: argparse.Namespace) -> int:
    if RUN_ID_RE.fullmatch(args.run_id) is None or args.attempt < 1:
        raise ValueError("run identity is not portable")
    policy = _validated(args.policy, args.schema_root, "effective-policy")
    task = _validated(args.task, args.schema_root, "task-contract")
    candidate = _validated(args.candidate, args.schema_root, "candidate")
    policy_sha = sha256_canonical(policy)
    task_sha = sha256_canonical(task)
    if (
        task["repository_id"] != policy["repository_id"]
        or candidate["repository_id"] != policy["repository_id"]
        or candidate["effective_policy_sha256"] != policy_sha
    ):
        raise ValueError("repository or policy identity mismatch")
    available = {gate["gate_id"]: gate for gate in policy["gates"]}
    gate_ids = list(task["required_gate_ids"])
    if any(item not in available for item in gate_ids):
        raise ValueError("task requests an unavailable protected gate")
    store = FilesystemArtifactStore(
        repository=args.repository,
        root=Path(policy["evidence_root"]),
        max_bytes=max(gate["max_output_bytes"] for gate in policy["gates"]) * 2,
    )
    prefix = f"{candidate_prefix(candidate['candidate_id'])}/runs/{args.run_id}-{args.attempt}"
    adapter = GitCliRepositoryAdapter(args.repository)

    def current_candidate() -> str:
        return adapter.identify(
            repository_id=policy["repository_id"],
            mode=candidate["mode"],
            base_commit=candidate["base_commit"],
            head_commit=candidate.get("head_commit"),
            effective_policy_sha256=policy_sha,
            evidence_root=policy["evidence_root"],
        )["candidate_id"]

    with tempfile.TemporaryDirectory(prefix="codex-governance-sandbox-") as temporary:
        supervisor = Path(temporary).resolve()
        try:
            provider_version = observe_container_provider(policy["sandbox"]["provider"])
        except RuntimeError:
            provider_version = None
        gate_references: dict[str, dict[str, str]] = {}
        results: list[dict[str, Any]] = []
        for gate_id, candidate_copy in iter_fresh_gate_copies(
            repository=args.repository,
            supervisor=supervisor,
            gate_ids=gate_ids,
            evidence_root=policy["evidence_root"],
        ):
            gate = available[gate_id]
            copied_candidate = GitCliRepositoryAdapter(candidate_copy).identify(
                repository_id=policy["repository_id"],
                mode=candidate["mode"],
                base_commit=candidate["base_commit"],
                head_commit=candidate.get("head_commit"),
                effective_policy_sha256=policy_sha,
                evidence_root=policy["evidence_root"],
            )
            if copied_candidate["candidate_id"] != candidate["candidate_id"]:
                raise RuntimeError("fresh gate candidate copy identity mismatch")
            sandbox_command = list(gate["command"])
            if gate["shell"]:
                sandbox_command = ["sh", "-c", gate["command"][0]]
            invocation = None
            if provider_version is not None:
                invocation = build_container_invocation(
                    executable=policy["sandbox"]["provider"],
                    provider_version=provider_version,
                    image=policy["sandbox"]["image"],
                    candidate_copy=candidate_copy,
                    candidate_id=candidate["candidate_id"],
                    command=sandbox_command,
                    process_limit=policy["sandbox"]["process_limit"],
                    memory_bytes=policy["sandbox"]["memory_bytes"],
                    cpu_seconds=gate["timeout_seconds"],
                    timeout_seconds=gate["timeout_seconds"],
                    output_bytes=gate["max_output_bytes"],
                    implementation_sha256=gate_implementation_sha256(),
                    verified_at=args.observed_at,
                    supervisor_cwd=supervisor,
                )
            gate_prefix = f"{prefix}/gates/{gate_id}"
            result = run_gate(
                gate_id=gate_id,
                profile=task["profile"],
                command=gate["command"],
                cwd=args.repository,
                sandbox_invocation=invocation,
                repository_id=policy["repository_id"],
                task_contract_sha256=task_sha,
                effective_policy_sha256=policy_sha,
                provenance_context={
                    "repository_digest": candidate["candidate_id"],
                    "gate_definition_sha256": sha256_canonical(gate),
                    "reviewer_prompt_sha256": sha256_bytes(args.reviewer_prompt.read_bytes()),
                    "producer": {
                        "builder_id": "codex-governed-change",
                        "implementation_sha256": gate_implementation_sha256(),
                        "version": PRODUCER_VERSION,
                    },
                    "workflow": {
                        "system": args.workflow_system,
                        "run_id": args.run_id,
                        "attempt": args.attempt,
                    },
                    "tools": [
                        {"name": "python", "version": f"{sys.version_info.major}.{sys.version_info.minor}"},
                        {"name": policy["sandbox"]["provider"], "version": provider_version or "unavailable"},
                    ],
                    "materials": [
                        {"name": "candidate", "sha256": candidate["candidate_id"]},
                        {"name": "task-contract", "sha256": task_sha},
                        {"name": "effective-policy", "sha256": policy_sha},
                    ],
                },
                candidate_supplier=current_candidate,
                artifact_store=store,
                artifact_prefix=gate_prefix,
                timeout_seconds=gate["timeout_seconds"],
                max_output_bytes=gate["max_output_bytes"],
                shell=gate["shell"],
                risk_label=gate["risk_label"] or None,
            )
            relative = f"{gate_prefix}/result.json"
            result_sha = sha256_bytes(canonical_json_bytes(result))
            gate_references[gate_id] = repository_reference(
                evidence_root=policy["evidence_root"],
                relative_path=relative,
                sha256=result_sha,
            )
            results.append(result)
    manifest = assemble_gate_manifest(
        repository_id=policy["repository_id"],
        task_contract_sha256=task_sha,
        candidate_id=candidate["candidate_id"],
        required_gate_ids=gate_ids,
        gate_references=gate_references,
        created_at=args.observed_at,
    )
    manifest_relative = f"{prefix}/gate-manifest.json"
    manifest_sha = store.write_bytes(manifest_relative, canonical_json_bytes(manifest))
    summary = {
        "repository_id": policy["repository_id"],
        "candidate_id": candidate["candidate_id"],
        "gate_manifest": repository_reference(
            evidence_root=policy["evidence_root"],
            relative_path=manifest_relative,
            sha256=manifest_sha,
        ),
        "results": [
            {"gate_id": item["gate_id"], "status": item["status"]}
            for item in results
        ],
    }
    if args.output:
        _write(args.output, summary)
    _emit(summary)
    if any(item["status"] == "FAIL" for item in results):
        return EXIT_BLOCK
    return EXIT_READY if all(item["status"] == "PASS" for item in results) else EXIT_UNKNOWN


def _prepare_review(args: argparse.Namespace) -> int:
    policy = _validated(args.policy, args.schema_root, "effective-policy")
    candidate = _validated(args.candidate, args.schema_root, "candidate")
    policy_sha = sha256_canonical(policy)
    if (
        candidate["repository_id"] != policy["repository_id"]
        or candidate["effective_policy_sha256"] != policy_sha
    ):
        raise ValueError("context policy and candidate binding mismatch")
    adapter = GitCliRepositoryAdapter(args.repository)
    observed_candidate = adapter.identify(
        repository_id=policy["repository_id"],
        mode=candidate["mode"],
        base_commit=candidate["base_commit"],
        head_commit=candidate.get("head_commit"),
        effective_policy_sha256=policy_sha,
        evidence_root=policy["evidence_root"],
    )
    if observed_candidate != candidate:
        raise ValueError("context candidate does not match the exact repository")
    affected_closure = adapter.conservative_affected_closure(
        candidate=observed_candidate,
        evidence_root=policy["evidence_root"],
    )
    compiled = compile_context(
        sources=_document(args.sources),
        candidate=observed_candidate,
        requested_profile=args.profile,
        token_budget=args.token_budget,
        changed_paths=observed_candidate["changed_paths"],
        affected_closure=affected_closure,
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        gate_failed=args.gate_failed,
        gate_missing=args.gate_missing,
        surviving_mutant=args.surviving_mutant,
        conflicting_oracle=args.conflicting_oracle,
        prompt_injection_risk=args.prompt_injection_risk,
        authority_incomplete=args.authority_incomplete,
        provenance_incomplete=args.provenance_incomplete,
        reviewer_uncertain=args.reviewer_uncertain,
        selector_uncertain=args.selector_uncertain,
    )
    _write(args.projection_output, compiled["projection"])
    _write(args.receipt_output, compiled["receipt"])
    result = {
        "state": compiled["state"].value,
        "profile": compiled["receipt"]["profile"],
        "projection_sha256": compiled["receipt"]["projection_sha256"],
        "receipt_id": compiled["receipt"]["receipt_id"],
    }
    _emit(result)
    return _state_exit(compiled["state"])


def _assemble_manifest(args: argparse.Namespace) -> int:
    inputs = _document(args.input)
    manifest = assemble_evidence_manifest(**inputs)
    schema = load_json(args.schema_root / "evidence-manifest.schema.json")
    if not isinstance(schema, dict):
        raise ValueError("evidence manifest schema is unavailable")
    errors = validate_instance(manifest, schema)
    errors.extend(validate_semantics(manifest, "evidence-manifest"))
    if errors:
        raise ValueError("assembled evidence manifest is invalid")
    _write(args.output, manifest)
    _emit({"state": "VALID", "manifest_id": manifest["manifest_id"]})
    return EXIT_READY


def _mutate(args: argparse.Namespace) -> int:
    if RUN_ID_RE.fullmatch(args.run_id) is None or args.attempt < 1:
        raise ValueError("run identity is not portable")
    policy = _validated(args.policy, args.schema_root, "effective-policy")
    task = _validated(args.task, args.schema_root, "task-contract")
    candidate = _validated(args.candidate, args.schema_root, "candidate")
    policy_sha = sha256_canonical(policy)
    task_sha = sha256_canonical(task)
    if (
        task["repository_id"] != policy["repository_id"]
        or candidate["repository_id"] != policy["repository_id"]
        or candidate["effective_policy_sha256"] != policy_sha
        or candidate["base_commit"] != task["base_commit"]
    ):
        raise ValueError("mutation authority or candidate binding mismatch")
    summary = run_governed_mutation_corpus(
        repository=args.repository,
        policy=policy,
        task=task,
        candidate=candidate,
        task_contract_sha256=task_sha,
        effective_policy_sha256=policy_sha,
        reviewer_prompt_sha256=sha256_bytes(args.reviewer_prompt.read_bytes()),
        run_id=args.run_id,
        attempt=args.attempt,
        workflow_system=args.workflow_system,
        observed_at=args.observed_at,
        implementation_sha256=mutation_implementation_sha256(),
    )
    if args.output:
        _write(args.output, summary)
    _emit(summary)
    return EXIT_READY if summary["state"] == "PASS" else (
        EXIT_BLOCK if summary["state"] == "BLOCK" else EXIT_UNKNOWN
    )


def _review(args: argparse.Namespace) -> int:
    candidate = _validated(args.candidate, args.schema_root, "candidate")
    policy = _validated(args.policy, args.schema_root, "effective-policy")
    permitted = _document(args.permitted_inputs)
    review_mode = permitted.get("review_mode")
    if review_mode not in {"conformance", "rapid_review"}:
        raise ValueError("review mode is unavailable")
    policy_sha = sha256_canonical(policy)
    prompt_sha = sha256_bytes(args.prompt.read_bytes())
    schema_sha = sha256_bytes(args.output_schema.read_bytes())
    expected_bindings = {
        "repository_id": policy["repository_id"],
        "candidate_id": candidate["candidate_id"],
        "candidate_path": "candidate",
        "effective_policy_sha256": policy_sha,
        "reviewer_prompt_sha256": prompt_sha,
    }
    if any(permitted.get(key) != value for key, value in expected_bindings.items()):
        raise ValueError("reviewer permitted-input binding mismatch")

    def evidence_path(key: str) -> Path:
        relative = normalize_repo_path(permitted[key])
        return args.repository.joinpath(*relative.split("/"))

    task = _validated(
        evidence_path("task_contract_path"), args.schema_root, "task-contract"
    )
    gate_manifest = _validated(
        evidence_path("gate_manifest_path"), args.schema_root, "gate-manifest"
    )
    receipt = _validated(
        evidence_path("context_receipt_path"), args.schema_root, "context-receipt"
    )
    qualification = _validated(
        evidence_path("reviewer_qualification_path"),
        args.schema_root,
        "reviewer-qualification",
    )
    codex_cli_version = observe_codex_cli_version(args.codex)
    identity = {
        "prompt_sha256": prompt_sha,
        "schema_sha256": schema_sha,
        "launcher_sha256": reviewer_launcher_sha256(),
        "codex_cli_version": codex_cli_version,
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
    }
    if (
        reviewer_qualification_state(
            identity,
            qualification,
            protected_qualification_id=policy["reviewer"]["qualification_ids"][review_mode],
        )
        is not DispositionState.READY_FOR_HUMAN
        or permitted.get("reviewer_qualification_id")
        != qualification.get("qualification_id")
        or task.get("repository_id") != policy["repository_id"]
        or task.get("base_commit") != candidate["base_commit"]
        or gate_manifest.get("repository_id") != policy["repository_id"]
        or gate_manifest.get("task_contract_sha256")
        != permitted.get("task_contract_sha256")
        or gate_manifest.get("candidate_id") != candidate["candidate_id"]
        or sha256_bytes(evidence_path("gate_manifest_path").read_bytes())
        != permitted.get("gate_manifest_sha256")
        or receipt.get("candidate_id") != candidate["candidate_id"]
        or receipt.get("repository_id") != policy["repository_id"]
        or receipt.get("projection_sha256")
        != permitted.get("context_projection_sha256")
        or receipt.get("model") != args.model
        or receipt.get("reasoning_effort") != args.reasoning_effort
        or receipt.get("truncation_status") == "CONTEXT_BUDGET_INSUFFICIENT"
        or args.timeout_seconds != policy["reviewer"]["timeout_seconds"]
        or args.max_output_bytes != policy["reviewer"]["max_output_bytes"]
        or args.attempt < 1
        or not args.run_id
    ):
        raise ValueError("reviewer identity or context is not qualified and exact")
    expected_result_bindings = {
        "repository_id": policy["repository_id"],
        "candidate_id": candidate["candidate_id"],
        "task_contract_sha256": permitted["task_contract_sha256"],
    }
    if review_mode == "conformance":
        expected_result_bindings.update(
            effective_policy_sha256=policy_sha,
            gate_manifest_sha256=permitted["gate_manifest_sha256"],
            context_receipt_sha256=permitted["context_receipt_sha256"],
            reviewer_prompt_sha256=prompt_sha,
            qualification_id=qualification["qualification_id"],
            model=args.model,
        )
    else:
        risk = _validated(
            evidence_path("risk_assessment_path"),
            args.schema_root,
            "risk-assessment",
        )
        charter = _validated(
            evidence_path("review_charter_path"),
            args.schema_root,
            "review-charter",
        )
        if (
            risk.get("repository_id") != policy["repository_id"]
            or risk.get("candidate_id") != candidate["candidate_id"]
            or risk.get("task_contract_sha256") != permitted["task_contract_sha256"]
            or charter.get("repository_id") != policy["repository_id"]
            or charter.get("candidate_id") != candidate["candidate_id"]
            or charter.get("task_contract_sha256") != permitted["task_contract_sha256"]
            or charter.get("risk_assessment_sha256") != risk.get("assessment_id")
        ):
            raise ValueError("rapid-review risk or charter binding mismatch")
        expected_result_bindings.update(
            charter_id=charter["charter_id"],
            charter_sha256=permitted["review_charter_sha256"],
            reviewer_prompt_sha256=prompt_sha,
            qualification_id=qualification["qualification_id"],
            model=args.model,
        )
    adapter = GitCliRepositoryAdapter(args.repository)

    def current_candidate() -> str:
        return adapter.identify(
            repository_id=policy["repository_id"],
            mode=candidate["mode"],
            base_commit=candidate["base_commit"],
            head_commit=candidate.get("head_commit"),
            effective_policy_sha256=policy_sha,
            evidence_root=policy["evidence_root"],
        )["candidate_id"]

    with tempfile.TemporaryDirectory(prefix="codex-governance-review-") as temporary:
        harness = prepare_sanitized_harness(
            candidate_repository=args.repository,
            harness_root=Path(temporary) / "harness",
            fixed_prompt_path=args.prompt,
            output_schema_path=args.output_schema,
            permitted_inputs=permitted,
            expected_candidate=candidate,
            evidence_root=policy["evidence_root"],
        )
        command = build_reviewer_command(
            codex_executable=args.codex,
            model=args.model,
            schema_path=harness["schema"],
            output_path=harness["output"],
            review_root=harness["root"],
            reasoning_effort=args.reasoning_effort,
        )
        stdin_text = build_reviewer_stdin(
            fixed_prompt=harness["prompt"].read_text(encoding="utf-8"),
            permitted_inputs=permitted,
        )
        result = launch_reviewer(
            command=command,
            stdin_text=stdin_text,
            schema_path=harness["schema"],
            output_path=harness["output"],
            expected_candidate_id=candidate["candidate_id"],
            candidate_supplier=current_candidate,
            expected_bindings=expected_result_bindings,
            review_mode=review_mode,
            timeout_seconds=args.timeout_seconds,
            max_output_bytes=args.max_output_bytes,
        )
        if result.get("execution_valid") and isinstance(result.get("result"), Mapping):
            _write(args.output, result["result"])
            result["output_sha256"] = sha256_bytes(args.output.read_bytes())
        execution_receipt = finalize_context_receipt(
            receipt,
            review_mode=review_mode,
            reviewer_output_sha256=result["output_sha256"],
            retrieval_expansions=(
                result["result"].get("retrieval_expansions", ())
                if isinstance(result.get("result"), Mapping)
                else ()
            ),
            usage_observed=result["usage_observed"],
            actual_input_tokens=result["input_tokens"],
            actual_output_tokens=result["output_tokens"],
            cached_input_tokens=result["cached_input_tokens"],
            reasoning_output_tokens=result["reasoning_output_tokens"],
            latency_ms=result["latency_ms"],
            cost="unavailable",
            created_at=result["ended_at"],
            limitations=result["limitations"],
        )
        _write(args.context_execution_output, execution_receipt)
        result["reviewer_prompt_sha256"] = prompt_sha
        execution_statement = build_reviewer_execution_statement(
            repository_id=policy["repository_id"],
            task_contract_sha256=permitted["task_contract_sha256"],
            effective_policy_sha256=policy_sha,
            candidate_id=candidate["candidate_id"],
            review_mode=review_mode,
            output_schema_sha256=schema_sha,
            launcher_sha256=identity["launcher_sha256"],
            qualification_id=qualification["qualification_id"],
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            input_context_receipt_sha256=permitted["context_receipt_sha256"],
            context_execution_receipt_sha256=sha256_canonical(execution_receipt),
            workflow_system=args.workflow_system,
            run_id=args.run_id,
            attempt=args.attempt,
            timeout_seconds=args.timeout_seconds,
            max_output_bytes=args.max_output_bytes,
            codex_cli_version=codex_cli_version,
            execution=result,
        )
        _write(args.execution_output, execution_statement)
    execution_complete = bool(
        result.get("execution_valid")
        and result.get("usage_observed")
        and isinstance(result.get("thread_id"), str)
        and result.get("thread_id")
    )
    if review_mode == "rapid_review":
        state = result.get("review_status") if execution_complete else "UNKNOWN"
        _emit(
            {
                "state": state,
                "return_code": result["return_code"],
                "timed_out": result["timed_out"],
                "output_valid": result["output_valid"],
                "bindings_match": result["bindings_match"],
                "output_truncated": result["output_truncated"],
                "stdout_sha256": result["stdout_sha256"],
                "stderr_sha256": result["stderr_sha256"],
            }
        )
        return EXIT_READY if state == "completed" else EXIT_UNKNOWN
    verdict = result["verdict"].value if execution_complete else "UNKNOWN"
    _emit(
        {
            "verdict": verdict,
            "return_code": result["return_code"],
            "timed_out": result["timed_out"],
            "output_valid": result["output_valid"],
            "candidate_matches": result["candidate_matches"],
            "bindings_match": result["bindings_match"],
            "output_truncated": result["output_truncated"],
            "stdout_sha256": result["stdout_sha256"],
            "stderr_sha256": result["stderr_sha256"],
        }
    )
    return EXIT_BLOCK if verdict == "BLOCK" else (
        EXIT_READY if verdict == "NO_BLOCKING_FINDING_OBSERVED" else EXIT_UNKNOWN
    )


def _import_reviewer(args: argparse.Namespace) -> int:
    result = _validated(args.source, args.schema_root, "reviewer-result")
    if (
        result["repository_id"] != args.repository_id
        or result["candidate_id"] != args.candidate_id
        or result["task_contract_sha256"] != args.task_contract_sha256
        or result["effective_policy_sha256"] != args.effective_policy_sha256
    ):
        _emit({"state": "UNKNOWN", "reason": "reviewer binding mismatch"})
        return EXIT_UNKNOWN
    store = FilesystemArtifactStore(repository=args.repository, root=args.evidence_root)
    digest = store.write_bytes(args.destination, canonical_json_bytes(result))
    _emit({"state": result["verdict"], "sha256": digest})
    return EXIT_BLOCK if result["verdict"] == "BLOCK" else (
        EXIT_READY if result["verdict"] == "NO_BLOCKING_FINDING_OBSERVED" else EXIT_UNKNOWN
    )


def _evaluate(args: argparse.Namespace) -> int:
    manifest = _validated(args.manifest, args.schema_root, "evidence-manifest")
    declared_candidate = _validated(args.candidate, args.schema_root, "candidate")
    policy = load_referenced_json(
        repository=args.repository,
        reference=manifest["effective_policy"],
        schema_path=args.schema_root / "effective-policy.schema.json",
    )
    candidate = GitCliRepositoryAdapter(args.repository).identify(
        repository_id=manifest["repository_id"],
        mode=declared_candidate["mode"],
        base_commit=declared_candidate["base_commit"],
        head_commit=declared_candidate.get("head_commit"),
        effective_policy_sha256=manifest["effective_policy"]["sha256"],
        evidence_root=policy["evidence_root"],
    )
    state, reasons = evaluate_manifest(
        repository=args.repository,
        manifest=manifest,
        schema_root=args.schema_root,
        current_candidate=candidate,
        evaluated_at=args.evaluated_at,
        verified_decision_ids=frozenset(
            require_sha256(item, name="verified_decision_id")
            for item in args.verified_decision_id
        ),
    )
    disposition = {
        "schema_version": "1.0.0",
        "repository_id": manifest["repository_id"],
        "task_contract_sha256": manifest["task_contract"]["sha256"],
        "effective_policy_sha256": manifest["effective_policy"]["sha256"],
        "candidate_id": candidate["candidate_id"],
        "manifest_sha256": sha256_bytes(canonical_json_bytes(manifest)),
        "state": state.value,
        "reasons": [
            {
                "code": f"EVIDENCE-{index + 1:03d}",
                "message": reason,
                "evidence_refs": [],
            }
            for index, reason in enumerate(
                reasons or ["no evaluable assurance reason was available"]
            )
        ],
        "human_action_required": True,
        "approved": False,
        "evaluated_at": args.evaluated_at,
        "producer_version": PRODUCER_VERSION,
    }
    _write(args.output, disposition)
    _emit(disposition)
    return _state_exit(state)


def _status(args: argparse.Namespace) -> int:
    disposition = _validated(args.disposition, args.schema_root, "disposition")
    if args.candidate:
        candidate = _validated(args.candidate, args.schema_root, "candidate")
        if candidate["candidate_id"] != disposition["candidate_id"]:
            _emit({"state": "UNKNOWN", "reason": "disposition is stale"})
            return EXIT_UNKNOWN
    _emit(
        {
            "repository_id": disposition["repository_id"],
            "candidate_id": disposition["candidate_id"],
            "state": disposition["state"],
            "human_action_required": True,
            "approved": False,
        }
    )
    return _state_exit(disposition["state"])


def _verify(args: argparse.Namespace) -> int:
    value = _validated(args.artifact, args.schema_root, args.schema)
    errors: list[str] = []
    if args.identity_field and not verify_content_address(value, args.identity_field):
        errors.append("content address does not reconstruct")
    _emit({"state": "VALID" if not errors else "UNKNOWN", "errors": errors})
    return EXIT_READY if not errors else EXIT_UNKNOWN


def _hook(args: argparse.Namespace) -> int:
    try:
        event = json.load(sys.stdin)
    except (UnicodeDecodeError, json.JSONDecodeError):
        event = {}
    policy = _validated(args.policy, args.schema_root, "effective-policy")
    task = _validated(args.task, args.schema_root, "task-contract")
    if task["repository_id"] != policy["repository_id"]:
        raise ValueError("hook authority binding mismatch")
    candidate = GitCliRepositoryAdapter(args.repository).identify(
        repository_id=policy["repository_id"],
        mode=args.mode,
        base_commit=task["base_commit"],
        head_commit=args.head,
        effective_policy_sha256=sha256_canonical(policy),
        evidence_root=policy["evidence_root"],
    )
    disposition: Mapping[str, Any] | None = None
    if args.disposition and args.disposition.is_file():
        try:
            disposition = _validated(args.disposition, args.schema_root, "disposition")
        except (OSError, ValueError):
            disposition = None
    _emit(
        decide_stop(
            event=event,
            current_candidate_id=candidate["candidate_id"],
            disposition=disposition,
        )
    )
    return EXIT_READY


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codex-governance")
    parser.add_argument("--schema-root", type=Path, default=Path("schemas"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    scope = subparsers.add_parser("scope")
    scope.add_argument("--task", type=Path, required=True)
    scope.add_argument("--policy", type=Path, required=True)
    scope.add_argument("--evidence-root")
    scope.add_argument("--output", type=Path)
    scope.set_defaults(handler=_scope)

    identify = subparsers.add_parser("identify")
    identify.add_argument("--repository", type=Path, default=Path.cwd())
    identify.add_argument("--policy", type=Path, required=True)
    identify.add_argument("--mode", choices=("commit", "working_tree"), required=True)
    identify.add_argument("--base", required=True)
    identify.add_argument("--head")
    identify.add_argument("--output", type=Path)
    identify.set_defaults(handler=_identify)

    gates = subparsers.add_parser("run-gates")
    gates.add_argument("--repository", type=Path, default=Path.cwd())
    gates.add_argument("--policy", type=Path, required=True)
    gates.add_argument("--task", type=Path, required=True)
    gates.add_argument("--candidate", type=Path, required=True)
    gates.add_argument("--reviewer-prompt", type=Path, required=True)
    gates.add_argument("--run-id", required=True)
    gates.add_argument("--attempt", type=int, default=1)
    gates.add_argument("--workflow-system", default="local")
    gates.add_argument("--observed-at", required=True)
    gates.add_argument("--output", type=Path)
    gates.set_defaults(handler=_run_gates)

    prepare = subparsers.add_parser("prepare-review")
    prepare.add_argument("--repository", type=Path, default=Path.cwd())
    prepare.add_argument("--policy", type=Path, required=True)
    prepare.add_argument("--sources", type=Path, required=True)
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--profile", choices=("COMPACT", "STANDARD", "DEEP"), required=True)
    prepare.add_argument("--token-budget", type=int, required=True)
    prepare.add_argument("--model", required=True)
    prepare.add_argument("--reasoning-effort", choices=("low", "medium", "high", "xhigh"), required=True)
    prepare.add_argument("--projection-output", type=Path, required=True)
    prepare.add_argument("--receipt-output", type=Path, required=True)
    for signal in (
        "gate_failed", "gate_missing", "surviving_mutant", "conflicting_oracle",
        "prompt_injection_risk", "authority_incomplete", "provenance_incomplete",
        "reviewer_uncertain", "selector_uncertain",
    ):
        prepare.add_argument("--" + signal.replace("_", "-"), action="store_true")
    prepare.set_defaults(handler=_prepare_review)

    assemble = subparsers.add_parser("assemble-manifest")
    assemble.add_argument("--repository", type=Path, default=Path.cwd())
    assemble.add_argument("--policy", type=Path, required=True)
    assemble.add_argument("--input", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.set_defaults(handler=_assemble_manifest)

    mutate = subparsers.add_parser("mutate")
    mutate.add_argument("--repository", type=Path, default=Path.cwd())
    mutate.add_argument("--policy", type=Path, required=True)
    mutate.add_argument("--task", type=Path, required=True)
    mutate.add_argument("--candidate", type=Path, required=True)
    mutate.add_argument("--reviewer-prompt", type=Path, required=True)
    mutate.add_argument("--run-id", required=True)
    mutate.add_argument("--attempt", type=int, default=1)
    mutate.add_argument("--workflow-system", default="local")
    mutate.add_argument("--observed-at", required=True)
    mutate.add_argument("--output", type=Path)
    mutate.set_defaults(handler=_mutate)

    review = subparsers.add_parser("review")
    review.add_argument("--repository", type=Path, default=Path.cwd())
    review.add_argument("--policy", type=Path, required=True)
    review.add_argument("--candidate", type=Path, required=True)
    review.add_argument("--permitted-inputs", type=Path, required=True)
    review.add_argument("--prompt", type=Path, required=True)
    review.add_argument("--output-schema", type=Path, required=True)
    review.add_argument("--output", type=Path, required=True)
    review.add_argument("--execution-output", type=Path, required=True)
    review.add_argument("--context-execution-output", type=Path, required=True)
    review.add_argument("--codex", default="codex")
    review.add_argument("--workflow-system", default="local")
    review.add_argument("--run-id", required=True)
    review.add_argument("--attempt", type=int, default=1)
    review.add_argument("--model", required=True)
    review.add_argument("--reasoning-effort", choices=("high", "xhigh"), default="xhigh")
    review.add_argument("--timeout-seconds", type=float, default=1800)
    review.add_argument("--max-output-bytes", type=int, default=1_000_000)
    review.set_defaults(handler=_review)

    imported = subparsers.add_parser("import-reviewer-result")
    imported.add_argument("--repository", type=Path, default=Path.cwd())
    imported.add_argument("--source", type=Path, required=True)
    imported.add_argument("--evidence-root", type=Path, required=True)
    imported.add_argument("--destination", required=True)
    imported.add_argument("--repository-id", required=True)
    imported.add_argument("--candidate-id", required=True)
    imported.add_argument("--task-contract-sha256", required=True)
    imported.add_argument("--effective-policy-sha256", required=True)
    imported.set_defaults(handler=_import_reviewer)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--repository", type=Path, default=Path.cwd())
    evaluate.add_argument("--manifest", type=Path, required=True)
    evaluate.add_argument("--candidate", type=Path, required=True)
    evaluate.add_argument("--evaluated-at", required=True)
    evaluate.add_argument("--verified-decision-id", action="append", default=[])
    evaluate.add_argument("--output", type=Path, required=True)
    evaluate.set_defaults(handler=_evaluate)

    status = subparsers.add_parser("status")
    status.add_argument("--disposition", type=Path, required=True)
    status.add_argument("--candidate", type=Path)
    status.set_defaults(handler=_status)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--artifact", type=Path, required=True)
    verify.add_argument("--schema", required=True)
    verify.add_argument("--identity-field")
    verify.set_defaults(handler=_verify)

    hook = subparsers.add_parser("hook")
    hook.add_argument("--repository", type=Path, default=Path.cwd())
    hook.add_argument("--policy", type=Path, required=True)
    hook.add_argument("--task", type=Path, required=True)
    hook.add_argument("--mode", choices=("commit", "working_tree"), required=True)
    hook.add_argument("--head")
    hook.add_argument("--disposition", type=Path)
    hook.set_defaults(handler=_hook)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one bounded use case with stable fail-closed exit codes."""
    args = _parser().parse_args(argv)
    try:
        lock = _pipeline_lock_for(args)
        with lock:
            return int(args.handler(args))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _emit(
            {
                "state": "UNKNOWN",
                "error": exc.__class__.__name__,
                "message": "the requested observation could not be completed",
            }
        )
        return EXIT_UNKNOWN


def _pipeline_lock_for(args: argparse.Namespace):
    policy_commands = {
        "identify",
        "run-gates",
        "prepare-review",
        "assemble-manifest",
        "mutate",
        "review",
        "hook",
    }
    if args.command in policy_commands:
        policy = _validated(args.policy, args.schema_root, "effective-policy")
        return PipelineLock(
            repository=args.repository,
            evidence_root=policy["evidence_root"],
        )
    if args.command == "import-reviewer-result":
        return PipelineLock(
            repository=args.repository,
            evidence_root=args.evidence_root,
        )
    if args.command == "evaluate":
        manifest = _validated(args.manifest, args.schema_root, "evidence-manifest")
        policy = load_referenced_json(
            repository=args.repository,
            reference=manifest["effective_policy"],
            schema_path=args.schema_root / "effective-policy.schema.json",
        )
        return PipelineLock(
            repository=args.repository,
            evidence_root=policy["evidence_root"],
        )
    return nullcontext()
