"""Standalone shell-free command-line orchestration boundary."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from pathlib import Path
from typing import Any, NoReturn

from codex_governance.artifacts import (
    FilesystemArtifactStore,
    read_bounded_repository_file,
)
from codex_governance.attestation import (
    gate_implementation_sha256,
    mutation_implementation_sha256,
)
from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import (
    canonical_json_bytes,
    normalize_repo_path,
    require_sha256,
    sha256_bytes,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.configuration import load_effective_policy, resolve_effective_configuration
from codex_governance.context import (
    build_protected_context_sources,
    build_repository_inventory,
    compile_context,
    finalize_context_receipt,
)
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
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.locking import PipelineLock
from codex_governance.mutation import REQUIRED_CURATED_MUTANTS
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
    reviewer_portable_source_literals,
    reviewer_stream_is_portable,
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
CLI_OUTPUT_ARGUMENTS = {
    "scope": ("output",),
    "identify": ("output",),
    "run-gates": ("output",),
    "prepare-review": ("sources_output", "projection_output", "receipt_output"),
    "assemble-manifest": ("output",),
    "mutate": ("output",),
    "review": (
        "output",
        "execution_output",
        "context_execution_output",
        "stdout_output",
        "stderr_output",
    ),
    "import-reviewer-result": ("destination",),
    "evaluate": ("output",),
}


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")


def _cli_output_authority(args: argparse.Namespace) -> tuple[Path, str]:
    repository = args.repository
    if args.command == "scope":
        task = _validated(args.task, args.schema_root, "task-contract")
        policy = load_effective_policy(
            policy_path=args.policy,
            schema_path=args.schema_root / "effective-policy.schema.json",
        )
        resolved, _ = resolve_effective_configuration(
            policy=policy,
            task_contract=task,
            evidence_root_override=args.evidence_root,
        )
        evidence_root = resolved["evidence_root"]
    elif args.command == "import-reviewer-result":
        evidence_root = normalize_repo_path(os.fspath(args.evidence_root))
    elif args.command == "evaluate":
        manifest = _validated(args.manifest, args.schema_root, "evidence-manifest")
        policy = load_referenced_json(
            repository=repository,
            reference=manifest["effective_policy"],
            schema_path=args.schema_root / "effective-policy.schema.json",
        )
        evidence_root = normalize_repo_path(policy["evidence_root"])
    else:
        policy = _validated(args.policy, args.schema_root, "effective-policy")
        evidence_root = normalize_repo_path(policy["evidence_root"])
    return repository, evidence_root


def _relative_cli_output(path: str, evidence_root: str) -> str:
    normalized = normalize_repo_path(path)
    prefix = evidence_root + "/"
    if not normalized.startswith(prefix):
        raise ValueError("CLI output must be beneath the configured evidence root")
    return normalize_repo_path(normalized.removeprefix(prefix))


def _preflight_cli_outputs(
    args: argparse.Namespace,
    *,
    expected_authority: tuple[Path, str, tuple[int, int] | None] | None = None,
) -> None:
    fields = CLI_OUTPUT_ARGUMENTS.get(args.command, ())
    if not fields:
        return
    repository, evidence_root = _cli_output_authority(args)
    if expected_authority is not None:
        expected_repository, expected_evidence_root, expected_root_identity = (
            expected_authority
        )
        if (
            repository.resolve() != expected_repository.resolve()
            or normalize_repo_path(evidence_root)
            != normalize_repo_path(expected_evidence_root)
        ):
            raise ValueError("CLI output authority changed after lock selection")
    store = FilesystemArtifactStore(
        repository=repository,
        root=Path(evidence_root),
        max_bytes=64_000_000,
        expected_root_identity=(
            expected_authority[2] if expected_authority is not None else None
        ),
    )
    store.validate_root_binding()
    relative_paths: dict[str, str] = {}
    for field in fields:
        value = getattr(args, field)
        if value is None:
            continue
        relative = _relative_cli_output(os.fspath(value), evidence_root)
        store.validate_target(relative)
        if relative in relative_paths.values():
            raise ValueError("CLI output paths must be unique")
        relative_paths[field] = relative
    args._cli_output_store = store
    args._cli_output_paths = relative_paths


def _write_cli_output(
    args: argparse.Namespace, field: str, value: Any
) -> str:
    store = args._cli_output_store
    relative = args._cli_output_paths[field]
    try:
        return store.write_bytes(relative, canonical_json_bytes(value))
    except FileExistsError:
        _raise_cli_output_conflict()


def _raise_cli_output_conflict() -> NoReturn:
    raise FileExistsError("write-once CLI output conflicts with existing content")


def _write_cli_bytes(args: argparse.Namespace, field: str, value: bytes) -> str:
    try:
        return args._cli_output_store.write_bytes(
            args._cli_output_paths[field], value
        )
    except FileExistsError:
        _raise_cli_output_conflict()


def _read_cli_output(args: argparse.Namespace, field: str) -> bytes:
    return args._cli_output_store.read_bytes(args._cli_output_paths[field])


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


def _repository_argument_path(repository: Path, path: Path) -> str:
    """Map an argument path into the repository without resolving symlinks."""
    root = repository.absolute()
    absolute = path.absolute() if path.is_absolute() else (root / path).absolute()
    try:
        relative = absolute.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("authoritative CLI input must be repository-relative") from exc
    return normalize_repo_path(relative)


def _read_repository_argument(
    repository: Path, path: Path, *, max_bytes: int = 8_000_000
) -> bytes:
    return read_bounded_repository_file(
        repository,
        _repository_argument_path(repository, path),
        max_bytes=max_bytes,
    )


def _state_exit(state: DispositionState | str) -> int:
    value = state.value if isinstance(state, DispositionState) else state
    return {"READY_FOR_HUMAN": 0, "BLOCK": 1, "UNKNOWN": 2}.get(value, 2)


def _gate_manifest_created_at(results: Sequence[Mapping[str, Any]]) -> str:
    if not results:
        raise ValueError("gate manifest requires at least one completed result")
    return max((str(item["ended_at"]) for item in results), key=parse_rfc3339)


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
        _write_cli_output(args, "output", result)
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
        _write_cli_output(args, "output", candidate)
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
    store = args._cli_output_store
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
        created_at=_gate_manifest_created_at(results),
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
        _write_cli_output(args, "output", summary)
    _emit(summary)
    if any(item["status"] == "FAIL" for item in results):
        return EXIT_BLOCK
    return EXIT_READY if all(item["status"] == "PASS" for item in results) else EXIT_UNKNOWN


def _prepare_review(args: argparse.Namespace) -> int:
    policy = _validated(args.policy, args.schema_root, "effective-policy")
    task = _validated(args.task, args.schema_root, "task-contract")
    candidate = _validated(args.candidate, args.schema_root, "candidate")
    qualification = _validated(
        args.context_qualification, args.schema_root, "context-qualification"
    )
    policy_sha = sha256_canonical(policy)
    task_sha = sha256_canonical(task)
    if (
        task["repository_id"] != policy["repository_id"]
        or task["base_commit"] != candidate["base_commit"]
        or candidate["repository_id"] != policy["repository_id"]
        or candidate["effective_policy_sha256"] != policy_sha
    ):
        raise ValueError("context policy and candidate binding mismatch")
    context_policy = policy["context"]
    profile_rank = {"COMPACT": 0, "STANDARD": 1, "DEEP": 2}
    expected_budget = context_policy[f"{args.profile.lower()}_tokens"]
    if (
        context_policy.get("projection_version") != qualification.get("projection_version")
        or qualification.get("qualification_id")
        != context_policy.get("qualification_ids", {}).get(args.profile)
        or profile_rank[args.profile] < profile_rank[context_policy["default_profile"]]
        or args.token_budget != expected_budget
        or args.model != policy["reviewer"]["model"]
        or args.reasoning_effort != policy["reviewer"]["reasoning_effort"]
    ):
        raise ValueError("context profile, budget, model, or qualification is not protected")
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
    repository_inventory = build_repository_inventory(
        args.repository,
        affected_closure=affected_closure,
        changed_paths=observed_candidate["changed_paths"],
    )
    gate_summary = _document(args.gate_summary)
    if (
        gate_summary.get("repository_id") != policy["repository_id"]
        or gate_summary.get("candidate_id") != observed_candidate["candidate_id"]
    ):
        raise ValueError("gate summary context binding mismatch")
    gate_manifest = load_referenced_json(
        repository=args.repository,
        reference=gate_summary["gate_manifest"],
        schema_path=args.schema_root / "gate-manifest.schema.json",
    )
    gate_results = [
        load_referenced_json(
            repository=args.repository,
            reference=item["reference"],
            schema_path=args.schema_root / "gate-result.schema.json",
        )
        for item in gate_manifest["gate_results"]
    ]
    if (
        gate_manifest.get("repository_id") != policy["repository_id"]
        or gate_manifest.get("candidate_id") != observed_candidate["candidate_id"]
        or gate_manifest.get("task_contract_sha256") != task_sha
        or gate_summary.get("results")
        != [
            {"gate_id": item.get("gate_id"), "status": result.get("status")}
            for item, result in zip(
                gate_manifest["gate_results"], gate_results, strict=True
            )
        ]
    ):
        raise ValueError("gate summary does not reconstruct exactly")
    mutation_summary = _document(args.mutation_summary)
    mutation_records = [
        load_referenced_json(
            repository=args.repository,
            reference=reference,
            schema_path=args.schema_root / "mutant-record.schema.json",
        )
        for reference in mutation_summary.get("mutant_records", ())
    ]
    expected_mutant_ids = {
        "MUTANT-" + mutant.upper() for mutant in REQUIRED_CURATED_MUTANTS
    }
    if (
        mutation_summary.get("state") != "PASS"
        or len(mutation_records) != len(expected_mutant_ids)
        or {item.get("mutant_id") for item in mutation_records}
        != expected_mutant_ids
        or any(
            item.get("repository_id") != policy["repository_id"]
            or item.get("candidate_id") != observed_candidate["candidate_id"]
            or item.get("effective_policy_sha256") != policy_sha
            or item.get("task_contract_sha256") != task_sha
            or item.get("outcome") != "KILLED"
            for item in mutation_records
        )
    ):
        raise ValueError("mutation summary is incomplete or not exact-candidate PASS")
    sources = build_protected_context_sources(
        candidate=observed_candidate,
        task=task,
        policy=policy,
        repository_inventory=repository_inventory,
        affected_closure=affected_closure,
        gate_results=gate_results,
        mutation_records=mutation_records,
        created_at=args.observed_at,
    )
    if args.sources is not None and _document(args.sources) != sources:
        raise ValueError("caller context sources do not match protected reconstruction")
    compiled = compile_context(
        sources=sources,
        candidate=observed_candidate,
        requested_profile=args.profile,
        token_budget=args.token_budget,
        changed_paths=observed_candidate["changed_paths"],
        affected_closure=affected_closure,
        model=args.model,
        reasoning_effort=args.reasoning_effort,
        context_qualification=qualification,
        protected_qualification_ids=context_policy["qualification_ids"],
    )
    _write_cli_output(args, "sources_output", compiled["source_bundle"])
    _write_cli_output(args, "projection_output", compiled["projection"])
    _write_cli_output(args, "receipt_output", compiled["receipt"])
    result = {
        "state": compiled["state"],
        "profile": compiled["receipt"]["profile"],
        "projection_sha256": compiled["receipt"]["projection_sha256"],
        "receipt_id": compiled["receipt"]["receipt_id"],
    }
    _emit(result)
    return EXIT_READY if compiled["state"] == "CONTEXT_READY" else EXIT_UNKNOWN


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
    _write_cli_output(args, "output", manifest)
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
        artifact_store=args._cli_output_store,
    )
    if args.output:
        _write_cli_output(args, "output", summary)
    _emit(summary)
    return EXIT_READY if summary["state"] == "PASS" else (
        EXIT_BLOCK if summary["state"] == "BLOCK" else EXIT_UNKNOWN
    )


def _review(args: argparse.Namespace) -> int:
    schema_cache: dict[str, Mapping[str, Any]] = {}

    def validated_bytes(data: bytes, name: str) -> dict[str, Any]:
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("authoritative reviewer input is not valid JSON") from exc
        schema = schema_cache.get(name)
        if schema is None:
            schema_bytes = _read_repository_argument(
                args.repository,
                args.schema_root / f"{name}.schema.json",
            )
            try:
                loaded_schema = json.loads(schema_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("protected reviewer schema is not valid JSON") from exc
            if not isinstance(loaded_schema, Mapping):
                raise ValueError("protected reviewer schema must be an object")
            schema = loaded_schema
            schema_cache[name] = schema
        errors = validate_instance(value, schema)
        errors.extend(validate_semantics(value, name))
        if errors or not isinstance(value, dict):
            raise ValueError("authoritative reviewer input fails its protected schema")
        return value

    candidate = validated_bytes(
        _read_repository_argument(args.repository, args.candidate), "candidate"
    )
    policy = validated_bytes(
        _read_repository_argument(args.repository, args.policy), "effective-policy"
    )
    permitted_bytes = _read_repository_argument(
        args.repository, args.permitted_inputs
    )
    try:
        permitted = json.loads(permitted_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("reviewer permitted inputs are not valid JSON") from exc
    if not isinstance(permitted, dict):
        raise ValueError("reviewer permitted inputs must be an object")
    review_mode = permitted.get("review_mode")
    if review_mode not in {"conformance", "rapid_review"}:
        raise ValueError("review mode is unavailable")
    policy_sha = sha256_canonical(policy)
    prompt_bytes = _read_repository_argument(args.repository, args.prompt)
    output_schema_bytes = _read_repository_argument(
        args.repository, args.output_schema
    )
    prompt_sha = sha256_bytes(prompt_bytes)
    schema_sha = sha256_bytes(output_schema_bytes)
    expected_bindings = {
        "repository_id": policy["repository_id"],
        "candidate_id": candidate["candidate_id"],
        "candidate_path": "candidate",
        "effective_policy_sha256": policy_sha,
        "reviewer_prompt_sha256": prompt_sha,
    }
    if any(permitted.get(key) != value for key, value in expected_bindings.items()):
        raise ValueError("reviewer permitted-input binding mismatch")

    prepared_evidence: dict[str, bytes] = {}

    def evidence_document(path_key: str, schema_name: str) -> dict[str, Any]:
        relative = normalize_repo_path(permitted[path_key])
        digest_key = path_key.removesuffix("_path") + "_sha256"
        data = read_bounded_repository_file(
            args.repository, relative, max_bytes=8_000_000
        )
        if sha256_bytes(data) != permitted.get(digest_key):
            raise ValueError("reviewer evidence digest mismatch")
        prepared_evidence[relative] = data
        return validated_bytes(data, schema_name)

    permitted_policy = evidence_document(
        "effective_policy_path", "effective-policy"
    )
    task = evidence_document("task_contract_path", "task-contract")
    gate_manifest = evidence_document("gate_manifest_path", "gate-manifest")
    receipt = evidence_document("context_receipt_path", "context-receipt")
    context_sources = evidence_document(
        "context_sources_path", "context-source-bundle"
    )
    context_projection = evidence_document(
        "context_projection_path", "context-projection"
    )
    context_qualification = evidence_document(
        "context_qualification_path", "context-qualification"
    )
    qualification = evidence_document(
        "reviewer_qualification_path", "reviewer-qualification"
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
            protected_corpus_sha256=policy["reviewer"][
                "qualification_corpus_sha256"
            ],
            protected_label_decision_id=policy["reviewer"][
                "qualification_label_decision_id"
            ],
        )
        is not DispositionState.READY_FOR_HUMAN
        or permitted.get("reviewer_qualification_id")
        != qualification.get("qualification_id")
        or permitted_policy != policy
        or task.get("repository_id") != policy["repository_id"]
        or task.get("base_commit") != candidate["base_commit"]
        or gate_manifest.get("repository_id") != policy["repository_id"]
        or gate_manifest.get("task_contract_sha256")
        != permitted.get("task_contract_sha256")
        or gate_manifest.get("candidate_id") != candidate["candidate_id"]
        or receipt.get("candidate_id") != candidate["candidate_id"]
        or receipt.get("repository_id") != policy["repository_id"]
        or context_sources.get("repository_id") != policy["repository_id"]
        or context_sources.get("candidate_id") != candidate["candidate_id"]
        or context_sources.get("effective_policy_sha256") != policy_sha
        or context_projection.get("source_bundle_id")
        != context_sources.get("source_bundle_id")
        or context_projection.get("candidate_id") != candidate["candidate_id"]
        or context_projection.get("context_qualification_id")
        != context_qualification.get("qualification_id")
        or context_qualification.get("qualification_id")
        != permitted.get("context_qualification_id")
        or context_qualification.get("qualification_id")
        != policy.get("context", {}).get("qualification_ids", {}).get(
            receipt.get("profile")
        )
        or receipt.get("source_bundle_sha256")
        != permitted.get("context_sources_sha256")
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
        risk = evidence_document("risk_assessment_path", "risk-assessment")
        charter = evidence_document("review_charter_path", "review-charter")
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
    for key, raw_path in permitted.items():
        if not key.endswith("_path") or key == "candidate_path":
            continue
        relative = normalize_repo_path(raw_path)
        if relative in prepared_evidence:
            continue
        digest_key = key.removesuffix("_path") + "_sha256"
        data = read_bounded_repository_file(
            args.repository, relative, max_bytes=8_000_000
        )
        if sha256_bytes(data) != permitted.get(digest_key):
            raise ValueError("reviewer evidence digest mismatch")
        prepared_evidence[relative] = data
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
            prepared_evidence=prepared_evidence,
            fixed_prompt_bytes=prompt_bytes,
            output_schema_bytes=output_schema_bytes,
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
            portable_source_literals=reviewer_portable_source_literals(
                harness["candidate"],
                protected_sources=(
                    prompt_bytes,
                    output_schema_bytes,
                    permitted_bytes,
                    *prepared_evidence.values(),
                ),
            ),
        )
        if not reviewer_stream_is_portable(
            result["stdout_bytes"]
        ) or not reviewer_stream_is_portable(result["stderr_bytes"]):
            raise ValueError("reviewer streams retain non-portable material")
        stdout_reference = {
            "path": normalize_repo_path(args.stdout_output),
            "sha256": _write_cli_bytes(args, "stdout_output", result["stdout_bytes"]),
        }
        stderr_reference = {
            "path": normalize_repo_path(args.stderr_output),
            "sha256": _write_cli_bytes(args, "stderr_output", result["stderr_bytes"]),
        }
        if result.get("execution_valid") and isinstance(result.get("result"), Mapping):
            _write_cli_output(args, "output", result["result"])
            result["output_sha256"] = sha256_bytes(
                _read_cli_output(args, "output")
            )
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
        _write_cli_output(
            args, "context_execution_output", execution_receipt
        )
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
            context_source_bundle_sha256=permitted["context_sources_sha256"],
            context_projection_sha256=permitted["context_projection_sha256"],
            context_qualification_id=permitted["context_qualification_id"],
            input_context_receipt_sha256=permitted["context_receipt_sha256"],
            context_execution_receipt_sha256=sha256_canonical(execution_receipt),
            workflow_system=args.workflow_system,
            run_id=args.run_id,
            attempt=args.attempt,
            timeout_seconds=args.timeout_seconds,
            max_output_bytes=args.max_output_bytes,
            codex_cli_version=codex_cli_version,
            stdout_reference=stdout_reference,
            stderr_reference=stderr_reference,
            execution=result,
        )
        _write_cli_output(args, "execution_output", execution_statement)
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
    digest = _write_cli_output(args, "destination", result)
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
    _write_cli_output(args, "output", disposition)
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
    scope.add_argument("--repository", type=Path, default=Path.cwd())
    scope.add_argument("--task", type=Path, required=True)
    scope.add_argument("--policy", type=Path, required=True)
    scope.add_argument("--evidence-root")
    scope.add_argument("--output")
    scope.set_defaults(handler=_scope)

    identify = subparsers.add_parser("identify")
    identify.add_argument("--repository", type=Path, default=Path.cwd())
    identify.add_argument("--policy", type=Path, required=True)
    identify.add_argument("--mode", choices=("commit", "working_tree"), required=True)
    identify.add_argument("--base", required=True)
    identify.add_argument("--head")
    identify.add_argument("--output")
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
    gates.add_argument("--output")
    gates.set_defaults(handler=_run_gates)

    prepare = subparsers.add_parser("prepare-review")
    prepare.add_argument("--repository", type=Path, default=Path.cwd())
    prepare.add_argument("--policy", type=Path, required=True)
    prepare.add_argument("--task", type=Path, required=True)
    prepare.add_argument("--gate-summary", type=Path, required=True)
    prepare.add_argument("--mutation-summary", type=Path, required=True)
    prepare.add_argument("--context-qualification", type=Path, required=True)
    prepare.add_argument("--sources", type=Path)
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--profile", choices=("COMPACT", "STANDARD", "DEEP"), required=True)
    prepare.add_argument("--token-budget", type=int, required=True)
    prepare.add_argument("--model", required=True)
    prepare.add_argument("--reasoning-effort", choices=("low", "medium", "high", "xhigh"), required=True)
    prepare.add_argument("--observed-at", required=True)
    prepare.add_argument("--sources-output", required=True)
    prepare.add_argument("--projection-output", required=True)
    prepare.add_argument("--receipt-output", required=True)
    prepare.set_defaults(handler=_prepare_review)

    assemble = subparsers.add_parser("assemble-manifest")
    assemble.add_argument("--repository", type=Path, default=Path.cwd())
    assemble.add_argument("--policy", type=Path, required=True)
    assemble.add_argument("--input", type=Path, required=True)
    assemble.add_argument("--output", required=True)
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
    mutate.add_argument("--output")
    mutate.set_defaults(handler=_mutate)

    review = subparsers.add_parser("review")
    review.add_argument("--repository", type=Path, default=Path.cwd())
    review.add_argument("--policy", type=Path, required=True)
    review.add_argument("--candidate", type=Path, required=True)
    review.add_argument("--permitted-inputs", type=Path, required=True)
    review.add_argument("--prompt", type=Path, required=True)
    review.add_argument("--output-schema", type=Path, required=True)
    review.add_argument("--output", required=True)
    review.add_argument("--execution-output", required=True)
    review.add_argument("--context-execution-output", required=True)
    review.add_argument("--stdout-output", required=True)
    review.add_argument("--stderr-output", required=True)
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
    evaluate.add_argument("--output", required=True)
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
            expected_authority = None
            assert_binding = getattr(lock, "assert_binding", None)
            if callable(assert_binding):
                assert_binding()
            if isinstance(getattr(lock, "repository", None), Path) and isinstance(
                getattr(lock, "root", None), Path
            ):
                root_identity = getattr(lock, "root_identity", None)
                expected_authority = (
                    lock.repository,
                    lock.root.relative_to(lock.repository).as_posix(),
                    root_identity if isinstance(root_identity, tuple) else None,
                )
            _preflight_cli_outputs(
                args, expected_authority=expected_authority
            )
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
    if args.command == "scope":
        repository, evidence_root = _cli_output_authority(args)
        return PipelineLock(
            repository=repository,
            evidence_root=evidence_root,
        )
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
