#!/usr/bin/env python3
"""Run the protected, non-authorizing T24 held-out paired comparison."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import tempfile
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

from common import (
    canonical_bytes,
    content_address,
    load_and_validate_once,
    load_json,
    read_bytes_fresh,
    read_bytes_once,
    sha256_bytes,
)
from paired_comparison import (
    TOKEN_FIELDS,
    _json_object,
    build_comparison_document,
    comparison_document_valid,
    ordinary_candidate_id,
    reconstruct_task,
    validate_comparison_inputs,
)
from codex_governance.reviewer import (
    _normalize_reviewer_stream,
    REVIEWER_TOOL_ENVIRONMENT_POLICY,
    build_reviewer_environment,
    build_reviewer_permission_profile,
    launch_reviewer,
    observe_codex_authentication,
    observe_codex_cli_version,
    parse_codex_jsonl_evidence,
    resolve_reviewer_runtime_read_roots,
)
from codex_governance.schema import validate_instance


MODEL = "gpt-5.6-sol"
REASONING_EFFORT = "xhigh"


def _qualification_module() -> ModuleType:
    path = Path(__file__).with_name("run-qualification.py")
    spec = importlib.util.spec_from_file_location("protected_run_qualification", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected qualification producer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_bytes_once(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(data)
    except FileExistsError:
        if read_bytes_once(path) != data:
            raise ValueError("comparison artifact replacement is forbidden") from None


def _store(
    *, root: Path, arm: str, case_id: str, name: str, data: bytes
) -> dict[str, str]:
    relative = f"comparison/{arm}/{case_id}/{name}"
    destination = root.joinpath(*relative.split("/"))
    _write_bytes_once(destination, data)
    return {"path": relative, "sha256": sha256_bytes(data)}


def _reader(root: Path, reference: Mapping[str, str]) -> bytes:
    path = reference.get("path")
    if not isinstance(path, str) or not path.startswith("comparison/"):
        raise ValueError("comparison artifact path is outside its package")
    source = root.joinpath(*path.split("/"))
    data = read_bytes_once(source)
    if sha256_bytes(data) != reference.get("sha256"):
        raise ValueError("comparison artifact digest mismatch")
    return data


def _ordinary_prompt(case: Mapping[str, Any], candidate_id: str | None = None) -> str:
    """Build a label-blind baseline task from only protected non-label fields."""
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


def _ordinary_command(
    *,
    codex: str,
    candidate: Path,
    schema: Path,
    result: Path,
    permission_profile: str,
) -> list[str]:
    return [
        codex,
        "exec",
        "--ephemeral",
        "--json",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--model",
        MODEL,
        "--sandbox",
        "read-only",
        "--config",
        'default_permissions="governed_reviewer"',
        "--config",
        permission_profile,
        "--config",
        'approval_policy="never"',
        "--config",
        REVIEWER_TOOL_ENVIRONMENT_POLICY,
        "--config",
        f'model_reasoning_effort="{REASONING_EFFORT}"',
        "--config",
        "features.hooks=false",
        "--config",
        "agents.enabled=false",
        "--output-schema",
        str(schema),
        "--output-last-message",
        str(result),
        "--cd",
        str(candidate),
        "--skip-git-repo-check",
        "-",
    ]


def _candidate_matches(candidate: Path, expected: Mapping[str, str]) -> bool:
    try:
        observed = sorted(
            path.relative_to(candidate).as_posix()
            for path in candidate.rglob("*")
            if path.is_file() or path.is_symlink()
        )
        if observed != sorted(expected):
            return False
        for relative, digest in expected.items():
            path = candidate.joinpath(*relative.split("/"))
            info = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or sha256_bytes(read_bytes_fresh(path)) != digest
            ):
                return False
        return True
    except OSError:
        return False


def _run_ordinary_case(
    *,
    case: Mapping[str, Any],
    codex: str,
    authentication: str,
    schema_path: Path,
    timeout_seconds: float,
    max_output_bytes: int,
    output: Path,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="codex-comparison-") as directory:
        root = Path(directory)
        candidate = root / "candidate"
        candidate.mkdir()
        expected_files: dict[str, str] = {}
        for relative, body in case["files"].items():
            if (
                not isinstance(relative, str)
                or not isinstance(body, str)
                or relative.startswith("/")
                or "\\" in relative
                or any(part in {"", ".", "..", ".git"} for part in relative.split("/"))
            ):
                raise ValueError("comparison candidate file is unsafe")
            path = candidate.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
            expected_files[relative] = sha256_bytes(body.encode("utf-8"))
        for path in sorted(candidate.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            info = path.lstat()
            if path.is_symlink() or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ValueError("comparison candidate contains an unsupported file")
            path.chmod(0o555 if path.is_dir() else 0o444)
        candidate.chmod(0o555)
        schema = root / "ordinary-result.schema.json"
        result_path = root / "ordinary-result.json"
        schema.write_bytes(read_bytes_once(schema_path))
        environment = build_reviewer_environment(os.environ)
        permission_profile = build_reviewer_permission_profile(
            resolve_reviewer_runtime_read_roots(codex, environment=environment),
            review_root=candidate,
        )
        command = _ordinary_command(
            codex=codex,
            candidate=candidate,
            schema=schema,
            result=result_path,
            permission_profile=permission_profile,
        )
        if observe_codex_authentication(codex, environment=environment) != authentication:
            raise ValueError("Codex authentication changed before comparison invocation")
        expected_candidate_id = ordinary_candidate_id(case)

        def current_candidate(observation_deadline: float) -> str:
            if time.monotonic() >= observation_deadline:
                raise TimeoutError("comparison candidate observation expired")
            if not _candidate_matches(candidate, expected_files):
                raise ValueError("comparison candidate changed")
            return expected_candidate_id

        launched = launch_reviewer(
            command=command,
            stdin_text=_ordinary_prompt(case, expected_candidate_id),
            schema_path=schema,
            output_path=result_path,
            expected_candidate_id=expected_candidate_id,
            candidate_supplier=current_candidate,
            review_mode="conformance",
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            environment=environment,
            absolute_deadline=time.monotonic() + timeout_seconds,
        )
        stdout = launched.get("stdout_bytes", b"")
        stderr = launched.get("stderr_bytes", b"")
        raw_result = launched.get("output_bytes", b"{}") or b"{}"
        if not all(isinstance(value, bytes) for value in (stdout, stderr, raw_result)):
            raise ValueError("comparison reviewer streams are unavailable")
        result, _result_redactions = _normalize_reviewer_stream(
            raw_result,
            command=command,
            schema_path=schema,
            output_path=result_path,
            environment=environment,
        )
        stream = parse_codex_jsonl_evidence(stdout)
        usage = {
            name: int(stream[name]) if stream["usage_observed"] is True else 0
            for name in TOKEN_FIELDS
        }
        references = {
            "result": _store(
                root=output, arm="ordinary", case_id=str(case["case_id"]),
                name="result.json", data=result,
            ),
            "stdout": _store(
                root=output, arm="ordinary", case_id=str(case["case_id"]),
                name="stdout.jsonl", data=stdout,
            ),
            "stderr": _store(
                root=output, arm="ordinary", case_id=str(case["case_id"]),
                name="stderr.bin", data=stderr,
            ),
        }
        primitive = {"reviewer_observation": launched.get("observation")}
        execution = content_address(
            {
                "schema_version": "1.0.0",
                "case_id": case["case_id"],
                "case_sha256": sha256_bytes(canonical_bytes(dict(case))),
                "arm": "ordinary",
                "candidate_id": expected_candidate_id,
                "result_sha256": references["result"]["sha256"],
                "stdout_sha256": references["stdout"]["sha256"],
                "stderr_sha256": references["stderr"]["sha256"],
                "execution_valid": launched.get("execution_valid") is True,
                "usage_observed": stream["usage_observed"] is True,
                **usage,
                "elapsed_ms": launched.get("latency_ms", 0),
                "primitive": primitive,
            },
            "execution_id",
        )
        references["execution"] = _store(
            root=output, arm="ordinary", case_id=str(case["case_id"]),
            name="execution.json", data=canonical_bytes(execution),
        )
        return reconstruct_task(
            arm="ordinary",
            case=case,
            artifacts=references,
            artifact_reader=lambda reference: _reader(output, reference),
        )


def _copy_governed_tasks(
    *,
    corpus: Mapping[str, Any],
    qualification_output: Path,
    output: Path,
    expected_identity: Mapping[str, Any],
) -> list[dict[str, Any]]:
    case_evidence = load_json(qualification_output / "conformance-cases.json")
    observations = case_evidence.get("observations")
    if not isinstance(observations, list) or len(observations) != len(corpus["cases"]):
        raise ValueError("governed comparison observations are incomplete")
    tasks: list[dict[str, Any]] = []
    for case, observation in zip(corpus["cases"], observations, strict=True):
        if observation.get("case_id") != case.get("case_id"):
            raise ValueError("governed comparison case order drifted")

        def source(reference: Mapping[str, str]) -> bytes:
            path = str(reference["path"])
            if not path.startswith("qualification/"):
                raise ValueError("governed qualification artifact path is invalid")
            data = read_bytes_once(
                qualification_output.joinpath("raw", *path[len("qualification/"):].split("/"))
            )
            if sha256_bytes(data) != reference.get("sha256"):
                raise ValueError("governed qualification artifact digest mismatch")
            return data

        source_execution = _json_object(source(observation["reviewer_execution"]))
        references = {
            "result": _store(
                root=output, arm="governed", case_id=str(case["case_id"]),
                name="result.json", data=source(observation["reviewer_output"]),
            ),
            "stdout": _store(
                root=output, arm="governed", case_id=str(case["case_id"]),
                name="stdout.jsonl", data=source(observation["stdout"]),
            ),
            "stderr": _store(
                root=output, arm="governed", case_id=str(case["case_id"]),
                name="stderr.bin", data=source(observation["stderr"]),
            ),
        }
        execution = content_address(
            {
                "schema_version": "1.0.0",
                "case_id": case["case_id"],
                "case_sha256": sha256_bytes(canonical_bytes(dict(case))),
                "arm": "governed",
                "result_sha256": references["result"]["sha256"],
                "stdout_sha256": references["stdout"]["sha256"],
                "stderr_sha256": references["stderr"]["sha256"],
                "execution_valid": source_execution.get("execution_valid") is True,
                "usage_observed": source_execution.get("usage_observed") is True,
                **{name: source_execution.get(name, 0) for name in TOKEN_FIELDS},
                "elapsed_ms": source_execution.get("latency_ms", 0),
                "primitive": {"reviewer_execution": source_execution},
            },
            "execution_id",
        )
        references["execution"] = _store(
            root=output, arm="governed", case_id=str(case["case_id"]),
            name="execution.json", data=canonical_bytes(execution),
        )
        tasks.append(
            reconstruct_task(
                arm="governed",
                case=case,
                artifacts=references,
                artifact_reader=lambda reference: _reader(output, reference),
                expected_identity=expected_identity,
            )
        )
    return tasks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--human-label-decision", type=Path, required=True)
    parser.add_argument("--prompt", type=Path, required=True)
    parser.add_argument("--governed-schema", type=Path, required=True)
    parser.add_argument("--ordinary-schema", type=Path, required=True)
    parser.add_argument("--corpus-schema", type=Path, required=True)
    parser.add_argument("--decision-schema", type=Path, required=True)
    parser.add_argument("--comparison-schema", type=Path, required=True)
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--expected-codex-version", required=True)
    parser.add_argument("--model", choices=[MODEL], required=True)
    parser.add_argument("--reasoning-effort", choices=[REASONING_EFFORT], required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--authority-repository", required=True)
    parser.add_argument("--authority-ref", choices=["refs/heads/governance-authority"], required=True)
    parser.add_argument("--authority-sha", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-attempt", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=900)
    parser.add_argument("--max-output-bytes", type=int, default=4_000_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        args.timeout_seconds <= 0
        or args.max_output_bytes < 1
        or args.workflow_attempt < 1
        or re.fullmatch(r"[0-9a-f]{40}", args.authority_sha) is None
        or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", args.actor) is None
    ):
        raise ValueError("comparison execution inputs are invalid")
    corpus = load_and_validate_once(args.corpus, args.corpus_schema)
    decision = load_and_validate_once(args.human_label_decision, args.decision_schema)
    evaluated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    validate_comparison_inputs(
        corpus,
        decision,
        actor=args.actor,
        authority_repository=args.authority_repository,
        authority_ref=args.authority_ref,
        evaluated_at=evaluated_at,
    )
    authentication = observe_codex_authentication(args.codex)
    cli_version = observe_codex_cli_version(args.codex)
    if cli_version != args.expected_codex_version:
        raise ValueError("Codex CLI version is not the protected comparison identity")
    identity = {
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "governed_profile": "STANDARD",
        "codex_cli_version": cli_version,
        "authentication": authentication,
        "governed_prompt_sha256": sha256_bytes(read_bytes_once(args.prompt)),
        "governed_schema_sha256": sha256_bytes(read_bytes_once(args.governed_schema)),
        "ordinary_schema_sha256": sha256_bytes(read_bytes_once(args.ordinary_schema)),
        "ordinary_prompt_version": "1.0.0",
        "same_case_bytes": True,
        "labels_excluded_from_prompts": True,
        "execution_controls": "matched_sanitized_read_only",
        "authority_repository": args.authority_repository,
        "authority_ref": args.authority_ref,
        "authority_sha": args.authority_sha,
        "workflow_run_id": args.workflow_run_id,
        "workflow_attempt": args.workflow_attempt,
    }
    qualification = _qualification_module()
    governed_output = args.output / "governed-qualification"
    qualification._run_mode(
        mode="conformance",
        corpus=corpus,
        label_decision=decision,
        prompt_path=args.prompt,
        schema_path=args.governed_schema,
        codex=args.codex,
        cli_version=cli_version,
        authentication=authentication,
        timeout_seconds=args.timeout_seconds,
        max_output_bytes=args.max_output_bytes,
        workflow_run_id=args.workflow_run_id,
        workflow_attempt=args.workflow_attempt,
        output=governed_output,
        requested_profile="STANDARD",
    )
    governed_tasks = _copy_governed_tasks(
        corpus=corpus,
        qualification_output=governed_output,
        output=args.output,
        expected_identity=identity,
    )
    ordinary_tasks = [
        _run_ordinary_case(
            case=case,
            codex=args.codex,
            authentication=authentication,
            schema_path=args.ordinary_schema,
            timeout_seconds=args.timeout_seconds,
            max_output_bytes=args.max_output_bytes,
            output=args.output,
        )
        for case in corpus["cases"]
    ]
    document = build_comparison_document(
        corpus=corpus,
        decision=decision,
        identity=identity,
        governed_tasks=governed_tasks,
        ordinary_tasks=ordinary_tasks,
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    if not comparison_document_valid(
        document,
        corpus=corpus,
        decision=decision,
        expected_identity=identity,
        artifact_reader=lambda reference: _reader(args.output, reference),
    ):
        raise ValueError("paired comparison evidence does not reconstruct")
    comparison_schema = load_json(args.comparison_schema)
    if not isinstance(comparison_schema, dict):
        raise ValueError("paired comparison schema is malformed")
    schema_errors = validate_instance(document, comparison_schema)
    if schema_errors:
        raise ValueError("paired comparison schema validation failed: " + "; ".join(schema_errors))
    _write_bytes_once(args.output / "comparison.json", canonical_bytes(document))
    if any(
        task["unknown"] is True
        for arm in document["arms"].values()
        for task in arm["tasks"]
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
