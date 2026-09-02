"""Fresh, schema-bound, read-only Codex reviewer process boundary."""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codex_governance.artifacts import read_bounded_repository_file
from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    normalize_repo_path,
    require_sha256,
    sha256_bytes,
    sha256_canonical,
)
from codex_governance.domain.model import ReviewerVerdict
from codex_governance.gate import (
    _BoundedCapture,
    _close_process_streams,
    _posix_process_group_exited,
    _terminate_process_tree,
)
from codex_governance.portability import SHAPED_VALUE_PATTERNS
from codex_governance.schema import (
    SchemaValidationError,
    parse_json_bytes,
    validate_loaded_instance,
)


PERMITTED_REVIEWER_INPUTS = frozenset(
    {
        "task_contract_path",
        "task_contract_sha256",
        "repository_id",
        "candidate_id",
        "candidate_path",
        "effective_policy_sha256",
        "effective_policy_path",
        "gate_manifest_path",
        "gate_manifest_sha256",
        "context_receipt_path",
        "context_receipt_sha256",
        "context_sources_path",
        "context_sources_sha256",
        "context_projection_path",
        "context_projection_sha256",
        "context_qualification_path",
        "context_qualification_sha256",
        "context_qualification_id",
        "reviewer_qualification_path",
        "reviewer_qualification_sha256",
        "reviewer_qualification_id",
        "provenance_manifest_path",
        "provenance_manifest_sha256",
        "evidence_root",
        "reviewer_prompt_sha256",
        "review_mode",
        "risk_assessment_path",
        "risk_assessment_sha256",
        "review_charter_path",
        "review_charter_sha256",
    }
)

REQUIRED_REVIEWER_INPUTS = frozenset(
    {
        "task_contract_path", "task_contract_sha256", "repository_id",
        "candidate_id", "candidate_path", "effective_policy_path",
        "effective_policy_sha256", "gate_manifest_path", "gate_manifest_sha256",
        "context_receipt_path", "context_receipt_sha256",
        "context_sources_path", "context_sources_sha256",
        "context_projection_path", "context_projection_sha256",
        "context_qualification_path", "context_qualification_sha256",
        "context_qualification_id",
        "reviewer_qualification_path", "reviewer_qualification_sha256",
        "reviewer_qualification_id", "reviewer_prompt_sha256", "review_mode",
    }
)
REQUIRED_RAPID_REVIEW_INPUTS = frozenset(
    {
        "risk_assessment_path", "risk_assessment_sha256",
        "review_charter_path", "review_charter_sha256",
    }
)

REVIEWER_TOOL_ENVIRONMENT_KEYS = (
    "PATH", "HOME", "ZDOTDIR", "XDG_CONFIG_HOME", "LANG", "LC_ALL",
    "TMPDIR", "TMP", "TEMP", "SystemRoot", "SYSTEMROOT",
)


def _runtime_prefix(executable: Path) -> Path:
    parent = executable.parent
    return parent.parent if parent.name.lower() in {"bin", "scripts"} else parent


def resolve_reviewer_runtime_read_roots(
    codex_executable: str, *, environment: Mapping[str, str] | None = None
) -> tuple[Path, ...]:
    """Resolve bounded installation roots needed by Codex sandbox re-execution."""
    source = environment if environment is not None else os.environ
    search_path = source.get("PATH") if isinstance(source.get("PATH"), str) else None
    executable = shutil.which(codex_executable, path=search_path)
    has_separator = os.sep in codex_executable or (
        os.altsep is not None and os.altsep in codex_executable
    )
    if executable is None and has_separator:
        executable = codex_executable
    if executable is None:
        raise ValueError("Codex executable is unavailable on the sanitized PATH")

    executable_paths = {Path(executable).resolve()}
    node = shutil.which("node", path=search_path)
    if node is not None:
        executable_paths.add(Path(node).resolve())

    home_value = source.get("HOME") or source.get("USERPROFILE")
    home = Path(home_value).resolve() if isinstance(home_value, str) and home_value else None
    roots = []
    for executable_path in executable_paths:
        candidate = _runtime_prefix(executable_path)
        if home is not None and candidate == home:
            candidate = executable_path.parent
        if not candidate.is_absolute() or candidate == Path(candidate.anchor):
            raise ValueError("reviewer runtime read root is unsafe")
        roots.append(candidate)
    return tuple(sorted(set(roots), key=os.fspath))


def build_reviewer_permission_profile(runtime_read_roots: Sequence[Path]) -> str:
    """Build a path-safe inline profile without persisting host path values."""
    entries = [
        '":root"="deny"',
        '":minimal"="read"',
        '":workspace_roots"={"."="read"}',
    ]
    for root in sorted({Path(path) for path in runtime_read_roots}, key=os.fspath):
        if not root.is_absolute() or root == Path(root.anchor):
            raise ValueError("reviewer runtime read root is unsafe")
        entries.append(f'{json.dumps(os.fspath(root))}="read"')
    return (
        'permissions={governed_reviewer={extends=":read-only",filesystem={'
        + ",".join(entries)
        + "},network={enabled=false}}}"
    )
REVIEWER_TOOL_ENVIRONMENT_POLICY = (
    'shell_environment_policy={inherit="all",ignore_default_excludes=false,'
    'include_only=['
    + ",".join(json.dumps(key) for key in REVIEWER_TOOL_ENVIRONMENT_KEYS)
    + '],set={HOME=".reviewer-home",ZDOTDIR=".reviewer-home",'
    'XDG_CONFIG_HOME=".reviewer-home",PYTHONDONTWRITEBYTECODE="1"}}'
)


def build_reviewer_command(
    *,
    codex_executable: str,
    model: str,
    schema_path: Path,
    output_path: Path,
    review_root: Path,
    reasoning_effort: str = "xhigh",
) -> list[str]:
    """Build a shell-free strict reviewer argv for a sanitized harness root."""
    if not all(
        isinstance(value, str) and value
        for value in (codex_executable, model, reasoning_effort)
    ):
        raise ValueError("reviewer executable, model and effort are required")
    permission_profile = build_reviewer_permission_profile(
        resolve_reviewer_runtime_read_roots(codex_executable)
    )
    return [
        codex_executable,
        "exec",
        "--ephemeral",
        "--json",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--model",
        model,
        "--config",
        'default_permissions="governed_reviewer"',
        "--config",
        permission_profile,
        "--config",
        'approval_policy="never"',
        "--config",
        REVIEWER_TOOL_ENVIRONMENT_POLICY,
        "--config",
        f'model_reasoning_effort="{reasoning_effort}"',
        "--config",
        "features.hooks=false",
        "--config",
        "agents.enabled=false",
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(output_path),
        "--cd",
        str(review_root),
        "-",
    ]


def build_reviewer_stdin(
    *, fixed_prompt: str, permitted_inputs: Mapping[str, Any]
) -> str:
    """Serialize only the reviewer input allowlist after the fixed prompt."""
    if not isinstance(fixed_prompt, str) or not fixed_prompt.strip():
        raise ValueError("fixed reviewer prompt is required")
    unexpected = set(permitted_inputs) - PERMITTED_REVIEWER_INPUTS
    if unexpected:
        raise ValueError(
            "reviewer input contains forbidden keys: " + ", ".join(sorted(unexpected))
        )
    missing = REQUIRED_REVIEWER_INPUTS - set(permitted_inputs)
    if permitted_inputs.get("review_mode") == "rapid_review":
        missing |= REQUIRED_RAPID_REVIEW_INPUTS - set(permitted_inputs)
    if missing:
        raise ValueError(
            "reviewer input is missing required keys: " + ", ".join(sorted(missing))
        )
    for key, value in permitted_inputs.items():
        if key.endswith("sha256") or key == "candidate_id":
            require_sha256(value, name=key)
        elif key == "review_mode" and value not in {"conformance", "rapid_review"}:
            raise ValueError("review_mode must be conformance or rapid_review")
        elif not isinstance(value, str) or not value:
            raise ValueError(f"reviewer input {key} must be a non-empty string")
    serialized = canonical_json_bytes(dict(permitted_inputs)).decode("utf-8")
    return fixed_prompt.rstrip() + "\n\nPERMITTED_INPUTS " + serialized + "\n"


def classify_reviewer_execution(
    *,
    return_code: int | None,
    timed_out: bool,
    observation_complete: bool,
    output_present: bool,
    output_valid: bool,
    candidate_matches: bool,
    output_truncated: bool,
    declared_verdict: str | None,
) -> ReviewerVerdict:
    """Classify reviewer process evidence."""
    if (
        return_code != 0
        or timed_out
        or not observation_complete
        or not output_present
        or not output_valid
        or not candidate_matches
        or output_truncated
    ):
        return ReviewerVerdict.UNKNOWN
    try:
        return ReviewerVerdict(declared_verdict)
    except (TypeError, ValueError):
        return ReviewerVerdict.UNKNOWN


def sanitized_invocation_descriptor(
    *, model: str, reasoning_effort: str, prompt_sha256: str
) -> dict[str, Any]:
    """Describe a launch without paths, environment values, or credentials."""
    return {
        "process": "codex exec",
        "fresh": True,
        "ephemeral": True,
        "ignore_user_config": True,
        "ignore_rules": True,
        "sandbox": "custom-read-only",
        "filesystem_read_scope": "sanitized-workspace-and-runtime-minimum",
        "host_root_readable": False,
        "tool_network_enabled": False,
        "tool_environment": "fixed-non-secret-key-allowlist",
        "approval_policy": "never",
        "hooks_enabled": False,
        "subagents_enabled": False,
        "schema_bound": True,
        "json_events": True,
        "author_context_available": False,
        "persisted_reasoning_available": False,
        "candidate_configuration_active": False,
        "connectors_available": False,
        "unrelated_mcp_available": False,
        "model": model,
        "reasoning_effort": reasoning_effort,
        "reviewer_prompt_sha256": require_sha256(prompt_sha256),
        "environment_values_recorded": False,
    }


REVIEWER_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT",
        "CODEX_HOME",
        "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR", "TMP", "TEMP",
        "LANG", "LC_ALL",
    }
)


def build_reviewer_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Return only runtime/authentication variables needed by a fresh Codex."""
    return {
        key: value
        for key, value in source.items()
        if key in REVIEWER_ENVIRONMENT_ALLOWLIST and isinstance(value, str)
    }


def _normalize_reviewer_stream(
    data: bytes,
    *,
    command: Sequence[str],
    schema_path: Path,
    output_path: Path,
    environment: Mapping[str, str],
) -> tuple[bytes, list[str]]:
    """Remove supervisor-only runtime values before hashing retained evidence."""
    replacements: set[bytes] = set()

    def remember(value: str | os.PathLike[str]) -> None:
        encoded = os.fsencode(value)
        if encoded:
            replacements.add(encoded)

    for path in (
        schema_path,
        schema_path.parent,
        output_path,
        output_path.parent,
        Path(__file__).resolve().parent,
    ):
        remember(path)
    for argument in command:
        if isinstance(argument, str) and os.path.isabs(argument):
            remember(argument)
    for key, value in environment.items():
        if key in {"LANG", "LC_ALL"} or not value:
            continue
        remember(value)
        if key == "PATH":
            for entry in value.split(os.pathsep):
                if entry and os.path.isabs(entry):
                    remember(entry)
    try:
        remember(socket.gethostname())
    except OSError:
        pass

    normalized = data
    for value in sorted(replacements, key=len, reverse=True):
        normalized = normalized.replace(value, b"<REVIEWER_RUNTIME>")
    redactions: list[str] = []
    for pattern in REVIEWER_AMBIGUOUS_PATTERNS:
        def replace(match: re.Match[bytes]) -> bytes:
            redactions.append("ambiguous_machine_or_credential_value")
            return b"<REVIEWER_REDACTED>"

        normalized = pattern.sub(replace, normalized)
    return normalized, sorted(set(redactions))


def _normalize_reviewer_jsonl(
    data: bytes,
    *,
    command: Sequence[str],
    schema_path: Path,
    output_path: Path,
    environment: Mapping[str, str],
) -> tuple[bytes, list[str]]:
    """Project transient command material and normalize retained JSONL facts."""
    redactions: list[str] = []

    def normalize_value(value: Any) -> Any:
        if isinstance(value, str):
            normalized, found = _normalize_reviewer_stream(
                value.encode("utf-8"),
                command=command,
                schema_path=schema_path,
                output_path=output_path,
                environment=environment,
            )
            redactions.extend(found)
            return normalized.decode("utf-8")
        if isinstance(value, list):
            return [normalize_value(item) for item in value]
        if isinstance(value, dict):
            return {key: normalize_value(item) for key, item in value.items()}
        return value

    normalized_lines: list[bytes] = []
    try:
        for raw in data.splitlines():
            if not raw.strip():
                continue
            event = json.loads(raw)
            item = event.get("item") if isinstance(event, Mapping) else None
            if isinstance(item, Mapping) and item.get("type") == "command_execution":
                event = dict(event)
                projected_item = dict(item)
                if "command" in projected_item:
                    projected_item["command"] = "<REVIEWER_COMMAND_OMITTED>"
                if "aggregated_output" in projected_item:
                    projected_item["aggregated_output"] = (
                        "<REVIEWER_COMMAND_OUTPUT_OMITTED>"
                    )
                event["item"] = projected_item
            normalized_lines.append(
                canonical_json_bytes(normalize_value(event))
            )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return _normalize_reviewer_stream(
            data,
            command=command,
            schema_path=schema_path,
            output_path=output_path,
            environment=environment,
        )
    normalized = b"\n".join(normalized_lines)
    if data.endswith((b"\n", b"\r")) and normalized_lines:
        normalized += b"\n"
    return normalized, sorted(set(redactions))


def observe_codex_cli_version(
    executable: str, *, environment: Mapping[str, str] | None = None
) -> str:
    """Observe a portable Codex CLI version without persisting its host path."""
    try:
        completed = subprocess.run(
            [executable, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=build_reviewer_environment(environment or os.environ),
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Codex CLI version is unavailable") from exc
    value = completed.stdout.decode("utf-8", "replace").strip()
    if (
        completed.returncode != 0
        or len(value) > 96
        or re.fullmatch(r"codex-cli [0-9][0-9A-Za-z._+-]{0,63}", value) is None
    ):
        raise RuntimeError("Codex CLI version is unavailable")
    return value


def parse_codex_jsonl_evidence(data: bytes) -> dict[str, Any]:
    """Parse bounded Codex JSONL into independently checkable terminal facts."""
    usage = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }
    observed = False
    thread_id: str | None = None
    final_message: str | None = None
    valid = True
    try:
        for raw in data.splitlines():
            if not raw.strip():
                continue
            event = json.loads(raw)
            if not isinstance(event, Mapping) or not isinstance(event.get("type"), str):
                raise ValueError("invalid Codex JSONL event")
            if event["type"] == "thread.started" and isinstance(event.get("thread_id"), str):
                thread_id = event["thread_id"]
            if event["type"] == "item.completed":
                item = event.get("item")
                if (
                    isinstance(item, Mapping)
                    and item.get("type") == "agent_message"
                    and isinstance(item.get("text"), str)
                ):
                    final_message = item["text"]
            if event["type"] == "turn.completed" and isinstance(event.get("usage"), Mapping):
                candidate = {
                    key: event["usage"].get(key, 0)
                    for key in usage
                }
                if any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                    for value in candidate.values()
                ):
                    raise ValueError("invalid Codex usage event")
                usage = candidate
                observed = True
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        valid = False
        observed = False
        usage = {key: 0 for key in usage}
        thread_id = None
        final_message = None
    return {
        "jsonl_valid": valid,
        "usage_observed": observed,
        "thread_id": thread_id,
        "final_message": final_message,
        **usage,
    }


def _parse_codex_jsonl(data: bytes) -> dict[str, Any]:
    parsed = parse_codex_jsonl_evidence(data)
    return {
        key: parsed[key]
        for key in (
            "usage_observed",
            "thread_id",
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        )
    }


REVIEWER_AMBIGUOUS_PATTERNS = tuple(
    pattern for pattern, _category in SHAPED_VALUE_PATTERNS
)
def reviewer_stream_is_portable(data: bytes) -> bool:
    """Reject retained secrets, machine endpoints, and absolute host locations."""
    try:
        data.decode("utf-8")
    except UnicodeError:
        return False
    return b"\x00" not in data and not any(
        pattern.search(data) for pattern in REVIEWER_AMBIGUOUS_PATTERNS
    )


def reviewer_observation_facts(observation: Mapping[str, Any]) -> dict[str, bool]:
    """Derive reviewer completion facts from primitive supervisor observations."""
    try:
        stdin = observation["stdin"]
        stdout = observation["stdout"]
        stderr = observation["stderr"]
        supervisor = observation["supervisor"]
        output = observation["output"]
        stdin_complete = bool(
            stdin["complete"] is True
            and stdin["bytes_expected"] == stdin["bytes_written"]
        )
        captures_complete = bool(
            all(
                stream["thread_completed"] is True
                and stream["eof"] is True
                and stream["read_failed"] is False
                and stream["truncated"] is False
                and stream["bytes_observed"] == stream["bytes_captured"]
                for stream in (stdout, stderr)
            )
        )
        streams_unambiguous = bool(
            all(
                stream.get("ambiguous_redaction") is False
                for stream in (stdout, stderr)
            )
        )
        supervisor_complete = bool(
            supervisor["boundary_available"] is True
            and supervisor["cleanup_complete"] is True
            and supervisor["descendants_observed"] is False
        )
        process_cleanup_complete = bool(
            observation["process_cleanup_complete"] is True
            and supervisor_complete
        )
        observation_complete = bool(
            observation["parent_exit_observed"] is True
            and observation["timed_out"] is False
            and stdin_complete
            and captures_complete
            and streams_unambiguous
            and process_cleanup_complete
        )
        output_valid = bool(
            output["present"] is True
            and output["regular"] is True
            and output["schema_valid"] is True
        )
        bindings_match = bool(
            output["candidate_matches"] is True
            and output["bindings_match"] is True
            and observation["candidate_unchanged"] is True
        )
        execution_valid = bool(
            observation["return_code"] == 0
            and observation_complete
            and output_valid
            and bindings_match
            and output["truncated"] is False
        )
    except (KeyError, TypeError):
        stdin_complete = captures_complete = process_cleanup_complete = False
        observation_complete = output_valid = bindings_match = execution_valid = False
    return {
        "stdin_delivery_complete": stdin_complete,
        "capture_threads_completed": captures_complete,
        "process_cleanup_complete": process_cleanup_complete,
        "observation_complete": observation_complete,
        "output_valid": output_valid,
        "bindings_match": bindings_match,
        "output_truncated": bool(
            (
                isinstance(observation.get("output"), Mapping)
                and observation["output"].get("truncated") is True
            )
            or (
                isinstance(observation.get("stdout"), Mapping)
                and observation["stdout"].get("truncated") is True
            )
            or (
                isinstance(observation.get("stderr"), Mapping)
                and observation["stderr"].get("truncated") is True
            )
        ),
        "execution_valid": execution_valid,
    }


def build_reviewer_execution_statement(
    *,
    repository_id: str,
    task_contract_sha256: str,
    effective_policy_sha256: str,
    candidate_id: str,
    review_mode: str,
    output_schema_sha256: str,
    launcher_sha256: str,
    qualification_id: str,
    model: str,
    reasoning_effort: str,
    context_source_bundle_sha256: str,
    context_projection_sha256: str,
    context_qualification_id: str,
    input_context_receipt_sha256: str,
    context_execution_receipt_sha256: str,
    workflow_system: str,
    run_id: str,
    attempt: int,
    timeout_seconds: float,
    max_output_bytes: int,
    codex_cli_version: str,
    stdout_reference: Mapping[str, str],
    stderr_reference: Mapping[str, str],
    execution: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a content-addressed statement for one fresh reviewer process."""
    if review_mode not in {"conformance", "rapid_review"}:
        raise ValueError("unknown review mode")
    if (
        not isinstance(workflow_system, str)
        or not workflow_system
        or not isinstance(run_id, str)
        or not run_id
        or not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
        or not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or max_output_bytes < 1
        or not isinstance(codex_cli_version, str)
        or not codex_cli_version
    ):
        raise ValueError("reviewer workflow, tool and limit evidence is incomplete")
    descriptor = sanitized_invocation_descriptor(
        model=model,
        reasoning_effort=reasoning_effort,
        prompt_sha256=execution.get("reviewer_prompt_sha256"),
    )
    observation = execution.get("observation")
    if not isinstance(observation, Mapping):
        raise ValueError("reviewer primitive observation is unavailable")
    facts = reviewer_observation_facts(observation)
    stream_references: dict[str, dict[str, str]] = {}
    for name, reference, expected_digest in (
        ("stdout", stdout_reference, execution.get("stdout_sha256")),
        ("stderr", stderr_reference, execution.get("stderr_sha256")),
    ):
        if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256"}:
            raise ValueError("reviewer stream reference is malformed")
        normalized = normalize_repo_path(reference["path"])
        digest = require_sha256(reference["sha256"])
        if digest != expected_digest:
            raise ValueError("reviewer stream reference digest mismatch")
        stream_references[name] = {"path": normalized, "sha256": digest}
    document = {
        "schema_version": "3.0.0",
        "repository_id": repository_id,
        "task_contract_sha256": require_sha256(task_contract_sha256),
        "effective_policy_sha256": require_sha256(effective_policy_sha256),
        "candidate_id": require_sha256(candidate_id, name="candidate_id"),
        "review_mode": review_mode,
        "prompt_sha256": require_sha256(execution.get("reviewer_prompt_sha256")),
        "output_schema_sha256": require_sha256(output_schema_sha256),
        "launcher_sha256": require_sha256(launcher_sha256),
        "qualification_id": require_sha256(qualification_id),
        "model": model,
        "reasoning_effort": reasoning_effort,
        "input_context_receipt_sha256": require_sha256(input_context_receipt_sha256),
        "context_execution_receipt_sha256": require_sha256(
            context_execution_receipt_sha256
        ),
        "reviewer_output_sha256": require_sha256(execution.get("output_sha256")),
        "candidate_before": require_sha256(execution.get("candidate_before")),
        "candidate_after": require_sha256(execution.get("candidate_after")),
        "observation": dict(observation),
        "invocation": descriptor,
        "argv_sha256": require_sha256(execution.get("argv_sha256")),
        "stdin_sha256": require_sha256(execution.get("stdin_sha256")),
        "codex_thread_id": (
            execution.get("thread_id")
            if isinstance(execution.get("thread_id"), str) and execution["thread_id"]
            else "unavailable"
        ),
        "workflow": {
            "system": workflow_system,
            "run_id": run_id,
            "attempt": attempt,
        },
        "limits": {
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
        },
        "tools": [{"name": "codex-cli", "version": codex_cli_version}],
        "materials": [
            {"name": "task-contract", "sha256": require_sha256(task_contract_sha256)},
            {"name": "effective-policy", "sha256": require_sha256(effective_policy_sha256)},
            {"name": "candidate", "sha256": require_sha256(candidate_id)},
            {"name": "reviewer-prompt", "sha256": require_sha256(execution.get("reviewer_prompt_sha256"))},
            {"name": "output-schema", "sha256": require_sha256(output_schema_sha256)},
            {"name": "launcher", "sha256": require_sha256(launcher_sha256)},
            {"name": "qualification", "sha256": require_sha256(qualification_id)},
            {"name": "context-source-bundle", "sha256": require_sha256(context_source_bundle_sha256)},
            {"name": "context-projection", "sha256": require_sha256(context_projection_sha256)},
            {"name": "context-qualification", "sha256": require_sha256(context_qualification_id)},
            {"name": "prepared-context", "sha256": require_sha256(input_context_receipt_sha256)},
            {"name": "post-run-context", "sha256": require_sha256(context_execution_receipt_sha256)},
        ],
        "environment_keys": list(execution.get("environment_keys", ())),
        "started_at": execution.get("started_at"),
        "ended_at": execution.get("ended_at"),
        "latency_ms": execution.get("latency_ms", 0),
        "return_code": observation.get("return_code", -1),
        "timed_out": observation.get("timed_out") is True,
        "stdin_delivery_complete": facts["stdin_delivery_complete"],
        "observation_complete": facts["observation_complete"],
        "capture_threads_completed": facts["capture_threads_completed"],
        "process_cleanup_complete": facts["process_cleanup_complete"],
        "execution_valid": facts["execution_valid"],
        "output_valid": facts["output_valid"],
        "bindings_match": facts["bindings_match"],
        "output_truncated": facts["output_truncated"],
        "stdout_sha256": require_sha256(execution.get("stdout_sha256")),
        "stderr_sha256": require_sha256(execution.get("stderr_sha256")),
        "stdout": stream_references["stdout"],
        "stderr": stream_references["stderr"],
        "usage_observed": execution.get("usage_observed") is True,
        "input_tokens": execution.get("input_tokens", 0),
        "cached_input_tokens": execution.get("cached_input_tokens", 0),
        "output_tokens": execution.get("output_tokens", 0),
        "reasoning_output_tokens": execution.get("reasoning_output_tokens", 0),
        "limitations": list(execution.get("limitations", ())),
    }
    return content_address(document, "execution_id")


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("reviewer absolute deadline expired")
    return remaining


def _run_git(
    repository: Path, *args: str, deadline: float | None = None
) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repository), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_remaining(deadline),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("review snapshot Git operation timed out") from exc
    if completed.returncode != 0:
        raise RuntimeError(
            "review snapshot Git operation failed: "
            + completed.stderr.decode("utf-8", "replace")[:300]
        )
    return completed.stdout


def _remove_scoped_tree(path: Path, *, boundary: Path) -> None:
    """Remove only a freshly-created harness subtree, never a broad target."""
    path.relative_to(boundary)
    if path.is_symlink() or path.is_file():
        path.unlink()
        return
    if path.is_dir():
        for child in path.iterdir():
            _remove_scoped_tree(child, boundary=boundary)
        path.rmdir()


def _candidate_paths(
    repository: Path,
    *,
    evidence_root: str | None = None,
    deadline: float | None = None,
) -> list[str]:
    output = _run_git(
        repository,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        deadline=deadline,
    )
    paths: list[str] = []
    for raw in output.split(b"\x00"):
        if not raw:
            continue
        try:
            path = normalize_repo_path(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError("review snapshot paths must be valid UTF-8") from exc
        if evidence_root is None or (
            path != evidence_root and not path.startswith(evidence_root + "/")
        ):
            paths.append(path)
    return sorted(set(paths))


def _copy_entry(
    source: Path, destination: Path, *, deadline: float | None = None
) -> None:
    _remaining(deadline)
    info = source.lstat()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if stat.S_ISLNK(info.st_mode):
        if destination.exists() or destination.is_symlink():
            _remove_scoped_tree(destination, boundary=destination.parent)
        destination.symlink_to(os.readlink(source))
    elif stat.S_ISREG(info.st_mode):
        shutil.copyfile(source, destination, follow_symlinks=False)
        destination.chmod(0o555 if info.st_mode & 0o111 else 0o444)
    elif stat.S_ISDIR(info.st_mode):
        # A Git submodule entry is represented as a directory. Copy only its
        # tracked/non-ignored candidate files, never its machine-specific .git.
        destination.mkdir(parents=True, exist_ok=True)
        for nested in _candidate_paths(source, deadline=deadline):
            nested_source = source.joinpath(*nested.split("/"))
            if nested_source.exists() or nested_source.is_symlink():
                _copy_entry(
                    nested_source,
                    destination.joinpath(*nested.split("/")),
                    deadline=deadline,
                )
    else:
        raise ValueError("unsupported candidate file type in reviewer snapshot")


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        info = path.stat()
        if path.is_dir():
            path.chmod(0o555)
        else:
            path.chmod(0o555 if info.st_mode & 0o111 else 0o444)
    root.chmod(0o555)


REVIEWER_LAUNCHER_FILES = (
    "__init__.py",
    "__main__.py",
    "adapters/__init__.py",
    "admission.py",
    "artifacts.py",
    "assurance.py",
    "attestation.py",
    "authority.py",
    "canonical.py",
    "candidate.py",
    "cli.py",
    "configuration.py",
    "context.py",
    "domain/__init__.py",
    "domain/model.py",
    "domain/policy.py",
    "evidence.py",
    "gate.py",
    "governance.py",
    "hook.py",
    "lifecycle.py",
    "locking.py",
    "locators.py",
    "mutation.py",
    "mutation_runner.py",
    "portability.py",
    "profiles.py",
    "qualification.py",
    "rapid_review.py",
    "reviewer.py",
    "reviewer_namespace.py",
    "reviewer_signal_guard.py",
    "reviewer_supervisor.py",
    "rollback.py",
    "rst_operations.py",
    "sandbox.py",
    "schema.py",
)


def _stop_reviewer_supervisor(
    process: subprocess.Popen[bytes], *, deadline: float
) -> bool:
    """Ask the dedicated subreaper to drain descendants before forced exit."""
    def reap_after_deadline() -> None:
        try:
            process.wait()
        except OSError:
            pass

    def retain_until_reaped() -> None:
        if process.poll() is None:
            import threading

            threading.Thread(target=reap_after_deadline, daemon=True).start()

    try:
        if process.poll() is None:
            process.terminate()
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            if process.poll() is None:
                process.kill()
                retain_until_reaped()
            return process.poll() is not None
        process.wait(timeout=remaining)
        return True
    except OSError:
        return False
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            remaining = max(0.0, deadline - time.monotonic())
            if remaining > 0:
                process.wait(timeout=remaining)
        except (OSError, subprocess.TimeoutExpired):
            pass
        retain_until_reaped()
        return False


def reviewer_launcher_sha256(package_root: Path | None = None) -> str:
    """Identify the full import-time Python orchestration boundary."""
    root = package_root or Path(__file__).resolve().parent
    closure = []
    for relative in REVIEWER_LAUNCHER_FILES:
        path = root.joinpath(*relative.split("/"))
        closure.append({"path": relative, "sha256": sha256_bytes(path.read_bytes())})
    return sha256_canonical(closure)


def _validate_snapshot_symlinks(snapshot: Path, candidate_paths: Sequence[str]) -> None:
    root = snapshot.resolve(strict=True)
    for relative in candidate_paths:
        path = snapshot.joinpath(*relative.split("/"))
        if not path.is_symlink():
            continue
        try:
            path.resolve(strict=False).relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError("review snapshot contains an escaping symlink") from exc


def _materialize_permitted_evidence(
    *,
    candidate_repository: Path,
    harness: Path,
    permitted_inputs: Mapping[str, Any],
    evidence_root: str,
    prepared_evidence: Mapping[str, bytes] | None = None,
    max_files: int = 512,
    max_total_bytes: int = 64_000_000,
) -> None:
    normalized_evidence_root = normalize_repo_path(evidence_root)
    path_keys = sorted(
        key
        for key in permitted_inputs
        if key.endswith("_path") and key != "candidate_path"
    )
    if len(path_keys) > max_files:
        raise ValueError("too many reviewer evidence files")
    total = 0
    destinations: dict[str, str] = {}
    pending_documents: list[tuple[str, bytes]] = []

    def materialize(relative: str, expected: str, *, direct: bool) -> None:
        nonlocal total
        normalized = normalize_repo_path(relative)
        inside_evidence = (
            normalized == normalized_evidence_root
            or normalized.startswith(normalized_evidence_root + "/")
        )
        if not inside_evidence:
            if direct:
                raise ValueError(
                    "review evidence paths must be beneath the protected evidence root"
                )
            return
        expected_digest = require_sha256(expected, name="review evidence digest")
        previous = destinations.get(normalized)
        if previous is not None:
            if previous != expected_digest:
                raise ValueError("conflicting reviewer evidence reference")
            return
        if len(destinations) >= max_files:
            raise ValueError("too many reviewer evidence files")
        if prepared_evidence is not None and normalized in prepared_evidence:
            data = bytes(prepared_evidence[normalized])
        elif prepared_evidence is not None and direct:
            raise ValueError("validated reviewer evidence bytes are unavailable")
        else:
            data = read_bounded_repository_file(
                candidate_repository, normalized, max_bytes=max_total_bytes
            )
        if sha256_bytes(data) != expected_digest:
            raise ValueError("review evidence digest mismatch")
        total += len(data)
        if total > max_total_bytes:
            raise ValueError("review evidence byte budget exceeded")
        destination = harness.joinpath(*normalized.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o444)
        destinations[normalized] = expected_digest
        pending_documents.append((normalized, data))

    for key in path_keys:
        relative = normalize_repo_path(permitted_inputs[key])
        digest_key = key.removesuffix("_path") + "_sha256"
        materialize(relative, permitted_inputs.get(digest_key), direct=True)

    inspected = 0
    while inspected < len(pending_documents):
        document_path, data = pending_documents[inspected]
        inspected += 1
        try:
            document = json.loads(data)
        except (UnicodeDecodeError, ValueError):
            continue
        if (
            isinstance(document, Mapping)
            and isinstance(document.get("sandbox_capability_sha256"), str)
            and document_path.endswith("/result.json")
        ):
            capability_path = (
                Path(document_path).parent / "sandbox-capability.json"
            ).as_posix()
            materialize(
                capability_path,
                document["sandbox_capability_sha256"],
                direct=False,
            )

        def references(value: Any) -> list[tuple[str, str]]:
            found: list[tuple[str, str]] = []
            if isinstance(value, Mapping):
                digest = value.get("sha256")
                for field in ("path", "reference"):
                    relative = value.get(field)
                    if isinstance(relative, str) and isinstance(digest, str):
                        found.append((relative, digest))
                for nested in value.values():
                    found.extend(references(nested))
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                for nested in value:
                    found.extend(references(nested))
            return found

        for relative, expected in references(document):
            materialize(relative, expected, direct=False)
    evidence = harness.joinpath(*normalized_evidence_root.split("/"))
    if evidence.exists():
        for directory in sorted(
            (item for item in evidence.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        evidence.chmod(0o555)


def prepare_sanitized_harness(
    *,
    candidate_repository: Path,
    harness_root: Path,
    fixed_prompt_path: Path,
    output_schema_path: Path,
    permitted_inputs: Mapping[str, Any],
    expected_candidate: Mapping[str, Any],
    evidence_root: str = "evidence",
    prepared_evidence: Mapping[str, bytes] | None = None,
    fixed_prompt_bytes: bytes | None = None,
    output_schema_bytes: bytes | None = None,
    deadline: float | None = None,
) -> dict[str, Path]:
    """Create an outer Git root with an immutable nested candidate snapshot."""
    candidate = candidate_repository.resolve()
    normalized_evidence_root = normalize_repo_path(evidence_root)
    if expected_candidate.get("submodules"):
        raise ValueError(
            "reviewer snapshots with submodules require immutable recursive materialization"
        )
    identity_arguments = {
        "repository_id": expected_candidate.get("repository_id"),
        "mode": expected_candidate.get("mode"),
        "base_commit": expected_candidate.get("base_commit"),
        "head_commit": expected_candidate.get("head_commit"),
        "effective_policy_sha256": expected_candidate.get(
            "effective_policy_sha256"
        ),
        "evidence_root": normalized_evidence_root,
    }
    _remaining(deadline)
    source_candidate = GitCliRepositoryAdapter(
        candidate, deadline=deadline
    ).identify(**identity_arguments)
    if source_candidate != dict(expected_candidate):
        raise ValueError("reviewer source does not match the expected candidate")
    if permitted_inputs.get("candidate_id") != expected_candidate.get("candidate_id"):
        raise ValueError("reviewer permitted candidate binding mismatch")
    paths = _candidate_paths(
        candidate,
        evidence_root=normalized_evidence_root,
        deadline=deadline,
    )
    harness = harness_root.resolve(strict=False)
    if harness == candidate:
        raise ValueError("review harness cannot be the candidate repository")
    if harness.exists() and any(harness.iterdir()):
        raise FileExistsError("review harness must be absent or empty")
    harness.mkdir(parents=True, exist_ok=True)
    snapshot = harness / "candidate"
    try:
        clone = subprocess.run(
            [
                "git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                os.fspath(candidate), os.fspath(snapshot),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_remaining(deadline),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("reviewer snapshot clone timed out") from exc
    if clone.returncode != 0:
        raise RuntimeError("unable to create reviewer candidate snapshot")
    _run_git(
        snapshot, "checkout", "--quiet", "--detach", "HEAD", deadline=deadline
    )
    _run_git(snapshot, "remote", "remove", "origin", deadline=deadline)
    logs = snapshot / ".git/logs"
    if logs.exists():
        _remove_scoped_tree(logs, boundary=snapshot)
    for relative in paths:
        source = candidate.joinpath(*relative.split("/"))
        destination = snapshot.joinpath(*relative.split("/"))
        if source.exists() or source.is_symlink():
            _copy_entry(source, destination, deadline=deadline)
        elif destination.exists() or destination.is_symlink():
            _remove_scoped_tree(destination, boundary=snapshot)
    _validate_snapshot_symlinks(snapshot, paths)
    copied_candidate = GitCliRepositoryAdapter(
        snapshot, deadline=deadline
    ).identify(**identity_arguments)
    if copied_candidate != dict(expected_candidate):
        raise ValueError("reviewer snapshot does not match the expected candidate")
    prompt = harness / "reviewer.prompt.md"
    schema = harness / "reviewer-output.schema.json"
    manifest = harness / "permitted-inputs.json"
    prompt.write_bytes(
        bytes(fixed_prompt_bytes)
        if fixed_prompt_bytes is not None
        else fixed_prompt_path.read_bytes()
    )
    schema.write_bytes(
        bytes(output_schema_bytes)
        if output_schema_bytes is not None
        else output_schema_path.read_bytes()
    )
    manifest.write_bytes(canonical_json_bytes(dict(permitted_inputs)))
    if sha256_bytes(prompt.read_bytes()) != require_sha256(
        permitted_inputs.get("reviewer_prompt_sha256"),
        name="reviewer_prompt_sha256",
    ):
        raise ValueError("reviewer prompt digest mismatch")
    _materialize_permitted_evidence(
        candidate_repository=candidate,
        harness=harness,
        permitted_inputs=permitted_inputs,
        evidence_root=evidence_root,
        prepared_evidence=prepared_evidence,
    )
    try:
        initialized = subprocess.run(
            [
                "git",
                "-c",
                "init.defaultBranch=review",
                "-C",
                os.fspath(harness),
                "init",
                "--quiet",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_remaining(deadline),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("reviewer harness initialization timed out") from exc
    if initialized.returncode != 0:
        raise RuntimeError("unable to initialize sanitized reviewer harness")
    _make_read_only(snapshot)
    for protected in (prompt, schema, manifest):
        protected.chmod(0o444)
    return {
        "root": harness,
        "candidate": snapshot,
        "prompt": prompt,
        "schema": schema,
        "permitted_inputs": manifest,
        "output": harness / "reviewer-result.json",
    }


class _ReviewerOutputReadError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        present: bool,
        regular: bool,
        truncated: bool = False,
    ) -> None:
        super().__init__(message)
        self.present = present
        self.regular = regular
        self.truncated = truncated


class _ReviewerOutputAuthority:
    """Retain and verify the directory authority for one reviewer output leaf."""

    def __init__(self, output_path: Path) -> None:
        if (
            os.name != "posix"
            or not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
        ):
            raise OSError("descriptor-bound reviewer output is unavailable")
        leaf = output_path.name
        if not leaf or normalize_repo_path(leaf) != leaf or "/" in leaf:
            raise ValueError("reviewer output must be a direct normalized leaf")
        parent = output_path.parent
        parent_before = parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_before.st_mode):
            raise ValueError("reviewer output parent must be a directory")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(parent, flags)
        try:
            parent_opened = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(parent_opened.st_mode)
                or (parent_before.st_dev, parent_before.st_ino)
                != (parent_opened.st_dev, parent_opened.st_ino)
            ):
                raise ValueError("reviewer output parent binding changed")
            try:
                os.stat(leaf, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError("stale output path exists")
        except Exception:
            os.close(descriptor)
            raise
        self.path = output_path
        self.parent = parent
        self.leaf = leaf
        self.descriptor = descriptor
        self.parent_identity = (parent_opened.st_dev, parent_opened.st_ino)

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def assert_parent_binding(self) -> None:
        try:
            observed = self.parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError("reviewer output parent binding changed") from exc
        if (
            not stat.S_ISDIR(observed.st_mode)
            or (observed.st_dev, observed.st_ino) != self.parent_identity
        ):
            raise ValueError("reviewer output parent binding changed")

    def read_once(self, max_bytes: int) -> bytes:
        """Open one bound regular leaf and retain its exact bytes once."""
        self.assert_parent_binding()
        try:
            entry_before = os.stat(
                self.leaf, dir_fd=self.descriptor, follow_symlinks=False
            )
        except FileNotFoundError as exc:
            raise _ReviewerOutputReadError(
                "reviewer output is absent", present=False, regular=False
            ) from exc
        if not stat.S_ISREG(entry_before.st_mode):
            raise _ReviewerOutputReadError(
                "reviewer output is not a regular file",
                present=True,
                regular=False,
            )
        if entry_before.st_size > max_bytes:
            raise _ReviewerOutputReadError(
                "reviewer output exceeds configured size bound",
                present=True,
                regular=True,
                truncated=True,
            )
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self.leaf, flags, dir_fd=self.descriptor)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (entry_before.st_dev, entry_before.st_ino)
            ):
                raise _ReviewerOutputReadError(
                    "reviewer output binding changed",
                    present=True,
                    regular=stat.S_ISREG(opened.st_mode),
                )
            chunks: list[bytes] = []
            observed_bytes = 0
            while observed_bytes <= max_bytes:
                chunk = os.read(
                    descriptor,
                    min(65_536, max_bytes + 1 - observed_bytes),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed_bytes += len(chunk)
            if observed_bytes > max_bytes:
                raise _ReviewerOutputReadError(
                    "reviewer output exceeds configured size bound",
                    present=True,
                    regular=True,
                    truncated=True,
                )
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            entry_after = os.stat(
                self.leaf, dir_fd=self.descriptor, follow_symlinks=False
            )
        except FileNotFoundError as exc:
            raise _ReviewerOutputReadError(
                "reviewer output binding changed", present=True, regular=True
            ) from exc
        identity_before = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        identity_after = (
            opened_after.st_dev,
            opened_after.st_ino,
            opened_after.st_size,
            opened_after.st_mtime_ns,
            opened_after.st_ctime_ns,
        )
        entry_identity = (
            entry_after.st_dev,
            entry_after.st_ino,
            entry_after.st_size,
            entry_after.st_mtime_ns,
            entry_after.st_ctime_ns,
        )
        data = b"".join(chunks)
        if (
            identity_before != identity_after
            or identity_after != entry_identity
            or len(data) != opened_after.st_size
        ):
            raise _ReviewerOutputReadError(
                "reviewer output binding changed", present=True, regular=True
            )
        self.assert_parent_binding()
        return data


def launch_reviewer(
    *,
    command: Sequence[str],
    stdin_text: str,
    schema_path: Path,
    output_path: Path,
    expected_candidate_id: str,
    candidate_supplier: Any,
    expected_bindings: Mapping[str, str] | None = None,
    review_mode: str = "conformance",
    timeout_seconds: float = 1800,
    max_output_bytes: int = 1_000_000,
    environment: Mapping[str, str] | None = None,
    absolute_deadline: float | None = None,
) -> dict[str, Any]:
    """Launch the fresh reviewer and validate its exact output and binding."""
    if review_mode not in {"conformance", "rapid_review"}:
        raise ValueError("review mode must be conformance or rapid_review")
    if timeout_seconds <= 0 or max_output_bytes < 1:
        raise ValueError("reviewer observation bounds must be positive")
    if not command or command[-1] != "-" or "resume" in command:
        raise ValueError("reviewer command must be a fresh stdin-driven exec")
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    started_monotonic = time.monotonic()
    deadline = (
        absolute_deadline
        if absolute_deadline is not None
        else started_monotonic + timeout_seconds
    )
    if deadline <= started_monotonic:
        return {
            "verdict": ReviewerVerdict.UNKNOWN,
            "reason": "reviewer absolute deadline expired before launch",
        }
    cleanup_reserve = min(5.0, timeout_seconds * 0.75)
    execution_deadline = deadline - cleanup_reserve

    def observe_candidate() -> tuple[bool, str]:
        outcome: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def observe() -> None:
            try:
                outcome.put((True, candidate_supplier(deadline)))
            except Exception as exc:  # trusted adapter failure becomes UNKNOWN
                outcome.put((False, exc.__class__.__name__))

        thread = threading.Thread(target=observe, daemon=True)
        thread.start()
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            return False, ""
        try:
            succeeded, value = outcome.get_nowait()
        except queue.Empty:
            return False, ""
        return succeeded and isinstance(value, str), value if isinstance(value, str) else ""

    before_observed, before = observe_candidate()
    if not before_observed:
        return {
            "verdict": ReviewerVerdict.UNKNOWN,
            "reason": "pre-review candidate observation was unavailable",
        }
    try:
        output_authority = _ReviewerOutputAuthority(output_path)
    except FileExistsError:
        return {"verdict": ReviewerVerdict.UNKNOWN, "reason": "stale output path exists"}
    except (OSError, ValueError):
        return {
            "verdict": ReviewerVerdict.UNKNOWN,
            "reason": "reviewer output authority was unavailable",
        }
    stdout_capture = _BoundedCapture(max_output_bytes)
    stderr_capture = _BoundedCapture(max_output_bytes)
    timed_out = False
    observation_complete = True
    capture_threads_completed = True
    process_cleanup_complete = True
    parent_exit_observed = False
    return_code: int | None = None
    threads = []
    process: subprocess.Popen[bytes] | None = None
    status_read: int | None = None
    status_write: int | None = None
    supervisor_status: Mapping[str, Any] | None = None
    stdin_payload = stdin_text.encode("utf-8")
    stdin_delivery = {
        "complete": False,
        "bytes_expected": len(stdin_payload),
        "bytes_written": 0,
    }
    stdin_thread: Any = None
    actual_command = list(command)
    sanitized_environment = build_reviewer_environment(environment or os.environ)
    try:
        if time.monotonic() >= execution_deadline:
            raise TimeoutError("reviewer execution budget exhausted before launch")
        if os.name != "posix":
            raise OSError("trusted reviewer descendant supervision is unavailable")
        status_read, status_write = os.pipe()
        os.set_blocking(status_read, False)
        os.set_inheritable(status_write, True)
        actual_command = [
            sys.executable,
            os.fspath(Path(__file__).with_name("reviewer_supervisor.py")),
            str(status_write),
            "--",
            *command,
        ]
        process = subprocess.Popen(
            actual_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=sanitized_environment,
            start_new_session=True,
            pass_fds=(status_write,),
        )
        os.close(status_write)
        status_write = None
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        threads = [
            threading.Thread(target=stdout_capture.read, args=(process.stdout,), daemon=True),
            threading.Thread(target=stderr_capture.read, args=(process.stderr,), daemon=True),
        ]
        for thread in threads:
            thread.start()

        def deliver_stdin() -> None:
            try:
                assert process is not None and process.stdin is not None
                remaining = memoryview(stdin_payload)
                while remaining:
                    written = process.stdin.write(remaining)
                    if not isinstance(written, int) or written <= 0:
                        return
                    stdin_delivery["bytes_written"] += written
                    remaining = remaining[written:]
                process.stdin.close()
                stdin_delivery["complete"] = True
            except (OSError, ValueError):
                return

        stdin_thread = threading.Thread(target=deliver_stdin, daemon=True)
        stdin_thread.start()
        try:
            remaining = execution_deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(actual_command, timeout_seconds)
            return_code = process.wait(timeout=remaining)
            parent_exit_observed = True
        except subprocess.TimeoutExpired:
            timed_out = True
            observation_complete = False
            process_cleanup_complete = _stop_reviewer_supervisor(
                process, deadline=deadline
            )
    except OSError:
        observation_complete = False
        process_cleanup_complete = False
        if process is not None:
            process_cleanup_complete = _stop_reviewer_supervisor(
                process, deadline=deadline
            )
    finally:
        if status_write is not None:
            try:
                os.close(status_write)
            except OSError:
                pass
        if stdin_thread is not None:
            stdin_thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if stdin_thread.is_alive():
                observation_complete = False
                if process is not None:
                    streams_closed = _close_process_streams(
                        process, deadline=deadline
                    )
                    process_cleanup_complete = (
                        process_cleanup_complete and streams_closed
                    )
                stdin_thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if stdin_thread.is_alive():
                process_cleanup_complete = False
            elif process is not None and process.stdin is not None:
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    process_cleanup_complete = False
        elif process is not None and process.stdin is not None:
            if not _close_process_streams(process, deadline=deadline):
                process_cleanup_complete = False
        if not stdin_delivery["complete"]:
            observation_complete = False
        if parent_exit_observed and process is not None:
            if os.name == "posix":
                if not _posix_process_group_exited(
                    process.pid, min(0.2, max(0.0, deadline - time.monotonic()))
                ):
                    observation_complete = False
                    cleaned = _terminate_process_tree(process, deadline=deadline)
                    process_cleanup_complete = process_cleanup_complete and cleaned
            else:
                observation_complete = False
                process_cleanup_complete = False
        if status_read is not None:
            try:
                raw_status = os.read(status_read, 4097)
                if len(raw_status) <= 4096:
                    parsed_status = json.loads(raw_status.decode("utf-8"))
                    if isinstance(parsed_status, Mapping):
                        supervisor_status = parsed_status
            except (OSError, UnicodeError, ValueError):
                supervisor_status = None
            finally:
                os.close(status_read)
        if (
            supervisor_status is None
            or supervisor_status.get("boundary_available") is not True
            or supervisor_status.get("cleanup_complete") is not True
        ):
            observation_complete = False
            process_cleanup_complete = False
        elif supervisor_status.get("descendants_observed") is True:
            observation_complete = False
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            observation_complete = False
            if process is not None:
                cleaned = _terminate_process_tree(process, deadline=deadline)
                process_cleanup_complete = process_cleanup_complete and cleaned
                if os.name != "posix":
                    process_cleanup_complete = False
                streams_closed = _close_process_streams(process, deadline=deadline)
                process_cleanup_complete = (
                    process_cleanup_complete and streams_closed
                )
            for thread in threads:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        capture_threads_completed = not any(thread.is_alive() for thread in threads)
        if threads and (not stdout_capture.eof or not stderr_capture.eof):
            observation_complete = False
        if not capture_threads_completed:
            process_cleanup_complete = False
    after_observed, after = observe_candidate()
    if not after_observed:
        observation_complete = False
    ended_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    latency_ms = max(0, int((time.monotonic() - started_monotonic) * 1000))
    output_bytes = b""
    output_present = False
    output_regular = False
    output_truncated = False
    output_valid = False
    candidate_matches = False
    bindings_match = False
    payload: Mapping[str, Any] | None = None
    try:
        output_bytes = output_authority.read_once(max_output_bytes)
        output_present = True
        output_regular = True
        parsed = parse_json_bytes(output_bytes)
        validate_loaded_instance(parsed, schema_path)
        if isinstance(parsed, Mapping):
            payload = parsed
            output_valid = True
            candidate_matches = parsed.get("candidate_id") == expected_candidate_id
            required_bindings = dict(expected_bindings or {})
            required_bindings.setdefault("candidate_id", expected_candidate_id)
            bindings_match = all(
                parsed.get(key) == value for key, value in required_bindings.items()
            )
    except _ReviewerOutputReadError as exc:
        output_present = exc.present
        output_regular = exc.regular
        output_truncated = exc.truncated
    except (OSError, ValueError, SchemaValidationError):
        pass
    finally:
        output_authority.close()
    truncated = (
        stdout_capture.truncated
        or stderr_capture.truncated
        or output_truncated
    )
    execution_valid = bool(
        return_code == 0
        and not timed_out
        and observation_complete
        and capture_threads_completed
        and process_cleanup_complete
        and output_present
        and output_valid
        and candidate_matches
        and bindings_match
        and before == expected_candidate_id
        and after == expected_candidate_id
        and not truncated
    )
    verdict = classify_reviewer_execution(
        return_code=return_code,
        timed_out=timed_out,
        observation_complete=observation_complete,
        output_present=output_present,
        output_valid=output_valid,
        candidate_matches=(
            candidate_matches
            and bindings_match
            and before == expected_candidate_id
            and after == expected_candidate_id
        ),
        output_truncated=truncated,
        declared_verdict=(
            payload.get("verdict")
            if payload and review_mode == "conformance"
            else (
                "NO_BLOCKING_FINDING_OBSERVED"
                if payload and payload.get("status") == "completed"
                else "UNKNOWN"
            )
        ),
    )
    output_sha256 = sha256_bytes(output_bytes)
    stdout_bytes, stdout_redactions = _normalize_reviewer_jsonl(
        bytes(stdout_capture.data),
        command=actual_command,
        schema_path=schema_path,
        output_path=output_path,
        environment=sanitized_environment,
    )
    stderr_bytes, stderr_redactions = _normalize_reviewer_stream(
        bytes(stderr_capture.data),
        command=actual_command,
        schema_path=schema_path,
        output_path=output_path,
        environment=sanitized_environment,
    )
    primitive_observation = {
        "parent_exit_observed": parent_exit_observed,
        "return_code": return_code if isinstance(return_code, int) else -1,
        "timed_out": timed_out,
        "candidate_unchanged": bool(
            before == expected_candidate_id and after == expected_candidate_id
        ),
        "stdin": dict(stdin_delivery),
        "stdout": {
            "bytes_observed": stdout_capture.total,
            "bytes_captured": len(stdout_capture.data),
            "bytes_normalized": len(stdout_bytes),
            "thread_completed": bool(threads and not threads[0].is_alive()),
            "eof": stdout_capture.eof,
            "read_failed": stdout_capture.failed,
            "truncated": stdout_capture.truncated,
            "ambiguous_redaction": bool(stdout_redactions),
        },
        "stderr": {
            "bytes_observed": stderr_capture.total,
            "bytes_captured": len(stderr_capture.data),
            "bytes_normalized": len(stderr_bytes),
            "thread_completed": bool(
                len(threads) > 1 and not threads[1].is_alive()
            ),
            "eof": stderr_capture.eof,
            "read_failed": stderr_capture.failed,
            "truncated": stderr_capture.truncated,
            "ambiguous_redaction": bool(stderr_redactions),
        },
        "supervisor": {
            "boundary_available": bool(
                supervisor_status
                and supervisor_status.get("boundary_available") is True
            ),
            "boundary_kind": (
                supervisor_status.get("boundary_kind")
                if supervisor_status
                and supervisor_status.get("boundary_kind")
                in {"pid_namespace", "seccomp_signal_guard"}
                else "unavailable"
            ),
            "descendants_observed": bool(
                supervisor_status
                and supervisor_status.get("descendants_observed") is True
            ),
            "cleanup_complete": bool(
                supervisor_status
                and supervisor_status.get("cleanup_complete") is True
            ),
        },
        "process_cleanup_complete": process_cleanup_complete,
        "output": {
            "present": output_present,
            "regular": output_regular,
            "bytes": len(output_bytes),
            "schema_valid": output_valid,
            "candidate_matches": candidate_matches,
            "bindings_match": bindings_match,
            "truncated": output_truncated,
        },
    }
    derived_facts = reviewer_observation_facts(primitive_observation)
    execution_valid = execution_valid and derived_facts["execution_valid"]
    observation_complete = (
        observation_complete and derived_facts["observation_complete"]
    )
    capture_threads_completed = derived_facts["capture_threads_completed"]
    process_cleanup_complete = derived_facts["process_cleanup_complete"]
    if not execution_valid and verdict is not ReviewerVerdict.BLOCK:
        verdict = ReviewerVerdict.UNKNOWN
    if stdout_redactions or stderr_redactions:
        execution_valid = False
        observation_complete = False
        verdict = ReviewerVerdict.UNKNOWN
    usage = _parse_codex_jsonl(stdout_bytes)
    if stdout_capture.truncated:
        usage = {
            "usage_observed": False,
            "thread_id": None,
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "output_tokens": 0,
            "reasoning_output_tokens": 0,
        }
    limitations = (
        []
        if usage["usage_observed"]
        else ["Codex JSONL usage was unavailable or malformed"]
    )
    if not observation_complete:
        limitations.append("reviewer process observation was incomplete")
    if not capture_threads_completed:
        limitations.append("reviewer capture threads did not complete")
    if not process_cleanup_complete:
        limitations.append("reviewer process cleanup could not be proven complete")
    if not stdin_delivery["complete"]:
        limitations.append("reviewer stdin delivery did not complete within the deadline")
    if stdout_redactions or stderr_redactions:
        limitations.append(
            "ambiguous machine- or credential-shaped reviewer stream bytes were redacted"
        )
    return {
        "verdict": verdict,
        "result": dict(payload) if payload else None,
        "return_code": return_code,
        "started_at": started_at,
        "ended_at": ended_at,
        "latency_ms": latency_ms,
        "candidate_before": before,
        "candidate_after": after,
        "environment_keys": sorted(sanitized_environment),
        "argv_sha256": sha256_canonical(actual_command),
        "stdin_sha256": sha256_bytes(stdin_text.encode("utf-8")),
        "output_sha256": output_sha256,
        "timed_out": timed_out,
        "observation_complete": observation_complete,
        "capture_threads_completed": capture_threads_completed,
        "process_cleanup_complete": process_cleanup_complete,
        "stdin_delivery_complete": stdin_delivery["complete"],
        "observation": primitive_observation,
        "stdout_sha256": sha256_bytes(stdout_bytes),
        "stderr_sha256": sha256_bytes(stderr_bytes),
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "output_bytes": output_bytes,
        "output_valid": output_valid,
        "candidate_matches": candidate_matches and before == after,
        "bindings_match": bindings_match,
        "execution_valid": execution_valid,
        "review_status": payload.get("status") if payload and review_mode == "rapid_review" else None,
        "output_truncated": truncated,
        "limitations": limitations,
        **usage,
    }
