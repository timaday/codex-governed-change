"""Fresh, schema-bound, read-only Codex reviewer process boundary."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
from codex_governance.schema import SchemaValidationError, load_and_validate


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
        "context_projection_path",
        "context_projection_sha256",
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
        "context_projection_path", "context_projection_sha256",
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
    'XDG_CONFIG_HOME=".reviewer-home"}}'
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


def _parse_codex_jsonl(data: bytes) -> dict[str, Any]:
    """Extract one final usage record from the bounded Codex JSONL stream."""
    usage = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
    }
    observed = False
    thread_id: str | None = None
    try:
        for raw in data.splitlines():
            if not raw.strip():
                continue
            event = json.loads(raw)
            if not isinstance(event, Mapping) or not isinstance(event.get("type"), str):
                raise ValueError("invalid Codex JSONL event")
            if event["type"] == "thread.started" and isinstance(event.get("thread_id"), str):
                thread_id = event["thread_id"]
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
        observed = False
        usage = {key: 0 for key in usage}
    return {"usage_observed": observed, "thread_id": thread_id, **usage}


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
    input_context_receipt_sha256: str,
    context_execution_receipt_sha256: str,
    workflow_system: str,
    run_id: str,
    attempt: int,
    timeout_seconds: float,
    max_output_bytes: int,
    codex_cli_version: str,
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
    document = {
        "schema_version": "2.0.0",
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
            {"name": "prepared-context", "sha256": require_sha256(input_context_receipt_sha256)},
            {"name": "post-run-context", "sha256": require_sha256(context_execution_receipt_sha256)},
        ],
        "environment_keys": list(execution.get("environment_keys", ())),
        "started_at": execution.get("started_at"),
        "ended_at": execution.get("ended_at"),
        "latency_ms": execution.get("latency_ms", 0),
        "return_code": (
            execution.get("return_code")
            if isinstance(execution.get("return_code"), int)
            else -1
        ),
        "timed_out": execution.get("timed_out") is True,
        "observation_complete": execution.get("observation_complete") is True,
        "capture_threads_completed": execution.get("capture_threads_completed") is True,
        "process_cleanup_complete": execution.get("process_cleanup_complete") is True,
        "execution_valid": execution.get("execution_valid") is True,
        "output_valid": execution.get("output_valid") is True,
        "bindings_match": execution.get("bindings_match") is True,
        "output_truncated": execution.get("output_truncated") is True,
        "stdout_sha256": require_sha256(execution.get("stdout_sha256")),
        "stderr_sha256": require_sha256(execution.get("stderr_sha256")),
        "usage_observed": execution.get("usage_observed") is True,
        "input_tokens": execution.get("input_tokens", 0),
        "cached_input_tokens": execution.get("cached_input_tokens", 0),
        "output_tokens": execution.get("output_tokens", 0),
        "reasoning_output_tokens": execution.get("reasoning_output_tokens", 0),
        "limitations": list(execution.get("limitations", ())),
    }
    return content_address(document, "execution_id")


def _run_git(repository: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
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


def _candidate_paths(repository: Path, *, evidence_root: str | None = None) -> list[str]:
    output = _run_git(
        repository, "ls-files", "-z", "--cached", "--others", "--exclude-standard"
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


def _copy_entry(source: Path, destination: Path) -> None:
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
        for nested in _candidate_paths(source):
            nested_source = source.joinpath(*nested.split("/"))
            if nested_source.exists() or nested_source.is_symlink():
                _copy_entry(nested_source, destination.joinpath(*nested.split("/")))
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
    "profiles.py",
    "qualification.py",
    "rapid_review.py",
    "reviewer.py",
    "reviewer_namespace.py",
    "reviewer_signal_guard.py",
    "reviewer_supervisor.py",
    "rst_operations.py",
    "sandbox.py",
    "schema.py",
)


def _stop_reviewer_supervisor(
    process: subprocess.Popen[bytes], *, timeout: float = 3.0
) -> bool:
    """Ask the dedicated subreaper to drain descendants before forced exit."""
    try:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=timeout)
        return True
    except OSError:
        return False
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            pass
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


def _bounded_regular_source(
    repository: Path, relative: str, *, max_bytes: int
) -> Path:
    normalized = normalize_repo_path(relative)
    root = repository.resolve()
    current = root
    for part in normalized.split("/"):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("review evidence source contains a symlink")
    current.resolve().relative_to(root)
    info = current.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        raise ValueError("review evidence source is not a bounded regular file")
    return current


def _materialize_permitted_evidence(
    *,
    candidate_repository: Path,
    harness: Path,
    permitted_inputs: Mapping[str, Any],
    evidence_root: str,
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
        source = _bounded_regular_source(
            candidate_repository, normalized, max_bytes=max_total_bytes
        )
        data = source.read_bytes()
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
    source_candidate = GitCliRepositoryAdapter(candidate).identify(**identity_arguments)
    if source_candidate != dict(expected_candidate):
        raise ValueError("reviewer source does not match the expected candidate")
    if permitted_inputs.get("candidate_id") != expected_candidate.get("candidate_id"):
        raise ValueError("reviewer permitted candidate binding mismatch")
    paths = _candidate_paths(candidate, evidence_root=normalized_evidence_root)
    harness = harness_root.resolve(strict=False)
    if harness == candidate:
        raise ValueError("review harness cannot be the candidate repository")
    if harness.exists() and any(harness.iterdir()):
        raise FileExistsError("review harness must be absent or empty")
    harness.mkdir(parents=True, exist_ok=True)
    snapshot = harness / "candidate"
    clone = subprocess.run(
        [
            "git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
            os.fspath(candidate), os.fspath(snapshot),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if clone.returncode != 0:
        raise RuntimeError("unable to create reviewer candidate snapshot")
    _run_git(snapshot, "checkout", "--quiet", "--detach", "HEAD")
    _run_git(snapshot, "remote", "remove", "origin")
    logs = snapshot / ".git/logs"
    if logs.exists():
        _remove_scoped_tree(logs, boundary=snapshot)
    for relative in paths:
        source = candidate.joinpath(*relative.split("/"))
        destination = snapshot.joinpath(*relative.split("/"))
        if source.exists() or source.is_symlink():
            _copy_entry(source, destination)
        elif destination.exists() or destination.is_symlink():
            _remove_scoped_tree(destination, boundary=snapshot)
    _validate_snapshot_symlinks(snapshot, paths)
    copied_candidate = GitCliRepositoryAdapter(snapshot).identify(**identity_arguments)
    if copied_candidate != dict(expected_candidate):
        raise ValueError("reviewer snapshot does not match the expected candidate")
    prompt = harness / "reviewer.prompt.md"
    schema = harness / "reviewer-output.schema.json"
    manifest = harness / "permitted-inputs.json"
    shutil.copyfile(fixed_prompt_path, prompt)
    shutil.copyfile(output_schema_path, schema)
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
    )
    initialized = subprocess.run(
        ["git", "-c", "init.defaultBranch=review", "-C", os.fspath(harness), "init", "--quiet"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
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
) -> dict[str, Any]:
    """Launch the fresh reviewer and validate its exact output and binding."""
    if review_mode not in {"conformance", "rapid_review"}:
        raise ValueError("review mode must be conformance or rapid_review")
    if not command or command[-1] != "-" or "resume" in command:
        raise ValueError("reviewer command must be a fresh stdin-driven exec")
    if output_path.exists() or output_path.is_symlink():
        return {"verdict": ReviewerVerdict.UNKNOWN, "reason": "stale output path exists"}
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    started_monotonic = time.monotonic()
    before = candidate_supplier()
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
    actual_command = list(command)
    sanitized_environment = build_reviewer_environment(environment or os.environ)
    try:
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
            env=sanitized_environment,
            start_new_session=True,
            pass_fds=(status_write,),
        )
        os.close(status_write)
        status_write = None
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        import threading

        threads = [
            threading.Thread(target=stdout_capture.read, args=(process.stdout,), daemon=True),
            threading.Thread(target=stderr_capture.read, args=(process.stderr,), daemon=True),
        ]
        for thread in threads:
            thread.start()
        process.stdin.write(stdin_text.encode("utf-8"))
        process.stdin.close()
        try:
            return_code = process.wait(timeout=timeout_seconds)
            parent_exit_observed = True
        except subprocess.TimeoutExpired:
            timed_out = True
            observation_complete = False
            process_cleanup_complete = _stop_reviewer_supervisor(process)
    except OSError:
        observation_complete = False
        process_cleanup_complete = False
        if process is not None:
            process_cleanup_complete = _stop_reviewer_supervisor(process)
    finally:
        if status_write is not None:
            try:
                os.close(status_write)
            except OSError:
                pass
        if process is not None and process.stdin is not None:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
        if parent_exit_observed and process is not None:
            if os.name == "posix":
                if not _posix_process_group_exited(process.pid, 0.2):
                    observation_complete = False
                    cleaned = _terminate_process_tree(process)
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
            thread.join(timeout=3)
        if any(thread.is_alive() for thread in threads):
            observation_complete = False
            if process is not None:
                cleaned = _terminate_process_tree(process)
                process_cleanup_complete = process_cleanup_complete and cleaned
                if os.name != "posix":
                    process_cleanup_complete = False
                streams_closed = _close_process_streams(process)
                process_cleanup_complete = (
                    process_cleanup_complete and streams_closed
                )
            for thread in threads:
                thread.join(timeout=1)
        capture_threads_completed = not any(thread.is_alive() for thread in threads)
        if threads and (not stdout_capture.eof or not stderr_capture.eof):
            observation_complete = False
        if not capture_threads_completed:
            process_cleanup_complete = False
    try:
        after = candidate_supplier()
    except Exception:
        after = ""
    ended_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    latency_ms = max(0, int((time.monotonic() - started_monotonic) * 1000))
    output_present = output_path.is_file() and not output_path.is_symlink()
    output_valid = False
    candidate_matches = False
    bindings_match = False
    payload: Mapping[str, Any] | None = None
    if output_present and output_path.stat().st_size <= max_output_bytes:
        try:
            parsed = load_and_validate(output_path, schema_path)
            if isinstance(parsed, Mapping):
                payload = parsed
                output_valid = True
                candidate_matches = parsed.get("candidate_id") == expected_candidate_id
                required_bindings = dict(expected_bindings or {})
                required_bindings.setdefault("candidate_id", expected_candidate_id)
                bindings_match = all(
                    parsed.get(key) == value for key, value in required_bindings.items()
                )
        except (OSError, ValueError, SchemaValidationError):
            pass
    truncated = (
        stdout_capture.truncated
        or stderr_capture.truncated
        or (output_present and output_path.stat().st_size > max_output_bytes)
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
    output_sha256 = sha256_bytes(b"")
    if output_present and output_path.stat().st_size <= max_output_bytes:
        output_sha256 = sha256_bytes(output_path.read_bytes())
    usage = _parse_codex_jsonl(bytes(stdout_capture.data))
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
        "stdout_sha256": sha256_bytes(bytes(stdout_capture.data)),
        "stderr_sha256": sha256_bytes(bytes(stderr_capture.data)),
        "output_valid": output_valid,
        "candidate_matches": candidate_matches and before == after,
        "bindings_match": bindings_match,
        "execution_valid": execution_valid,
        "review_status": payload.get("status") if payload and review_mode == "rapid_review" else None,
        "output_truncated": truncated,
        "limitations": limitations,
        **usage,
    }
