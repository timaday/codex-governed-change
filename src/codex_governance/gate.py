"""Bounded deterministic gate process adapter."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from codex_governance.artifacts import FilesystemArtifactStore
from codex_governance.attestation import build_provenance_statement
from codex_governance.canonical import canonical_json_bytes, normalize_repo_path, sha256_bytes
from codex_governance.domain.model import GateStatus
from codex_governance.lifecycle import parse_rfc3339
from codex_governance.portability import SHAPED_VALUE_PATTERNS
from codex_governance.sandbox import (
    SandboxInvocation,
    build_container_start_command,
    cleanup_container,
    create_container,
    validate_sandbox_capability,
)


def classify_gate_result(
    *,
    termination_kind: str,
    exit_code: int | None,
    observation_complete: bool,
    required_output_truncated: bool,
    candidate_before: str,
    candidate_after: str,
) -> GateStatus:
    """Classify a gate without confusing failure and observation uncertainty."""
    if candidate_before != candidate_after:
        return GateStatus.UNKNOWN
    if (
        termination_kind != "exited"
        or exit_code is None
        or not observation_complete
        or required_output_truncated
    ):
        return GateStatus.UNKNOWN
    return GateStatus.PASS if exit_code == 0 else GateStatus.FAIL


class _BoundedCapture:
    def __init__(self, limit: int):
        self.limit = limit
        self.data = bytearray()
        self.total = 0
        self.eof = False
        self.failed = False

    def read(self, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    self.eof = True
                    return
                self.total += len(chunk)
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
        except (OSError, ValueError):
            self.failed = True
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                self.failed = True

    @property
    def truncated(self) -> bool:
        return self.total > len(self.data)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _redact_runtime_paths(
    data: bytes, sandbox_invocation: SandboxInvocation | None
) -> tuple[bytes, list[dict[str, Any]]]:
    """Remove known host values and credential-shaped bytes before persistence."""
    replacements: list[tuple[bytes, bytes, str]] = []
    if sandbox_invocation is not None:
        for value, replacement, category in (
            (
                sandbox_invocation.candidate_copy,
                b"<SANDBOX_CANDIDATE>",
                "sandbox_candidate_path",
            ),
            (
                sandbox_invocation.supervisor_cwd,
                b"<SANDBOX_SUPERVISOR>",
                "supervisor_path",
            ),
        ):
            if isinstance(value, Path):
                encoded = os.fsencode(value)
                if encoded:
                    replacements.append((encoded, replacement, category))
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    host_values = {
        hostname,
        *(os.environ.get(key, "") for key in (
            "HOME", "USERPROFILE", "HOSTNAME", "COMPUTERNAME",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR", "TMP", "TEMP",
        )),
    }
    path_value = os.environ.get("PATH", "")
    host_values.update(path_value.split(os.pathsep))
    for value in sorted(host_values):
        encoded = os.fsencode(value)
        if encoded:
            replacements.append(
                (encoded, b"<REDACTED_HOST_VALUE>", "host_value")
            )
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"):
        encoded = os.fsencode(os.environ.get(key, ""))
        if encoded:
            replacements.append(
                (encoded, b"<REDACTED_CREDENTIAL>", "credential")
            )
    result = data
    redactions: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for original, replacement, category in sorted(
        replacements, key=lambda item: len(item[0]), reverse=True
    ):
        if original in seen:
            continue
        seen.add(original)
        occurrences = result.count(original)
        if occurrences:
            result = result.replace(original, replacement)
            redactions.append(
                {
                    "category": category,
                    "replacement": replacement.decode("ascii"),
                    "occurrences": occurrences,
                }
            )
    for _pass in range(2):
        changed = False
        for pattern, category in SHAPED_VALUE_PATTERNS:
            replacement = (
                b"<REDACTED_HOST_PATH>"
                if category == "generic_host_path"
                else (
                    b"<REDACTED_ENDPOINT>"
                    if category == "endpoint"
                    else b"<REDACTED_CREDENTIAL>"
                )
            )
            result, occurrences = pattern.subn(replacement, result)
            if occurrences:
                changed = True
                redactions.append(
                    {
                        "category": category,
                        "replacement": replacement.decode("ascii"),
                        "occurrences": occurrences,
                    }
                )
        if not changed:
            break
    return result, redactions


def _posix_process_group_exited(
    process_group: int, timeout: float, *, allow_zombie_only: bool = False
) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        if allow_zombie_only and _linux_process_group_is_zombie_only(process_group):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _linux_process_group_is_zombie_only(process_group: int) -> bool:
    """Prove through procfs that a lingering Linux group has no live members."""
    proc = Path("/proc")
    if not sys.platform.startswith("linux") or not proc.is_dir():
        return False
    matched = False
    try:
        entries = list(proc.iterdir())
    except OSError:
        return False
    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return False
        _, separator, suffix = raw.rpartition(")")
        fields = suffix.split()
        if not separator or len(fields) < 3:
            return False
        try:
            member_group = int(fields[2])
        except ValueError:
            return False
        if member_group != process_group:
            continue
        matched = True
        if fields[0] != "Z":
            return False
    return matched


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _terminate_process_tree(
    process: subprocess.Popen[bytes], *, deadline: float | None = None
) -> bool:
    """Terminate an isolated process tree and report whether cleanup was proven."""
    cleanup_deadline = deadline if deadline is not None else time.monotonic() + 3.2
    if os.name == "posix":
        process_group = process.pid
        try:
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        if _remaining(cleanup_deadline) > 0:
            try:
                process.wait(timeout=min(0.2, _remaining(cleanup_deadline)))
            except subprocess.TimeoutExpired:
                pass
        if _posix_process_group_exited(
            process_group,
            min(1.0, _remaining(cleanup_deadline)),
            allow_zombie_only=True,
        ):
            return process.poll() is not None
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            return False
        if _remaining(cleanup_deadline) <= 0:
            return process.poll() is not None and _posix_process_group_exited(
                process_group, 0.0, allow_zombie_only=True
            )
        try:
            process.wait(timeout=min(1.0, _remaining(cleanup_deadline)))
        except subprocess.TimeoutExpired:
            return False
        return _posix_process_group_exited(
            process_group,
            min(1.0, _remaining(cleanup_deadline)),
            allow_zombie_only=True,
        )

    try:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=_remaining(cleanup_deadline))
        return process.poll() is not None
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=_remaining(cleanup_deadline))
        except (OSError, subprocess.TimeoutExpired):
            return False
        return process.poll() is not None


def _close_process_streams(
    process: subprocess.Popen[bytes], *, timeout: float = 0.2,
    deadline: float | None = None,
) -> bool:
    """Close captured streams without letting a buffered close stall control flow."""
    close_threads: list[threading.Thread] = []

    def close(stream: BinaryIO) -> None:
        try:
            stream.close()
        except (OSError, ValueError):
            pass

    for stream in (process.stdout, process.stderr):
        if stream is None or stream.closed:
            continue
        thread = threading.Thread(target=close, args=(stream,), daemon=True)
        close_threads.append(thread)
        thread.start()
    close_deadline = (
        deadline if deadline is not None else time.monotonic() + max(0.0, timeout)
    )
    for thread in close_threads:
        thread.join(timeout=_remaining(close_deadline))
    return not any(thread.is_alive() for thread in close_threads)


def run_gate(
    *,
    gate_id: str,
    profile: str,
    command: Sequence[str],
    cwd: Path,
    sandbox_invocation: SandboxInvocation | None,
    repository_id: str,
    task_contract_sha256: str,
    effective_policy_sha256: str,
    provenance_context: Mapping[str, Any],
    candidate_supplier: Callable[[], str],
    artifact_store: FilesystemArtifactStore,
    artifact_prefix: str,
    timeout_seconds: float = 600,
    max_output_bytes: int = 1_000_000,
    shell: bool = False,
    risk_label: str | None = None,
    producer_version: str = "0.1.0",
    absolute_deadline: float | None = None,
    observation_started_at: str | None = None,
    observation_started_ns: int | None = None,
    preparation_error: str | None = None,
) -> dict[str, Any]:
    """Run one gate through a protected invocation and persist bounded evidence."""
    if not command or not all(isinstance(item, str) and item for item in command):
        raise ValueError("gate command must be a non-empty argument array")
    if timeout_seconds <= 0 or max_output_bytes < 1:
        raise ValueError("gate bounds must be positive")
    if shell and (len(command) != 1 or not risk_label):
        raise ValueError("shell mode requires one command string and a risk label")
    if not isinstance(cwd, Path):
        raise TypeError("gate working directory descriptor must be a path")
    prefix = normalize_repo_path(artifact_prefix)
    evidence_root = normalize_repo_path(
        artifact_store.root.relative_to(artifact_store.repository).as_posix()
    )

    def repository_artifact_path(relative: str) -> str:
        return normalize_repo_path(f"{evidence_root}/{relative}")

    started_at = observation_started_at or _utc_now()
    started = observation_started_ns or time.monotonic_ns()
    deadline = absolute_deadline or (time.monotonic() + timeout_seconds)
    post_execution_reserve = min(10.0, max(0.01, timeout_seconds * 0.1))
    execution_deadline = deadline - post_execution_reserve
    try:
        before = candidate_supplier()
        before_observed = True
    except Exception:
        before = "sha256:" + "0" * 64
        before_observed = False
    stdout_capture = _BoundedCapture(max_output_bytes)
    stderr_capture = _BoundedCapture(max_output_bytes)
    termination: dict[str, Any]
    observation_complete = before_observed
    return_code: int | None = None
    threads: list[threading.Thread] = []
    container_cleanup_complete = True
    container_id: str | None = None
    capability_report = (
        dict(sandbox_invocation.capability_report)
        if isinstance(sandbox_invocation, SandboxInvocation)
        else None
    )
    capability_valid = bool(
        capability_report is not None
        and not validate_sandbox_capability(capability_report)
    )
    if capability_valid:
        try:
            capability_valid = parse_rfc3339(
                str(capability_report["verified_at"])
            ) <= parse_rfc3339(started_at)
        except (KeyError, TypeError, ValueError):
            capability_valid = False
    if preparation_error is not None:
        termination = {
            "kind": "launch_error",
            "detail": "candidate_preparation_incomplete",
        }
        observation_complete = False
    elif not capability_valid:
        termination = {"kind": "launch_error", "detail": "sandbox_capability_unavailable"}
        observation_complete = False
    elif time.monotonic() >= execution_deadline:
        termination = {"kind": "timeout"}
        observation_complete = False
    else:
        try:
            creationflags = (
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            )
            runtime_argv = list(sandbox_invocation.argv)
            if sandbox_invocation.container_provider is not None:
                remaining = execution_deadline - time.monotonic()
                container_id = create_container(
                    sandbox_invocation, timeout_seconds=remaining
                )
                if container_id is None:
                    raise OSError("container identity unavailable")
                runtime_argv = build_container_start_command(
                    sandbox_invocation, container_id
                )
            process = subprocess.Popen(
                runtime_argv,
                cwd=sandbox_invocation.supervisor_cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=os.name == "posix",
                creationflags=creationflags,
            )
            assert process.stdout is not None and process.stderr is not None
            threads = [
                threading.Thread(
                    target=stdout_capture.read, args=(process.stdout,), daemon=True
                ),
                threading.Thread(
                    target=stderr_capture.read, args=(process.stderr,), daemon=True
                ),
            ]
            for thread in threads:
                thread.start()
            try:
                remaining = execution_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(runtime_argv, timeout_seconds)
                return_code = process.wait(timeout=remaining)
                if return_code < 0:
                    termination = {"kind": "signal", "signal": str(-return_code)}
                    observation_complete = False
                else:
                    termination = {"kind": "exited", "exit_code": return_code}
            except subprocess.TimeoutExpired:
                termination = {"kind": "timeout"}
                observation_complete = False
                if not _terminate_process_tree(process, deadline=deadline):
                    observation_complete = False
        except OSError as exc:
            termination = {
                "kind": "launch_error",
                "detail": exc.__class__.__name__,
            }
            observation_complete = False
        finally:
            if sandbox_invocation.container_provider is not None:
                container_cleanup_complete = cleanup_container(
                    sandbox_invocation,
                    container_id,
                    timeout_seconds=max(0.0, deadline - time.monotonic()),
                )
                if not container_cleanup_complete:
                    observation_complete = False
            for thread in threads:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
                if thread.is_alive():
                    observation_complete = False
            if any(thread.is_alive() for thread in threads) and "process" in locals():
                _terminate_process_tree(process, deadline=deadline)
                if not _close_process_streams(process, deadline=deadline):
                    observation_complete = False
                for thread in threads:
                    thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if threads and (
                any(thread.is_alive() for thread in threads)
                or not stdout_capture.eof
                or not stderr_capture.eof
            ):
                observation_complete = False
    ended = time.monotonic_ns()
    ended_at = _utc_now()
    try:
        after = candidate_supplier()
    except Exception:
        after = "sha256:" + "0" * 64
        observation_complete = False
    stdout, stdout_redactions = _redact_runtime_paths(
        bytes(stdout_capture.data), sandbox_invocation
    )
    stderr, stderr_redactions = _redact_runtime_paths(
        bytes(stderr_capture.data), sandbox_invocation
    )
    redactions = stdout_redactions + stderr_redactions
    ambiguous_redaction = any(
        item.get("category")
        in {"credential", "endpoint", "generic_host_path", "host_value"}
        for item in redactions
    )
    if ambiguous_redaction:
        observation_complete = False
    stdout_path = f"{prefix}/stdout.bin"
    stderr_path = f"{prefix}/stderr.bin"
    artifact_store.write_bytes(stdout_path, stdout)
    artifact_store.write_bytes(stderr_path, stderr)
    capability_path = f"{prefix}/sandbox-capability.json"
    capability_bytes = canonical_json_bytes(capability_report or {})
    capability_sha256 = artifact_store.write_bytes(capability_path, capability_bytes)
    truncated = stdout_capture.truncated or stderr_capture.truncated
    status = classify_gate_result(
        termination_kind=termination["kind"],
        exit_code=return_code,
        observation_complete=observation_complete,
        required_output_truncated=truncated,
        candidate_before=before,
        candidate_after=after,
    )
    limitations: list[str] = []
    if truncated:
        limitations.append("required process output exceeded the configured capture bound")
    if before != after:
        limitations.append("candidate identity changed during gate observation")
    if not observation_complete:
        limitations.append("process observation was incomplete")
    if preparation_error is not None:
        limitations.append("candidate preparation was incomplete")
    if not capability_valid:
        limitations.append("required disposable sandbox capability was unavailable")
    if not container_cleanup_complete:
        limitations.append("sandbox container cleanup could not be proven")
    if ambiguous_redaction:
        limitations.append(
            "secret-shaped or unbound host data was redacted; output evidence is ambiguous"
        )
    provenance = build_provenance_statement(
        repository_id=repository_id,
        candidate_id=before,
        repository_digest=provenance_context["repository_digest"],
        task_contract_sha256=task_contract_sha256,
        effective_policy_sha256=effective_policy_sha256,
        gate_definition_sha256=provenance_context["gate_definition_sha256"],
        reviewer_prompt_sha256=provenance_context["reviewer_prompt_sha256"],
        producer=provenance_context["producer"],
        workflow=provenance_context["workflow"],
        tools=provenance_context["tools"],
        environment={
            "source_identity": (capability_report or {}).get("source_identity", "sha256:" + "0" * 64),
            "execution_identity": (capability_report or {}).get("execution_identity", "sha256:" + "0" * 64),
            "sandbox_capability_sha256": capability_sha256,
        },
        materials=provenance_context["materials"],
        started_at=started_at,
        ended_at=ended_at,
        result=status.value,
        limits={
            "timeout_seconds": max(1, int(timeout_seconds)),
            "max_output_bytes": max_output_bytes,
            "process_limit": max(1, int((capability_report or {}).get("process_limit", 1))),
            "memory_bytes": max(1, int((capability_report or {}).get("memory_bytes", 1))),
            "cpu_seconds": max(1, int((capability_report or {}).get("cpu_seconds", 1))),
        },
        artifacts=[
            {"name": "stdout", "sha256": sha256_bytes(stdout)},
            {"name": "stderr", "sha256": sha256_bytes(stderr)},
            {"name": "sandbox-capability", "sha256": capability_sha256},
        ],
        limitations=limitations,
    )
    provenance_path = f"{prefix}/provenance.json"
    provenance_sha256 = artifact_store.write_bytes(
        provenance_path, canonical_json_bytes(provenance)
    )
    result = {
        "schema_version": "1.0.0",
        "repository_id": repository_id,
        "task_contract_sha256": task_contract_sha256,
        "gate_id": gate_id,
        "profile": profile,
        "candidate_before": before,
        "candidate_after": after,
        "source_identity": (capability_report or {}).get("source_identity", "sha256:" + "0" * 64),
        "execution_identity": (capability_report or {}).get("execution_identity", "sha256:" + "0" * 64),
        "sandbox_capability_sha256": capability_sha256,
        "command": list(command),
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": max(0, (ended - started) // 1_000_000),
        "termination": termination,
        "artifacts": [
            {
                "stream": "stdout",
                "path": repository_artifact_path(stdout_path),
                "bytes": len(stdout),
                "sha256": sha256_bytes(stdout),
                "truncated": stdout_capture.truncated,
            },
            {
                "stream": "stderr",
                "path": repository_artifact_path(stderr_path),
                "bytes": len(stderr),
                "sha256": sha256_bytes(stderr),
                "truncated": stderr_capture.truncated,
            },
        ],
        "redactions": redactions,
        "observation_complete": observation_complete,
        "status": status.value,
        "limitations": limitations,
        "provenance_statement": {
            "path": repository_artifact_path(provenance_path),
            "sha256": provenance_sha256,
        },
        "producer_version": producer_version,
    }
    artifact_store.write_bytes(f"{prefix}/result.json", canonical_json_bytes(result))
    return result
