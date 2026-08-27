"""Bounded deterministic gate process adapter."""

from __future__ import annotations

import os
import signal
import subprocess
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
from codex_governance.sandbox import SandboxInvocation, validate_sandbox_capability


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

    def read(self, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                self.total += len(chunk)
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
        finally:
            stream.close()

    @property
    def truncated(self) -> bool:
        return self.total > len(self.data)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _redact_runtime_paths(
    data: bytes, sandbox_invocation: SandboxInvocation | None
) -> tuple[bytes, list[dict[str, Any]]]:
    """Remove supervisor-only machine paths before evidence enters a repository."""
    if sandbox_invocation is None:
        return data, []
    replacements: list[tuple[bytes, bytes, str]] = []
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
    result = data
    redactions: list[dict[str, Any]] = []
    for original, replacement, category in replacements:
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
    return result, redactions


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


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

    before = candidate_supplier()
    started_at = _utc_now()
    started = time.monotonic_ns()
    stdout_capture = _BoundedCapture(max_output_bytes)
    stderr_capture = _BoundedCapture(max_output_bytes)
    termination: dict[str, Any]
    observation_complete = True
    return_code: int | None = None
    threads: list[threading.Thread] = []
    capability_report = (
        dict(sandbox_invocation.capability_report)
        if isinstance(sandbox_invocation, SandboxInvocation)
        else None
    )
    if capability_report is None or validate_sandbox_capability(capability_report):
        termination = {"kind": "launch_error", "detail": "sandbox_capability_unavailable"}
        observation_complete = False
    else:
        try:
            creationflags = (
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            )
            process = subprocess.Popen(
                list(sandbox_invocation.argv),
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
                return_code = process.wait(timeout=timeout_seconds)
                if return_code < 0:
                    termination = {"kind": "signal", "signal": str(-return_code)}
                    observation_complete = False
                else:
                    termination = {"kind": "exited", "exit_code": return_code}
            except subprocess.TimeoutExpired:
                termination = {"kind": "timeout"}
                observation_complete = False
                _terminate_process_tree(process)
        except OSError as exc:
            termination = {
                "kind": "launch_error",
                "detail": exc.__class__.__name__,
            }
            observation_complete = False
        finally:
            for thread in threads:
                thread.join(timeout=3)
                if thread.is_alive():
                    observation_complete = False
            if any(thread.is_alive() for thread in threads) and "process" in locals():
                _terminate_process_tree(process)
                for thread in threads:
                    thread.join(timeout=1)
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
    if capability_report is None or validate_sandbox_capability(capability_report):
        limitations.append("required disposable sandbox capability was unavailable")
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
