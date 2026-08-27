"""Protected disposable-container sandbox command and capability policy."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_governance.canonical import (
    content_address,
    require_sha256,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.domain.model import GateStatus
from codex_governance.lifecycle import parse_rfc3339


GATE_COPY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class SandboxInvocation:
    """A protected adapter's already-resolved provider invocation."""

    argv: tuple[str, ...]
    capability_report: Mapping[str, Any]
    supervisor_cwd: Path | None = None
    candidate_copy: Path | None = None


def _run_git(repository: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("candidate-copy Git operation failed")
    return completed.stdout


def _remove_scoped(path: Path, boundary: Path) -> None:
    path.relative_to(boundary)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        for child in path.iterdir():
            _remove_scoped(child, boundary)
        path.rmdir()


def _copy_candidate_entry(source: Path, destination: Path) -> None:
    info = source.lstat()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        _remove_scoped(destination, destination.parent)
    if stat.S_ISLNK(info.st_mode):
        destination.symlink_to(os.readlink(source))
    elif stat.S_ISREG(info.st_mode):
        shutil.copyfile(source, destination, follow_symlinks=False)
        destination.chmod(0o755 if info.st_mode & 0o111 else 0o644)
    elif stat.S_ISDIR(info.st_mode):
        shutil.copytree(
            source,
            destination,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", ".git/**"),
        )
    else:
        raise ValueError("unsupported candidate-copy file type")


def prepare_candidate_copy(
    *, repository: Path, destination: Path, evidence_root: str
) -> Path:
    """Create a writable, disposable Git snapshot without ignored machine state."""
    source = repository.resolve(strict=True)
    target = destination.resolve(strict=False)
    evidence = Path(evidence_root)
    if evidence.is_absolute() or ".." in evidence.parts:
        raise ValueError("evidence root must be repository-relative")
    try:
        target.relative_to(source)
    except ValueError:
        pass
    else:
        raise ValueError("sandbox copy must be outside the source repository")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise FileExistsError("sandbox destination must be absent or empty")
    target.parent.mkdir(parents=True, exist_ok=True)
    clone = subprocess.run(
        [
            "git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
            os.fspath(source), os.fspath(target),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if clone.returncode != 0:
        raise RuntimeError("unable to create disposable candidate copy")
    _run_git(target, "checkout", "--quiet", "--detach", "HEAD")
    _run_git(target, "remote", "remove", "origin")
    logs = target / ".git" / "logs"
    if logs.exists():
        _remove_scoped(logs, target)
    names = _run_git(
        source, "ls-files", "-z", "--cached", "--others", "--exclude-standard"
    )
    evidence_posix = evidence.as_posix()
    for raw in names.split(b"\x00"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("candidate-copy paths must be valid UTF-8") from exc
        if relative == evidence_posix or relative.startswith(evidence_posix + "/"):
            continue
        source_path = source.joinpath(*relative.split("/"))
        target_path = target.joinpath(*relative.split("/"))
        if source_path.exists() or source_path.is_symlink():
            _copy_candidate_entry(source_path, target_path)
        elif target_path.exists() or target_path.is_symlink():
            _remove_scoped(target_path, target)
    copied_evidence = target.joinpath(*evidence.parts)
    if copied_evidence.exists() or copied_evidence.is_symlink():
        _remove_scoped(copied_evidence, target)
    return target


def iter_fresh_gate_copies(
    *,
    repository: Path,
    supervisor: Path,
    gate_ids: Sequence[str],
    evidence_root: str,
) -> Iterator[tuple[str, Path]]:
    """Yield a newly reconstructed writable candidate copy for every gate."""
    root = supervisor.resolve(strict=True)
    seen: set[str] = set()
    for gate_id in gate_ids:
        if (
            not isinstance(gate_id, str)
            or GATE_COPY_ID_RE.fullmatch(gate_id) is None
            or gate_id in seen
        ):
            raise ValueError("gate copy identity is invalid or duplicated")
        seen.add(gate_id)
        yield gate_id, prepare_candidate_copy(
            repository=repository,
            destination=root / "gate-candidates" / gate_id,
            evidence_root=evidence_root,
        )


def observe_container_provider(executable: str) -> str:
    """Return a bounded provider version or fail without exposing host details."""
    if executable not in {"docker", "podman"}:
        raise ValueError("unsupported sandbox provider")
    template = "{{.Server.Version}}" if executable == "docker" else "{{.Version}}"
    try:
        completed = subprocess.run(
            [executable, "version", "--format", template],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("sandbox provider is unavailable") from exc
    value = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 or not value or len(value) > 128:
        raise RuntimeError("sandbox provider version is unavailable")
    return value


def validate_sandbox_capability(report: Mapping[str, Any]) -> list[str]:
    """Validate a supervisor-produced report; an assertion alone is not proof."""
    errors: list[str] = []
    if report.get("schema_version") != "1.0.0":
        errors.append("unsupported sandbox capability schema")
    if not verify_content_address(report, "capability_id"):
        errors.append("sandbox capability ID does not reconstruct")
    for key in ("provider", "provider_version"):
        if not isinstance(report.get(key), str) or not report[key]:
            errors.append(f"missing sandbox provider field: {key}")
    try:
        require_sha256(report.get("implementation_sha256"), name="implementation_sha256")
    except ValueError:
        errors.append("missing sandbox implementation identity")
    try:
        parse_rfc3339(report.get("verified_at"))
    except (TypeError, ValueError):
        errors.append("invalid sandbox verification timestamp")
    limitations = report.get("limitations")
    if not isinstance(limitations, list) or not all(
        isinstance(item, str) and item for item in limitations
    ):
        errors.append("invalid sandbox limitations")
    expected = {
        "disposable": True,
        "secrets_present": False,
        "network_mode": "none",
        "candidate_copy_writable": True,
        "protected_paths_writable": False,
        "evidence_paths_writable": False,
        "supervisor_paths_writable": False,
    }
    errors.extend(
        f"unsafe sandbox capability: {key}"
        for key, value in expected.items()
        if report.get(key) != value
    )
    for key in ("process_limit", "memory_bytes", "cpu_seconds", "timeout_seconds", "output_bytes"):
        value = report.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append(f"missing positive sandbox limit: {key}")
    for key in ("source_identity", "execution_identity"):
        value = report.get(key)
        if not isinstance(value, str) or not value.startswith("sha256:"):
            errors.append(f"missing sandbox identity: {key}")
    return sorted(set(errors))


def classify_sandbox_execution(
    *,
    capability_report: Mapping[str, Any] | None,
    termination: str,
    exit_code: int | None,
    output_complete: bool,
) -> GateStatus:
    if not isinstance(capability_report, Mapping) or validate_sandbox_capability(capability_report):
        return GateStatus.UNKNOWN
    if termination != "exited" or exit_code is None or not output_complete:
        return GateStatus.UNKNOWN
    return GateStatus.PASS if exit_code == 0 else GateStatus.FAIL


def build_container_command(
    *,
    executable: str,
    image: str,
    candidate_copy: str,
    command: Sequence[str],
    process_limit: int,
    memory_bytes: int,
    cpu_seconds: int,
) -> list[str]:
    if executable not in {"docker", "podman"}:
        raise ValueError("protected sandbox provider must be docker or podman")
    candidate_path = Path(candidate_copy)
    if (
        "@sha256:" not in image
        or not command
        or process_limit < 1
        or memory_bytes < 1
        or cpu_seconds < 1
    ):
        raise ValueError("sandbox image, command and limits are required")
    if (
        not candidate_copy
        or not candidate_path.is_absolute()
        or candidate_path.resolve(strict=False) != candidate_path
        or any(not isinstance(item, str) or item == "" for item in command)
    ):
        raise ValueError("candidate copy and command values must be non-empty")
    user_arguments: list[str] = []
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if callable(getuid) and callable(getgid):
        user_arguments = ["--user", f"{getuid()}:{getgid()}"]
    return [
        executable,
        "run",
        "--rm",
        "--network=none",
        *user_arguments,
        f"--pids-limit={process_limit}",
        f"--memory={memory_bytes}",
        "--ulimit",
        f"cpu={cpu_seconds}:{cpu_seconds}",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,exec,nosuid,nodev,size=67108864",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--mount",
        f"type=bind,src={candidate_copy},dst=/workspace",
        "--workdir=/workspace",
        image,
        *command,
    ]


def build_container_invocation(
    *,
    executable: str,
    provider_version: str,
    image: str,
    candidate_copy: Path,
    candidate_id: str,
    command: Sequence[str],
    process_limit: int,
    memory_bytes: int,
    cpu_seconds: int,
    timeout_seconds: int,
    output_bytes: int,
    implementation_sha256: str,
    verified_at: str,
    supervisor_cwd: Path | None = None,
) -> SandboxInvocation:
    """Build the only supported production sandbox invocation and its receipt."""
    source_identity = require_sha256(candidate_id, name="candidate_id")
    implementation_identity = require_sha256(
        implementation_sha256, name="implementation_sha256"
    )
    parse_rfc3339(verified_at)
    if timeout_seconds < 1 or output_bytes < 1 or not provider_version:
        raise ValueError("sandbox observation bounds and provider version are required")
    resolved_copy = candidate_copy.resolve(strict=True)
    if not resolved_copy.is_dir() or resolved_copy != candidate_copy:
        raise ValueError("candidate copy must be an absolute, resolved directory")
    argv = build_container_command(
        executable=executable,
        image=image,
        candidate_copy=str(resolved_copy),
        command=command,
        process_limit=process_limit,
        memory_bytes=memory_bytes,
        cpu_seconds=cpu_seconds,
    )
    execution_identity = sha256_canonical(
        {
            "provider": executable,
            "provider_version": provider_version,
            "image": image,
            "command": list(command),
            "process_limit": process_limit,
            "memory_bytes": memory_bytes,
            "cpu_seconds": cpu_seconds,
            "timeout_seconds": timeout_seconds,
            "output_bytes": output_bytes,
        }
    )
    report = content_address(
        {
            "schema_version": "1.0.0",
            "provider": executable,
            "provider_version": provider_version,
            "implementation_sha256": implementation_identity,
            "source_identity": source_identity,
            "execution_identity": execution_identity,
            "disposable": True,
            "secrets_present": False,
            "network_mode": "none",
            "candidate_copy_writable": True,
            "protected_paths_writable": False,
            "evidence_paths_writable": False,
            "supervisor_paths_writable": False,
            "process_limit": process_limit,
            "memory_bytes": memory_bytes,
            "cpu_seconds": cpu_seconds,
            "timeout_seconds": timeout_seconds,
            "output_bytes": output_bytes,
            "verified_at": verified_at,
            "limitations": ["unsigned local capability report"],
        },
        "capability_id",
    )
    errors = validate_sandbox_capability(report)
    if errors:
        raise ValueError("; ".join(errors))
    return SandboxInvocation(tuple(argv), report, supervisor_cwd, resolved_copy)
