"""Protected disposable-container sandbox command and capability policy."""

from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
import subprocess
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_governance.artifacts import (
    ArtifactSafetyError,
    copy_bounded_repository_entry,
    read_bounded_path_file,
)
from codex_governance.canonical import (
    content_address,
    normalize_repo_path,
    require_git_object,
    require_sha256,
    sha256_bytes,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.domain.model import GateStatus
from codex_governance.lifecycle import parse_rfc3339


GATE_COPY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
PROTECTED_PACKAGE_CONTAINER_ROOT = "/opt/codex-governance"


class CandidatePreparationError(RuntimeError):
    """A disposable candidate could not be prepared within its bound."""


@dataclass(frozen=True, slots=True)
class SandboxInvocation:
    """A protected adapter's already-resolved provider invocation."""

    argv: tuple[str, ...]
    capability_report: Mapping[str, Any]
    supervisor_cwd: Path | None = None
    candidate_copy: Path | None = None
    container_provider: str | None = None
    container_name: str | None = None
    container_id_file: Path | None = None
    protected_source_root: Path | None = None


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CandidatePreparationError("candidate preparation deadline expired")
    return remaining


def _run_git(repository: Path, *args: str, deadline: float | None = None) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(repository), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_remaining(deadline),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidatePreparationError(
            "candidate-copy Git operation unavailable"
        ) from exc
    if completed.returncode != 0:
        raise CandidatePreparationError("candidate-copy Git operation failed")
    return completed.stdout


def _remove_scoped(path: Path, boundary: Path) -> None:
    path.relative_to(boundary)
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        for child in path.iterdir():
            _remove_scoped(child, boundary)
        path.rmdir()


def _copy_candidate_entry(
    repository: Path,
    relative_path: str,
    destination: Path,
    *,
    deadline: float | None = None,
) -> None:
    if destination.exists() or destination.is_symlink():
        _remove_scoped(destination, destination.parent)
    try:
        copy_bounded_repository_entry(
            repository,
            relative_path,
            destination,
            deadline=deadline,
        )
    except ArtifactSafetyError as exc:
        raise CandidatePreparationError(
            "candidate entry copy was unavailable"
        ) from exc


def _submodule_states(
    repository: Path, *, deadline: float | None = None
) -> list[dict[str, str]]:
    output = _run_git(
        repository, "submodule", "status", "--recursive", deadline=deadline
    ).decode(
        "utf-8", "strict"
    )
    states: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line:
            continue
        marker, fields = line[0], line[1:].split()
        if marker in {"-", "+", "U"} or len(fields) < 2:
            raise ValueError("submodule state is unavailable or dirty")
        states.append(
            {
                "path": normalize_repo_path(fields[1]),
                "commit": require_git_object(fields[0], name="submodule commit"),
            }
        )
    return sorted(states, key=lambda item: (item["path"].count("/"), item["path"]))


def _copy_submodule(
    source: Path,
    destination: Path,
    commit: str,
    boundary: Path,
    *,
    deadline: float | None = None,
) -> None:
    if destination.exists() or destination.is_symlink():
        _remove_scoped(destination, boundary)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        cloned = subprocess.run(
            [
                "git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                os.fspath(source), os.fspath(destination),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_remaining(deadline),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidatePreparationError(
            "candidate submodule clone unavailable"
        ) from exc
    if cloned.returncode != 0:
        raise CandidatePreparationError("unable to reconstruct candidate submodule")
    _run_git(
        destination,
        "checkout",
        "--quiet",
        "--detach",
        commit,
        deadline=deadline,
    )
    _run_git(destination, "remote", "remove", "origin", deadline=deadline)
    logs = destination / ".git" / "logs"
    if logs.exists():
        _remove_scoped(logs, destination)
    observed_commit = (
        _run_git(destination, "rev-parse", "HEAD", deadline=deadline)
        .decode("ascii")
        .strip()
    )
    if observed_commit != commit:
        raise RuntimeError("candidate submodule commit mismatch")


def prepare_protected_package_copy(*, package_root: Path, destination: Path) -> Path:
    """Materialize and verify exactly the package producer manifest."""
    from codex_governance.attestation import producer_implementation_manifest

    source = package_root.resolve(strict=True)
    target = destination.resolve(strict=False)
    if not source.is_dir():
        raise ValueError("protected package source must be a directory")
    try:
        target.relative_to(source)
    except ValueError:
        pass
    else:
        raise ValueError("protected package copy must be outside its source")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise FileExistsError("protected package destination must be absent or empty")
    target.mkdir(parents=True, exist_ok=True)
    manifest = producer_implementation_manifest("gate", source)
    package_name = source.name
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", package_name):
        raise ValueError("protected package name is not importable")
    expected: set[str] = set()
    for entry in manifest["files"]:
        relative = normalize_repo_path(entry["path"])
        source_path = source.joinpath(*relative.split("/"))
        if source_path.is_symlink() or not source_path.is_file():
            raise ValueError("protected package closure contains an unsafe file")
        resolved = source_path.resolve(strict=True)
        try:
            resolved.relative_to(source)
        except ValueError as exc:
            raise ValueError("protected package closure escapes its source") from exc
        data = resolved.read_bytes()
        if len(data) != entry["bytes"] or sha256_bytes(data) != entry["sha256"]:
            raise ValueError("protected package source does not match its manifest")
        destination_path = target / package_name / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved, destination_path, follow_symlinks=False)
        if sha256_bytes(destination_path.read_bytes()) != entry["sha256"]:
            raise ValueError("protected package copy does not match its manifest")
        destination_path.chmod(0o444)
        expected.add(f"{package_name}/{relative}")
    observed = {
        path.relative_to(target).as_posix()
        for path in target.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if observed != expected:
        raise ValueError("protected package materialization contains unexpected files")
    directories = sorted(
        (path for path in target.rglob("*") if path.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    )
    for directory in directories:
        directory.chmod(0o555)
    target.chmod(0o555)
    return target


def prepare_candidate_copy(
    *,
    repository: Path,
    destination: Path,
    evidence_root: str,
    deadline: float | None = None,
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
    try:
        clone = subprocess.run(
            [
                "git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                os.fspath(source), os.fspath(target),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_remaining(deadline),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidatePreparationError("disposable candidate clone unavailable") from exc
    if clone.returncode != 0:
        raise CandidatePreparationError("unable to create disposable candidate copy")
    _run_git(target, "checkout", "--quiet", "--detach", "HEAD", deadline=deadline)
    _run_git(target, "remote", "remove", "origin", deadline=deadline)
    logs = target / ".git" / "logs"
    if logs.exists():
        _remove_scoped(logs, target)
    submodules = _submodule_states(source, deadline=deadline)
    submodule_paths = {item["path"] for item in submodules}
    names = _run_git(
        source, "ls-files", "-z", "--cached", "--others", "--exclude-standard",
        deadline=deadline,
    )
    deleted_names = {
        normalize_repo_path(raw.decode("utf-8"))
        for raw in _run_git(
            source, "ls-files", "-z", "--deleted", deadline=deadline
        ).split(b"\x00")
        if raw
    }
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
        if relative in submodule_paths:
            continue
        target_path = target.joinpath(*relative.split("/"))
        if relative not in deleted_names:
            _copy_candidate_entry(
                source,
                relative,
                target_path,
                deadline=deadline,
            )
        elif target_path.exists() or target_path.is_symlink():
            _remove_scoped(target_path, target)
    for submodule in submodules:
        relative = submodule["path"]
        _copy_submodule(
            source.joinpath(*relative.split("/")),
            target.joinpath(*relative.split("/")),
            submodule["commit"],
            target,
            deadline=deadline,
        )
    copied_evidence = target.joinpath(*evidence.parts)
    if copied_evidence.exists() or copied_evidence.is_symlink():
        _remove_scoped(copied_evidence, target)
    _remaining(deadline)
    return target


def iter_fresh_gate_copies(
    *,
    repository: Path,
    supervisor: Path,
    gate_ids: Sequence[str],
    evidence_root: str,
    deadline: float | None = None,
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
            deadline=deadline,
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
    if report.get("schema_version") != "2.0.0":
        errors.append("unsupported sandbox capability schema")
    if not verify_content_address(report, "capability_id"):
        errors.append("sandbox capability ID does not reconstruct")
    for key in ("provider", "provider_version", "image"):
        if not isinstance(report.get(key), str) or not report[key]:
            errors.append(f"missing sandbox provider field: {key}")
    command = report.get("command")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) or not item for item in command)
    ):
        errors.append("missing sandbox command identity")
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
    try:
        reconstructed_identity = sandbox_execution_identity(
            provider=report["provider"],
            provider_version=report["provider_version"],
            image=report["image"],
            command=report["command"],
            process_limit=report["process_limit"],
            memory_bytes=report["memory_bytes"],
            cpu_seconds=report["cpu_seconds"],
            timeout_seconds=report["timeout_seconds"],
            output_bytes=report["output_bytes"],
        )
        if reconstructed_identity != report.get("execution_identity"):
            errors.append("sandbox execution identity does not reconstruct")
    except (KeyError, TypeError, ValueError):
        errors.append("sandbox execution identity inputs are incomplete")
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


def sandbox_execution_identity(
    *,
    provider: str,
    provider_version: str,
    image: str,
    command: Sequence[str],
    process_limit: int,
    memory_bytes: int,
    cpu_seconds: int,
    timeout_seconds: int,
    output_bytes: int,
) -> str:
    """Reconstruct the complete protected container execution identity."""
    if (
        provider not in {"docker", "podman"}
        or not isinstance(provider_version, str)
        or not provider_version
        or not isinstance(image, str)
        or "@sha256:" not in image
        or not command
        or any(not isinstance(item, str) or not item for item in command)
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 1
            for value in (
                process_limit, memory_bytes, cpu_seconds,
                timeout_seconds, output_bytes,
            )
        )
    ):
        raise ValueError("complete sandbox execution inputs are required")
    return sha256_canonical(
        {
            "provider": provider,
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


def build_container_command(
    *,
    executable: str,
    image: str,
    candidate_copy: str,
    command: Sequence[str],
    process_limit: int,
    memory_bytes: int,
    cpu_seconds: int,
    container_name: str,
    container_id_file: str,
    protected_source_root: str | None = None,
) -> list[str]:
    if executable not in {"docker", "podman"}:
        raise ValueError("protected sandbox provider must be docker or podman")
    candidate_path = Path(candidate_copy)
    cidfile_path = Path(container_id_file)
    protected_path = (
        Path(protected_source_root) if protected_source_root is not None else None
    )
    if (
        "@sha256:" not in image
        or not command
        or process_limit < 1
        or memory_bytes < 1
        or cpu_seconds < 1
        or CONTAINER_NAME_RE.fullmatch(container_name) is None
    ):
        raise ValueError("sandbox image, command and limits are required")
    if (
        not candidate_copy
        or not candidate_path.is_absolute()
        or candidate_path.resolve(strict=False) != candidate_path
        or not container_id_file
        or not cidfile_path.is_absolute()
        or cidfile_path.resolve(strict=False) != cidfile_path
        or any(not isinstance(item, str) or item == "" for item in command)
        or (
            protected_path is not None
            and (
                not protected_path.is_absolute()
                or protected_path.resolve(strict=True) != protected_path
                or not protected_path.is_dir()
            )
        )
    ):
        raise ValueError("candidate copy and command values must be non-empty")
    user_arguments: list[str] = []
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if callable(getuid) and callable(getgid):
        user_arguments = ["--user", f"{getuid()}:{getgid()}"]
    return [
        executable,
        "create",
        "--name",
        container_name,
        "--cidfile",
        container_id_file,
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
        *(
            [
                "--mount",
                (
                    f"type=bind,src={protected_source_root},"
                    f"dst={PROTECTED_PACKAGE_CONTAINER_ROOT},readonly"
                ),
            ]
            if protected_source_root is not None
            else []
        ),
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
    protected_source_root: Path | None = None,
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
    runtime_root = (supervisor_cwd or resolved_copy.parent).resolve(strict=True)
    try:
        resolved_copy.relative_to(runtime_root)
    except ValueError as exc:
        raise ValueError("candidate copy must be beneath the sandbox supervisor") from exc
    resolved_protected_source: Path | None = None
    if protected_source_root is not None:
        resolved_protected_source = protected_source_root.resolve(strict=True)
        if not resolved_protected_source.is_dir():
            raise ValueError("protected source root must be a directory")
        try:
            resolved_protected_source.relative_to(resolved_copy)
        except ValueError:
            pass
        else:
            raise ValueError("protected source root cannot come from the candidate copy")
    container_name = "codex-governance-" + secrets.token_hex(16)
    container_id_file = runtime_root / f"{container_name}.cid"
    if container_id_file.exists() or container_id_file.is_symlink():
        raise ValueError("container identity file must not already exist")
    argv = build_container_command(
        executable=executable,
        image=image,
        candidate_copy=str(resolved_copy),
        command=command,
        process_limit=process_limit,
        memory_bytes=memory_bytes,
        cpu_seconds=cpu_seconds,
        container_name=container_name,
        container_id_file=os.fspath(container_id_file),
        protected_source_root=(
            os.fspath(resolved_protected_source)
            if resolved_protected_source is not None
            else None
        ),
    )
    execution_identity = sandbox_execution_identity(
        provider=executable,
        provider_version=provider_version,
        image=image,
        command=command,
        process_limit=process_limit,
        memory_bytes=memory_bytes,
        cpu_seconds=cpu_seconds,
        timeout_seconds=timeout_seconds,
        output_bytes=output_bytes,
    )
    report = content_address(
        {
            "schema_version": "2.0.0",
            "provider": executable,
            "provider_version": provider_version,
            "image": image,
            "command": list(command),
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
            "limitations": [],
        },
        "capability_id",
    )
    errors = validate_sandbox_capability(report)
    if errors:
        raise ValueError("; ".join(errors))
    return SandboxInvocation(
        tuple(argv),
        report,
        runtime_root,
        resolved_copy,
        executable,
        container_name,
        container_id_file,
        resolved_protected_source,
    )


def _container_identity(invocation: SandboxInvocation) -> tuple[str, str, Path] | None:
    provider = invocation.container_provider
    name = invocation.container_name
    cidfile = invocation.container_id_file
    if (
        provider not in {"docker", "podman"}
        or not isinstance(name, str)
        or CONTAINER_NAME_RE.fullmatch(name) is None
        or not isinstance(cidfile, Path)
        or not cidfile.is_absolute()
        or cidfile.resolve(strict=False) != cidfile
    ):
        return None
    return provider, name, cidfile


def create_container(
    invocation: SandboxInvocation, *, timeout_seconds: float
) -> str | None:
    """Complete bounded container creation and validate its immutable identity."""
    identity = _container_identity(invocation)
    if identity is None or timeout_seconds <= 0:
        return None
    provider, name, cidfile = identity
    deadline = time.monotonic() + timeout_seconds
    if cidfile.exists() or cidfile.is_symlink():
        return None
    try:
        created = subprocess.run(
            list(invocation.argv),
            cwd=invocation.supervisor_cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=max(0.001, deadline - time.monotonic()),
            check=False,
        )
        if created.returncode != 0:
            return None
        container_id = _read_container_id_file(cidfile, deadline=deadline)
        stdout_id = created.stdout.decode("ascii").strip()
        if (
            CONTAINER_ID_RE.fullmatch(container_id) is None
            or stdout_id != container_id
        ):
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        inspected = subprocess.run(
            [
                provider,
                "container",
                "inspect",
                "--format",
                "{{.Id}} {{.Name}}",
                container_id,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=min(10.0, remaining),
            check=False,
        )
        if (
            inspected.returncode != 0
            or inspected.stdout.decode("utf-8").strip()
            != f"{container_id} /{name}"
        ):
            return None
        return container_id
    except (
        ArtifactSafetyError,
        OSError,
        subprocess.TimeoutExpired,
        UnicodeError,
        ValueError,
    ):
        return None


def build_container_start_command(
    invocation: SandboxInvocation, container_id: str
) -> list[str]:
    identity = _container_identity(invocation)
    if identity is None or CONTAINER_ID_RE.fullmatch(container_id) is None:
        raise ValueError("validated immutable container identity is required")
    return [identity[0], "start", "--attach", container_id]


def _listed_containers(
    provider: str, *, filter_value: str, deadline: float
) -> list[tuple[str, str]] | None:
    """Return validated all-container rows; provider failure is inconclusive."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        observed = subprocess.run(
            [
                provider,
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--format",
                "{{.ID}} {{.Names}}",
                "--filter",
                filter_value,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=min(10.0, remaining),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if observed.returncode != 0:
        return None
    rows: list[tuple[str, str]] = []
    try:
        text = observed.stdout.decode("utf-8")
    except UnicodeError:
        return None
    for raw in text.splitlines():
        fields = raw.strip().split()
        if len(fields) != 2 or CONTAINER_ID_RE.fullmatch(fields[0]) is None:
            return None
        rows.append((fields[0], fields[1]))
    return rows


def _read_container_id_file(cidfile: Path, *, deadline: float) -> str:
    value = read_bounded_path_file(
        cidfile, max_bytes=129, deadline=deadline
    ).decode("ascii").strip()
    if CONTAINER_ID_RE.fullmatch(value) is None:
        raise ValueError("container ID file is invalid")
    return value


def _cidfile_identity(
    cidfile: Path, *, deadline: float
) -> tuple[bool, str | None]:
    if not cidfile.exists() and not cidfile.is_symlink():
        return True, None
    try:
        value = _read_container_id_file(cidfile, deadline=deadline)
    except (ArtifactSafetyError, OSError, UnicodeError, ValueError):
        return False, None
    return True, value


def cleanup_container(
    invocation: SandboxInvocation,
    container_id: str | None,
    *,
    timeout_seconds: float = 10.0,
) -> bool:
    """Remove resolved exact IDs and prove stable provider-confirmed absence."""
    identity = _container_identity(invocation)
    if identity is None or timeout_seconds <= 0:
        return False
    provider, name, cidfile = identity
    deadline = time.monotonic() + timeout_seconds
    supplied_valid = (
        isinstance(container_id, str)
        and CONTAINER_ID_RE.fullmatch(container_id) is not None
    )
    resolved_ids: set[str] = {container_id} if supplied_valid else set()
    removal_failed = False
    identity_tainted = False
    removed_ids: set[str] = set()
    stable_absence = 0
    try:
        while time.monotonic() < deadline:
            cidfile_valid, cidfile_id = _cidfile_identity(
                cidfile, deadline=deadline
            )
            if not cidfile_valid:
                return False
            if cidfile_id is not None:
                if supplied_valid and cidfile_id != container_id:
                    identity_tainted = True
                resolved_ids.add(cidfile_id)

            name_rows = _listed_containers(
                provider, filter_value=f"name=^/{name}$", deadline=deadline
            )
            if name_rows is None or any(row_name != name for _, row_name in name_rows):
                return False
            if supplied_valid and any(row_id != container_id for row_id, _ in name_rows):
                identity_tainted = True
            resolved_ids.update(row_id for row_id, _ in name_rows)

            for resolved in sorted(resolved_ids - removed_ids):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                removed = subprocess.run(
                    [provider, "rm", "--force", resolved],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=min(10.0, remaining),
                    check=False,
                )
                removed_ids.add(resolved)
                if removed.returncode != 0:
                    removal_failed = True

            id_present = False
            for resolved in sorted(resolved_ids):
                rows = _listed_containers(
                    provider, filter_value=f"id={resolved}", deadline=deadline
                )
                if rows is None or any(row_id != resolved for row_id, _ in rows):
                    return False
                if any(row_name != name for _, row_name in rows):
                    identity_tainted = True
                id_present = id_present or bool(rows)
            name_rows = _listed_containers(
                provider, filter_value=f"name=^/{name}$", deadline=deadline
            )
            if name_rows is None or any(row_name != name for _, row_name in name_rows):
                return False
            if not id_present and not name_rows:
                stable_absence += 1
                if stable_absence >= 3:
                    complete_identity = bool(
                        supplied_valid
                        and cidfile_id == container_id
                        and container_id in removed_ids
                    )
                    if complete_identity and not removal_failed and not identity_tainted:
                        cidfile.unlink()
                        return True
                    if supplied_valid and cidfile_id == container_id:
                        return False
                    # An unresolved create may materialize after any fixed
                    # number of empty polls. Keep the reserved name under
                    # quarantine for the complete bounded cleanup interval.
            else:
                stable_absence = 0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.1, remaining))
        return False
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return False
