"""Small standard-library helpers for the protected authority adapters."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
AUTHORITATIVE_READ_TIMEOUT_SECONDS = 5.0
_OBSERVED_FILE_BYTES: dict[Path, bytes] = {}
_DESCRIPTOR_READ_PROGRAM = """import os, sys
source = int(sys.argv[1])
remaining = int(sys.argv[2]) + 1
while remaining:
    block = os.read(source, min(65536, remaining))
    if not block:
        break
    sys.stdout.buffer.write(block)
    remaining -= len(block)
sys.stdout.buffer.flush()
"""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def content_address(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result.pop(field, None)
    result[field] = sha256_bytes(canonical_bytes(result))
    return result


def verify_decision_source_assertion(
    observation: Mapping[str, Any],
    decisions: Sequence[Mapping[str, Any]],
    *,
    authorization_receipt: Mapping[str, Any] | None = None,
) -> set[str]:
    """Authenticate decisions selected by a dispatch or its protected receipt."""
    assertion = observation.get("decision_source_assertion")
    if not isinstance(assertion, Mapping) or set(assertion) != {
        "event_name",
        "actor",
        "authority_repository",
        "authority_ref",
        "authority_commit",
        "authority_basis_commit",
        "workflow_run_id",
        "approved_decision_ids",
        "authorization_receipt_id",
    }:
        raise ValueError("decision source assertion is missing or malformed")
    expected_digest = sha256_bytes(canonical_bytes(dict(assertion)))
    actor = assertion.get("actor")
    repository = require_repository(assertion.get("authority_repository"))
    ref = assertion.get("authority_ref")
    selected = assertion.get("approved_decision_ids")
    event_name = assertion.get("event_name")
    receipt_id = assertion.get("authorization_receipt_id")
    if (
        observation.get("decision_source_assertion_sha256") != expected_digest
        or event_name not in {"workflow_dispatch", "schedule"}
        or not isinstance(actor, str)
        or not actor.startswith("github:")
        or len(actor) <= len("github:")
        or ref != "refs/heads/governance-authority"
        or observation.get("authority_commit") != assertion.get("authority_commit")
        or observation.get("authority_basis_commit")
        != assertion.get("authority_basis_commit")
        or not isinstance(assertion.get("workflow_run_id"), str)
        or not assertion.get("workflow_run_id")
        or not isinstance(selected, list)
        or any(not isinstance(item, str) or DIGEST_RE.fullmatch(item) is None for item in selected)
        or len(selected) != len(set(selected))
    ):
        raise ValueError("decision source assertion does not reconstruct")
    require_sha(assertion.get("authority_commit"), "authority commit")
    require_sha(assertion.get("authority_basis_commit"), "authority basis commit")
    if event_name == "workflow_dispatch":
        if receipt_id is not None or authorization_receipt is not None:
            raise ValueError("manual decision assertion cannot inherit an authorization receipt")
    else:
        if not isinstance(authorization_receipt, Mapping):
            raise ValueError("scheduled decision assertion lacks its protected receipt")
        receipt = dict(authorization_receipt)
        if (
            set(receipt)
            != {
                "schema_version",
                "receipt_id",
                "repository_id",
                "target_id",
                "authority_repository",
                "authority_ref",
                "authority_decision_commit",
                "authority_basis_commit",
                "actor",
                "approved_decision_ids",
                "decision_source_assertion",
                "decision_source_assertion_sha256",
            }
            or receipt.get("schema_version") != "1.0.0"
            or content_address(receipt, "receipt_id") != receipt
            or receipt_id != receipt.get("receipt_id")
            or not isinstance(observation.get("authorization_receipt"), Mapping)
            or observation["authorization_receipt"].get("receipt_id") != receipt_id
            or receipt.get("authority_repository") != repository
            or receipt.get("authority_ref") != ref
            or receipt.get("authority_basis_commit")
            != assertion.get("authority_basis_commit")
            or receipt.get("approved_decision_ids") != selected
            or receipt.get("actor") != actor
        ):
            raise ValueError("scheduled authorization receipt does not reconstruct")
        original = receipt.get("decision_source_assertion")
        if (
            not isinstance(original, Mapping)
            or set(original) != set(assertion)
            or original.get("event_name") != "workflow_dispatch"
            or original.get("authorization_receipt_id") is not None
            or not isinstance(original.get("workflow_run_id"), str)
            or not original.get("workflow_run_id")
            or original.get("actor") != actor
            or original.get("authority_repository") != repository
            or original.get("authority_ref") != ref
            or original.get("authority_commit")
            != receipt.get("authority_decision_commit")
            or original.get("authority_basis_commit")
            != receipt.get("authority_basis_commit")
            or original.get("approved_decision_ids") != selected
            or receipt.get("decision_source_assertion_sha256")
            != sha256_bytes(canonical_bytes(dict(original)))
        ):
            raise ValueError("original authenticated dispatch receipt is invalid")
        require_sha(receipt.get("authority_decision_commit"), "authority decision commit")
    descriptor = {
        "subject": actor,
        "authentication_method": "github-actions-workflow-dispatch",
        "protected_source": repository + "@" + str(ref),
    }
    observed_ids: set[str] = set()
    for decision in decisions:
        decision_id = require_digest(decision.get("decision_id"), "selected decision")
        if content_address(dict(decision), "decision_id") != dict(decision):
            raise ValueError("selected decision identity does not reconstruct")
        issuer = decision.get("issuer")
        if not isinstance(issuer, Mapping) or dict(issuer) != {
            **descriptor,
            "assertion_sha256": sha256_bytes(canonical_bytes(descriptor)),
        }:
            raise ValueError("selected decision issuer assertion does not reconstruct")
        observed_ids.add(decision_id)
    if observed_ids != set(selected):
        raise ValueError("selected decision set differs from authenticated dispatch")
    return observed_ids


def require_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a full Git commit SHA")
    return value


def require_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 digest")
    return value


def require_repository(value: Any) -> str:
    if not isinstance(value, str) or REPOSITORY_RE.fullmatch(value) is None:
        raise ValueError("repository must be owner/name")
    return value


def _normalize_repo_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("repository path must be a non-empty POSIX string")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/"):
        raise ValueError("repository path must be relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("repository path is not normalized")
    if path.as_posix() != value:
        raise ValueError("repository path is not canonical")
    return value


def _candidate_entries(
    entries: Sequence[Mapping[str, Any]], *, submodule: bool
) -> list[dict[str, str]]:
    if isinstance(entries, (str, bytes)):
        raise ValueError("candidate entries must be a list")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    required = {"path", "commit"} if submodule else {"path", "mode", "sha256"}
    for raw in entries:
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise ValueError("candidate entry has unexpected properties")
        path = _normalize_repo_path(raw["path"])
        if path in seen:
            raise ValueError("candidate paths must be unique")
        seen.add(path)
        if submodule:
            result.append(
                {"path": path, "commit": require_sha(raw["commit"], "submodule commit")}
            )
        else:
            mode = raw["mode"]
            if (
                not isinstance(mode, str)
                or len(mode) != 6
                or any(char not in "01234567" for char in mode)
            ):
                raise ValueError("entry mode must be a six-digit octal Git mode")
            result.append(
                {
                    "path": path,
                    "mode": mode,
                    "sha256": require_digest(raw["sha256"], "entry sha256"),
                }
            )
    return sorted(result, key=lambda item: item["path"])


def verify_candidate_identity(candidate: Mapping[str, Any]) -> bool:
    """Reconstruct the candidate ID using the protected implementation's algorithm."""
    try:
        repository_id = candidate["repository_id"]
        if not isinstance(repository_id, str) or not repository_id.startswith("repo:"):
            raise ValueError("repository_id must be protected")
        mode = candidate["mode"]
        if mode not in {"commit", "working_tree"}:
            raise ValueError("unsupported candidate mode")
        base = require_sha(candidate["base_commit"], "base_commit")
        raw_head = candidate.get("head_commit")
        head = require_sha(raw_head, "head_commit") if raw_head is not None else None
        if mode == "commit" and head is None:
            raise ValueError("commit mode requires head_commit")
        raw_changed = candidate["changed_paths"]
        if not isinstance(raw_changed, Sequence) or isinstance(raw_changed, (str, bytes)):
            raise ValueError("changed_paths must be a list")
        changed = sorted(_normalize_repo_path(path) for path in raw_changed)
        if len(changed) != len(set(changed)):
            raise ValueError("changed_paths must be unique")
        raw_untracked = candidate["untracked_entries"]
        raw_submodules = candidate["submodules"]
        if not isinstance(raw_untracked, Sequence) or not isinstance(raw_submodules, Sequence):
            raise ValueError("candidate entries must be lists")
        untracked = _candidate_entries(raw_untracked, submodule=False)
        if mode == "commit" and untracked:
            raise ValueError("commit mode cannot contain untracked entries")
        if not {item["path"] for item in untracked}.issubset(changed):
            raise ValueError("untracked entries must be changed paths")
        payload = {
            "schema_version": "1.0.0",
            "repository_id": repository_id,
            "mode": mode,
            "base_commit": base,
            "tracked_diff_sha256": require_digest(
                candidate["tracked_diff_sha256"], "tracked_diff_sha256"
            ),
            "changed_paths": changed,
            "untracked_entries": untracked,
            "submodules": _candidate_entries(raw_submodules, submodule=True),
            "effective_policy_sha256": require_digest(
                candidate["effective_policy_sha256"], "effective_policy_sha256"
            ),
        }
        if head is not None:
            payload["head_commit"] = head
        return require_digest(candidate["candidate_id"], "candidate_id") == sha256_bytes(
            canonical_bytes(payload)
        )
    except (KeyError, TypeError, ValueError):
        return False


def reset_authoritative_read_session() -> None:
    """Start a new command-level observation session (primarily for in-process tests)."""
    _OBSERVED_FILE_BYTES.clear()


def _entry_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_descriptor(source: int, *, max_bytes: int, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("authoritative input deadline expired")
    cleanup_reserve = min(0.25, max(0.01, remaining * 0.1))
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            _DESCRIPTOR_READ_PROGRAM,
            str(source),
            str(max_bytes),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        pass_fds=(source,),
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(
            timeout=max(0.001, remaining - cleanup_reserve)
        )
    except subprocess.TimeoutExpired as exc:
        process.kill()
        try:
            process.communicate(timeout=max(0.001, deadline - time.monotonic()))
        except (subprocess.TimeoutExpired, ValueError) as cleanup_exc:
            raise ValueError("authoritative input cleanup was incomplete") from cleanup_exc
        raise ValueError("authoritative input read timed out") from exc
    if process.returncode != 0 or len(output) > max_bytes:
        raise ValueError("authoritative input read failed or exceeded its bound")
    if time.monotonic() >= deadline:
        raise ValueError("authoritative input deadline expired")
    return output


def read_bytes_fresh(path: Path, *, max_bytes: int = 8_000_000) -> bytes:
    """Make one fresh descriptor-bound observation for mutable-state checks."""
    if max_bytes < 1:
        raise ValueError("authoritative input size bound must be positive")
    observed = Path(os.path.abspath(os.fspath(path)))
    if (
        os.name != "posix"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or observed.anchor != os.sep
    ):
        raise ValueError("descriptor-bound authoritative reads are unavailable")
    parts = observed.parts[1:]
    if not parts:
        raise ValueError("authoritative input must name a file")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    bindings: list[tuple[int, str, tuple[int, int]]] = []
    leaf_descriptor = -1
    deadline = time.monotonic() + AUTHORITATIVE_READ_TIMEOUT_SECONDS
    try:
        parent = os.open(os.sep, directory_flags)
        descriptors.append(parent)
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=parent)
            child_info = os.fstat(child)
            if not stat.S_ISDIR(child_info.st_mode):
                os.close(child)
                raise ValueError("authoritative input parent is not a directory")
            bindings.append((parent, part, (child_info.st_dev, child_info.st_ino)))
            descriptors.append(child)
            parent = child
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        leaf_descriptor = os.open(
            parts[-1],
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
        opened = os.fstat(leaf_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _entry_identity(before) != _entry_identity(opened)
            or opened.st_size > max_bytes
        ):
            raise ValueError("authoritative input leaf is unsafe")
        data = _read_descriptor(
            leaf_descriptor, max_bytes=max_bytes, deadline=deadline
        )
        if _entry_identity(os.fstat(leaf_descriptor)) != _entry_identity(opened):
            raise ValueError("authoritative input changed during read")
        for parent_descriptor, name, identity in bindings:
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or (
                current.st_dev,
                current.st_ino,
            ) != identity:
                raise ValueError("authoritative input parent binding changed")
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if _entry_identity(current) != _entry_identity(opened):
            raise ValueError("authoritative input leaf binding changed")
        return data
    except OSError as exc:
        raise ValueError(f"unsafe authoritative input: {path}") from exc
    finally:
        if leaf_descriptor >= 0:
            os.close(leaf_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read_bytes_once(path: Path, *, max_bytes: int = 8_000_000) -> bytes:
    """Reuse one descriptor-bound, no-follow observation for this command."""
    observed = Path(os.path.abspath(os.fspath(path)))
    cached = _OBSERVED_FILE_BYTES.get(observed)
    if cached is not None:
        if len(cached) > max_bytes:
            raise ValueError(f"oversized authoritative input: {path}")
        return cached
    data = read_bytes_fresh(observed, max_bytes=max_bytes)
    _OBSERVED_FILE_BYTES[observed] = data
    return data


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_nonfinite_json_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def load_json(path: Path) -> Any:
    return json.loads(
        read_bytes_once(path).decode("utf-8"),
        object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=_reject_nonfinite_json_number,
    )


def load_and_validate_once(instance_path: Path, schema_path: Path) -> Any:
    """Validate instance and schema from the command's exact cached observations."""
    from codex_governance.schema import (
        SchemaValidationError,
        validate_instance,
        validate_semantics,
    )

    instance = load_json(instance_path)
    schema = load_json(schema_path)
    if not isinstance(schema, dict):
        raise SchemaValidationError(["$: schema must be an object"])
    errors = validate_instance(instance, schema)
    errors.extend(
        validate_semantics(
            instance, schema_path.name.removesuffix(".schema.json")
        )
    )
    if errors:
        raise SchemaValidationError(errors)
    return instance


def ensure_within(root: Path, path: Path) -> Path:
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    lexical_path = Path(os.path.abspath(os.fspath(path)))
    lexical_path.relative_to(lexical_root)
    return lexical_path


def require_json_within(
    repository: Path, evidence_root: Path, relative_path: Any
) -> Path:
    """Resolve a repository reference only when it is inside the evidence root."""
    normalized = _normalize_repo_path(relative_path)
    repository = Path(os.path.abspath(os.fspath(repository)))
    evidence_root = ensure_within(repository, evidence_root)
    path = ensure_within(repository, repository.joinpath(*normalized.split("/")))
    path.relative_to(evidence_root)
    load_json(path)
    return path


def write_once(path: Path, value: Any) -> None:
    data = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError:
        if read_bytes_once(path, max_bytes=max(1, len(data))) != data:
            raise ValueError(f"refusing to replace authority output: {path}")
        return
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def copy_json_once(source: Path, destination: Path) -> Any:
    """Validate JSON and preserve the exact protected source bytes."""
    data = read_bytes_once(source)
    value = load_json(source)
    _write_bytes_once(destination, data)
    return value


def copy_bytes_once(source: Path, destination: Path, *, max_bytes: int) -> str:
    data = read_bytes_once(source, max_bytes=max_bytes)
    _write_bytes_once(destination, data)
    return sha256_bytes(data)


def _write_bytes_once(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError:
        if read_bytes_once(destination, max_bytes=max(1, len(data))) != data:
            raise ValueError(f"refusing to replace authority output: {destination}")
    else:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)


def file_reference(repository: Path, path: Path) -> dict[str, str]:
    relative = ensure_within(repository, path).relative_to(
        Path(os.path.abspath(os.fspath(repository)))
    ).as_posix()
    data = read_bytes_once(path)
    return {"path": relative, "sha256": sha256_bytes(data)}
