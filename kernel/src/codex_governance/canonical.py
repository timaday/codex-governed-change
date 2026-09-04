"""Canonical, portable representations used at trust boundaries."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import PurePosixPath
from typing import Any


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite numbers are not canonical JSON")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON object keys must be strings")
            _reject_non_finite(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_finite(item)


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON with no insignificant whitespace."""
    _reject_non_finite(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_canonical(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def content_address(document: dict[str, Any] | Any, identity_field: str) -> dict[str, Any]:
    """Bind a canonical document to all top-level fields except its own ID."""
    if not isinstance(document, dict):
        document = dict(document)
    payload = dict(document)
    payload.pop(identity_field, None)
    result = dict(payload)
    result[identity_field] = sha256_bytes(canonical_json_bytes(payload))
    return result


def verify_content_address(document: Any, identity_field: str) -> bool:
    if not isinstance(document, dict):
        try:
            document = dict(document)
        except (TypeError, ValueError):
            return False
    try:
        expected = require_sha256(document.get(identity_field), name=identity_field)
    except ValueError:
        return False
    payload = dict(document)
    payload.pop(identity_field, None)
    return sha256_bytes(canonical_json_bytes(payload)) == expected


def require_sha256(value: Any, *, name: str = "digest") -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase sha256 digest")
    return value


def require_git_object(value: Any, *, name: str = "commit") -> str:
    if not isinstance(value, str) or GIT_OBJECT_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase full Git object id")
    return value


def normalize_repo_path(value: Any) -> str:
    """Validate a repository-relative canonical POSIX path."""
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("repository path must be a non-empty POSIX string")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("/"):
        raise ValueError("repository path must be relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("repository path is not normalized")
    normalized = path.as_posix()
    if normalized != value:
        raise ValueError("repository path is not canonical")
    return normalized
