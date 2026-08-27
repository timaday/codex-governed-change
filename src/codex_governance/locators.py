"""Typed, digest-bound repository and artifact locator resolution."""

from __future__ import annotations

import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codex_governance.canonical import normalize_repo_path, require_sha256, sha256_bytes


def _safe_file(repository: Path, relative_path: Any) -> Path:
    root = repository.resolve()
    normalized = normalize_repo_path(relative_path)
    target = root.joinpath(*normalized.split("/"))
    current = root
    for part in normalized.split("/"):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("evidence locator traverses a symlink")
    if not stat.S_ISREG(target.stat().st_mode):
        raise ValueError("evidence locator does not resolve to a regular file")
    target.resolve().relative_to(root)
    return target


def resolve_evidence_locator(
    repository: Path,
    locator: Mapping[str, Any],
    *,
    max_bytes: int = 8_000_000,
) -> bytes:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    target = _safe_file(repository, locator.get("path"))
    if target.stat().st_size > max_bytes:
        raise ValueError("evidence locator exceeds the size bound")
    data = target.read_bytes()
    if sha256_bytes(data) != require_sha256(locator.get("artifact_sha256")):
        raise ValueError("evidence locator artifact digest mismatch")
    kind = locator.get("kind")
    if kind in {"artifact", "repository_file"}:
        return data
    if kind != "repository_excerpt":
        raise ValueError("unknown evidence locator kind")
    start = locator.get("start_line")
    end = locator.get("end_line")
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
        raise ValueError("excerpt locator has invalid line bounds")
    lines = data.splitlines(keepends=True)
    if end > len(lines):
        raise ValueError("excerpt locator line is outside the artifact")
    excerpt = b"".join(lines[start - 1 : end])
    if sha256_bytes(excerpt) != require_sha256(locator.get("excerpt_sha256")):
        raise ValueError("evidence locator excerpt digest mismatch")
    return excerpt
