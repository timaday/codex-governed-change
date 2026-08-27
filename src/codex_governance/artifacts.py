"""Atomic, bounded, repository-contained evidence storage."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from codex_governance.canonical import normalize_repo_path, require_sha256, sha256_bytes


class ArtifactSafetyError(ValueError):
    pass


class FilesystemArtifactStore:
    def __init__(self, *, repository: Path, root: Path, max_bytes: int = 8_000_000):
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.repository = repository.resolve()
        if root.is_absolute():
            root_candidate = root
        else:
            normalized_root = normalize_repo_path(root.as_posix())
            root_candidate = self.repository.joinpath(*normalized_root.split("/"))
        try:
            relative = root_candidate.relative_to(self.repository)
        except ValueError as exc:
            raise ArtifactSafetyError("evidence root escapes repository") from exc
        if relative == Path("."):
            raise ArtifactSafetyError("evidence root cannot be the repository root")
        self.root = root_candidate
        self.max_bytes = max_bytes
        self._reject_symlink_chain(self.root, include_leaf=True)
        try:
            self.root.resolve(strict=False).relative_to(self.repository)
        except ValueError as exc:
            raise ArtifactSafetyError("evidence root resolves outside repository") from exc

    def _reject_symlink_chain(self, path: Path, *, include_leaf: bool) -> None:
        try:
            relative = path.relative_to(self.repository)
        except ValueError as exc:
            raise ArtifactSafetyError("artifact path escapes repository") from exc
        current = self.repository
        parts = relative.parts if include_leaf else relative.parts[:-1]
        for part in parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode):
                raise ArtifactSafetyError("artifact path contains a symlink")
            if current != path and not stat.S_ISDIR(info.st_mode):
                raise ArtifactSafetyError("artifact parent is not a directory")

    def _target(self, relative_path: str) -> Path:
        normalized = normalize_repo_path(relative_path)
        target = self.root.joinpath(*normalized.split("/"))
        self._reject_symlink_chain(target, include_leaf=True)
        return target

    def write_bytes(self, relative_path: str, data: bytes, *, overwrite: bool = False) -> str:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        if len(data) > self.max_bytes:
            raise ArtifactSafetyError("artifact exceeds configured size bound")
        target = self._target(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        self._reject_symlink_chain(target, include_leaf=True)
        if overwrite:
            # Retained only as a fail-closed compatibility parameter. Authority
            # artifacts are never mutable, regardless of caller intent.
            overwrite = False
        if target.exists():
            existing = self.read_bytes(relative_path)
            if existing == data:
                return sha256_bytes(data)
            raise FileExistsError("write-once artifact conflicts with existing content")
        temporary = target.parent / f".{target.name}.tmp-{secrets.token_hex(12)}"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            self._reject_symlink_chain(target, include_leaf=True)
            try:
                os.link(temporary, target)
            except FileExistsError as exc:
                try:
                    existing = self.read_bytes(relative_path)
                except (OSError, ValueError):
                    raise FileExistsError("write-once artifact won a conflicting race") from exc
                if existing != data:
                    raise FileExistsError("write-once artifact won a conflicting race") from exc
                return sha256_bytes(data)
            temporary.unlink()
            directory_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return sha256_bytes(data)

    def read_bytes(self, relative_path: str, *, expected_sha256: str | None = None) -> bytes:
        target = self._target(relative_path)
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ArtifactSafetyError("artifact is not a regular file")
        if info.st_size > self.max_bytes:
            raise ArtifactSafetyError("artifact exceeds configured size bound")
        data = target.read_bytes()
        if expected_sha256 is not None and sha256_bytes(data) != require_sha256(expected_sha256):
            raise ArtifactSafetyError("artifact digest mismatch")
        return data

    def verify(self, relative_path: str, expected_sha256: str) -> bool:
        try:
            self.read_bytes(relative_path, expected_sha256=expected_sha256)
        except (OSError, ValueError):
            return False
        return True
