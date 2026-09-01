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
    def __init__(
        self,
        *,
        repository: Path,
        root: Path,
        max_bytes: int = 8_000_000,
        expected_root_identity: tuple[int, int] | None = None,
    ):
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
        normalized_relative = normalize_repo_path(relative.as_posix())
        self._root_parts = tuple(normalized_relative.split("/"))
        self.root = self.repository.joinpath(*self._root_parts)
        self.max_bytes = max_bytes
        self.expected_root_identity = expected_root_identity
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

    def validate_target(self, relative_path: str) -> None:
        """Validate an artifact destination without creating any directories."""
        self._target(relative_path)

    def validate_root_binding(self) -> None:
        """Prove the configured root still names the expected bound directory."""
        if not self._secure_dir_fd_available():
            raise ArtifactSafetyError(
                "directory-bound no-follow artifact access is unavailable"
            )
        descriptor = self._open_bound_directory(self._root_parts, create=False)
        try:
            self._assert_directory_binding(self.root, descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _secure_dir_fd_available() -> bool:
        required = (os.open, os.mkdir, os.link, os.unlink, os.stat)
        return bool(
            os.name == "posix"
            and hasattr(os, "O_DIRECTORY")
            and hasattr(os, "O_NOFOLLOW")
            and all(function in os.supports_dir_fd for function in required)
        )

    def _open_bound_directory(
        self, parts: tuple[str, ...], *, create: bool
    ) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(self.repository, flags)
        try:
            for index, part in enumerate(parts):
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    child = os.open(part, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise ArtifactSafetyError(
                        "artifact path contains an unsafe parent"
                    ) from exc
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode):
                    os.close(child)
                    raise ArtifactSafetyError("artifact parent is not a directory")
                if (
                    self.expected_root_identity is not None
                    and index + 1 == len(self._root_parts)
                    and (info.st_dev, info.st_ino) != self.expected_root_identity
                ):
                    os.close(child)
                    raise ArtifactSafetyError("evidence root binding changed")
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _assert_directory_binding(self, directory: Path, descriptor: int) -> None:
        try:
            self._reject_symlink_chain(directory, include_leaf=True)
            current = directory.stat(follow_symlinks=False)
            held = os.fstat(descriptor)
        except OSError as exc:
            raise ArtifactSafetyError("artifact parent binding changed") from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)
        ):
            raise ArtifactSafetyError("artifact parent binding changed")

    def _read_bound_leaf(self, parent: int, leaf: str) -> tuple[bytes, os.stat_result]:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(leaf, flags, dir_fd=parent)
        except OSError as exc:
            raise ArtifactSafetyError("artifact leaf is unavailable") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ArtifactSafetyError("artifact is not a regular file")
            if info.st_size > self.max_bytes:
                raise ArtifactSafetyError("artifact exceeds configured size bound")
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                descriptor = -1
                data = stream.read(self.max_bytes + 1)
            if len(data) > self.max_bytes:
                raise ArtifactSafetyError("artifact exceeds configured size bound")
            return data, info
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _unlink_bound_identity(
        parent: int, leaf: str, expected: os.stat_result
    ) -> None:
        try:
            current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
                os.unlink(leaf, dir_fd=parent)
        except FileNotFoundError:
            pass

    def _write_bytes_secure(self, relative_path: str, data: bytes) -> str:
        normalized = normalize_repo_path(relative_path)
        relative_parts = tuple(normalized.split("/"))
        target = self.root.joinpath(*relative_parts)
        parent = self._open_bound_directory(
            self._root_parts + relative_parts[:-1], create=True
        )
        temporary = f".{relative_parts[-1]}.tmp-{secrets.token_hex(12)}"
        temporary_created = False
        published: os.stat_result | None = None
        try:
            self._assert_directory_binding(target.parent, parent)
            try:
                existing, _ = self._read_bound_leaf(parent, relative_parts[-1])
            except FileNotFoundError:
                existing = None
            except ArtifactSafetyError:
                try:
                    os.stat(relative_parts[-1], dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    existing = None
                else:
                    raise
            if existing is not None:
                self._assert_directory_binding(target.parent, parent)
                if existing == data:
                    return sha256_bytes(data)
                raise FileExistsError("write-once artifact conflicts with existing content")

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600, dir_fd=parent)
            temporary_created = True
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temporary_info = os.stat(
                temporary, dir_fd=parent, follow_symlinks=False
            )
            self._assert_directory_binding(target.parent, parent)
            try:
                os.link(
                    temporary,
                    relative_parts[-1],
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
                published = temporary_info
            except FileExistsError as exc:
                existing, _ = self._read_bound_leaf(parent, relative_parts[-1])
                self._assert_directory_binding(target.parent, parent)
                if existing != data:
                    raise FileExistsError(
                        "write-once artifact won a conflicting race"
                    ) from exc
                return sha256_bytes(data)
            os.unlink(temporary, dir_fd=parent)
            temporary_created = False
            self._assert_directory_binding(target.parent, parent)
            observed, observed_info = self._read_bound_leaf(
                parent, relative_parts[-1]
            )
            if (
                observed != data
                or (observed_info.st_dev, observed_info.st_ino)
                != (temporary_info.st_dev, temporary_info.st_ino)
            ):
                raise ArtifactSafetyError("published artifact identity changed")
            os.fsync(parent)
            return sha256_bytes(data)
        except BaseException:
            if published is not None:
                self._unlink_bound_identity(parent, relative_parts[-1], published)
            raise
        finally:
            if temporary_created:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
            os.close(parent)

    def write_bytes(self, relative_path: str, data: bytes, *, overwrite: bool = False) -> str:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        if len(data) > self.max_bytes:
            raise ArtifactSafetyError("artifact exceeds configured size bound")
        if not self._secure_dir_fd_available():
            raise ArtifactSafetyError(
                "directory-bound no-follow artifact publication is unavailable"
            )
        return self._write_bytes_secure(relative_path, data)

    def read_bytes(self, relative_path: str, *, expected_sha256: str | None = None) -> bytes:
        if not self._secure_dir_fd_available():
            raise ArtifactSafetyError(
                "directory-bound no-follow artifact readback is unavailable"
            )
        normalized = normalize_repo_path(relative_path)
        relative_parts = tuple(normalized.split("/"))
        target = self._target(normalized)
        parent = self._open_bound_directory(
            self._root_parts + relative_parts[:-1], create=False
        )
        try:
            self._assert_directory_binding(target.parent, parent)
            data, _ = self._read_bound_leaf(parent, relative_parts[-1])
            self._assert_directory_binding(target.parent, parent)
        finally:
            os.close(parent)
        if expected_sha256 is not None and sha256_bytes(data) != require_sha256(expected_sha256):
            raise ArtifactSafetyError("artifact digest mismatch")
        return data

    def verify(self, relative_path: str, expected_sha256: str) -> bool:
        try:
            self.read_bytes(relative_path, expected_sha256=expected_sha256)
        except (OSError, ValueError):
            return False
        return True
