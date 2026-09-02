"""Atomic, bounded, repository-contained evidence storage."""

from __future__ import annotations

import os
import errno
import secrets
import stat
from pathlib import Path

from codex_governance.canonical import normalize_repo_path, require_sha256, sha256_bytes


class ArtifactSafetyError(ValueError):
    pass


def secure_repository_reads_available() -> bool:
    """Return whether directory-bound no-follow reads are supported."""
    return bool(
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.readlink in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
    )


def _entry_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_bounded_repository_entry(
    repository: Path, relative_path: str, *, max_bytes: int = 8_000_000
) -> tuple[str, bytes, os.stat_result]:
    """Observe one regular file or symbolic-link target through retained descriptors."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if not secure_repository_reads_available():
        raise ArtifactSafetyError(
            "directory-bound no-follow repository reads are unavailable"
        )
    normalized = normalize_repo_path(relative_path)
    parts = tuple(normalized.split("/"))
    root = repository.resolve(strict=True)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[int] = []
    bindings: list[tuple[int, str, tuple[int, int]]] = []
    leaf_descriptor = -1
    try:
        root_before = root.stat(follow_symlinks=False)
        root_descriptor = os.open(root, directory_flags)
        descriptors.append(root_descriptor)
        root_held = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_held.st_mode)
            or (root_before.st_dev, root_before.st_ino)
            != (root_held.st_dev, root_held.st_ino)
        ):
            raise ArtifactSafetyError("repository root binding changed")
        parent = root_descriptor
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=parent)
            child_info = os.fstat(child)
            if not stat.S_ISDIR(child_info.st_mode):
                os.close(child)
                raise ArtifactSafetyError("repository file parent is not a directory")
            bindings.append(
                (parent, part, (child_info.st_dev, child_info.st_ino))
            )
            descriptors.append(child)
            parent = child
        leaf_before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if stat.S_ISREG(leaf_before.st_mode):
            leaf_flags = (
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            leaf_descriptor = os.open(parts[-1], leaf_flags, dir_fd=parent)
            leaf_info = os.fstat(leaf_descriptor)
            if (
                not stat.S_ISREG(leaf_info.st_mode)
                or _entry_identity(leaf_before) != _entry_identity(leaf_info)
            ):
                raise ArtifactSafetyError("repository leaf binding changed")
            if leaf_info.st_size > max_bytes:
                raise ArtifactSafetyError("repository reference exceeds the size bound")
            with os.fdopen(leaf_descriptor, "rb", closefd=True) as stream:
                leaf_descriptor = -1
                data = stream.read(max_bytes + 1)
                leaf_after_read = os.fstat(stream.fileno())
            if _entry_identity(leaf_after_read) != _entry_identity(leaf_info):
                raise ArtifactSafetyError("repository leaf changed during read")
            kind = "regular"
        elif stat.S_ISLNK(leaf_before.st_mode):
            target = os.readlink(parts[-1], dir_fd=parent)
            data = os.fsencode(target)
            leaf_info = leaf_before
            kind = "symlink"
        else:
            raise ArtifactSafetyError(
                "repository reference is not a regular file or symbolic link"
            )
        if len(data) > max_bytes:
            raise ArtifactSafetyError("repository reference exceeds the size bound")

        current_root = root.stat(follow_symlinks=False)
        if (current_root.st_dev, current_root.st_ino) != (
            root_held.st_dev,
            root_held.st_ino,
        ):
            raise ArtifactSafetyError("repository root binding changed")
        for parent_descriptor, name, expected in bindings:
            current = os.stat(
                name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (
                not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != expected
            ):
                raise ArtifactSafetyError("repository parent binding changed")
        current_leaf = os.stat(
            parts[-1], dir_fd=parent, follow_symlinks=False
        )
        if _entry_identity(current_leaf) != _entry_identity(leaf_info):
            raise ArtifactSafetyError("repository leaf binding changed")
        return kind, data, leaf_info
    except ArtifactSafetyError:
        raise
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ArtifactSafetyError("repository reference is a symlink") from exc
        raise ArtifactSafetyError("repository reference is unavailable") from exc
    finally:
        if leaf_descriptor >= 0:
            os.close(leaf_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read_bounded_repository_file(
    repository: Path, relative_path: str, *, max_bytes: int = 8_000_000
) -> bytes:
    """Read an exact regular repository file through retained descriptors."""
    kind, data, _ = read_bounded_repository_entry(
        repository, relative_path, max_bytes=max_bytes
    )
    if kind != "regular":
        raise ArtifactSafetyError("repository reference is a symlink")
    return data


def read_bounded_path_file(path: Path, *, max_bytes: int = 8_000_000) -> bytes:
    """Read an authoritative pathname without following any path component."""
    absolute = path.absolute()
    if not absolute.is_absolute() or absolute.anchor != os.sep:
        raise ArtifactSafetyError("authoritative path is unsupported")
    relative_parts = absolute.parts[1:]
    if not relative_parts:
        raise ArtifactSafetyError("authoritative path must name a file")
    return read_bounded_repository_file(
        Path(absolute.anchor),
        "/".join(relative_parts),
        max_bytes=max_bytes,
    )


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
            secure_repository_reads_available()
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
        no_follow = os.O_NOFOLLOW
        flags = os.O_RDONLY | no_follow | getattr(os, "O_NONBLOCK", 0)
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
            try:
                current = os.stat(
                    leaf, dir_fd=parent, follow_symlinks=not bool(no_follow)
                )
            except OSError as exc:
                raise ArtifactSafetyError("artifact leaf binding changed") from exc
            if (
                not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ArtifactSafetyError("artifact leaf binding changed")
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
