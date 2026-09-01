"""Portable fail-closed working-tree pipeline lock."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

from codex_governance.canonical import normalize_repo_path


class PipelineLockError(RuntimeError):
    """The governed working tree is already in use or cannot be locked."""


class PipelineLock:
    """Hold one non-blocking OS-backed lock beneath the evidence root."""

    def __init__(self, *, repository: Path, evidence_root: str | Path):
        self.repository = repository.resolve(strict=True)
        raw_root = evidence_root.as_posix() if isinstance(evidence_root, Path) else evidence_root
        normalized = normalize_repo_path(raw_root)
        self.root = self.repository.joinpath(*normalized.split("/"))
        self.path = self.root
        self._descriptor: int | None = None
        self._root_descriptor: int | None = None

    @staticmethod
    def _secure_dir_fd_available() -> bool:
        return bool(
            os.name == "posix"
            and hasattr(os, "O_DIRECTORY")
            and hasattr(os, "O_NOFOLLOW")
            and os.open in os.supports_dir_fd
            and os.mkdir in os.supports_dir_fd
        )

    def _reject_symlinks(self) -> None:
        current = self.repository
        for part in self.root.relative_to(self.repository).parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode):
                raise PipelineLockError("pipeline lock path contains a symlink")
            if not stat.S_ISDIR(info.st_mode):
                raise PipelineLockError("pipeline lock parent is not a directory")

    def _open_bound_root(self) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            descriptor = os.open(self.repository, flags)
        except OSError as exc:
            raise PipelineLockError("repository lock root is unavailable") from exc
        try:
            for part in self.root.relative_to(self.repository).parts:
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    try:
                        os.mkdir(part, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=descriptor)
                except OSError as exc:
                    try:
                        parent_entry = os.stat(
                            part, dir_fd=descriptor, follow_symlinks=False
                        )
                    except OSError:
                        parent_entry = None
                    if parent_entry is not None and stat.S_ISLNK(parent_entry.st_mode):
                        raise PipelineLockError(
                            "pipeline lock path contains a symlink"
                        ) from exc
                    raise PipelineLockError(
                        "pipeline lock path contains an unsafe parent"
                    ) from exc
                info = os.fstat(child)
                if not stat.S_ISDIR(info.st_mode):
                    os.close(child)
                    raise PipelineLockError("pipeline lock parent is not a directory")
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @property
    def root_identity(self) -> tuple[int, int]:
        if self._root_descriptor is None:
            raise PipelineLockError("pipeline lock root is not bound")
        info = os.fstat(self._root_descriptor)
        return info.st_dev, info.st_ino

    def assert_binding(self) -> None:
        if self._root_descriptor is None:
            raise PipelineLockError("pipeline lock root is not bound")
        try:
            self._reject_symlinks()
            current = self.root.stat(follow_symlinks=False)
        except OSError as exc:
            raise PipelineLockError("pipeline lock root binding changed") from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != self.root_identity
        ):
            raise PipelineLockError("pipeline lock root binding changed")

    def acquire(self) -> None:
        if self._descriptor is not None or self._root_descriptor is not None:
            raise PipelineLockError("pipeline lock is already held by this object")
        if not self._secure_dir_fd_available():
            raise PipelineLockError(
                "directory-bound no-follow pipeline locking is unavailable"
            )
        root_descriptor = self._open_bound_root()
        self._root_descriptor = root_descriptor
        try:
            self.assert_binding()
        except BaseException:
            self._root_descriptor = None
            os.close(root_descriptor)
            raise
        descriptor: int | None = None
        try:
            descriptor = os.dup(root_descriptor)
            self._lock_descriptor(descriptor)
            self.assert_binding()
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            self._root_descriptor = None
            os.close(root_descriptor)
            raise
        self._descriptor = descriptor

    @staticmethod
    def _lock_descriptor(descriptor: int) -> None:
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                raise PipelineLockError("OS-backed pipeline locking is unavailable")
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise PipelineLockError("governance pipeline lock is contended") from exc
            raise PipelineLockError("governance pipeline lock failed") from exc

    @staticmethod
    def _unlock_descriptor(descriptor: int) -> None:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)

    def release(self) -> None:
        descriptor = self._descriptor
        root_descriptor = self._root_descriptor
        self._descriptor = None
        self._root_descriptor = None
        if descriptor is None and root_descriptor is None:
            return
        try:
            if descriptor is not None:
                self._unlock_descriptor(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)

    def __enter__(self) -> "PipelineLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()
