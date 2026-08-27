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
        self.path = self.root / ".pipeline.lock"
        self._descriptor: int | None = None

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

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise PipelineLockError("pipeline lock is already held by this object")
        self._reject_symlinks()
        self.root.mkdir(parents=True, exist_ok=True)
        self._reject_symlinks()
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise PipelineLockError("pipeline lock file is unavailable") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise PipelineLockError("pipeline lock is not a regular file")
            if info.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            self._lock_descriptor(descriptor)
        except BaseException:
            os.close(descriptor)
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
        self._descriptor = None
        if descriptor is None:
            return
        try:
            self._unlock_descriptor(descriptor)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "PipelineLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()
