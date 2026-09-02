"""Deterministic Git candidate identity adapter."""

from __future__ import annotations

import os
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_governance.canonical import (
    normalize_repo_path,
    require_git_object,
    require_sha256,
    sha256_bytes,
    sha256_canonical,
)


def _canonical_entries(
    entries: Sequence[Mapping[str, Any]], *, submodule: bool
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise ValueError("candidate entry must be an object")
        required = {"path", "commit"} if submodule else {"path", "mode", "sha256"}
        if set(raw) != required:
            raise ValueError("candidate entry has unexpected properties")
        path = normalize_repo_path(raw["path"])
        if path in seen:
            raise ValueError(f"duplicate candidate path: {path}")
        seen.add(path)
        if submodule:
            result.append(
                {
                    "path": path,
                    "commit": require_git_object(raw["commit"], name="submodule commit"),
                }
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
                    "sha256": require_sha256(raw["sha256"]),
                }
            )
    return sorted(result, key=lambda item: item["path"])


def _canonical_paths(paths: Sequence[str]) -> list[str]:
    normalized = [normalize_repo_path(path) for path in paths]
    if len(normalized) != len(set(normalized)):
        raise ValueError("candidate changed paths must be unique")
    return sorted(normalized)


def candidate_id_from_components(
    *,
    repository_id: str,
    mode: str,
    base_commit: str,
    head_commit: str | None,
    tracked_diff_sha256: str,
    changed_paths: Sequence[str],
    untracked_entries: Sequence[Mapping[str, Any]],
    submodules: Sequence[Mapping[str, Any]],
    effective_policy_sha256: str,
) -> str:
    """Return the digest of a canonical, validated candidate description."""
    if mode not in {"commit", "working_tree"}:
        raise ValueError("candidate mode must be commit or working_tree")
    if not isinstance(repository_id, str) or not repository_id.startswith("repo:"):
        raise ValueError("repository_id must be a protected stable repository identity")
    base = require_git_object(base_commit, name="base_commit")
    head = (
        require_git_object(head_commit, name="head_commit")
        if head_commit is not None
        else None
    )
    if mode == "commit" and head is None:
        raise ValueError("commit mode requires head_commit")
    if mode == "commit" and untracked_entries:
        raise ValueError("commit mode cannot contain untracked entries")
    canonical_untracked = _canonical_entries(untracked_entries, submodule=False)
    canonical_changed = _canonical_paths(changed_paths)
    if not {item["path"] for item in canonical_untracked}.issubset(canonical_changed):
        raise ValueError("every untracked candidate entry must be a changed path")
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "repository_id": repository_id,
        "mode": mode,
        "base_commit": base,
        "tracked_diff_sha256": require_sha256(
            tracked_diff_sha256, name="tracked_diff_sha256"
        ),
        "changed_paths": canonical_changed,
        "untracked_entries": canonical_untracked,
        "submodules": _canonical_entries(submodules, submodule=True),
        "effective_policy_sha256": require_sha256(
            effective_policy_sha256, name="effective_policy_sha256"
        ),
    }
    if head is not None:
        payload["head_commit"] = head
    return sha256_canonical(payload)


def verify_candidate_identity(candidate: Mapping[str, Any]) -> bool:
    """Reconstruct a candidate identity from every identity-bearing field."""
    try:
        reconstructed = candidate_id_from_components(
            repository_id=candidate["repository_id"],
            mode=candidate["mode"],
            base_commit=candidate["base_commit"],
            head_commit=candidate.get("head_commit"),
            tracked_diff_sha256=candidate["tracked_diff_sha256"],
            changed_paths=candidate["changed_paths"],
            untracked_entries=candidate["untracked_entries"],
            submodules=candidate["submodules"],
            effective_policy_sha256=candidate["effective_policy_sha256"],
        )
    except (KeyError, TypeError, ValueError):
        return False
    return reconstructed == candidate.get("candidate_id")


class GitCommandError(RuntimeError):
    """A Git observation could not be completed."""


class GitCliRepositoryAdapter:
    """Read-only Git adapter using shell-free argument arrays."""

    def __init__(
        self,
        repository: Path,
        *,
        git_executable: str = "git",
        deadline: float | None = None,
    ):
        self.repository = repository.resolve()
        self.git_executable = git_executable
        self.deadline = deadline
        if not self.repository.is_dir():
            raise ValueError("repository must be an existing directory")
        root = Path(self._git("rev-parse", "--show-toplevel").decode("utf-8").strip())
        if root.resolve() != self.repository:
            raise ValueError("repository must be the Git worktree root")

    def _git(self, *args: str) -> bytes:
        timeout = None
        if self.deadline is not None:
            timeout = self.deadline - time.monotonic()
            if timeout <= 0:
                raise GitCommandError("Git observation deadline expired")
        try:
            completed = subprocess.run(
                [self.git_executable, "-C", os.fspath(self.repository), *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitCommandError(
                f"unable to launch Git: {exc.__class__.__name__}"
            ) from exc
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()[:500]
            raise GitCommandError(
                f"Git command failed ({completed.returncode}): {detail}"
            )
        return completed.stdout

    def resolve_commit(self, revision: str) -> str:
        value = (
            self._git("rev-parse", "--verify", f"{revision}^{{commit}}")
            .decode("ascii")
            .strip()
        )
        return require_git_object(value)

    @staticmethod
    def _outside_evidence(path: str, evidence_root: str | None) -> bool:
        return evidence_root is None or (
            path != evidence_root and not path.startswith(evidence_root + "/")
        )

    def _untracked(self, evidence_root: str | None) -> list[dict[str, str]]:
        names = self._git(
            "ls-files", "-z", "--others", "--exclude-standard"
        ).split(b"\x00")
        entries: list[dict[str, str]] = []
        for name in names:
            if not name:
                continue
            try:
                path = normalize_repo_path(name.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise ValueError("candidate paths must be valid UTF-8") from exc
            if not self._outside_evidence(path, evidence_root):
                continue
            absolute = self.repository.joinpath(*path.split("/"))
            info = absolute.lstat()
            if stat.S_ISLNK(info.st_mode):
                content = os.fsencode(os.readlink(absolute))
                mode = "120000"
            elif stat.S_ISREG(info.st_mode):
                content = absolute.read_bytes()
                mode = "100755" if info.st_mode & 0o111 else "100644"
            else:
                raise ValueError(
                    f"unsupported untracked candidate file type: {path}"
                )
            entries.append(
                {"path": path, "mode": mode, "sha256": sha256_bytes(content)}
            )
        return sorted(entries, key=lambda item: item["path"])

    def _submodules(self) -> list[dict[str, str]]:
        output = self._git("submodule", "status", "--recursive").decode(
            "utf-8", "strict"
        )
        entries: list[dict[str, str]] = []
        for line in output.splitlines():
            if not line:
                continue
            marker, remainder = line[0], line[1:]
            fields = remainder.split()
            if marker in {"-", "+", "U"} or len(fields) < 2:
                raise ValueError("submodule state is unavailable or dirty")
            entries.append(
                {
                    "path": normalize_repo_path(fields[1]),
                    "commit": require_git_object(fields[0]),
                }
            )
        return sorted(entries, key=lambda item: item["path"])

    def _tracked_changed_paths(self, base: str, head: str | None) -> list[str]:
        arguments = ["diff", "--name-only", "-z", "--no-renames", base]
        if head is not None:
            arguments.append(head)
        arguments.append("--")
        paths: list[str] = []
        for raw in self._git(*arguments).split(b"\x00"):
            if not raw:
                continue
            try:
                paths.append(normalize_repo_path(raw.decode("utf-8")))
            except UnicodeDecodeError as exc:
                raise ValueError("candidate paths must be valid UTF-8") from exc
        return _canonical_paths(paths)

    def conservative_affected_closure(
        self,
        *,
        candidate: Mapping[str, Any],
        evidence_root: str | None,
    ) -> list[str]:
        """Return the complete Git-visible repository closure for a candidate."""
        if not verify_candidate_identity(candidate):
            raise ValueError("affected closure requires a verified candidate")
        evidence = (
            normalize_repo_path(evidence_root) if evidence_root is not None else None
        )
        paths: list[str] = []
        for raw in self._git(
            "ls-files", "-z", "--cached", "--others", "--exclude-standard"
        ).split(b"\x00"):
            if not raw:
                continue
            try:
                path = normalize_repo_path(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise ValueError("candidate paths must be valid UTF-8") from exc
            if self._outside_evidence(path, evidence):
                paths.append(path)
        return _canonical_paths(
            sorted({*paths, *candidate.get("changed_paths", ())})
        )

    def identify(
        self,
        *,
        repository_id: str,
        mode: str,
        base_commit: str,
        effective_policy_sha256: str,
        head_commit: str | None = None,
        evidence_root: str | None = None,
    ) -> dict[str, Any]:
        base = self.resolve_commit(base_commit)
        evidence = (
            normalize_repo_path(evidence_root) if evidence_root is not None else None
        )
        if mode == "commit":
            head = self.resolve_commit(head_commit or "HEAD")
            actual_head = self.resolve_commit("HEAD")
            if actual_head != head:
                raise ValueError(
                    "actual checkout HEAD does not match requested head_commit"
                )
        elif mode == "working_tree":
            head = self.resolve_commit(head_commit or "HEAD")
        else:
            raise ValueError("candidate mode must be commit or working_tree")
        submodules = self._submodules()
        if self._submodules_dirty(submodules):
            raise ValueError("dirty submodule working trees cannot be identified")
        if mode == "commit":
            tracked_status = self._git(
                "status", "--porcelain=v1", "-z", "--untracked-files=no"
            )
            if tracked_status or self._untracked(evidence):
                raise ValueError("commit mode requires a clean checkout")
            diff = self._git(
                "diff", "--binary", "--no-ext-diff", "--full-index", base, head, "--"
            )
            untracked: list[dict[str, str]] = []
            changed_paths = self._tracked_changed_paths(base, head)
            dirty = False
        elif mode == "working_tree":
            diff = self._git(
                "diff", "--binary", "--no-ext-diff", "--full-index", base, "--"
            )
            untracked = self._untracked(evidence)
            changed_paths = _canonical_paths(
                [
                    *self._tracked_changed_paths(base, None),
                    *(item["path"] for item in untracked),
                ]
            )
            dirty = bool(diff or untracked)
        tracked_digest = sha256_bytes(diff)
        candidate_id = candidate_id_from_components(
            repository_id=repository_id,
            mode=mode,
            base_commit=base,
            head_commit=head,
            tracked_diff_sha256=tracked_digest,
            changed_paths=changed_paths,
            untracked_entries=untracked,
            submodules=submodules,
            effective_policy_sha256=effective_policy_sha256,
        )
        return {
            "schema_version": "1.0.0",
            "repository_id": repository_id,
            "candidate_id": candidate_id,
            "mode": mode,
            "base_commit": base,
            "head_commit": head,
            "tracked_diff_sha256": tracked_digest,
            "changed_paths": changed_paths,
            "untracked_entries": untracked,
            "submodules": submodules,
            "effective_policy_sha256": require_sha256(effective_policy_sha256),
            "dirty": dirty,
        }

    def _submodules_dirty(self, submodules: Sequence[Mapping[str, str]]) -> bool:
        for submodule in submodules:
            output = self._git(
                "-C",
                submodule["path"],
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            )
            if output:
                return True
        return False


def identify_candidate(**kwargs: Any) -> dict[str, Any]:
    repository = Path(kwargs.pop("repository"))
    return GitCliRepositoryAdapter(repository).identify(**kwargs)
