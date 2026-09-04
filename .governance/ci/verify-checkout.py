#!/usr/bin/env python3
"""Verify the actual clean Git checkout, not only a resolvable commit argument."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from common import require_sha


def git(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("Git checkout verification failed")
    return completed.stdout


def normalize_prefix(value: str) -> str:
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if (
        not value
        or value != normalized
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("allowed untracked prefix must be a normalized relative path")
    return normalized


def verify_checkout(
    repository: Path,
    expected_head: str,
    allowed_untracked_prefixes: Sequence[str] = (),
) -> dict[str, object]:
    root = repository.resolve()
    if not root.is_dir():
        raise ValueError("repository must be an existing directory")
    observed_root = Path(
        git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    ).resolve()
    expected = require_sha(expected_head, "expected_head")
    observed = require_sha(
        git(root, "rev-parse", "--verify", "HEAD^{commit}")
        .decode("ascii")
        .strip(),
        "observed_head",
    )
    allowed = tuple(normalize_prefix(value) for value in allowed_untracked_prefixes)
    tracked_status = git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=no",
        "--ignore-submodules=none",
    )
    if tracked_status:
        raise ValueError("actual checkout does not match the exact clean commit")

    ordinary_untracked = git(
        root,
        "ls-files",
        "-z",
        "--others",
        "--exclude-standard",
    )
    ignored_untracked = git(
        root,
        "ls-files",
        "-z",
        "--others",
        "--ignored",
        "--exclude-standard",
    )
    allowed_count = 0
    ignored_count = 0
    paths = [
        (entry, ignored)
        for entries, ignored in (
            (ordinary_untracked, False),
            (ignored_untracked, True),
        )
        for entry in entries.split(b"\0")
        if entry
    ]
    for entry, ignored in paths:
        try:
            path = entry.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("checkout path is not valid UTF-8") from exc
        if ignored:
            ignored_count += 1
        normalized_path = PurePosixPath(path)
        normalized = normalized_path.as_posix()
        if (
            path != normalized
            or normalized_path.is_absolute()
            or any(part in {"", ".", ".."} for part in normalized_path.parts)
            or not any(path.startswith(prefix + "/") for prefix in allowed)
        ):
            raise ValueError("actual checkout does not match the exact clean commit")
        allowed_count += 1
    if observed_root != root or observed != expected:
        raise ValueError("actual checkout does not match the exact clean commit")
    return {
        "head_sha": observed,
        "tracked_clean": True,
        "allowed_untracked_count": allowed_count,
        "allowed_ignored_count": ignored_count,
        "verified": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--allow-untracked-prefix", action="append", default=[])
    args = parser.parse_args()
    print(
        json.dumps(
            verify_checkout(
                args.repository,
                args.expected_head,
                args.allow_untracked_prefix,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
