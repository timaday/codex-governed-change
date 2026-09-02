#!/usr/bin/env python3
"""Rehearse materializing and validating one protected rollback target."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def run(
    command: list[str], *, cwd: Path, timeout: float
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def main(argv: list[str]) -> int:
    if len(argv) != 1 or COMMIT_RE.fullmatch(argv[0]) is None:
        print("ROLLBACK_REHEARSAL=UNKNOWN reason=invalid-target")
        return 2
    target = argv[0]
    repository = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="rollback-rehearsal-") as temporary:
        worktree = Path(temporary) / "target"
        added = run(
            ["git", "worktree", "add", "--detach", "--force", str(worktree), target],
            cwd=repository,
            timeout=60,
        )
        if added.returncode != 0:
            print("ROLLBACK_REHEARSAL=UNKNOWN reason=target-unavailable")
            return 2
        validation: subprocess.CompletedProcess[bytes] | None = None
        cleanup_complete = False
        try:
            validation = run(
                [sys.executable, "scripts/validate_blueprint.py"],
                cwd=worktree,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            validation = None
        finally:
            removed = run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=repository,
                timeout=30,
            )
            cleanup_complete = removed.returncode == 0
            run(["git", "worktree", "prune"], cwd=repository, timeout=30)
        if (
            validation is None
            or validation.returncode != 0
            or not cleanup_complete
        ):
            print("ROLLBACK_REHEARSAL=UNKNOWN reason=validation-or-cleanup")
            return 2
        print(f"ROLLBACK_REHEARSAL=PASS target={target}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
