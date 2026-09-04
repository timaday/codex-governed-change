"""Protected rollback-target materialization and validation."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


COMMIT_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
PROTECTED_PACKAGE_CONTAINER_ROOT = "/opt/codex-governance"
PROTECTED_ROLLBACK_LAUNCHER = (
    "import runpy,sys;"
    f"sys.path.insert(0,{PROTECTED_PACKAGE_CONTAINER_ROOT!r});"
    "runpy.run_module('codex_governance.rollback',run_name='__main__',alter_sys=True)"
)


def protected_rollback_command(target: str) -> list[str]:
    """Return the portable argv that imports rollback only from the protected mount."""
    if COMMIT_RE.fullmatch(target) is None:
        raise ValueError("rollback target must be a full Git commit")
    return [
        "/usr/bin/env",
        "python3",
        "-I",
        "-S",
        "-c",
        PROTECTED_ROLLBACK_LAUNCHER,
        target,
    ]


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


def main(argv: list[str], *, repository: Path | None = None) -> int:
    """Validate one exact rollback commit and emit one machine-readable result."""
    if len(argv) != 1 or COMMIT_RE.fullmatch(argv[0]) is None:
        print("ROLLBACK_REHEARSAL=UNKNOWN reason=invalid-target")
        return 2
    target = argv[0]
    root = (repository or Path.cwd()).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="rollback-rehearsal-") as temporary:
        worktree = Path(temporary) / "target"
        added = run(
            ["git", "worktree", "add", "--detach", "--force", str(worktree), target],
            cwd=root,
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
                cwd=root,
                timeout=30,
            )
            cleanup_complete = removed.returncode == 0
            run(["git", "worktree", "prune"], cwd=root, timeout=30)
        if validation is None or validation.returncode != 0 or not cleanup_complete:
            print("ROLLBACK_REHEARSAL=UNKNOWN reason=validation-or-cleanup")
            return 2
        print(f"ROLLBACK_REHEARSAL=PASS target={target}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
