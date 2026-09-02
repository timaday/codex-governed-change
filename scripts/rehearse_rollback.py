#!/usr/bin/env python3
"""Portable repository wrapper for the protected rollback implementation."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))

from codex_governance.rollback import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:], repository=REPOSITORY))
