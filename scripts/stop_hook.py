#!/usr/bin/env python3
"""Fail-closed Codex Stop-hook wrapper.

The blueprint baseline cannot produce READY_FOR_HUMAN. Until T08 implements the
domain policy, this wrapper allows one corrective continuation and then stops with
an explicit implementation blocker.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def blocked(active: bool, detail: str) -> dict[str, Any]:
    reason = f"GOVERNANCE=UNKNOWN/BLOCK: {detail}"
    if active:
        return {"continue": False, "stopReason": reason, "systemMessage": reason}
    return {"decision": "block", "reason": reason}


def main() -> int:
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook input must be an object")
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        print(json.dumps(blocked(True, f"invalid Stop-hook input: {exc}"), sort_keys=True))
        return 0

    active = event.get("stop_hook_active") is True
    try:
        from codex_governance.hook import decide_stop

        result = decide_stop(
            event=event,
            current_candidate_id="UNAVAILABLE_IN_BLUEPRINT_BASELINE",
            disposition=None,
        )
    except Exception as exc:  # The hook must turn any proof-path failure into a blocker.
        result = blocked(active, f"Stop-hook implementation is not qualified: {type(exc).__name__}")

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
