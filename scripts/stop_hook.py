#!/usr/bin/env python3
"""Portable fail-closed Codex Stop-hook wrapper."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def blocked(active: bool, detail: str) -> dict[str, Any]:
    reason = f"GOVERNANCE=UNKNOWN/BLOCK: {detail}"
    if active:
        return {"continue": False, "stopReason": reason, "systemMessage": reason}
    return {"decision": "block", "reason": reason}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--disposition", type=Path)
    parser.add_argument("--mode", choices=("commit", "working_tree"), default="working_tree")
    args = parser.parse_args()
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook input must be an object")
    except (json.JSONDecodeError, OSError, ValueError):
        print(json.dumps(blocked(True, "invalid Stop-hook input"), sort_keys=True))
        return 0

    active = event.get("stop_hook_active") is True
    try:
        from codex_governance.candidate import GitCliRepositoryAdapter
        from codex_governance.canonical import sha256_canonical
        from codex_governance.hook import decide_stop
        from codex_governance.schema import load_and_validate

        policy = load_and_validate(
            args.policy, ROOT / "schemas/effective-policy.schema.json"
        )
        task = load_and_validate(
            args.task, ROOT / "schemas/task-contract.schema.json"
        )
        if (
            not isinstance(policy, dict)
            or not isinstance(task, dict)
            or policy["repository_id"] != task["repository_id"]
        ):
            raise ValueError("hook authority binding mismatch")
        candidate = GitCliRepositoryAdapter(args.repository).identify(
            repository_id=policy["repository_id"],
            mode=args.mode,
            base_commit=task["base_commit"],
            effective_policy_sha256=sha256_canonical(policy),
            evidence_root=policy["evidence_root"],
        )
        disposition = None
        if args.disposition and args.disposition.is_file():
            value = load_and_validate(
                args.disposition, ROOT / "schemas/disposition.schema.json"
            )
            if isinstance(value, dict):
                disposition = value
        result = decide_stop(
            event=event,
            current_candidate_id=candidate["candidate_id"],
            disposition=disposition,
        )
    except Exception:
        result = blocked(active, "current candidate evidence is unavailable")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
