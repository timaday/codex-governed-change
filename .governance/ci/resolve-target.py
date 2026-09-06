#!/usr/bin/env python3
"""Resolve one protected target entry; dispatch cannot choose an arbitrary SHA."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    load_json,
    require_digest,
    require_repository,
    require_sha,
    write_once,
)


EXPECTED_TARGET = {
    "target_id": "release-v0.1.0",
    "enabled": True,
    "repository": "timaday/codex-governed-change",
    "repository_id": "repo:timaday/codex-governed-change",
    "target_kind": "release",
    "target_ref": "refs/heads/main",
    "base_sha": "5393338571f8ed5de5192613dcdd6131044932dc",
    "head_sha": "8364322b1220830037527f0604e3f7228c0a6423",
    "kernel_source_commit": "8364322b1220830037527f0604e3f7228c0a6423",
    "lkg_governance_commit": "a0a0b01a19e87f2591c7e97e892cd040ce9c6e58",
    "governance_transition": {
        "mode": "initial_lkg_bootstrap",
        "basis_commit": "a0a0b01a19e87f2591c7e97e892cd040ce9c6e58",
        "bootstrap_decision_type": "lkg_bootstrap",
        "promotion_decision_type": "lkg_promotion",
        "reusable": False,
    },
    "release_directory": ".governance/releases/v0.1.0",
}
VARIABLE_DIGEST_FIELDS = {
    "expected_candidate_id",
    "expected_policy_sha256",
    "expected_proposed_policy_sha256",
    "expected_task_contract_sha256",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    document = load_json(args.targets)
    if document.get("schema_version") != "1.0.0":
        raise ValueError("unsupported target registry")
    entries = document.get("targets")
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("v0.1.0 bootstrap registry must contain exactly one target")
    if args.target_id != EXPECTED_TARGET["target_id"]:
        raise ValueError("v0.1.0 bootstrap target identifier is fixed")
    matches = [
        item
        for item in entries
        if isinstance(item, dict) and item.get("target_id") == args.target_id
    ]
    if len(matches) != 1 or matches[0].get("enabled") is not True:
        raise ValueError("target is absent, ambiguous, or disabled")
    target = dict(matches[0])
    if set(target) != {*EXPECTED_TARGET, *VARIABLE_DIGEST_FIELDS} or any(
        target.get(field) != value for field, value in EXPECTED_TARGET.items()
    ):
        raise ValueError("v0.1.0 bootstrap target binding is not exact")
    require_repository(target.get("repository"))
    if target.get("target_kind") != "release":
        raise ValueError("unsupported protected target kind")
    target_ref = target.get("target_ref")
    if (
        not isinstance(target_ref, str)
        or not target_ref.startswith("refs/heads/")
        or ".." in target_ref
        or not target_ref.removeprefix("refs/heads/")
    ):
        raise ValueError("target_ref must be a protected branch ref")
    require_sha(target.get("base_sha"), "base_sha")
    require_sha(target.get("head_sha"), "head_sha")
    require_sha(target.get("kernel_source_commit"), "kernel_source_commit")
    require_sha(target.get("lkg_governance_commit"), "lkg_governance_commit")
    transition = target.get("governance_transition")
    if (
        not isinstance(transition, dict)
        or set(transition)
        != {
            "mode",
            "basis_commit",
            "bootstrap_decision_type",
            "promotion_decision_type",
            "reusable",
        }
        or transition.get("mode") != "initial_lkg_bootstrap"
        or transition.get("basis_commit") != target.get("lkg_governance_commit")
        or transition.get("bootstrap_decision_type") != "lkg_bootstrap"
        or transition.get("promotion_decision_type") != "lkg_promotion"
        or transition.get("reusable") is not False
    ):
        raise ValueError("v0.1.0 requires one non-reusable initial-LKG bootstrap")
    require_digest(target.get("expected_candidate_id"), "expected_candidate_id")
    require_digest(target.get("expected_policy_sha256"), "expected_policy_sha256")
    require_digest(
        target.get("expected_proposed_policy_sha256"),
        "expected_proposed_policy_sha256",
    )
    require_digest(
        target.get("expected_task_contract_sha256"),
        "expected_task_contract_sha256",
    )
    if target.get("repository_id") != "repo:" + target["repository"].lower():
        raise ValueError("repository identity does not match the target repository")
    release_directory = target.get("release_directory")
    if (
        not isinstance(release_directory, str)
        or not release_directory.startswith(".governance/releases/")
        or ".." in Path(release_directory).parts
        or Path(release_directory).is_absolute()
    ):
        raise ValueError("release directory is not protected and relative")
    write_once(args.output, target)


if __name__ == "__main__":
    main()
