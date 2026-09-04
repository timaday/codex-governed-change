#!/usr/bin/env python3
"""Package a live protected rollback rehearsal for exact admission."""

from __future__ import annotations

import argparse
import stat
from pathlib import Path

from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import verify_content_address

from common import (
    canonical_bytes,
    content_address,
    copy_bytes_once,
    ensure_within,
    load_and_validate_once,
    load_json,
    read_bytes_once,
    require_json_within,
    sha256_bytes,
    verify_candidate_identity,
    write_once,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--candidate-identity", type=Path, required=True)
    parser.add_argument("--gate-summary", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    authority = args.authority.resolve()
    candidate_root = args.candidate.resolve()
    output = args.output.resolve()
    target = load_json(args.target)
    release = authority / target["release_directory"]
    plan_path = release / "rollback-plan.json"
    plan = load_json(plan_path)
    if content_address(plan, "rollback_plan_id") != plan:
        raise ValueError("protected rollback plan is not content-addressed")
    policy_path = authority / ".governance/effective-policy.json"
    policy = load_json(policy_path)
    policy_sha = sha256_bytes(read_bytes_once(policy_path))
    current_task_path = release / "task-contract.json"
    current_task_bytes = read_bytes_once(current_task_path)
    current_task = load_json(current_task_path)
    current_task_sha = sha256_bytes(current_task_bytes)
    rollback_task_path = release / "rollback-task-contract.json"
    rollback_task = load_and_validate_once(
        rollback_task_path, authority / "kernel/schemas/task-contract.schema.json"
    )
    rollback_task_bytes = read_bytes_once(rollback_task_path)
    rollback_task_sha = sha256_bytes(rollback_task_bytes)
    proposed_path = release / "proposed-policy.json"
    proposed = load_json(proposed_path)
    proposed_sha = sha256_bytes(read_bytes_once(proposed_path))
    schema_root = authority / "kernel/schemas"
    load_and_validate_once(proposed_path, schema_root / "effective-policy.schema.json")
    rollback_candidate = load_and_validate_once(
        args.candidate_identity, schema_root / "candidate.schema.json"
    )
    observed_candidate = GitCliRepositoryAdapter(candidate_root).identify(
        repository_id=target["repository_id"],
        mode="commit",
        base_commit=target["lkg_governance_commit"],
        head_commit=target["lkg_governance_commit"],
        effective_policy_sha256=policy_sha,
        evidence_root=policy["evidence_root"],
    )
    actual_checkout_head = GitCliRepositoryAdapter(candidate_root).resolve_commit("HEAD")
    if (
        current_task_bytes != canonical_bytes(current_task)
        or rollback_task_bytes != canonical_bytes(rollback_task)
        or not verify_candidate_identity(rollback_candidate)
        or observed_candidate != rollback_candidate
        or actual_checkout_head != target.get("lkg_governance_commit")
        or plan.get("repository_id") != target.get("repository_id")
        or plan.get("task_contract_sha256") != current_task_sha
        or plan.get("rollback_task_contract_sha256") != rollback_task_sha
        or plan.get("bootstrap_policy_sha256") != policy_sha
        or plan.get("current_candidate_id") != target.get("expected_candidate_id")
        or plan.get("rollback_target_commit") != target.get("lkg_governance_commit")
        or plan.get("rollback_source_identity")
        != rollback_candidate.get("candidate_id")
        or rollback_candidate.get("base_commit") != target.get("lkg_governance_commit")
        or rollback_candidate.get("head_commit") != target.get("lkg_governance_commit")
        or rollback_task.get("repository_id") != target.get("repository_id")
        or rollback_task.get("base_commit") != target.get("lkg_governance_commit")
        or rollback_task.get("required_gate_ids")
        != [plan["gate_definition"]["gate_id"]]
        or proposed.get("repository_id") != target.get("repository_id")
        or proposed.get("lkg_governance_commit") != target.get("head_sha")
        or proposed_sha == policy_sha
    ):
        raise ValueError("rollback source, tasks, plan, target, or policy disagree")
    for source in rollback_task.get("authoritative_sources", []):
        path = ensure_within(candidate_root, candidate_root / str(source.get("path")))
        if sha256_bytes(read_bytes_once(path)) != source.get("sha256"):
            raise ValueError("rollback authoritative source digest mismatch")

    evidence_root = ensure_within(
        candidate_root, candidate_root / policy["evidence_root"]
    )
    summary = load_json(args.gate_summary)
    if summary.get("results") != [
        {"gate_id": plan["gate_definition"]["gate_id"], "status": "PASS"}
    ]:
        raise ValueError("rollback gate summary is not one exact pass")
    manifest_path = require_json_within(
        candidate_root, evidence_root, summary.get("gate_manifest", {}).get("path")
    )
    manifest = load_and_validate_once(
        manifest_path, schema_root / "gate-manifest.schema.json"
    )
    if (
        sha256_bytes(read_bytes_once(manifest_path))
        != summary.get("gate_manifest", {}).get("sha256")
        or not verify_content_address(manifest, "gate_manifest_id")
        or manifest.get("candidate_id") != rollback_candidate.get("candidate_id")
        or manifest.get("task_contract_sha256") != rollback_task_sha
        or manifest.get("required_gate_ids")
        != [plan["gate_definition"]["gate_id"]]
        or len(manifest.get("gate_results", ())) != 1
    ):
        raise ValueError("rollback gate manifest does not reconstruct")
    result_ref = manifest["gate_results"][0]["reference"]
    result_path = require_json_within(candidate_root, evidence_root, result_ref["path"])
    if sha256_bytes(read_bytes_once(result_path)) != result_ref.get("sha256"):
        raise ValueError("rollback gate result reference is invalid")
    result = load_and_validate_once(
        result_path, schema_root / "gate-result.schema.json"
    )
    capability_path = result_path.with_name("sandbox-capability.json")
    capability = load_and_validate_once(
        capability_path, schema_root / "sandbox-capability.schema.json"
    )
    provenance_ref = result.get("provenance_statement", {})
    provenance_path = require_json_within(
        candidate_root, evidence_root, provenance_ref.get("path")
    )
    provenance = load_and_validate_once(
        provenance_path, schema_root / "provenance-statement.schema.json"
    )
    capability_sha = sha256_bytes(read_bytes_once(capability_path))
    provenance_sha = sha256_bytes(read_bytes_once(provenance_path))
    if (
        result.get("sandbox_capability_sha256") != capability_sha
        or provenance_ref.get("sha256") != provenance_sha
    ):
        raise ValueError("rollback gate capability or provenance reference is invalid")

    raw_by_stream = {}
    for artifact in result.get("artifacts", ()):
        if not isinstance(artifact, dict) or artifact.get("stream") in raw_by_stream:
            raise ValueError("rollback gate raw stream set is invalid")
        source = ensure_within(
            candidate_root, candidate_root / str(artifact.get("path"))
        )
        source.relative_to(evidence_root)
        info = source.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size != artifact.get("bytes")
            or info.st_size > plan["gate_definition"]["max_output_bytes"]
            or sha256_bytes(read_bytes_once(source)) != artifact.get("sha256")
            or artifact.get("truncated") is not False
        ):
            raise ValueError("rollback raw stream does not reconstruct")
        raw_by_stream[artifact["stream"]] = source
    if set(raw_by_stream) != {"stdout", "stderr"}:
        raise ValueError("rollback gate must provide stdout and stderr")

    package = output / "rollback"
    write_once(package / "candidate.json", rollback_candidate)
    write_once(package / "sandbox-capability.json", capability)
    write_once(package / "provenance-statement.json", provenance)
    copy_bytes_once(
        raw_by_stream["stdout"],
        package / "stdout.bin",
        max_bytes=plan["gate_definition"]["max_output_bytes"],
    )
    copy_bytes_once(
        raw_by_stream["stderr"],
        package / "stderr.bin",
        max_bytes=plan["gate_definition"]["max_output_bytes"],
    )
    packaged_result = dict(result)
    packaged_result["artifacts"] = [
        {
            **item,
            "path": plan["raw_artifacts"][item["stream"]],
        }
        for item in result["artifacts"]
    ]
    packaged_result["provenance_statement"] = {
        "path": "artifacts/governance/completion/evidence/rollback/provenance-statement.json",
        "sha256": provenance_sha,
    }
    write_once(package / "gate-result.json", packaged_result)
    packaged_gate_sha = sha256_bytes(read_bytes_once(package / "gate-result.json"))
    rollback = content_address(
        {
            "schema_version": "2.0.0",
            "repository_id": target["repository_id"],
            "task_contract_sha256": current_task_sha,
            "candidate_id": target["expected_candidate_id"],
            "previous_lkg_policy_sha256": policy_sha,
            "proposed_policy_sha256": proposed_sha,
            "rollback_target_commit": target["lkg_governance_commit"],
            "gate_result": {
                "path": "artifacts/governance/completion/evidence/rollback/gate-result.json",
                "sha256": packaged_gate_sha,
            },
            "sandbox_capability": {
                "path": "artifacts/governance/completion/evidence/rollback/sandbox-capability.json",
                "sha256": capability_sha,
            },
            "provenance_statement": {
                "path": "artifacts/governance/completion/evidence/rollback/provenance-statement.json",
                "sha256": provenance_sha,
            },
            "status": "PASS",
            "created_at": args.created_at,
            "limitations": [],
        },
        "rollback_evidence_id",
    )
    write_once(package / "rollback-evidence.json", rollback)


if __name__ == "__main__":
    main()
