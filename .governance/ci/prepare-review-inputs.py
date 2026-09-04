#!/usr/bin/env python3
"""Create the fixed reviewer allowlists from protected candidate-bound inputs."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import ensure_within, load_json, read_bytes_once, sha256_bytes, write_once


def relative(repository: Path, path: Path) -> str:
    return path.resolve().relative_to(repository.resolve()).as_posix()


def digest(path: Path) -> str:
    return sha256_bytes(read_bytes_once(path))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--reviewer-prompt", type=Path, required=True)
    args = parser.parse_args()

    repository = args.candidate.resolve()
    evidence = ensure_within(repository, args.evidence)
    reviewer_prompt = args.reviewer_prompt.resolve()
    if reviewer_prompt.is_symlink() or not reviewer_prompt.is_file():
        raise ValueError("protected reviewer prompt must be a regular file")
    candidate = load_json(evidence / "candidate.json")
    policy = load_json(evidence / "effective-policy.json")
    gate_summary = load_json(evidence / "gate-summary.json")
    receipt = load_json(evidence / "context-receipt.json")
    context_qualification = load_json(evidence / "context-qualification.json")
    common = {
        "repository_id": candidate["repository_id"],
        "candidate_id": candidate["candidate_id"],
        "candidate_path": "candidate",
        "task_contract_path": relative(repository, evidence / "task-contract.json"),
        "task_contract_sha256": digest(evidence / "task-contract.json"),
        "effective_policy_path": relative(repository, evidence / "effective-policy.json"),
        "effective_policy_sha256": digest(evidence / "effective-policy.json"),
        "gate_manifest_path": gate_summary["gate_manifest"]["path"],
        "gate_manifest_sha256": gate_summary["gate_manifest"]["sha256"],
        "reviewer_prompt_sha256": digest(reviewer_prompt),
        "evidence_root": policy["evidence_root"],
        "context_receipt_path": relative(repository, evidence / "context-receipt.json"),
        "context_receipt_sha256": digest(evidence / "context-receipt.json"),
        "context_sources_path": relative(repository, evidence / "context-sources.json"),
        "context_sources_sha256": digest(evidence / "context-sources.json"),
        "context_projection_path": relative(repository, evidence / "context-projection.json"),
        "context_projection_sha256": receipt["projection_sha256"],
        "context_qualification_path": relative(
            repository, evidence / "context-qualification.json"
        ),
        "context_qualification_sha256": digest(
            evidence / "context-qualification.json"
        ),
        "context_qualification_id": context_qualification["qualification_id"],
    }
    conformance_qualification = evidence / "reviewer-qualification.json"
    conformance = dict(common)
    conformance.update(
        review_mode="conformance",
        reviewer_qualification_path=relative(repository, conformance_qualification),
        reviewer_qualification_sha256=digest(conformance_qualification),
        reviewer_qualification_id=load_json(conformance_qualification)["qualification_id"],
    )
    write_once(evidence / "reviewer-permitted-inputs.json", conformance)

    rapid_qualification = evidence / "rapid-review-qualification.json"
    rapid_root = evidence / "rapid-review-inputs"
    rapid_inputs = []
    for charter_path in sorted(evidence.glob("review-charter-*.json")):
        charter = load_json(charter_path)
        permitted = dict(common)
        permitted.update(
            review_mode="rapid_review",
            reviewer_qualification_path=relative(repository, rapid_qualification),
            reviewer_qualification_sha256=digest(rapid_qualification),
            reviewer_qualification_id=load_json(rapid_qualification)["qualification_id"],
            risk_assessment_path=relative(repository, evidence / "risk-assessment.json"),
            risk_assessment_sha256=digest(evidence / "risk-assessment.json"),
            review_charter_path=relative(repository, charter_path),
            review_charter_sha256=digest(charter_path),
        )
        destination = rapid_root / (charter["charter_id"].lower() + ".json")
        write_once(destination, permitted)
        rapid_inputs.append(relative(repository, destination))
    if len(rapid_inputs) < 2:
        raise ValueError("elevated policy requires at least two rapid-review inputs")
    write_once(
        evidence / "review-input-index.json",
        {
            "schema_version": "1.0.0",
            "repository_id": policy["repository_id"],
            "candidate_id": candidate["candidate_id"],
            "conformance": relative(repository, evidence / "reviewer-permitted-inputs.json"),
            "rapid_review": rapid_inputs,
        },
    )


if __name__ == "__main__":
    main()
