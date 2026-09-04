#!/usr/bin/env python3
"""Convert reconstructed admission into a fixed fail-closed check payload."""

from __future__ import annotations

import argparse
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from common import (
    content_address,
    load_json,
    read_bytes_once,
    require_digest,
    require_repository,
    require_sha,
    sha256_bytes,
    verify_candidate_identity,
    write_once,
)


REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,127}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)"
    r"(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$"
)
DISPOSITION_FIELDS = {
    "schema_version",
    "repository_id",
    "task_contract_sha256",
    "effective_policy_sha256",
    "candidate_id",
    "manifest_sha256",
    "state",
    "reasons",
    "human_action_required",
    "approved",
    "evaluated_at",
    "producer_version",
}
CANDIDATE_FIELDS = {
    "schema_version",
    "repository_id",
    "candidate_id",
    "mode",
    "base_commit",
    "head_commit",
    "tracked_diff_sha256",
    "changed_paths",
    "untracked_entries",
    "submodules",
    "effective_policy_sha256",
    "dirty",
}


def validate_disposition(value: object) -> list[str]:
    if not isinstance(value, Mapping) or set(value) != DISPOSITION_FIELDS:
        raise ValueError("disposition fields do not match the protected schema")
    if value.get("schema_version") != "1.0.0":
        raise ValueError("unsupported disposition schema")
    for field in (
        "task_contract_sha256",
        "effective_policy_sha256",
        "candidate_id",
        "manifest_sha256",
    ):
        require_digest(value.get(field), field)
    if value.get("state") not in {"READY_FOR_HUMAN", "BLOCK", "UNKNOWN"}:
        raise ValueError("invalid disposition state")
    if value.get("human_action_required") is not True or value.get("approved") is not False:
        raise ValueError("disposition crossed the human authority boundary")
    timestamp = value.get("evaluated_at")
    if not isinstance(timestamp, str) or TIMESTAMP_RE.fullmatch(timestamp) is None:
        raise ValueError("disposition timestamp is invalid")
    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    producer = value.get("producer_version")
    if not isinstance(producer, str) or not producer:
        raise ValueError("disposition producer version is absent")
    reasons = value.get("reasons")
    if not isinstance(reasons, list) or not reasons:
        raise ValueError("disposition must contain at least one reason")
    codes: list[str] = []
    for item in reasons:
        if not isinstance(item, Mapping) or set(item) != {"code", "message", "evidence_refs"}:
            raise ValueError("disposition reason is malformed")
        code = item.get("code")
        message = item.get("message")
        evidence_refs = item.get("evidence_refs")
        if (
            not isinstance(code, str)
            or REASON_RE.fullmatch(code) is None
            or not isinstance(message, str)
            or not message
            or not isinstance(evidence_refs, list)
            or any(not isinstance(reference, str) or not reference for reference in evidence_refs)
        ):
            raise ValueError("disposition reason violates the protected schema")
        codes.append(code)
    return codes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--disposition", type=Path)
    parser.add_argument("--details-url", required=True)
    parser.add_argument("--workflow-run", required=True)
    parser.add_argument("--authority-repository", required=True)
    parser.add_argument("--authority-sha", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--fallback-reason", default="ADMISSION_EVIDENCE_UNAVAILABLE")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    target = load_json(args.target)
    authority_repository = require_repository(args.authority_repository)
    authority_sha = require_sha(args.authority_sha, "authority_sha")
    source_repository = require_repository(args.source_repository)
    source_head_sha = require_sha(args.source_head_sha, "source_head_sha")
    target_id = target.get("target_id")
    target_ref = target.get("target_ref")
    if not isinstance(target_id, str) or not target_id or not isinstance(target_ref, str):
        raise ValueError("protected target identity is absent")
    repository = require_repository(target.get("repository"))
    head = require_sha(target.get("head_sha"), "head_sha")
    expected_candidate = require_digest(
        target.get("expected_candidate_id"), "expected_candidate_id"
    )
    expected_policy = require_digest(
        target.get("expected_policy_sha256"), "expected_policy_sha256"
    )
    expected_task = require_digest(
        target.get("expected_task_contract_sha256"),
        "expected_task_contract_sha256",
    )
    reason_codes = []
    ready = False
    candidate_id = expected_candidate
    manifest_id = "sha256:" + "0" * 64
    manifest_sha256 = "sha256:" + "0" * 64
    disposition_sha256 = "sha256:" + "0" * 64
    try:
        if not args.candidate or not args.manifest or not args.disposition:
            raise ValueError("required admission artifact is absent")
        candidate = load_json(args.candidate)
        manifest = load_json(args.manifest)
        disposition = load_json(args.disposition)
        if not isinstance(candidate, Mapping) or set(candidate) != CANDIDATE_FIELDS:
            raise ValueError("candidate fields do not match the protected schema")
        observed_candidate_id = require_digest(
            candidate.get("candidate_id"), "candidate_id"
        )
        manifest_id = require_digest(manifest.get("manifest_id"), "manifest_id")
        reason_codes = validate_disposition(disposition)
        if not verify_candidate_identity(candidate):
            raise ValueError("candidate identity does not reconstruct")
        if content_address(manifest, "manifest_id") != manifest:
            raise ValueError("manifest identity is not content-addressed")
        manifest_sha256 = sha256_bytes(read_bytes_once(args.manifest))
        disposition_sha256 = sha256_bytes(read_bytes_once(args.disposition))
        if (
            observed_candidate_id != expected_candidate
            or candidate.get("head_commit") != head
            or candidate.get("mode") != "commit"
            or candidate.get("dirty") is not False
            or candidate.get("repository_id") != target.get("repository_id")
            or candidate.get("effective_policy_sha256") != expected_policy
            or manifest.get("candidate_id") != observed_candidate_id
            or disposition.get("candidate_id") != observed_candidate_id
            or disposition.get("repository_id") != target.get("repository_id")
            or disposition.get("manifest_sha256") != manifest_sha256
            or disposition.get("effective_policy_sha256") != expected_policy
            or disposition.get("task_contract_sha256") != expected_task
        ):
            raise ValueError("publication bindings do not match the protected target")
        ready = disposition.get("state") == "READY_FOR_HUMAN"
        if ready:
            reason_codes = ["READY_FOR_HUMAN"]
        elif not reason_codes:
            reason_codes = ["ADMISSION_NOT_READY"]
        require_digest(manifest_id, "manifest_id")
    except (KeyError, OSError, TypeError, ValueError):
        reason = args.fallback_reason
        reason_codes = [reason if REASON_RE.fullmatch(reason) else "ADMISSION_EVIDENCE_INVALID"]
        ready = False

    conclusion = "success" if ready else "failure"
    title = "Ready for human review" if ready else "Governed admission blocked"
    summary = (
        "Protected admission reconstructed READY_FOR_HUMAN for the exact candidate. Human approval is still required."
        if ready
        else "Protected admission did not establish readiness. Reason codes: "
        + ", ".join(sorted(set(reason_codes)))
    )
    publication = {
        "schema_version": "1.0.0",
        "target_id": target_id,
        "target_ref": target_ref,
        "authority_repository": authority_repository,
        "authority_ref": "refs/heads/governance-authority",
        "authority_sha": authority_sha,
        "source_repository": source_repository,
        "source_head_sha": source_head_sha,
        "repository": repository,
        "repository_id": target["repository_id"],
        "head_sha": head,
        "candidate_id": candidate_id,
        "task_contract_sha256": expected_task,
        "effective_policy_sha256": expected_policy,
        "manifest_id": manifest_id,
        "manifest_sha256": manifest_sha256,
        "disposition_sha256": disposition_sha256,
        "check_name": "disposition",
        "status": "completed",
        "conclusion": conclusion,
        "title": title,
        "summary": summary,
        "details_url": args.details_url,
        "workflow_run": args.workflow_run,
        "external_id": "governed-change:" + args.workflow_run + ":" + candidate_id,
        "reason_codes": sorted(set(reason_codes)),
    }
    write_once(args.output, publication)


if __name__ == "__main__":
    main()
