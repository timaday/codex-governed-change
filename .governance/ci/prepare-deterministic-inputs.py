#!/usr/bin/env python3
"""Materialize protected, exact-candidate inputs outside pull-request control."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from common import (
    canonical_bytes,
    content_address,
    copy_bytes_once,
    copy_json_once,
    ensure_within,
    load_and_validate_once,
    load_json,
    read_bytes_once,
    require_digest,
    require_repository,
    require_sha,
    sha256_bytes,
    write_once,
)
from qualification_verifier import validate_qualification_bundle
from codex_governance.qualification import context_qualification_evidence_valid


ACTOR_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
AUTHENTICATION_METHOD = "github-actions-workflow-dispatch"


def issuer_descriptor(*, actor: str, repository: str, ref: str) -> dict[str, str]:
    return {
        "subject": "github:" + actor,
        "authentication_method": AUTHENTICATION_METHOD,
        "protected_source": repository + "@" + ref,
    }


def verify_selected_issuer(
    decision: Mapping[str, Any], *, actor: str, repository: str, ref: str
) -> None:
    expected = issuer_descriptor(actor=actor, repository=repository, ref=ref)
    issuer = decision.get("issuer")
    if not isinstance(issuer, Mapping) or dict(issuer) != {
        **expected,
        "assertion_sha256": sha256_bytes(canonical_bytes(expected)),
    }:
        raise ValueError("selected decision issuer assertion does not reconstruct")


def parse_selected_decision_ids(raw: str) -> list[str]:
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("approved_decision_ids must be a JSON array") from error
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ValueError("approved_decision_ids must be a JSON string array")
    selected = [require_digest(item, "approved decision ID") for item in values]
    if len(selected) != len(set(selected)):
        raise ValueError("approved_decision_ids contains duplicates")
    return selected


def git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def exact_case_references(case_evidence: Mapping[str, Any]) -> dict[str, str]:
    """Return the exact direct artifact references in a qualification case set."""
    result: dict[str, str] = {}
    observations = case_evidence.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("qualification case observations are unavailable")
    for observation in observations:
        if not isinstance(observation, Mapping):
            raise ValueError("qualification observation is malformed")
        for value in observation.values():
            if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
                continue
            path = value.get("path")
            digest = require_digest(value.get("sha256"), "qualification artifact")
            if not isinstance(path, str) or not path.startswith("qualification/"):
                raise ValueError("qualification artifact path is not canonical")
            prior = result.setdefault(path, digest)
            if prior != digest:
                raise ValueError("qualification artifact has conflicting digests")
    return result


def _verify_decision_commit(
    authority: Path, *, commit: str, release_directory: str
) -> str:
    parents = git(authority, "rev-list", "--parents", "-n", "1", commit).split()
    if len(parents) != 2 or parents[0] != commit:
        raise ValueError("authority decision commit must have exactly one basis parent")
    authority_basis = require_sha(parents[1], "authority basis commit")
    decision_prefix = release_directory + "/decisions/"
    allowed_exact = {
        "MANIFEST.json",
        release_directory + "/bootstrap-decision.json",
    }
    changed = set(
        git(authority, "diff", "--name-only", authority_basis, commit).splitlines()
    )
    if (
        not changed
        or any(
            path not in allowed_exact and not path.startswith(decision_prefix)
            for path in changed
        )
        or not any(
            path.startswith(decision_prefix)
            or path.endswith("bootstrap-decision.json")
            for path in changed
        )
    ):
        raise ValueError("authority HEAD is not a decision-only commit over its protected basis")
    return authority_basis


def verify_authority_decision_commit(
    authority: Path, *, release_directory: str
) -> tuple[str, str, str]:
    """Accept a decision child or one receipt-only child over that decision commit."""
    authority_head = require_sha(git(authority, "rev-parse", "HEAD"), "authority HEAD")
    try:
        basis = _verify_decision_commit(
            authority, commit=authority_head, release_directory=release_directory
        )
        return authority_head, basis, authority_head
    except ValueError as decision_error:
        parents = git(
            authority, "rev-list", "--parents", "-n", "1", authority_head
        ).split()
        if len(parents) != 2 or parents[0] != authority_head:
            raise decision_error
        decision_commit = require_sha(parents[1], "authority decision commit")
        receipt_path = release_directory + "/authorization-receipt.json"
        changed = set(
            git(
                authority,
                "diff",
                "--name-only",
                decision_commit,
                authority_head,
            ).splitlines()
        )
        if changed != {"MANIFEST.json", receipt_path}:
            raise decision_error
        basis = _verify_decision_commit(
            authority, commit=decision_commit, release_directory=release_directory
        )
        return authority_head, basis, decision_commit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--authority-repository", required=True)
    parser.add_argument("--authority-ref", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--approved-decision-ids", required=True)
    parser.add_argument("--authority-observation", type=Path, required=True)
    args = parser.parse_args()

    authority = args.authority.resolve()
    candidate = args.candidate.resolve()
    output = ensure_within(candidate, args.output)
    target = load_json(args.target)
    selected_ids = parse_selected_decision_ids(args.approved_decision_ids)
    authority_repository = require_repository(args.authority_repository)
    if args.authority_ref != "refs/heads/governance-authority" or not args.workflow_run_id:
        raise ValueError("decision source is not the protected authority ref")
    if args.event_name not in {"workflow_dispatch", "schedule"}:
        raise ValueError("unsupported decision source event")
    if args.event_name == "workflow_dispatch" and not ACTOR_RE.fullmatch(args.actor):
        raise ValueError("authenticated GitHub actor is invalid")
    if args.event_name == "schedule" and selected_ids:
        raise ValueError("scheduled runs cannot supply caller-selected decisions")
    base = require_sha(target.get("base_sha"), "base_sha")
    head = require_sha(target.get("head_sha"), "head_sha")
    require_digest(target.get("expected_candidate_id"), "expected_candidate_id")
    if git(candidate, "rev-parse", "HEAD") != head:
        raise ValueError("candidate checkout does not match protected head")
    git(candidate, "cat-file", "-e", base + "^{commit}")
    git(candidate, "cat-file", "-e", target["lkg_governance_commit"] + "^{commit}")

    authority_head, authority_basis, authority_decision_commit = verify_authority_decision_commit(
        authority, release_directory=target["release_directory"]
    )
    release = ensure_within(authority, authority / target["release_directory"])
    policy_path = authority / ".governance/effective-policy.json"
    if sha256_bytes(read_bytes_once(policy_path)) != target.get("expected_policy_sha256"):
        raise ValueError("protected policy bytes do not match the target registry")
    policy = copy_json_once(policy_path, output / "effective-policy.json")
    proposed_policy_path = release / "proposed-policy.json"
    proposed_policy_bytes = read_bytes_once(proposed_policy_path)
    if sha256_bytes(proposed_policy_bytes) != target.get(
        "expected_proposed_policy_sha256"
    ):
        raise ValueError("protected proposed policy bytes do not match the target registry")
    proposed_policy = copy_json_once(
        proposed_policy_path, output / "proposed-policy.json"
    )
    task_path = release / "task-contract.json"
    task_bytes = read_bytes_once(task_path)
    task_value = load_json(task_path)
    if (
        task_bytes != canonical_bytes(task_value)
        or sha256_bytes(task_bytes) != target.get("expected_task_contract_sha256")
    ):
        raise ValueError("protected task bytes do not match the target registry")
    task = copy_json_once(task_path, output / "task-contract.json")
    if (
        policy.get("repository_id") != target.get("repository_id")
        or task.get("repository_id") != target.get("repository_id")
        or task.get("base_commit") != base
        or policy.get("lkg_governance_commit")
        != base
        or proposed_policy.get("repository_id") != target.get("repository_id")
        or proposed_policy.get("lkg_governance_commit") != head
    ):
        raise ValueError("protected task, policy, and target bindings disagree")
    for source in task.get("authoritative_sources", []):
        path = source.get("path")
        if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("task authority path is not repository-relative")
        actual = sha256_bytes(read_bytes_once(candidate / path))
        if source.get("sha256") != actual:
            raise ValueError("candidate authority source digest mismatch")

    mutation_relative = policy.get("mutation", {}).get("corpus_path")
    mutation_path = release / "mutation-corpus.json"
    if (
        mutation_relative != ".governance/releases/v0.1.0/mutation-corpus.json"
        or sha256_bytes(read_bytes_once(mutation_path))
        != policy.get("mutation", {}).get("corpus_sha256")
    ):
        raise ValueError("protected mutation corpus does not match policy")

    context_ids = policy.get("context", {}).get("qualification_ids")
    if not isinstance(context_ids, Mapping) or set(context_ids) != {
        "COMPACT",
        "STANDARD",
        "DEEP",
    }:
        raise ValueError("protected context qualification registry is incomplete")
    context_records: dict[str, dict[str, Any]] = {}
    for profile, expected_id in context_ids.items():
        context_source = authority / ".governance/context-qualifications" / (
            profile + ".json"
        )
        context_qualification = load_and_validate_once(
            context_source,
            authority / "kernel/schemas/context-qualification.schema.json",
        )
        if (
            context_qualification.get("profile") != profile
            or context_qualification.get("qualification_id") != expected_id
            or content_address(context_qualification, "qualification_id")
            != context_qualification
            or context_qualification.get("evidence_class") != "empirical"
            or context_qualification.get("qualified") is not True
        ):
            raise ValueError("protected context qualification is invalid")
        context_records[profile] = context_qualification

    qualification = release / "qualification"
    label_decision = load_json(qualification / "human-label-decision.json")
    label_decision_id = require_digest(
        label_decision.get("decision_id"), "human label decision"
    )

    rollback_plan_path = release / "rollback-plan.json"
    rollback_plan = copy_json_once(rollback_plan_path, output / "rollback-plan.json")
    rollback_task_path = release / "rollback-task-contract.json"
    rollback_task_bytes = read_bytes_once(rollback_task_path)
    rollback_task_value = load_json(rollback_task_path)
    if rollback_task_bytes != canonical_bytes(rollback_task_value):
        raise ValueError("protected rollback task bytes are not canonical")
    rollback_task_sha = sha256_bytes(rollback_task_bytes)
    rollback_task = copy_json_once(
        rollback_task_path, output / "rollback-task-contract.json"
    )
    if (
        content_address(rollback_plan, "rollback_plan_id") != rollback_plan
        or rollback_plan.get("repository_id") != target.get("repository_id")
        or rollback_plan.get("task_contract_sha256")
        != target.get("expected_task_contract_sha256")
        or rollback_plan.get("rollback_task_contract_sha256") != rollback_task_sha
        or rollback_plan.get("bootstrap_policy_sha256")
        != target.get("expected_policy_sha256")
        or rollback_plan.get("current_candidate_id")
        != target.get("expected_candidate_id")
        or rollback_plan.get("rollback_target_commit")
        != target.get("lkg_governance_commit")
        or rollback_task.get("repository_id") != target.get("repository_id")
        or rollback_task.get("base_commit") != target.get("lkg_governance_commit")
        or rollback_task.get("required_gate_ids")
        != [rollback_plan.get("gate_definition", {}).get("gate_id")]
    ):
        raise ValueError("protected rollback plan does not match the target")

    selectable: dict[str, tuple[Path, str]] = {}
    for source in sorted((release / "decisions").glob("*.json")):
        decision = load_json(source)
        decision_id = require_digest(decision.get("decision_id"), "protected decision")
        if content_address(decision, "decision_id") != decision or decision_id in selectable:
            raise ValueError("protected decision identity is invalid or duplicated")
        selectable[decision_id] = (source, "decision")
    bootstrap_source = release / "bootstrap-decision.json"
    if bootstrap_source.is_file():
        bootstrap_value = load_json(bootstrap_source)
        bootstrap_id = require_digest(
            bootstrap_value.get("decision_id"), "bootstrap decision"
        )
        if content_address(bootstrap_value, "decision_id") != bootstrap_value:
            raise ValueError("bootstrap decision identity does not reconstruct")
        if bootstrap_id in selectable:
            raise ValueError("bootstrap decision identity is duplicated")
        selectable[bootstrap_id] = (bootstrap_source, "bootstrap")
    if label_decision_id in selectable:
        raise ValueError("human label decision identity is duplicated")
    selectable[label_decision_id] = (
        qualification / "human-label-decision.json",
        "label",
    )
    authorization_receipt = None
    receipt_source = release / "authorization-receipt.json"
    if args.event_name == "schedule":
        if authority_decision_commit == authority_head or not receipt_source.is_file():
            raise ValueError("scheduled authorization receipt is not protected at authority HEAD")
        authorization_receipt = load_json(receipt_source)
        original = authorization_receipt.get("decision_source_assertion")
        if (
            content_address(authorization_receipt, "receipt_id")
            != authorization_receipt
            or authorization_receipt.get("schema_version") != "1.0.0"
            or authorization_receipt.get("repository_id")
            != target.get("repository_id")
            or authorization_receipt.get("target_id") != target.get("target_id")
            or authorization_receipt.get("authority_repository")
            != authority_repository
            or authorization_receipt.get("authority_ref") != args.authority_ref
            or authorization_receipt.get("authority_decision_commit")
            != authority_decision_commit
            or authorization_receipt.get("authority_basis_commit")
            != authority_basis
            or not isinstance(original, Mapping)
            or authorization_receipt.get("decision_source_assertion_sha256")
            != sha256_bytes(canonical_bytes(dict(original)))
            or original.get("event_name") != "workflow_dispatch"
            or original.get("authority_commit") != authority_decision_commit
            or original.get("authority_basis_commit") != authority_basis
            or original.get("authority_repository") != authority_repository
            or original.get("authority_ref") != args.authority_ref
            or original.get("authorization_receipt_id") is not None
        ):
            raise ValueError("protected scheduled authorization receipt is invalid")
        selected_ids = list(authorization_receipt.get("approved_decision_ids", ()))
        if selected_ids != original.get("approved_decision_ids"):
            raise ValueError("scheduled decision set differs from its authenticated dispatch")
        original_actor = original.get("actor")
        if (
            not isinstance(original_actor, str)
            or not original_actor.startswith("github:")
            or not ACTOR_RE.fullmatch(original_actor.removeprefix("github:"))
        ):
            raise ValueError("scheduled authorization actor is invalid")
        decision_actor = original_actor.removeprefix("github:")
    else:
        decision_actor = args.actor
    unknown = set(selected_ids) - set(selectable)
    if unknown:
        raise ValueError("manual dispatch selected an unknown protected decision")

    decision_output = output / "decisions"
    decisions = []
    bootstrap_decision = None
    authenticated_label_decision_id = ""
    for decision_id in selected_ids:
        source, kind = selectable[decision_id]
        decision = load_json(source)
        verify_selected_issuer(
            decision,
            actor=decision_actor,
            repository=authority_repository,
            ref=args.authority_ref,
        )
        if kind == "label":
            authenticated_label_decision_id = decision_id
            continue
        destination = (
            output / "bootstrap-decision.json"
            if kind == "bootstrap"
            else decision_output / source.name
        )
        copied = copy_json_once(source, destination)
        reference = {
            "decision_id": copied.get("decision_id"),
            "path": destination.resolve().relative_to(candidate).as_posix(),
            "sha256": sha256_bytes(read_bytes_once(destination)),
        }
        if kind == "bootstrap":
            bootstrap_decision = reference
        else:
            decisions.append(reference)

    validate_qualification_bundle(
        corpus_path=qualification / "corpus.json",
        label_decision_path=qualification / "human-label-decision.json",
        conformance_record_path=qualification / "conformance.json",
        conformance_cases_path=qualification / "conformance-cases.json",
        rapid_record_path=qualification / "rapid-review.json",
        rapid_cases_path=qualification / "rapid-review-cases.json",
        policy_path=policy_path,
        authenticated_label_decision_id=authenticated_label_decision_id,
        artifact_root=qualification / "raw",
    )
    context_reference_digests: dict[str, str] = {}

    def retain_context_reference(reference: Mapping[str, Any]) -> bytes:
        path = reference.get("path")
        digest = require_digest(reference.get("sha256"), "context qualification artifact")
        if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("context qualification reference is unsafe")
        prior = context_reference_digests.setdefault(path, digest)
        if prior != digest:
            raise ValueError("context qualification reference conflicts")
        data = read_bytes_once(authority / path)
        if sha256_bytes(data) != digest:
            raise ValueError("context qualification reference digest mismatch")
        return data

    for record in context_records.values():
        measurement = record.get("measurement_evidence")
        if not isinstance(measurement, Mapping):
            raise ValueError("context qualification measurement package is absent")
        retain_context_reference(measurement["corpus"])
        retain_context_reference(measurement["label_decision"])
        for role in ("baseline", "candidate"):
            profile_evidence = measurement.get(role)
            if not isinstance(profile_evidence, Mapping):
                raise ValueError("context qualification profile evidence is absent")
            profile = profile_evidence.get("profile")
            for mode in ("conformance", "rapid_review"):
                mode_evidence = profile_evidence.get(mode)
                if not isinstance(mode_evidence, Mapping):
                    raise ValueError("context qualification mode evidence is absent")
                retain_context_reference(mode_evidence["record"])
                cases_bytes = retain_context_reference(mode_evidence["cases"])
                cases = json.loads(cases_bytes)
                parent = str(mode_evidence["cases"]["path"]).rsplit("/", 1)[0]
                for raw_path, digest in exact_case_references(cases).items():
                    prefix = f"qualification/{profile}/"
                    if not raw_path.startswith(prefix):
                        raise ValueError("context qualification raw profile differs")
                    retain_context_reference(
                        {
                            "path": f"{parent}/raw/{profile}/{raw_path[len(prefix):]}",
                            "sha256": digest,
                        }
                    )
        if not context_qualification_evidence_valid(
            record=record,
            artifact_reader=retain_context_reference,
            schema_root=authority / "kernel/schemas",
            protected_repository_id=target["repository_id"],
            verified_decision_ids=frozenset({authenticated_label_decision_id}),
            evaluated_at=record["created_at"],
            prompt_bytes=read_bytes_once(
                authority / "kernel/.codex/review/reviewer.prompt.md"
            ),
        ):
            raise ValueError("protected context qualification does not reconstruct")
    context_evidence_root = qualification / "evidence" / "context-variants"
    observed_context_files = {
        path.relative_to(authority).as_posix()
        for path in context_evidence_root.rglob("*")
        if path.is_file()
    }
    expected_context_files = {
        path for path in context_reference_digests if "/context-variants/" in path
    }
    if (
        observed_context_files != expected_context_files
        or any(path.is_symlink() for path in context_evidence_root.rglob("*"))
    ):
        raise ValueError("context qualification package inventory is not exact")
    qualification_authority = output / "context-qualification-authority"
    for path in sorted(context_reference_digests):
        copy_bytes_once(
            authority / path,
            qualification_authority / path,
            max_bytes=8_000_000,
        )
    copy_json_once(
        authority / ".governance/context-qualifications/DEEP.json",
        output / "context-qualification.json",
    )
    copy_json_once(
        qualification / "conformance.json", output / "reviewer-qualification.json"
    )
    copy_json_once(
        qualification / "rapid-review.json", output / "rapid-review-qualification.json"
    )
    copy_json_once(
        qualification / "conformance-cases.json",
        output / "reviewer-qualification-cases.json",
    )
    copy_json_once(
        qualification / "rapid-review-cases.json",
        output / "rapid-review-qualification-cases.json",
    )
    copy_json_once(qualification / "corpus.json", output / "reviewer-corpus.json")
    copy_json_once(
        qualification / "human-label-decision.json",
        output / "reviewer-label-decision.json",
    )
    raw_root = qualification / "raw"
    raw_files = sorted(path for path in raw_root.rglob("*") if path.is_file())
    expected_raw = {}
    for cases_name in ("conformance-cases.json", "rapid-review-cases.json"):
        expected_raw.update(exact_case_references(load_json(qualification / cases_name)))
    observed_raw = {
        "qualification/" + path.relative_to(raw_root).as_posix(): sha256_bytes(
            read_bytes_once(path)
        )
        for path in raw_files
    }
    if expected_raw != observed_raw or any(
        path.is_symlink() for path in raw_root.rglob("*")
    ):
        raise ValueError("protected qualification raw artifact inventory is incomplete")
    for source in raw_files:
        relative = source.relative_to(raw_root)
        copy_bytes_once(
            source,
            output / "qualification" / relative,
            max_bytes=8_000_000,
        )

    source_assertion = {
        "event_name": args.event_name,
        "actor": "github:" + decision_actor,
        "authority_repository": authority_repository,
        "authority_ref": args.authority_ref,
        "authority_commit": authority_head,
        "authority_basis_commit": authority_basis,
        "workflow_run_id": args.workflow_run_id,
        "approved_decision_ids": selected_ids,
        "authorization_receipt_id": (
            authorization_receipt.get("receipt_id")
            if isinstance(authorization_receipt, Mapping)
            else None
        ),
    }
    authority_observation = load_json(args.authority_observation)
    if (
        set(authority_observation)
        != {
            "schema_version",
            "repository",
            "ref",
            "commit",
            "manifest_commit",
            "manifest_sha256",
            "visibility",
            "ruleset",
            "observed_at",
        }
        or authority_observation.get("schema_version") != "1.0.0"
        or authority_observation.get("repository") != authority_repository
        or authority_observation.get("ref") != args.authority_ref
        or authority_observation.get("commit") != authority_head
        or authority_observation.get("manifest_commit") != authority_head
        or authority_observation.get("manifest_sha256")
        != sha256_bytes(read_bytes_once(authority / "MANIFEST.json"))
        or authority_observation.get("visibility") != "public"
    ):
        raise ValueError("live authority observation does not match protected inputs")
    authority_state = {
        **authority_observation,
        "source_assertion": source_assertion,
        "source_assertion_sha256": sha256_bytes(canonical_bytes(source_assertion)),
    }
    write_once(output / "authority-state.json", authority_state)

    if (
        args.event_name == "workflow_dispatch"
        and selected_ids
        and authority_decision_commit == authority_head
    ):
        receipt_proposal = content_address(
            {
                "schema_version": "1.0.0",
                "repository_id": target["repository_id"],
                "target_id": target["target_id"],
                "authority_repository": authority_repository,
                "authority_ref": args.authority_ref,
                "authority_decision_commit": authority_decision_commit,
                "authority_basis_commit": authority_basis,
                "actor": source_assertion["actor"],
                "approved_decision_ids": selected_ids,
                "decision_source_assertion": source_assertion,
                "decision_source_assertion_sha256": sha256_bytes(
                    canonical_bytes(source_assertion)
                ),
            },
            "receipt_id",
        )
        write_once(output / "authorization-receipt-proposal.json", receipt_proposal)
    if isinstance(authorization_receipt, Mapping):
        copied_receipt = copy_json_once(
            receipt_source, output / "authorization-receipt.json"
        )
        receipt_reference = {
            "receipt_id": copied_receipt["receipt_id"],
            "path": (output / "authorization-receipt.json")
            .relative_to(candidate)
            .as_posix(),
            "sha256": sha256_bytes(
                read_bytes_once(output / "authorization-receipt.json")
            ),
        }
    else:
        receipt_reference = None

    observation = {
        "schema_version": "1.0.0",
        "authority_commit": authority_head,
        "authority_basis_commit": authority_basis,
        "repository": target["repository"],
        "repository_id": target["repository_id"],
        "base_sha": base,
        "head_sha": head,
        "kernel_source_commit": target["kernel_source_commit"],
        "lkg_governance_commit": target["lkg_governance_commit"],
        "governance_transition": target["governance_transition"],
        "rollback_plan_id": rollback_plan["rollback_plan_id"],
        "rollback_plan_sha256": sha256_bytes(
            read_bytes_once(output / "rollback-plan.json")
        ),
        "bootstrap_decision": bootstrap_decision,
        "authenticated_label_decision_id": authenticated_label_decision_id or None,
        "authorization_receipt": receipt_reference,
        "decision_source_assertion": source_assertion,
        "decision_source_assertion_sha256": sha256_bytes(
            canonical_bytes(source_assertion)
        ),
        "effective_policy_sha256": target["expected_policy_sha256"],
        "expected_candidate_id": target["expected_candidate_id"],
        "verified_decisions": decisions,
        "limitations": [
            "An empty protected decision set blocks task, label, promotion, risk, and release authority."
        ],
    }
    write_once(output / "decision-source-observation.json", observation)


if __name__ == "__main__":
    main()
