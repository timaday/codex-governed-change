#!/usr/bin/env python3
"""Assemble reference-only admission inputs from fixed protected locations."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    content_address,
    ensure_within,
    file_reference,
    load_json,
    read_bytes_once,
    require_json_within,
    require_digest,
    sha256_bytes,
    verify_decision_source_assertion,
    write_once,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--verified-decision-ids-output", type=Path, required=True)
    args = parser.parse_args()

    repository = args.candidate.resolve()
    evidence = ensure_within(repository, args.evidence)

    def required_reference(relative: str) -> Path:
        return require_json_within(repository, evidence, relative)

    def required_evidence(relative: str) -> Path:
        path = ensure_within(evidence, evidence / relative)
        load_json(path)
        return path

    def reference(relative: str) -> dict[str, str]:
        return file_reference(repository, required_evidence(relative))

    def references(pattern: str, minimum: int = 0) -> list[dict[str, str]]:
        paths = sorted(evidence.glob(pattern))
        if len(paths) < minimum:
            raise ValueError(f"required evidence set is incomplete: {pattern}")
        return [file_reference(repository, path) for path in paths]

    candidate = load_json(evidence / "candidate.json")
    task = load_json(evidence / "task-contract.json")
    gate_summary = load_json(evidence / "gate-summary.json")
    gate_manifest_path = required_reference(gate_summary["gate_manifest"]["path"])
    gate_manifest = load_json(gate_manifest_path)
    mutation = load_json(evidence / "mutation-summary.json")

    gate_references = {
        item["gate_id"]: item["reference"] for item in gate_manifest["gate_results"]
    }
    provenance = []
    capabilities = []
    for item in gate_manifest["gate_results"]:
        result_path = required_reference(item["reference"]["path"])
        result = load_json(result_path)
        provenance.append(result["provenance_statement"])
        capability_path = result_path.with_name("sandbox-capability.json")
        capability = file_reference(repository, capability_path)
        if capability["sha256"] != result["sandbox_capability_sha256"]:
            raise ValueError("gate sandbox capability reference mismatch")
        capabilities.append(capability)
    provenance.extend(mutation.get("provenance_statements", []))
    capabilities.extend(mutation.get("sandbox_capabilities", []))

    observation = load_json(evidence / "decision-source-observation.json")
    decision_references = []
    decision_documents = []
    verified_ids = []
    for item in observation.get("verified_decisions", []):
        path = required_reference(item["path"])
        decision = load_json(path)
        decision_id = require_digest(decision.get("decision_id"), "decision_id")
        if content_address(decision, "decision_id") != decision:
            raise ValueError("protected decision is not content-addressed")
        actual = file_reference(repository, path)
        if actual["sha256"] != item.get("sha256") or decision_id != item.get("decision_id"):
            raise ValueError("protected decision observation does not reconstruct")
        decision_references.append(actual)
        decision_documents.append(decision)
        verified_ids.append(decision_id)
    if not decision_references:
        raise ValueError("authenticated protected decisions are absent")
    promotion_references = [
        reference
        for reference, decision in zip(
            decision_references, decision_documents, strict=True
        )
        if decision.get("decision_type") == "lkg_promotion"
    ]
    if len(promotion_references) != 1:
        raise ValueError("exactly one protected initial-bootstrap promotion is required")
    bootstrap_reference = observation.get("bootstrap_decision")
    if not isinstance(bootstrap_reference, dict):
        raise ValueError("authenticated bootstrap decision is absent")
    bootstrap_path = required_reference(bootstrap_reference.get("path"))
    bootstrap_decision = load_json(bootstrap_path)
    if (
        file_reference(repository, bootstrap_path)["sha256"]
        != bootstrap_reference.get("sha256")
        or bootstrap_decision.get("decision_id")
        != bootstrap_reference.get("decision_id")
    ):
        raise ValueError("bootstrap decision observation does not reconstruct")
    label_decision = load_json(evidence / "reviewer-label-decision.json")
    if (
        observation.get("authenticated_label_decision_id")
        != label_decision.get("decision_id")
    ):
        raise ValueError("qualification label decision is not authenticated")
    receipt_reference = observation.get("authorization_receipt")
    receipt_path = (
        required_reference(receipt_reference.get("path"))
        if isinstance(receipt_reference, dict)
        else None
    )
    authorization_receipt = load_json(receipt_path) if receipt_path else None
    if receipt_path and (
        receipt_reference.get("sha256") != sha256_bytes(read_bytes_once(receipt_path))
        or receipt_reference.get("receipt_id")
        != authorization_receipt.get("receipt_id")
    ):
        raise ValueError("protected authorization receipt reference does not reconstruct")
    authenticated_ids = verify_decision_source_assertion(
        observation,
        [*decision_documents, bootstrap_decision, label_decision],
        authorization_receipt=authorization_receipt,
    )
    if set(verified_ids) | {
        bootstrap_decision["decision_id"],
        label_decision["decision_id"],
    } != authenticated_ids:
        raise ValueError("authenticated decision source contains an unexpected decision")

    imported_reviewer = "imported/reviewer-result.json"
    rapid_sessions = references("rapid-review-sessions/*.json", minimum=2)
    rapid_executions = references("rapid-review-executions/*.json", minimum=2)
    rapid_context = references(
        "rapid-review-context-executions/*.json", minimum=2
    )
    protected_locators = references("evidence-locators/*.json", minimum=9)
    manifest_input = {
        "repository_id": candidate["repository_id"],
        "candidate_id": candidate["candidate_id"],
        "task_contract": reference("task-contract.json"),
        "effective_policy": reference("effective-policy.json"),
        "authenticated_decisions": decision_references,
        "initial_bootstrap_decision": file_reference(repository, bootstrap_path),
        "initial_bootstrap_verification": reference("promotion-verification.json"),
        "proposed_policy": reference("proposed-policy.json"),
        "lkg_promotion_decision": promotion_references[0],
        "rollback_evidence": reference("rollback/rollback-evidence.json"),
        "evidence_locators": [*mutation.get("evidence_locators", []), *protected_locators],
        "sandbox_capabilities": capabilities,
        "provenance_statements": provenance,
        "gate_manifest": file_reference(repository, gate_manifest_path),
        "required_gate_ids": task["required_gate_ids"],
        "gate_references": gate_references,
        "mutation_corpus": mutation["corpus"],
        "mutation_baseline": mutation["baseline"],
        "mutant_records": mutation["mutant_records"],
        "reviewer_qualification": reference(
            "reviewer-qualification.json"
        ),
        "rapid_review_qualification": reference(
            "rapid-review-qualification.json"
        ),
        "reviewer_qualification_cases": reference(
            "reviewer-qualification-cases.json"
        ),
        "rapid_review_qualification_cases": reference(
            "rapid-review-qualification-cases.json"
        ),
        "reviewer_qualification_corpus": reference("reviewer-corpus.json"),
        "reviewer_qualification_label_decision": reference(
            "reviewer-label-decision.json"
        ),
        "context_sources": reference("context-sources.json"),
        "context_projection": reference("context-projection.json"),
        "context_qualification": reference("context-qualification.json"),
        "context_receipt": reference("context-receipt.json"),
        "context_execution_receipt": reference(
            "context-execution-receipt.json"
        ),
        "reviewer_result": reference(imported_reviewer),
        "reviewer_execution": reference("reviewer-execution.json"),
        "rapid_review_executions": rapid_executions,
        "rapid_review_context_execution_receipts": rapid_context,
        "risk_register": reference("risk-register.json"),
        "oracle_references": references("oracle-references/*.json", minimum=1),
        "coverage_notes": references("coverage-notes/*.json", minimum=1),
        "follow_ups": references("follow-ups/*.json"),
        "assurance_case": reference("assurance-case.json"),
        "risk_assessment": reference("risk-assessment.json"),
        "rapid_review_charters": references("review-charter-*.json", minimum=2),
        "rapid_review_sessions": rapid_sessions,
        "rapid_review_debrief": reference(
            "rapid-review-debrief.json"
        ),
        "risk_disposition": reference("risk-disposition.json"),
        "created_at": args.created_at,
    }
    write_once(evidence / "manifest-input.json", manifest_input)
    write_once(args.verified_decision_ids_output, sorted(authenticated_ids))


if __name__ == "__main__":
    main()
