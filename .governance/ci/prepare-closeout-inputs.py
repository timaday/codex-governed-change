#!/usr/bin/env python3
"""Derive RST closeout and assurance inputs without granting model authority."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from bootstrap import validate_initial_bootstrap
from common import (
    content_address,
    ensure_within,
    load_and_validate_once,
    load_json,
    read_bytes_once,
    require_json_within,
    sha256_bytes,
    verify_decision_source_assertion,
    write_once,
)


CLAIM_RULES = {
    "scope_authorized": "RULE_SCOPE_AUTH",
    "candidate_current": "RULE_CANDIDATE_CURRENT",
    "gates_complete": "RULE_GATES_COMPLETE",
    "governance_integrity": "RULE_GOVERNANCE_LKG",
    "rst_complete": "RULE_RST_COMPLETE",
    "mutation_complete": "RULE_MUTATION_COMPLETE",
    "fresh_review_complete": "RULE_FRESH_REVIEW",
    "residual_risk_visible": "RULE_RISK_VISIBLE",
    "context_complete": "RULE_CONTEXT_COMPLETE",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    args = parser.parse_args()

    repository = args.candidate.resolve()
    evidence = ensure_within(repository, args.evidence)
    authority_root = Path(__file__).resolve().parents[2]
    schema_root = authority_root / "kernel" / "schemas"
    candidate = load_json(evidence / "candidate.json")
    task_sha = sha256_bytes(read_bytes_once(evidence / "task-contract.json"))
    policy_sha = sha256_bytes(read_bytes_once(evidence / "effective-policy.json"))
    policy = load_json(evidence / "effective-policy.json")
    risk = load_json(evidence / "risk-assessment.json")
    gate_summary = load_json(evidence / "gate-summary.json")
    mutation = load_json(evidence / "mutation-summary.json")
    reviewer = load_json(evidence / "reviewer-result.json")
    qualifications = [
        load_json(evidence / "reviewer-qualification.json"),
        load_json(evidence / "rapid-review-qualification.json"),
    ]
    sessions = [load_json(path) for path in sorted((evidence / "rapid-review-sessions").glob("*.json"))]
    if len(sessions) < 2:
        raise ValueError("elevated closeout requires two rapid-review sessions")
    if (
        any(item.get("qualified") is not True or item.get("human_labelled") is not True for item in qualifications)
        or reviewer.get("verdict") != "NO_BLOCKING_FINDING_OBSERVED"
        or reviewer.get("findings")
        or reviewer.get("missing_evidence")
        or any(session.get("status") != "completed" for session in sessions)
        or any(item.get("status") != "PASS" for item in gate_summary.get("results", []))
        or mutation.get("state") != "PASS"
    ):
        raise ValueError("protected closeout prerequisites are not successful")

    observation = load_json(evidence / "decision-source-observation.json")
    decisions = []
    for item in observation.get("verified_decisions", []):
        decisions.append(
            load_json(require_json_within(repository, evidence, item["path"]))
        )
    bootstrap_reference = observation.get("bootstrap_decision")
    if not isinstance(bootstrap_reference, dict):
        raise ValueError("protected initial-LKG bootstrap decision is absent")
    bootstrap_path = require_json_within(
        repository, evidence, bootstrap_reference.get("path")
    )
    bootstrap_decision = load_and_validate_once(
        bootstrap_path,
        authority_root
        / ".governance/schemas/initial-lkg-bootstrap-decision.schema.json",
    )
    if (
        sha256_bytes(
            read_bytes_once(bootstrap_path)
        )
        != bootstrap_reference.get("sha256")
        or bootstrap_decision.get("decision_id")
        != bootstrap_reference.get("decision_id")
    ):
        raise ValueError("protected initial-LKG bootstrap observation does not reconstruct")
    label_decision = load_json(evidence / "reviewer-label-decision.json")
    if (
        observation.get("authenticated_label_decision_id")
        != label_decision.get("decision_id")
    ):
        raise ValueError("protected reviewer label decision is not authenticated")
    receipt_reference = observation.get("authorization_receipt")
    receipt_path = (
        require_json_within(repository, evidence, receipt_reference.get("path"))
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
        [*decisions, bootstrap_decision, label_decision],
        authorization_receipt=authorization_receipt,
    )
    if authenticated_ids != {
        *(item["decision_id"] for item in decisions),
        bootstrap_decision["decision_id"],
        label_decision["decision_id"],
    }:
        raise ValueError("authenticated decision set does not reconstruct")
    types = {item.get("decision_type") for item in decisions}
    if not {
        "task_approval",
        "governance_authorization",
        "lkg_promotion",
    }.issubset(types):
        raise ValueError("task, governance, and promotion decisions are required")
    label_authority = any(
        item.get("decision_type") == "governance_authorization"
        and "reviewer-corpus-labels" in item.get("scope", [])
        for item in decisions
    )
    if not label_authority:
        raise ValueError("protected reviewer corpus label authority is absent")

    rollback_plan_path = evidence / "rollback-plan.json"
    rollback_plan = load_json(rollback_plan_path)
    rollback_task_path = evidence / "rollback-task-contract.json"
    rollback_task = load_and_validate_once(
        rollback_task_path, schema_root / "task-contract.schema.json"
    )
    proposed_path = evidence / "proposed-policy.json"
    rollback_root = evidence / "rollback"
    rollback_path = rollback_root / "rollback-evidence.json"
    rollback_candidate_path = rollback_root / "candidate.json"
    rollback_gate_path = rollback_root / "gate-result.json"
    rollback_capability_path = rollback_root / "sandbox-capability.json"
    rollback_provenance_path = rollback_root / "provenance-statement.json"
    proposed = load_and_validate_once(
        proposed_path, schema_root / "effective-policy.schema.json"
    )
    rollback = load_and_validate_once(
        rollback_path, schema_root / "rollback-evidence.schema.json"
    )
    rollback_candidate = load_and_validate_once(
        rollback_candidate_path, schema_root / "candidate.schema.json"
    )
    rollback_gate = load_and_validate_once(
        rollback_gate_path, schema_root / "gate-result.schema.json"
    )
    rollback_capability = load_and_validate_once(
        rollback_capability_path, schema_root / "sandbox-capability.schema.json"
    )
    rollback_provenance = load_and_validate_once(
        rollback_provenance_path, schema_root / "provenance-statement.schema.json"
    )
    proposed_sha = sha256_bytes(read_bytes_once(proposed_path))
    rollback_gate_sha = sha256_bytes(read_bytes_once(rollback_gate_path))
    rollback_capability_sha = sha256_bytes(read_bytes_once(rollback_capability_path))
    rollback_provenance_sha = sha256_bytes(read_bytes_once(rollback_provenance_path))
    promotion_verification = validate_initial_bootstrap(
        repository=repository,
        evidence=evidence,
        candidate=candidate,
        bootstrap_policy=policy,
        bootstrap_policy_sha256=policy_sha,
        task_contract_sha256=task_sha,
        rollback_task=rollback_task,
        rollback_task_sha256=sha256_bytes(read_bytes_once(rollback_task_path)),
        proposed_policy=proposed,
        proposed_policy_sha256=proposed_sha,
        rollback_plan=rollback_plan,
        rollback_plan_sha256=sha256_bytes(read_bytes_once(rollback_plan_path)),
        rollback_candidate=rollback_candidate,
        rollback_candidate_sha256=sha256_bytes(
            read_bytes_once(rollback_candidate_path)
        ),
        rollback=rollback,
        rollback_gate=rollback_gate,
        rollback_gate_sha256=rollback_gate_sha,
        rollback_capability=rollback_capability,
        rollback_capability_sha256=rollback_capability_sha,
        rollback_provenance=rollback_provenance,
        rollback_provenance_sha256=rollback_provenance_sha,
        observation=observation,
        decisions=[bootstrap_decision, *decisions],
        verified_decision_ids={
            bootstrap_decision["decision_id"],
            *(item["decision_id"] for item in decisions),
        },
        evaluated_at=datetime.fromisoformat(args.created_at.replace("Z", "+00:00")),
    )
    write_once(evidence / "promotion-verification.json", promotion_verification)

    oracles = []
    for suffix, name, source, heuristic, fallibility, applicability in (
        (
            "AUTHORITY",
            "Protected authority consistency",
            "docs/requirements.md",
            "Compare every decision, policy, and admission input with the protected source and exact candidate.",
            "A protected policy can still omit a novel authority surface.",
            "Governance, workflow, schema, reviewer, and admission changes.",
        ),
        (
            "PORTABILITY",
            "Public portability and credential exclusion",
            "docs/specification.md",
            "Search candidate and evidence for machine-derived state and reconcile real runtime capabilities.",
            "Pattern scans cannot identify every sensitive or machine-derived value.",
            "All public repository content and hosted evidence.",
        ),
    ):
        document = {
            "schema_version": "1.0.0",
            "repository_id": candidate["repository_id"],
            "task_contract_sha256": task_sha,
            "candidate_id": candidate["candidate_id"],
            "name": name,
            "source": source,
            "source_sha256": sha256_bytes(read_bytes_once(repository / source)),
            "heuristic": heuristic,
            "known_fallibility": [fallibility],
            "applicability": applicability,
            "created_at": args.created_at,
        }
        document = content_address(document, "oracle_id")
        path = evidence / "oracle-references" / (suffix.lower() + ".json")
        write_once(path, document)
        oracles.append(document)

    coverage_documents = []
    evidence_refs = []
    all_findings = []
    all_residuals = []
    follow_ups = []
    for session in sessions:
        session_evidence = [
            ref
            for experiment in session.get("experiments", [])
            for ref in experiment.get("evidence_refs", [])
        ]
        evidence_refs.extend(session_evidence)
        all_findings.extend(session.get("findings", []))
        all_residuals.extend(session.get("residual_risks", []))
        coverage = {
            "schema_version": "1.0.0",
            "repository_id": candidate["repository_id"],
            "task_contract_sha256": task_sha,
            "candidate_id": candidate["candidate_id"],
            "session_id": session["session_id"],
            "covered": session["coverage_achieved"],
            "omitted": session["omitted_areas"],
            "oracle_refs": [item["oracle_id"] for item in oracles],
            "limitations": session["obstacles"],
            "created_at": args.created_at,
        }
        coverage = content_address(coverage, "coverage_note_id")
        write_once(
            evidence / "coverage-notes" / (session["session_id"].lower() + ".json"),
            coverage,
        )
        coverage_documents.append(coverage)
        for index, description in enumerate(
            [*session.get("follow_up_charters", []), *session.get("new_risks", [])],
            start=1,
        ):
            follow_up = {
                "schema_version": "1.0.0",
                "repository_id": candidate["repository_id"],
                "task_contract_sha256": task_sha,
                "candidate_id": candidate["candidate_id"],
                "kind": "charter",
                "source_kind": "observation",
                "source_id": session["session_id"],
                "description": description,
                "priority": "high",
                "required": True,
                "status": "unknown",
                "created_at": args.created_at,
            }
            follow_up = content_address(follow_up, "follow_up_id")
            write_once(
                evidence / "follow-ups" / f"{session['session_id'].lower()}-{index}.json",
                follow_up,
            )
            follow_ups.append(follow_up)
    if follow_ups:
        raise ValueError("rapid review requested unresolved follow-up work")
    if not evidence_refs:
        raise ValueError("rapid review contains no direct evidence references")

    residual_descriptions = [item["description"] for item in all_residuals]
    if not residual_descriptions:
        raise ValueError("rapid review must state residual risk")
    session_ids = [item["session_id"] for item in sessions]
    unique_evidence = sorted(set(evidence_refs))
    debrief = {
        "schema_version": "1.0.0",
        "repository_id": candidate["repository_id"],
        "task_contract_sha256": task_sha,
        "debrief_id": "T24-PROTECTED-DEBRIEF-001",
        "candidate_id": candidate["candidate_id"],
        "session_refs": session_ids,
        "product_story": {
            "summary": "The candidate was investigated against protected purpose, authority, portability, and human-control values.",
            "evidence_refs": unique_evidence,
            "limitations": ["Investigative review cannot prove absence of unknown defects."],
        },
        "testing_story": {
            "summary": "Two elevated-risk charters combined real deterministic checks, mutation evidence, and fresh read-only investigation.",
            "evidence_refs": unique_evidence,
            "limitations": ["The curated mutation and charter sets are finite."],
        },
        "quality_of_testing_story": {
            "summary": "Direct schemas, fixed gates, provenance reconstruction, and fallible RST oracles provide complementary evidence.",
            "evidence_refs": unique_evidence,
            "limitations": ["Same-model correlated blind spots remain possible and visible as residual risk."],
        },
        "actionable_findings": [item["finding_id"] for item in all_findings],
        "residual_risks": residual_descriptions,
        "created_at": args.created_at,
        "producer_version": "0.1.0-authority-bootstrap",
        "provenance": {
            "produced_by": "protected deterministic closeout adapter",
            "method": "Three-story aggregation of exact-candidate rapid-review sessions",
            "source_refs": session_ids,
        },
    }
    write_once(evidence / "rapid-review-debrief.json", debrief)

    decision_by_scope = {}
    for decision in decisions:
        if decision.get("decision_type") == "risk_reduction":
            for scope in decision.get("scope", []):
                decision_by_scope[scope] = decision["decision_id"]
    disposition_items = []
    blocked = False
    for finding in all_findings:
        item_id = finding["finding_id"]
        decision_ref = decision_by_scope.get(item_id, "")
        severe = finding["severity"] in {"critical", "high"}
        accepted = severe and bool(decision_ref)
        disposition = "accepted" if accepted else ("unknown" if severe else "deferred")
        blocked = blocked or disposition == "unknown"
        disposition_items.append(
            {
                "item_id": item_id,
                "kind": "finding",
                "severity": finding["severity"],
                "disposition": disposition,
                "rationale": "Protected human risk decision applies." if accepted else "No material-risk authority was inferred by the adapter.",
                "evidence_refs": finding["evidence_refs"],
                "decision_ref": decision_ref,
            }
        )
    for residual in all_residuals:
        item_id = residual["risk_id"]
        decision_ref = decision_by_scope.get(item_id, "")
        material = residual["material"] is True
        accepted = material and bool(decision_ref)
        disposition = "accepted" if accepted else ("unknown" if material else "deferred")
        blocked = blocked or disposition == "unknown"
        disposition_items.append(
            {
                "item_id": item_id,
                "kind": "residual_risk",
                "severity": "high" if material else "low",
                "disposition": disposition,
                "rationale": "Protected human risk decision applies." if accepted else "Non-material risk remains visible without automated acceptance." if not material else "Material risk lacks protected human authority.",
                "evidence_refs": residual["evidence_refs"],
                "decision_ref": decision_ref,
            }
        )
    if not disposition_items:
        raise ValueError("risk disposition cannot be empty")
    risk_disposition = {
        "schema_version": "1.0.0",
        "risk_disposition_id": "T24-PROTECTED-RISK-DISPOSITION-001",
        "repository_id": candidate["repository_id"],
        "task_contract_sha256": task_sha,
        "candidate_id": candidate["candidate_id"],
        "debrief_sha256": sha256_bytes(read_bytes_once(evidence / "rapid-review-debrief.json")),
        "items": disposition_items,
        "state": "BLOCK" if blocked else "READY_FOR_HUMAN",
        "human_owned": True,
        "approved": False,
        "created_at": args.created_at,
        "producer_version": "0.1.0-authority-bootstrap",
        "provenance": {
            "produced_by": "protected deterministic closeout adapter",
            "method": "Exact finding and residual-risk aggregation with protected risk-decision lookup",
            "source_refs": [
                "artifacts/governance/completion/evidence/rapid-review-debrief.json"
            ],
        },
    }
    write_once(evidence / "risk-disposition.json", risk_disposition)
    if blocked:
        raise ValueError("material finding or residual risk lacks protected human disposition")

    register_risks = []
    for index, hypothesis in enumerate(risk["risk_hypotheses"], start=1):
        register_risks.append(
            {
                "risk_id": f"T24-RISK-{index:03d}",
                "description": hypothesis,
                "threatened_value": risk["value_at_risk"][0],
                "impact": "critical" if index <= 4 else "high",
                "status": "investigating",
                "source_refs": [
                    "artifacts/governance/completion/evidence/risk-assessment.json"
                ],
                "charter_refs": [session["charter_id"] for session in sessions],
            }
        )
    risk_register = {
        "schema_version": "1.0.0",
        "repository_id": candidate["repository_id"],
        "task_contract_sha256": task_sha,
        "candidate_id": candidate["candidate_id"],
        "risks": register_risks,
        "updated_from": session_ids,
        "created_at": args.created_at,
        "producer_version": "0.1.0-authority-bootstrap",
    }
    risk_register = content_address(risk_register, "risk_register_id")
    write_once(evidence / "risk-register.json", risk_register)

    def locator(
        name: str, path: Path, media_type: str = "application/json"
    ) -> dict:
        document = {
            "schema_version": "1.0.0",
            "repository_id": candidate["repository_id"],
            "task_contract_sha256": task_sha,
            "candidate_id": candidate["candidate_id"],
            "kind": "artifact",
            "path": path.resolve().relative_to(repository).as_posix(),
            "artifact_sha256": sha256_bytes(read_bytes_once(path)),
            "media_type": media_type,
        }
        document = content_address(document, "locator_id")
        write_once(evidence / "evidence-locators" / (name + ".json"), document)
        return document

    locator_by_claim = {
        "scope_authorized": locator("scope-authorized", evidence / "decision-source-observation.json"),
        "candidate_current": locator("candidate-current", evidence / "candidate.json"),
        "gates_complete": locator("gates-complete", repository / gate_summary["gate_manifest"]["path"]),
        "governance_integrity": locator("governance-integrity", evidence / "promotion-verification.json"),
        "rst_complete": locator("rst-complete", evidence / "rapid-review-debrief.json"),
        "mutation_complete": locator("mutation-complete", evidence / "mutation-summary.json"),
        "fresh_review_complete": locator("fresh-review-complete", evidence / "reviewer-result.json"),
        "residual_risk_visible": locator("residual-risk-visible", evidence / "risk-disposition.json"),
        "context_complete": locator("context-complete", evidence / "context-execution-receipt.json"),
    }
    for name, path in (
        ("rollback-plan", rollback_plan_path),
        ("proposed-policy", proposed_path),
        ("rollback-evidence", rollback_path),
        ("rollback-candidate", rollback_candidate_path),
        ("rollback-gate", rollback_gate_path),
        ("rollback-capability", rollback_capability_path),
        ("rollback-provenance", rollback_provenance_path),
    ):
        locator(name, path)
    locator("rollback-stdout", rollback_root / "stdout.bin", "application/octet-stream")
    locator("rollback-stderr", rollback_root / "stderr.bin", "application/octet-stream")
    claims = []
    for claim_id, rule in CLAIM_RULES.items():
        support = locator_by_claim[claim_id]
        claims.append(
            {
                "claim_id": claim_id,
                "argument_rule": rule,
                "supporting_evidence": [
                    {"locator_id": support["locator_id"], "sha256": support["artifact_sha256"]}
                ],
                "refuting_evidence": [],
                "limitations": ["The claim is bounded to the exact referenced evidence."],
                "unresolved_defeaters": [],
                "classification": "DIRECTLY_OBSERVED" if claim_id == "candidate_current" else "VERIFIED_WITHIN_SCOPE",
            }
        )
    assurance = {
        "schema_version": "1.0.0",
        "repository_id": candidate["repository_id"],
        "candidate_id": candidate["candidate_id"],
        "task_contract_sha256": task_sha,
        "effective_policy_sha256": policy_sha,
        "claims": claims,
        "unresolved_defeaters": [],
        "state": "READY_FOR_HUMAN",
        "created_at": args.created_at,
        "producer_version": "0.1.0-authority-bootstrap",
    }
    assurance = content_address(assurance, "assurance_case_id")
    write_once(evidence / "assurance-case.json", assurance)


if __name__ == "__main__":
    main()
