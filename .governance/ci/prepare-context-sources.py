#!/usr/bin/env python3
"""Build exact-candidate RST inputs and the deterministic context source set."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    content_address,
    ensure_within,
    load_json,
    read_bytes_once,
    sha256_bytes,
    write_once,
)


def risk_assessment(
    *, candidate: dict, task: dict, task_sha: str, created_at: str
) -> dict:
    surfaces = sorted({item["path"] for item in task["affected_surfaces"]})
    document = {
        "schema_version": "1.0.0",
        "repository_id": candidate["repository_id"],
        "task_contract_sha256": task_sha,
        "candidate_id": candidate["candidate_id"],
        "change_kind": "governance",
        "risk_profile": "elevated",
        "hazard_classes": [
            "authorization",
            "data_integrity",
            "governance_boundary",
            "security",
        ],
        "assessed_surfaces": surfaces,
        "stakeholders": [
            "change authors",
            "human approvers",
            "public repository adopters",
            "repository maintainers",
            "reviewers",
        ],
        "value_at_risk": [
            "correct fail-closed readiness decisions",
            "human ownership of approval and risk acceptance",
            "portable operation without developer-machine coupling",
            "separation of candidate, reviewer, and acceptance authority",
        ],
        "risk_hypotheses": [
            "Candidate-controlled code may modify or bypass its own acceptance authority.",
            "Incomplete, stale, forged, conflicting, symlinked, or truncated evidence may be promoted to success.",
            "The declared sandbox may not match its real container capability.",
            "Reviewer model, prompt, schema, launcher, context, candidate snapshot, or authentication may drift.",
            "A same-name check from another source may be mistaken for the protected GitHub App check.",
            "Developer-specific paths, endpoints, identities, or credentials may enter public content.",
        ],
        "mandatory_charter_count": 2,
        "rapid_review_required": True,
        "skip_rationale": "Authorization, evidence, sandbox, reviewer, portability, and admission boundaries are hazardous.",
        "created_at": created_at,
        "producer_version": "0.1.0-authority-bootstrap",
        "provenance": {
            "produced_by": "protected authority adapter",
            "method": "Exact-candidate hazard analysis against the protected task and policy",
            "source_refs": [
                "artifacts/governance/completion/evidence/task-contract.json",
                "artifacts/governance/completion/evidence/candidate.json",
                "docs/requirements.md",
                "docs/threat-model.md",
            ],
        },
    }
    return content_address(document, "assessment_id")


def charter(
    *,
    charter_id: str,
    mission: str,
    target: str,
    candidate: dict,
    task_sha: str,
    assessment_id: str,
    created_at: str,
    affected_surfaces: list[str],
    coverage_areas: list[str],
    risk_hypotheses: list[str],
    techniques: list[str],
    oracle_heuristics: list[str],
    resources: list[str],
    constraints: list[str],
) -> dict:
    return {
        "schema_version": "1.0.0",
        "repository_id": candidate["repository_id"],
        "task_contract_sha256": task_sha,
        "charter_id": charter_id,
        "candidate_id": candidate["candidate_id"],
        "risk_assessment_sha256": assessment_id,
        "mission": mission,
        "target": target,
        "affected_surfaces": affected_surfaces,
        "stakeholders": [
            "human approvers",
            "public repository adopters",
            "repository maintainers",
        ],
        "value_at_risk": [
            "fail-closed readiness decisions",
            "human approval authority",
            "reconstructable exact-candidate evidence",
        ],
        "risk_hypotheses": risk_hypotheses,
        "quality_criteria": [
            "authority separation",
            "fail-closed monotonicity",
            "repository and candidate binding",
            "direct evidence for every finding",
        ],
        "coverage_areas": coverage_areas,
        "techniques": techniques,
        "oracle_heuristics": oracle_heuristics,
        "resources": resources,
        "constraints": constraints,
        "timebox_minutes": 60,
        "required_evidence": [
            "direct source and test locations for every finding",
            "exact violated requirement or acceptance oracle",
            "explicit omitted areas and residual risks",
        ],
        "stopping_heuristic": "Stop only after tracing the named risks through negative paths, or report a blocking obstacle and follow-up charter.",
        "created_at": created_at,
        "producer_version": "0.1.0-authority-bootstrap",
        "provenance": {
            "produced_by": "protected authority adapter",
            "method": "Risk-proportionate charter selection from the exact-candidate assessment",
            "source_refs": [
                "artifacts/governance/completion/evidence/risk-assessment.json",
                "docs/requirements.md",
                "docs/traceability.md",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--reviewer-prompt", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    args = parser.parse_args()

    repository = args.candidate.resolve()
    evidence = ensure_within(repository, args.evidence)
    reviewer_prompt = args.reviewer_prompt.resolve()
    if reviewer_prompt.is_symlink() or not reviewer_prompt.is_file():
        raise ValueError("protected reviewer prompt must be a regular file")
    candidate = load_json(evidence / "candidate.json")
    task = load_json(evidence / "task-contract.json")
    policy = load_json(evidence / "effective-policy.json")
    task_sha = sha256_bytes(read_bytes_once(evidence / "task-contract.json"))

    risk = risk_assessment(
        candidate=candidate,
        task=task,
        task_sha=task_sha,
        created_at=args.created_at,
    )
    write_once(evidence / "risk-assessment.json", risk)
    authority_charter = charter(
        charter_id="T24-AUTHORITY-AND-EVIDENCE-001",
        mission="Find any path that lets candidate code, incomplete evidence, or a non-human actor authorize readiness.",
        target="Candidate identity, protected configuration, decisions, evidence reconstruction, assurance, and admission",
        candidate=candidate,
        task_sha=task_sha,
        assessment_id=risk["assessment_id"],
        created_at=args.created_at,
        affected_surfaces=[
            "src/codex_governance/admission.py",
            "src/codex_governance/assurance.py",
            "src/codex_governance/authority.py",
            "src/codex_governance/evidence.py",
            "schemas/",
            "examples/github/governed-change.yml",
        ],
        coverage_areas=[
            "LKG policy authority",
            "candidate and evidence replay",
            "reviewer and human authority separation",
            "missing, failed, stale, and unknown transitions",
        ],
        risk_hypotheses=[
            "A proposed policy can evaluate its own promotion.",
            "A stale or cross-repository artifact can satisfy admission.",
            "A reviewer, App, or mutable workflow can substitute for a human decision.",
            "Missing or truncated observations can become success.",
        ],
        techniques=[
            "adversarial state-transition analysis",
            "cross-repository and stale-evidence substitution",
            "negative-path oracle tracing",
        ],
        oracle_heuristics=[
            "GOV-003",
            "GOV-008",
            "GOV-030",
            "GOV-041",
            "GOV-048",
            "GOV-050",
        ],
        resources=[
            "exact candidate snapshot",
            "protected gate and mutation evidence",
            "requirements and traceability contracts",
        ],
        constraints=[
            "read-only candidate access",
            "no implementer transcript",
            "no candidate-controlled reviewer rules",
            "no authority inference from model output",
        ],
    )
    runtime_charter = charter(
        charter_id="T24-RUNTIME-REVIEWER-PORTABILITY-002",
        mission="Find false isolation, reviewer leakage, model drift, unsafe execution, credential dependence, or machine coupling.",
        target="Disposable gates, mutation, sanitized Codex review, context, App publication, and portability",
        candidate=candidate,
        task_sha=task_sha,
        assessment_id=risk["assessment_id"],
        created_at=args.created_at,
        affected_surfaces=[
            "src/codex_governance/sandbox.py",
            "src/codex_governance/gate.py",
            "src/codex_governance/mutation_runner.py",
            "src/codex_governance/reviewer.py",
            "src/codex_governance/context.py",
            ".codex/",
            "tests/acceptance/test_public_portability.py",
        ],
        coverage_areas=[
            "container isolation and capabilities",
            "reviewer environment and instruction allowlists",
            "model and authentication identity",
            "context truncation and retrieval",
            "public portability and credential exclusion",
        ],
        risk_hypotheses=[
            "The real container cannot establish its declared boundary.",
            "The reviewer can inherit author context, rules, hooks, agents, connectors, or credentials.",
            "The qualified identity can drift from model, prompt, schema, launcher, or CLI.",
            "A machine path, endpoint, credential, or host assumption can enter public content.",
            "The context compiler can omit a failure, survivor, limitation, or affected path.",
        ],
        techniques=[
            "real-container execution",
            "environment and instruction canaries",
            "identity-digest reconstruction",
            "path and credential scanning",
            "context-budget boundary experiments",
        ],
        oracle_heuristics=[
            "GOV-005",
            "GOV-006",
            "GOV-021",
            "GOV-044",
            "GOV-055",
            "GOV-062",
        ],
        resources=[
            "immutable container image digest",
            "sandbox and provenance statements",
            "reviewer prompt and schema digests",
            "public portability tests",
            "context receipts and projections",
        ],
        constraints=[
            "networkless candidate execution",
            "no candidate or reviewer secrets",
            "ChatGPT-authenticated gpt-5.6-sol only",
            "no OpenAI API-key path",
        ],
    )
    charters = [
        ("review-charter-authority.json", authority_charter),
        ("review-charter-runtime.json", runtime_charter),
    ]
    for name, document in charters:
        write_once(evidence / name, document)


if __name__ == "__main__":
    main()
