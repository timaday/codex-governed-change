import unittest
from copy import deepcopy
from datetime import datetime, timezone

from codex_governance.canonical import content_address
from codex_governance.domain.model import DispositionState
from codex_governance.rapid_review import (
    evaluate_rapid_review,
    select_risk_profile,
)
from codex_governance.reviewer import build_reviewer_stdin


class RapidReviewAcceptanceTest(unittest.TestCase):
    REPOSITORY = "repo:example/project"
    CANDIDATE = "sha256:" + "a" * 64
    TASK = "sha256:" + "b" * 64
    POLICY = "sha256:" + "c" * 64
    ASSESSMENT = "sha256:" + "1" * 64

    def assessment(self, *, profile: str = "standard", kind: str = "code") -> dict:
        return {
            "assessment_id": self.ASSESSMENT,
            "candidate_id": self.CANDIDATE,
            "change_kind": kind,
            "risk_profile": profile,
            "hazard_classes": [],
            "mandatory_charter_count": 0 if profile == "low" else (1 if profile == "standard" else 2),
            "rapid_review_required": profile != "low",
            "skip_rationale": "Policy-valid low-risk skip." if profile == "low" else "Rapid review required.",
        }

    def charter(self, suffix: str = "1") -> dict:
        return {
            "charter_id": f"CHARTER-{suffix}",
            "candidate_id": self.CANDIDATE,
            "risk_assessment_sha256": self.ASSESSMENT,
            "mission": "Investigate candidate-bound evidence risk.",
            "oracle_heuristics": ["requirements", "purpose"],
            "required_evidence": ["direct observation"],
        }

    def session(self, suffix: str = "1") -> dict:
        return {
            "session_id": f"SESSION-{suffix}",
            "candidate_id": self.CANDIDATE,
            "charter_id": f"CHARTER-{suffix}",
            "status": "completed",
            "experiments": [
                {
                    "id": f"EXP-{suffix}",
                    "activity_kind": "investigation",
                    "procedure": "Substitute stale evidence.",
                    "observation": "The mismatch was rejected.",
                    "oracle": "exact candidate binding",
                    "evidence_refs": [f"evidence/experiment-{suffix}.json"],
                }
            ],
            "findings": [],
            "counter_hypotheses": ["The mismatch might be normalized away."],
            "coverage_achieved": ["candidate mismatch"],
            "omitted_areas": ["hosted CI was not exercised"],
            "obstacles": ["none observed"],
            "residual_risks": [
                {
                    "risk_id": f"RESIDUAL-{suffix}",
                    "description": "Semantic blind spots remain possible.",
                    "material": False,
                    "evidence_refs": [f"evidence/experiment-{suffix}.json"],
                }
            ],
        }

    def debrief(self, count: int = 1) -> dict:
        story = {
            "summary": "Candidate-bound evidence behavior was investigated.",
            "evidence_refs": ["evidence/session.json"],
            "limitations": ["The investigation cannot prove absence of defects."],
        }
        return {
            "candidate_id": self.CANDIDATE,
            "session_refs": [f"SESSION-{index}" for index in range(1, count + 1)],
            "product_story": deepcopy(story),
            "testing_story": deepcopy(story),
            "quality_of_testing_story": deepcopy(story),
            "residual_risks": ["Semantic blind spots remain possible."],
        }

    def risk_disposition(self, count: int = 1) -> dict:
        return {
            "candidate_id": self.CANDIDATE,
            "items": [
                {
                    "item_id": f"RESIDUAL-{index}",
                    "kind": "residual_risk",
                    "severity": "low",
                    "disposition": "deferred",
                    "decision_ref": "",
                    "evidence_refs": ["evidence/session.json"],
                }
                for index in range(1, count + 1)
            ],
        }

    def evaluate(self, *, profile: str = "standard", kind: str = "code") -> DispositionState:
        count = 1 if profile == "standard" else 2
        return evaluate_rapid_review(
            candidate_id=self.CANDIDATE,
            risk_assessment=self.assessment(profile=profile, kind=kind),
            charters=[self.charter(str(index)) for index in range(1, count + 1)],
            sessions=[self.session(str(index)) for index in range(1, count + 1)],
            debrief=self.debrief(count),
            risk_disposition=self.risk_disposition(count),
            authorized_humans={"maintainer"},
        )

    def test_risk_profile_selects_required_review_work(self) -> None:
        self.assertEqual(("low", 0, False), select_risk_profile("low", [], "recorded rationale"))
        self.assertEqual(("standard", 1, True), select_risk_profile("standard", [], ""))
        self.assertEqual(("elevated", 2, True), select_risk_profile("elevated", [], ""))

    def test_hazardous_work_never_silently_uses_low_profile(self) -> None:
        for hazard in (
            "security", "authorization", "destructive_operations", "migration",
            "concurrency", "data_integrity", "public_api", "governance_boundary",
        ):
            with self.subTest(hazard=hazard):
                self.assertEqual("elevated", select_risk_profile("low", [hazard], "skip")[0])

    def test_low_risk_skip_requires_recorded_rationale(self) -> None:
        with self.assertRaises(ValueError):
            select_risk_profile("low", [], "")
        assessment = self.assessment(profile="low")
        self.assertEqual(
            DispositionState.READY_FOR_HUMAN,
            evaluate_rapid_review(
                candidate_id=self.CANDIDATE,
                risk_assessment=assessment,
                charters=[],
                sessions=[],
                debrief=None,
                risk_disposition=None,
                authorized_humans=set(),
            ),
        )

    def test_missing_mandatory_charter_is_unknown(self) -> None:
        self.assertEqual(
            DispositionState.UNKNOWN,
            evaluate_rapid_review(
                candidate_id=self.CANDIDATE,
                risk_assessment=self.assessment(),
                charters=[], sessions=[], debrief=None, risk_disposition=None,
                authorized_humans=set(),
            ),
        )

    def test_candidate_mismatch_and_stale_session_are_unknown(self) -> None:
        session = self.session()
        session["candidate_id"] = "sha256:" + "b" * 64
        self.assertEqual(
            DispositionState.UNKNOWN,
            evaluate_rapid_review(
                candidate_id=self.CANDIDATE,
                risk_assessment=self.assessment(),
                charters=[self.charter()], sessions=[session],
                debrief=self.debrief(), risk_disposition=self.risk_disposition(),
                authorized_humans=set(),
            ),
        )

    def test_missing_oracle_or_evidence_linkage_is_unknown(self) -> None:
        for field, value in (("oracle", ""), ("evidence_refs", [])):
            session = self.session()
            session["experiments"][0][field] = value
            with self.subTest(field=field):
                self.assertEqual(
                    DispositionState.UNKNOWN,
                    evaluate_rapid_review(
                        candidate_id=self.CANDIDATE,
                        risk_assessment=self.assessment(), charters=[self.charter()],
                        sessions=[session], debrief=self.debrief(),
                        risk_disposition=self.risk_disposition(), authorized_humans=set(),
                    ),
                )

    def test_no_findings_without_coverage_and_residual_reporting_is_unknown(self) -> None:
        for field in ("coverage_achieved", "residual_risks"):
            session = self.session()
            session[field] = []
            with self.subTest(field=field):
                self.assertEqual(
                    DispositionState.UNKNOWN,
                    evaluate_rapid_review(
                        candidate_id=self.CANDIDATE,
                        risk_assessment=self.assessment(), charters=[self.charter()],
                        sessions=[session], debrief=self.debrief(),
                        risk_disposition=self.risk_disposition(), authorized_humans=set(),
                    ),
                )

    def test_obstructed_or_inconclusive_session_is_unknown(self) -> None:
        for status in ("blocked", "inconclusive"):
            session = self.session()
            session["status"] = status
            with self.subTest(status=status):
                self.assertEqual(
                    DispositionState.UNKNOWN,
                    evaluate_rapid_review(
                        candidate_id=self.CANDIDATE,
                        risk_assessment=self.assessment(), charters=[self.charter()],
                        sessions=[session], debrief=self.debrief(),
                        risk_disposition=self.risk_disposition(), authorized_humans=set(),
                    ),
                )

    def test_unresolved_high_finding_blocks_and_only_human_may_accept(self) -> None:
        session = self.session()
        session["findings"] = [{
            "finding_id": "FINDING-HIGH", "severity": "high", "confidence": "high",
            "impact": "Stale evidence could authorize the wrong candidate.",
            "oracle": "exact candidate binding", "evidence_refs": ["evidence/finding.json"],
            "threatened_value": "human approval authority",
        }]
        disposition = self.risk_disposition()
        disposition["items"].append({
            "item_id": "FINDING-HIGH", "kind": "finding", "severity": "high",
            "disposition": "accepted", "decision_ref": "sha256:" + "9" * 64,
            "evidence_refs": ["evidence/finding.json"],
        })
        arguments = dict(
            candidate_id=self.CANDIDATE, risk_assessment=self.assessment(),
            charters=[self.charter()], sessions=[session], debrief=self.debrief(),
            risk_disposition=disposition,
        )
        self.assertEqual(
            DispositionState.BLOCK,
            evaluate_rapid_review(**arguments, authorized_humans={"maintainer"}),
        )
        decision = content_address(
            {
                "schema_version": "1.0.0", "repository_id": self.REPOSITORY,
                "decision_type": "risk_reduction",
                "task_contract_sha256": self.TASK,
                "candidate_id": self.CANDIDATE, "base_commit": "1" * 40,
                "effective_policy_sha256": self.POLICY,
                "scope": ["FINDING-HIGH"],
                "issuer": {
                    "subject": "protected-maintainer",
                    "authentication_method": "protected-source-assertion",
                    "protected_source": "decisions/risk.json",
                    "assertion_sha256": "sha256:" + "d" * 64,
                },
                "issued_at": "2026-08-26T10:00:00Z",
                "expires_at": "2026-08-27T10:00:00Z",
                "single_use": False, "consumption_id": "",
            },
            "decision_id",
        )
        disposition["items"][-1]["decision_ref"] = decision["decision_id"]
        self.assertEqual(
            DispositionState.READY_FOR_HUMAN,
            evaluate_rapid_review(
                **arguments,
                authorized_humans={"maintainer"},
                authenticated_decisions={decision["decision_id"]: decision},
                verified_decision_ids=frozenset({decision["decision_id"]}),
                repository_id=self.REPOSITORY,
                task_contract_sha256=self.TASK,
                policy_sha256=self.POLICY,
                now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
            ),
        )

    def test_specification_and_code_profiles_both_work(self) -> None:
        self.assertEqual(DispositionState.READY_FOR_HUMAN, self.evaluate(kind="specification"))
        self.assertEqual(DispositionState.READY_FOR_HUMAN, self.evaluate(kind="code"))

    def test_heuristic_checklist_completion_alone_is_unknown(self) -> None:
        session = self.session()
        session["experiments"][0]["activity_kind"] = "checking"
        self.assertEqual(
            DispositionState.UNKNOWN,
            evaluate_rapid_review(
                candidate_id=self.CANDIDATE, risk_assessment=self.assessment(),
                charters=[self.charter()], sessions=[session], debrief=self.debrief(),
                risk_disposition=self.risk_disposition(), authorized_humans=set(),
            ),
        )

    def test_rapid_reviewer_input_is_allowlisted_and_fresh_context_only(self) -> None:
        digest = lambda character: "sha256:" + character * 64
        payload = build_reviewer_stdin(
            fixed_prompt="FIXED PROTECTED RAPID REVIEW",
            permitted_inputs={
                "review_mode": "rapid_review",
                "repository_id": "repo:example/project",
                "candidate_id": self.CANDIDATE,
                "candidate_path": "candidate",
                "task_contract_path": "evidence/task.json",
                "task_contract_sha256": digest("3"),
                "effective_policy_path": "evidence/policy.json",
                "effective_policy_sha256": digest("4"),
                "gate_manifest_path": "evidence/gates.json",
                "gate_manifest_sha256": digest("5"),
                "context_receipt_path": "evidence/context.json",
                "context_receipt_sha256": digest("6"),
                "context_projection_path": "evidence/projection.json",
                "context_projection_sha256": digest("7"),
                "reviewer_qualification_path": "evidence/qualification.json",
                "reviewer_qualification_sha256": digest("8"),
                "reviewer_qualification_id": digest("9"),
                "reviewer_prompt_sha256": digest("a"),
                "risk_assessment_path": "evidence/risk-assessment.json",
                "risk_assessment_sha256": self.ASSESSMENT,
                "review_charter_path": "evidence/charter.json",
                "review_charter_sha256": "sha256:" + "2" * 64,
            },
        )
        self.assertIn('"review_mode":"rapid_review"', payload)
        self.assertNotIn("author_transcript", payload)
        with self.assertRaises(ValueError):
            build_reviewer_stdin(
                fixed_prompt="FIXED",
                permitted_inputs={
                    "candidate_id": self.CANDIDATE,
                    "review_mode": "rapid_review",
                    "author_transcript": "private implementer chat",
                },
            )


if __name__ == "__main__":
    unittest.main()
