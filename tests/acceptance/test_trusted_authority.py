import unittest
from copy import deepcopy
from datetime import datetime, timezone

from codex_governance.domain.model import DispositionState
from codex_governance.evidence import content_address


class TrustedAuthorityAcceptanceTest(unittest.TestCase):
    REPOSITORY = "repo:example/project"
    CANDIDATE = "sha256:" + "a" * 64
    TASK = "sha256:" + "b" * 64
    POLICY = "sha256:" + "c" * 64

    def decision(self, kind: str = "governance_authorization") -> dict:
        return content_address({
            "schema_version": "1.0.0",
            "repository_id": self.REPOSITORY,
            "decision_type": kind,
            "task_contract_sha256": self.TASK,
            "candidate_id": self.CANDIDATE,
            "base_commit": "1" * 40,
            "effective_policy_sha256": self.POLICY,
            "scope": ["schemas/"],
            "issuer": {
                "subject": "repository-maintainer",
                "authentication_method": "protected-source-assertion",
                "protected_source": "decisions/governance.json",
                "assertion_sha256": "sha256:" + "d" * 64,
            },
            "issued_at": "2026-08-26T10:00:00Z",
            "expires_at": "2026-08-27T10:00:00Z",
            "single_use": True,
            "consumption_id": "",
        }, "decision_id")

    def test_boolean_or_free_text_never_proves_governance_authority(self) -> None:
        from codex_governance.authority import authorize_governance_change

        self.assertEqual(
            DispositionState.BLOCK,
            authorize_governance_change(
                repository_id=self.REPOSITORY, candidate_id=self.CANDIDATE,
                task_contract_sha256=self.TASK, policy_sha256=self.POLICY,
                changed_paths=["schemas/example.schema.json"], decisions=[],
                verified_decision_ids=frozenset(),
                governance_change_authorized=True, approver="maintainer",
                now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
            ),
        )

    def test_exact_authenticated_decision_allows_other_gates_to_continue(self) -> None:
        from codex_governance.authority import authorize_governance_change

        decision = self.decision()
        self.assertIsNone(
            authorize_governance_change(
                repository_id=self.REPOSITORY, candidate_id=self.CANDIDATE,
                task_contract_sha256=self.TASK, policy_sha256=self.POLICY,
                changed_paths=["schemas/example.schema.json"], decisions=[decision],
                verified_decision_ids=frozenset({decision["decision_id"]}),
                governance_change_authorized=False, approver="",
                now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
            )
        )
        self.assertEqual(
            DispositionState.BLOCK,
            authorize_governance_change(
                repository_id=self.REPOSITORY, candidate_id=self.CANDIDATE,
                task_contract_sha256=self.TASK, policy_sha256=self.POLICY,
                changed_paths=["schemas/example.schema.json"], decisions=[decision],
                verified_decision_ids=frozenset(),
                governance_change_authorized=False, approver="",
                now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
            ),
        )

    def test_forged_stale_or_cross_repository_decision_blocks(self) -> None:
        from codex_governance.authority import decision_applies

        for field, value in (
            ("repository_id", "repo:other/project"),
            ("candidate_id", "sha256:" + "e" * 64),
            ("task_contract_sha256", "sha256:" + "f" * 64),
            ("effective_policy_sha256", "sha256:" + "0" * 64),
        ):
            decision = deepcopy(self.decision())
            decision[field] = value
            decision = content_address(decision, "decision_id")
            with self.subTest(field=field):
                self.assertFalse(
                    decision_applies(
                        decision=decision, repository_id=self.REPOSITORY,
                        candidate_id=self.CANDIDATE, task_contract_sha256=self.TASK,
                        policy_sha256=self.POLICY, required_type="governance_authorization",
                        required_scope=["schemas/"],
                        now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
                        source_verified=True,
                    )
                )

        forged = self.decision()
        forged["issuer"]["subject"] = "forged-subject"
        self.assertFalse(
            decision_applies(
                decision=forged, repository_id=self.REPOSITORY,
                candidate_id=self.CANDIDATE, task_contract_sha256=self.TASK,
                policy_sha256=self.POLICY, required_type="governance_authorization",
                required_scope=["schemas/"],
                now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
                source_verified=True,
            )
        )

    def test_task_may_increase_but_not_reduce_protected_obligations(self) -> None:
        from codex_governance.authority import resolve_protected_obligations

        result = resolve_protected_obligations(
            changed_paths=["schemas/example.schema.json"], affected_surfaces=["governance"],
            protected_rules=[{"path_prefix": "schemas/", "risk_profile": "elevated", "gate_ids": ["acceptance", "mutation"]}],
            requested_risk="low", requested_gates=["acceptance"], reduction_decisions=[],
        )
        self.assertEqual("elevated", result["risk_profile"])
        self.assertEqual({"acceptance", "mutation"}, set(result["gate_ids"]))

        closure_only = resolve_protected_obligations(
            changed_paths=["src/service.py"],
            affected_surfaces=["schemas/service.schema.json"],
            protected_rules=[{
                "path_prefix": "schemas/", "risk_profile": "elevated",
                "gate_ids": ["schema-compatibility"],
            }],
            requested_risk="standard", requested_gates=["unit"],
            reduction_decisions=[],
        )
        self.assertEqual("elevated", closure_only["risk_profile"])
        self.assertEqual(
            {"unit", "schema-compatibility"}, set(closure_only["gate_ids"])
        )

    def test_proposed_policy_cannot_approve_its_own_lkg_promotion(self) -> None:
        from codex_governance.authority import evaluate_lkg_promotion

        self.assertEqual(
            DispositionState.BLOCK,
            evaluate_lkg_promotion(
                repository_id=self.REPOSITORY,
                candidate_id=self.CANDIDATE,
                task_contract_sha256=self.TASK,
                evaluating_policy_sha256="sha256:" + "1" * 64,
                previous_lkg_policy_sha256="sha256:" + "2" * 64,
                proposed_policy_sha256="sha256:" + "1" * 64,
                promotion_decision=None, rollback_evidence=None,
                verified_decision_ids=frozenset(),
                now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
            ),
        )

    def test_lkg_promotion_requires_exact_decision_and_rollback_evidence(self) -> None:
        from codex_governance.authority import evaluate_lkg_promotion

        previous = "sha256:" + "1" * 64
        proposed = "sha256:" + "2" * 64
        rollback = content_address(
            {
                "schema_version": "1.0.0", "repository_id": self.REPOSITORY,
                "task_contract_sha256": self.TASK, "candidate_id": self.CANDIDATE,
                "previous_lkg_policy_sha256": previous,
                "proposed_policy_sha256": proposed, "rollback_target_commit": "1" * 40,
                "gate_result_sha256": "sha256:" + "3" * 64,
                "sandbox_capability_sha256": "sha256:" + "4" * 64,
                "provenance_statement_sha256": "sha256:" + "5" * 64,
                "status": "PASS", "created_at": "2026-08-26T10:00:00Z",
                "limitations": ["fixture"],
            },
            "rollback_evidence_id",
        )
        decision = self.decision("lkg_promotion")
        decision["effective_policy_sha256"] = previous
        decision["scope"] = [
            f"promote:{proposed}", f"rollback:{rollback['rollback_evidence_id']}"
        ]
        decision = content_address(decision, "decision_id")
        arguments = {
            "repository_id": self.REPOSITORY, "candidate_id": self.CANDIDATE,
            "task_contract_sha256": self.TASK,
            "evaluating_policy_sha256": previous,
            "previous_lkg_policy_sha256": previous,
            "proposed_policy_sha256": proposed, "promotion_decision": decision,
            "rollback_evidence": rollback,
            "verified_decision_ids": frozenset({decision["decision_id"]}),
            "now": datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
        }
        self.assertEqual(
            DispositionState.READY_FOR_HUMAN,
            evaluate_lkg_promotion(**arguments),
        )
        forged = deepcopy(rollback)
        forged["status"] = "PASS"
        forged["limitations"] = ["forged without rebuilding identity"]
        arguments["rollback_evidence"] = forged
        self.assertEqual(DispositionState.BLOCK, evaluate_lkg_promotion(**arguments))


if __name__ == "__main__":
    unittest.main()
