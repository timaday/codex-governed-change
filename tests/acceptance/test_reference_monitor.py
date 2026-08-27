import unittest

from codex_governance.domain.model import DispositionState


class ReferenceMonitorAcceptanceTest(unittest.TestCase):
    def complete_case(self) -> dict:
        return {
            "repository_id": "repo:example/project",
            "candidate_id": "sha256:" + "a" * 64,
            "upstream_results": {"gates": "success", "mutation": "success", "review": "success"},
            "claims": {
                name: {"classification": "VERIFIED_WITHIN_SCOPE", "defeaters": []}
                for name in (
                    "scope_authorized", "candidate_current", "gates_complete",
                    "governance_integrity", "rst_complete", "mutation_complete",
                    "fresh_review_complete", "residual_risk_visible", "context_complete",
                )
            },
            "required_claim_ids": (
                "scope_authorized", "candidate_current", "gates_complete",
                "governance_integrity", "rst_complete", "mutation_complete",
                "fresh_review_complete", "residual_risk_visible", "context_complete",
            ),
        }

    def evaluate(self, values: dict) -> DispositionState:
        from codex_governance.admission import evaluate_admission

        return evaluate_admission(**values)

    def test_only_complete_successful_case_reaches_ready_for_human(self) -> None:
        self.assertEqual(DispositionState.READY_FOR_HUMAN, self.evaluate(self.complete_case()))

    def test_every_non_success_upstream_outcome_blocks_readiness(self) -> None:
        for outcome in ("failure", "cancelled", "skipped", "neutral", "absent"):
            values = self.complete_case()
            values["upstream_results"]["review"] = outcome
            with self.subTest(outcome=outcome):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, self.evaluate(values))

    def test_missing_claim_or_unknown_defeater_never_improves(self) -> None:
        baseline = self.complete_case()
        baseline["claims"]["gates_complete"]["classification"] = "UNKNOWN"
        self.assertEqual(DispositionState.UNKNOWN, self.evaluate(baseline))
        baseline["claims"]["gates_complete"]["defeaters"] = ["gate output missing"]
        self.assertNotEqual(DispositionState.READY_FOR_HUMAN, self.evaluate(baseline))

    def test_admission_kernel_has_no_mutating_capabilities(self) -> None:
        from codex_governance.admission import AdmissionKernel

        forbidden = {"merge", "deploy", "grant_waiver", "create_credential", "change_settings"}
        self.assertTrue(forbidden.isdisjoint(set(dir(AdmissionKernel))))


if __name__ == "__main__":
    unittest.main()
