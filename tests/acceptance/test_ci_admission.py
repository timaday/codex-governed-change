import unittest
from pathlib import Path


class CiAdmissionAcceptanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = Path("examples/github/governed-change.yml").read_text(encoding="utf-8")
        cls.final_job = cls.workflow.split("  disposition:", 1)[1]

    def test_final_disposition_always_runs_and_names_every_direct_dependency(self) -> None:
        self.assertIn("if: ${{ always() }}", self.final_job)
        self.assertIn("needs: [deterministic_evidence, fresh_context_review]", self.final_job)
        self.assertIn("needs.deterministic_evidence.result", self.final_job)
        self.assertIn("needs.fresh_context_review.result", self.final_job)

    def test_final_job_requires_explicit_success_before_artifact_evaluation(self) -> None:
        self.assertIn('DETERMINISTIC_RESULT: ${{ needs.deterministic_evidence.result }}', self.final_job)
        self.assertIn('REVIEW_RESULT: ${{ needs.fresh_context_review.result }}', self.final_job)
        self.assertIn('[[ "$DETERMINISTIC_RESULT" == "success" ]]', self.final_job)
        self.assertIn('[[ "$REVIEW_RESULT" == "success" ]]', self.final_job)

    def test_reference_uses_sha_pins_and_documents_required_check_source(self) -> None:
        for line in self.workflow.splitlines():
            if "uses:" in line:
                reference = line.split("@", 1)[-1].split()[0]
                self.assertRegex(reference, r"^[0-9a-f]{40}$")
        for required in ("expected GitHub App", "no bypass", "merge queue", "up-to-date"):
            self.assertIn(required, self.workflow)

    def test_reference_is_only_an_authority_owned_required_workflow_template(self) -> None:
        for required in (
            "AUTHORITY-OWNED REQUIRED-WORKFLOW TEMPLATE",
            "separately protected authority repository",
            "MUST NOT be copied into the evaluated repository",
            "candidate-local code with the same workflow, job or check name has no authority",
        ):
            self.assertIn(required, self.workflow)

    def test_reference_uses_current_fail_closed_cli_contract(self) -> None:
        for stale in (
            "--governance-root",
            "--from-env",
            "--require READY_FOR_HUMAN",
        ):
            self.assertNotIn(stale, self.workflow)
        for current in (
            "governance/schemas identify",
            "governance/schemas run-gates",
            "governance/schemas mutate",
            "governance/schemas prepare-review",
            "governance/schemas review",
            "governance/schemas import-reviewer-result",
            "governance/schemas assemble-manifest",
            "governance/schemas evaluate",
        ):
            self.assertIn(current, self.workflow)
        self.assertIn("qualification-matched", self.workflow)
        self.assertIn('--candidate "$CANDIDATE"', self.workflow)
        self.assertIn("--execution-output", self.workflow)
        self.assertIn("--context-execution-output", self.workflow)
        self.assertIn("rapid-review-inputs", self.workflow)
        self.assertIn("rapid-review-session.schema.json", self.workflow)
        self.assertIn("governed-reviewed-evidence", self.final_job)
        self.assertIn("target-branch `.governance/ci/` adapter", self.workflow)
        self.assertIn("--verified-decision-id", self.workflow)

    def test_reference_passes_the_executable_static_policy(self) -> None:
        from codex_governance.governance import validate_ci_policy

        self.assertEqual([], validate_ci_policy(self.workflow))
        weakened = self.workflow.replace("if: ${{ always() }}", "if: ${{ success() }}")
        self.assertTrue(validate_ci_policy(weakened))

    def test_executable_prerequisite_matrix_fails_closed_for_every_non_success(self) -> None:
        from codex_governance.admission import evaluate_ci_prerequisites
        from codex_governance.domain.model import DispositionState

        required = ("deterministic_evidence", "fresh_context_review")
        self.assertEqual(
            DispositionState.READY_FOR_HUMAN,
            evaluate_ci_prerequisites(
                required,
                {"deterministic_evidence": "success", "fresh_context_review": "success"},
            ),
        )
        for outcome in ("failure", "cancelled", "skipped", "neutral", "absent", ""):
            with self.subTest(outcome=outcome):
                self.assertNotEqual(
                    DispositionState.READY_FOR_HUMAN,
                    evaluate_ci_prerequisites(
                        required,
                        {"deterministic_evidence": "success", "fresh_context_review": outcome},
                    ),
                )
        self.assertEqual(
            DispositionState.UNKNOWN,
            evaluate_ci_prerequisites(
                required, {"deterministic_evidence": "success"}
            ),
        )


if __name__ == "__main__":
    unittest.main()
