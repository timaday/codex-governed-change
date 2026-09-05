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
            "--schema-root schemas review",
            "governance/schemas import-reviewer-result",
            "governance/schemas assemble-manifest",
            "--schema-root schemas evaluate",
        ):
            self.assertIn(current, self.workflow)
        self.assertIn("qualification-matched", self.workflow)
        self.assertIn('--candidate "$CANDIDATE"', self.workflow)
        self.assertIn('--proposed-policy "$PROPOSED_POLICY"', self.workflow)
        self.assertIn("--governance-repository governance", self.workflow)
        self.assertIn("--mutation-corpus tests/mutation/corpus.json", self.workflow)
        self.assertNotIn("scripts/rehearse_rollback.py", self.workflow)
        self.assertIn("--execution-output", self.workflow)
        self.assertIn("--context-execution-output", self.workflow)
        self.assertIn("--stdout-output", self.workflow)
        self.assertIn("--stderr-output", self.workflow)
        self.assertIn("rapid-review-inputs", self.workflow)
        self.assertIn("rapid-review-session.schema.json", self.workflow)
        self.assertIn("governed-reviewed-evidence", self.final_job)
        self.assertIn("target-branch `.governance/ci/` adapter", self.workflow)
        self.assertIn("--verified-decision-id", self.workflow)
        self.assertNotIn("pull_request.updated_at", self.workflow)
        self.assertGreaterEqual(
            self.workflow.count("date -u '+%Y-%m-%dT%H:%M:%SZ'"), 2
        )

    def test_split_checkout_review_commands_use_exact_roots_and_policy_limits(self) -> None:
        review_step = self.workflow.split(
            "      - name: Run qualification-matched fresh read-only review", 1
        )[1].split("      - name: Upload reviewed candidate-bound evidence", 1)[0]
        self.assertEqual(2, review_step.count("--authority-root governance"))
        self.assertEqual(2, review_step.count("--schema-root schemas review"))
        self.assertEqual(2, review_step.count("--policy artifacts/governance/effective-policy.json"))
        self.assertEqual(2, review_step.count("--candidate artifacts/governance/candidate.json"))
        self.assertEqual(2, review_step.count("--prompt .codex/review/reviewer.prompt.md"))
        self.assertEqual(2, review_step.count("--timeout-seconds \"$REVIEW_TIMEOUT_SECONDS\""))
        self.assertEqual(2, review_step.count("--max-output-bytes \"$REVIEW_MAX_OUTPUT_BYTES\""))
        self.assertNotIn("--policy candidate/", review_step)
        self.assertNotIn("--candidate candidate/", review_step)
        self.assertNotIn("--prompt governance/", review_step)
        self.assertIn('json.load(open("candidate/artifacts/governance/effective-policy.json"', review_step)
        self.assertEqual(
            1,
            self.workflow.count(
                '--timeout-seconds "$PREPARATION_TIMEOUT_SECONDS"'
            ),
        )
        self.assertIn(
            'json.load(open(sys.argv[1], encoding="utf-8"))["reviewer"]["timeout_seconds"]',
            self.workflow,
        )
        self.assertEqual(1, self.final_job.count("--authority-root governance"))
        self.assertEqual(
            1,
            self.final_job.count("--prompt .codex/review/reviewer.prompt.md"),
        )
        self.assertNotIn("--authority-root candidate", self.final_job)
        self.assertEqual(
            1,
            self.final_job.count(
                '--timeout-seconds "$ADMISSION_TIMEOUT_SECONDS"'
            ),
        )
        self.assertIn(
            'json.load(open("candidate/artifacts/governance/effective-policy.json", encoding="utf-8"))["reviewer"]["timeout_seconds"]',
            self.final_job,
        )

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
