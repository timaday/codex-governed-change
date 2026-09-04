import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FREE = ROOT / "examples" / "github" / "free"


class GitHubFreeTopologyAcceptanceTest(unittest.TestCase):
    def load_json(self, name: str) -> dict[str, object]:
        return json.loads((FREE / name).read_text(encoding="utf-8"))

    def load_workflow(self, name: str) -> str:
        return (FREE / name).read_text(encoding="utf-8")

    def test_public_authority_ref_has_sole_user_and_reviewed_profiles(self) -> None:
        sole = self.load_json("authority-ref.ruleset.json")
        reviewed = self.load_json("authority-ref-reviewed.ruleset.json")
        for ruleset in (sole, reviewed):
            self.assertEqual("active", ruleset["enforcement"])
            self.assertEqual([], ruleset["bypass_actors"])
            self.assertEqual(
                ["refs/heads/governance-authority"],
                ruleset["conditions"]["ref_name"]["include"],
            )
            rule_types = {rule["type"] for rule in ruleset["rules"]}
            self.assertTrue({"deletion", "non_fast_forward", "pull_request"} <= rule_types)
        sole_pr = next(rule for rule in sole["rules"] if rule["type"] == "pull_request")
        reviewed_pr = next(
            rule for rule in reviewed["rules"] if rule["type"] == "pull_request"
        )
        self.assertEqual(0, sole_pr["parameters"]["required_approving_review_count"])
        self.assertFalse(sole_pr["parameters"]["require_last_push_approval"])
        self.assertEqual(1, reviewed_pr["parameters"]["required_approving_review_count"])
        self.assertTrue(reviewed_pr["parameters"]["require_last_push_approval"])
        for rule in (sole_pr, reviewed_pr):
            self.assertTrue(rule["parameters"]["dismiss_stale_reviews_on_push"])
            self.assertTrue(rule["parameters"]["required_review_thread_resolution"])

    def test_target_ruleset_is_fail_closed_and_app_source_bound(self) -> None:
        ruleset = self.load_json("target-main.ruleset.template.json")
        self.assertEqual("disabled", ruleset["enforcement"])
        self.assertEqual([], ruleset["bypass_actors"])
        status_rule = next(
            rule for rule in ruleset["rules"] if rule["type"] == "required_status_checks"
        )
        self.assertTrue(status_rule["parameters"]["strict_required_status_checks_policy"])
        self.assertEqual(
            [{"context": "disposition", "integration_id": "__GITHUB_APP_INTEGRATION_ID__"}],
            status_rule["parameters"]["required_status_checks"],
        )

    def test_private_broker_has_only_closed_triggers(self) -> None:
        disposition = self.load_workflow("private-broker-disposition.yml")
        qualification = self.load_workflow("private-broker-qualify.yml")
        finalizer = self.load_workflow("private-broker-finalize.yml")
        self.assertIn("workflow_dispatch:", disposition)
        self.assertIn("schedule:", disposition)
        self.assertIn("workflow_dispatch:", qualification)
        self.assertIn("workflow_run:", finalizer)
        combined = "\n".join((disposition, qualification, finalizer))
        for forbidden in (
            "pull_request:",
            "pull_request_target:",
            "repository_dispatch:",
            "issue_comment:",
            "issues:",
            "push:",
        ):
            self.assertNotIn(forbidden, combined)

    def test_every_broker_call_pins_a_public_authority_workflow_by_full_sha(self) -> None:
        for name in (
            "private-broker-disposition.yml",
            "private-broker-qualify.yml",
            "private-broker-finalize.yml",
        ):
            workflow = self.load_workflow(name)
            references = re.findall(
                r"^\s+uses:\s+[^\s]+/\.github/workflows/[^@\s]+@([0-9a-f]+)\s*$",
                workflow,
                flags=re.MULTILINE,
            )
            self.assertEqual(1, len(references), name)
            self.assertRegex(references[0], r"^[0-9a-f]{40}$")
            self.assertNotIn("${{", references[0])
            self.assertNotIn("authority_repository:", workflow)
            self.assertNotIn("authority_ref:", workflow)
            self.assertNotIn("authority_sha:", workflow)
            self.assertNotIn("target_id:", workflow)
            self.assertIn("github.repository == 'example/governed-broker'", workflow)

    def test_broker_cannot_supply_trigger_actor_or_source_run_identity(self) -> None:
        disposition = self.load_workflow("private-broker-disposition.yml")
        qualification = self.load_workflow("private-broker-qualify.yml")
        finalizer = self.load_workflow("private-broker-finalize.yml")
        self.assertNotIn("trigger_event:", disposition)
        self.assertNotIn("authenticated_actor:", disposition)
        self.assertNotIn("source_run_", finalizer)
        self.assertNotIn("with:", qualification)

    def test_app_secret_is_passed_only_to_disposition_publishers(self) -> None:
        disposition = self.load_workflow("private-broker-disposition.yml")
        qualification = self.load_workflow("private-broker-qualify.yml")
        finalizer = self.load_workflow("private-broker-finalize.yml")
        for workflow in (disposition, finalizer):
            self.assertIn(
                "disposition_app_id: ${{ vars.DISPOSITION_APP_ID }}", workflow
            )
            self.assertIn(
                "disposition_app_private_key: ${{ secrets.DISPOSITION_APP_PRIVATE_KEY }}",
                workflow,
            )
        self.assertNotIn("DISPOSITION_APP_PRIVATE_KEY", qualification)
        self.assertNotIn("OPENAI_API_KEY", "\n".join((disposition, qualification, finalizer)))

    def test_reviewer_runner_is_private_broker_scoped_by_contract(self) -> None:
        qualification = self.load_workflow("private-broker-qualify.yml")
        contract = (ROOT / "docs" / "specification.md").read_text(encoding="utf-8")
        self.assertIn("governed-reviewer-jit", qualification)
        self.assertIn("registered only to the private broker", contract)
        self.assertIn("gpt-5.6-sol", contract)
        self.assertIn("OpenAI API-key", contract)


if __name__ == "__main__":
    unittest.main()
