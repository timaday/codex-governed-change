from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FreeTopologyAuthorityTest(unittest.TestCase):
    def text(self, path: str) -> str:
        return (ROOT / path).read_text(encoding="utf-8")

    def document(self, path: str) -> dict[str, object]:
        return json.loads(self.text(path))

    def test_public_authority_rulesets_are_exact_and_no_bypass(self) -> None:
        sole = self.document("rulesets/authority-ref.ruleset.json")
        reviewed = self.document("rulesets/authority-ref-reviewed.ruleset.json")
        for ruleset in (sole, reviewed):
            self.assertEqual("active", ruleset["enforcement"])
            self.assertEqual([], ruleset["bypass_actors"])
            self.assertEqual(
                ["refs/heads/governance-authority"],
                ruleset["conditions"]["ref_name"]["include"],
            )
            self.assertEqual(
                {
                    "deletion",
                    "non_fast_forward",
                    "required_linear_history",
                    "pull_request",
                },
                {rule["type"] for rule in ruleset["rules"]},
            )
        sole_pr = next(
            rule["parameters"] for rule in sole["rules"]
            if rule["type"] == "pull_request"
        )
        reviewed_pr = next(
            rule["parameters"] for rule in reviewed["rules"]
            if rule["type"] == "pull_request"
        )
        self.assertEqual(0, sole_pr["required_approving_review_count"])
        self.assertFalse(sole_pr["require_last_push_approval"])
        self.assertEqual(1, reviewed_pr["required_approving_review_count"])
        self.assertTrue(reviewed_pr["require_last_push_approval"])
        for parameters in (sole_pr, reviewed_pr):
            self.assertTrue(parameters["dismiss_stale_reviews_on_push"])
            self.assertTrue(parameters["required_review_thread_resolution"])

    def test_private_broker_contract_has_no_paid_or_public_runner_dependency(self) -> None:
        broker = self.document(".governance/private-broker.json")
        self.assertEqual("private", broker["required_visibility"])
        self.assertEqual(
            ["workflow_dispatch", "schedule"], broker["allowed_external_triggers"]
        )
        self.assertEqual(["workflow_run:completed"], broker["allowed_internal_triggers"])
        self.assertEqual(
            ["DISPOSITION_APP_PRIVATE_KEY"], broker["repository_secrets"]
        )
        self.assertEqual(
            ["DISPOSITION_APP_ID", "GOVERNED_SCHEDULE_ENABLED"],
            broker["repository_variables"],
        )
        runner = broker["reviewer_runner"]
        self.assertEqual("private_broker_repository_only", runner["scope"])
        self.assertEqual("single_job_destroy_after_completion", runner["lifecycle"])
        self.assertEqual("chatgpt", runner["authentication"])
        self.assertEqual("gpt-5.6-sol", runner["model"])
        self.assertFalse(runner["openai_api_key_permitted"])

    def test_public_workflows_are_reusable_only(self) -> None:
        for name in (
            "disposition.yml",
            "finalize-disposition.yml",
            "qualify-reviewer.yml",
        ):
            workflow = self.text(f".github/workflows/{name}")
            trigger = workflow.split("permissions:", 1)[0]
            self.assertIn("workflow_call:", trigger, name)
            for forbidden in (
                "workflow_dispatch:",
                "schedule:",
                "workflow_run:",
                "pull_request:",
                "pull_request_target:",
                "repository_dispatch:",
                "issue_comment:",
                "issues:",
                "push:",
            ):
                self.assertNotIn(forbidden, trigger, (name, forbidden))

    def test_public_workflows_disable_bytecode_before_python(self) -> None:
        for name in (
            "disposition.yml",
            "finalize-disposition.yml",
            "qualify-reviewer.yml",
        ):
            workflow = self.text(f".github/workflows/{name}")
            self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', workflow, name)
            self.assertLess(
                workflow.index('PYTHONDONTWRITEBYTECODE: "1"'),
                workflow.index("python3 "),
                name,
            )

    def test_identifier_selected_artifacts_extract_at_destination_root(self) -> None:
        for name in ("disposition.yml", "finalize-disposition.yml"):
            workflow = self.text(f".github/workflows/{name}")
            blocks = workflow.split("uses: actions/download-artifact@")[1:]
            for block in blocks:
                step = block.split("\n      - name:", 1)[0]
                if "artifact-ids:" in step:
                    self.assertIn("merge-multiple: true", step, name)

    def test_reusable_workflows_derive_immutable_public_authority(self) -> None:
        for name in (
            "disposition.yml",
            "finalize-disposition.yml",
            "qualify-reviewer.yml",
        ):
            workflow = self.text(f".github/workflows/{name}")
            input_section = workflow.split("permissions:", 1)[0]
            for forbidden in (
                "authority_repository:",
                "authority_ref:",
                "authority_sha:",
                "target_id:",
                "repository: ${{ inputs.authority_repository }}",
                "ref: ${{ inputs.authority_sha }}",
            ):
                self.assertNotIn(forbidden, input_section, (name, forbidden))
            for required in (
                "AUTHORITY_REPOSITORY: timaday/codex-governed-change",
                "AUTHORITY_REF: refs/heads/governance-authority",
                "repository: timaday/codex-governed-change",
                "ref: ${{ job.workflow_sha }}",
                '--repository "$AUTHORITY_REPOSITORY"',
                '--ref "$AUTHORITY_REF"',
                '--expected-sha "${{ job.workflow_sha }}"',
                "github.repository == 'timaday/codex-governed-change-authority'",
            ):
                self.assertIn(required, workflow, (name, required))
            self.assertNotIn("--require-private", workflow)

    def test_broker_templates_pin_one_exact_authority_workflow(self) -> None:
        for name in (
            "disposition.yml",
            "finalize-disposition.yml",
            "qualify-reviewer.yml",
        ):
            template = self.text(f".governance/broker-templates/{name}")
            refs = re.findall(
                r"^\s+uses:\s+timaday/codex-governed-change/\.github/workflows/[^@\s]+@(__AUTHORITY_SHA__)\s*$",
                template,
                flags=re.MULTILINE,
            )
            self.assertEqual(["__AUTHORITY_SHA__"], refs, name)
            self.assertNotIn("authority_repository:", template)
            self.assertNotIn("authority_ref:", template)
            self.assertNotIn("authority_sha:", template)
            self.assertIn(
                "github.repository == 'timaday/codex-governed-change-authority'",
                template,
            )
        disposition = self.text(".governance/broker-templates/disposition.yml")
        finalizer = self.text(".governance/broker-templates/finalize-disposition.yml")
        reusable_finalizer = self.text(".github/workflows/finalize-disposition.yml")
        self.assertIn(
            "github.event_name != 'schedule' || "
            "vars.GOVERNED_SCHEDULE_ENABLED == 'true'",
            disposition,
        )
        self.assertNotIn("concurrency:", finalizer)
        self.assertEqual(1, reusable_finalizer.count("concurrency:"))

    def test_bootstrap_sequence_blocks_every_stale_broker_pin(self) -> None:
        sequence = self.document(".governance/bootstrap-sequence.json")
        states = sequence["states"]
        self.assertEqual(
            [
                "initial-bootstrap-pinned",
                "qualification-and-decisions-committed",
                "decision-commit-pinned",
                "receipt-committed",
                "receipt-commit-pinned",
            ],
            [state["state"] for state in states],
        )
        for state in states:
            pins_match = (
                state["authority_ref_state"] == state["all_broker_caller_pins"]
            )
            self.assertEqual(bool(state["permitted_broker_runs"]), pins_match)
        self.assertEqual([], states[1]["permitted_broker_runs"])
        self.assertEqual([], states[3]["permitted_broker_runs"])
        self.assertEqual(
            [False, False, False, False, True],
            [state["scheduled_producer_enabled"] for state in states],
        )
        self.assertIn("automatically triggered", sequence["permitted_broker_runs_semantics"])
        active_brokers = {
            path.stem.removeprefix("broker-")
            for path in (ROOT / ".governance/broker-templates").glob("*.yml")
        }
        declared_runs = {
            run
            for state in states
            for run in state["permitted_broker_runs"]
        }
        self.assertEqual(active_brokers, declared_runs)
        self.assertIn("finalize-disposition", states[2]["permitted_broker_runs"])

    def test_app_secret_is_declared_only_for_reusable_publication(self) -> None:
        disposition = self.text(".github/workflows/disposition.yml")
        finalizer = self.text(".github/workflows/finalize-disposition.yml")
        qualification = self.text(".github/workflows/qualify-reviewer.yml")
        for workflow in (disposition, finalizer):
            self.assertIn("disposition_app_private_key:", workflow)
            self.assertIn("${{ secrets.disposition_app_private_key }}", workflow)
            self.assertNotIn("environment: disposition-publisher", workflow)
        self.assertNotIn("disposition_app_private_key", qualification)
        self.assertNotIn(
            "OPENAI_API_KEY", "\n".join((disposition, finalizer, qualification))
        )

    def test_no_public_workflow_can_schedule_a_runner_from_a_public_event(self) -> None:
        disposition = self.text(".github/workflows/disposition.yml")
        qualification = self.text(".github/workflows/qualify-reviewer.yml")
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, governed-reviewer-jit]",
            disposition,
        )
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, governed-reviewer-jit]",
            qualification,
        )
        self.assertIn("github.event.repository.private == true", disposition)
        self.assertIn("github.event.repository.private == true", qualification)


if __name__ == "__main__":
    unittest.main()
