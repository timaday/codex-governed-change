import json
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_governance.domain.model import ReviewerVerdict
from codex_governance.reviewer import (
    build_reviewer_command,
    build_reviewer_stdin,
    classify_reviewer_execution,
)


class ReviewerIsolationAcceptanceTest(unittest.TestCase):
    def test_model_facing_output_schemas_are_strict_structured_outputs(self) -> None:
        def inspect(node: object) -> None:
            if not isinstance(node, dict):
                return
            if "properties" in node:
                properties = node["properties"]
                self.assertIsInstance(properties, dict)
                self.assertFalse(node.get("additionalProperties", True))
                self.assertEqual(set(properties), set(node.get("required", [])))
            for name, value in node.get("properties", {}).items():
                self.assertTrue(
                    isinstance(value, dict)
                    and ("type" in value or "$ref" in value or "anyOf" in value),
                    f"model-facing property lacks an explicit type: {name}",
                )
            for value in node.values():
                if isinstance(value, dict):
                    inspect(value)
                elif isinstance(value, list):
                    for item in value:
                        inspect(item)

        for path in (
            Path("schemas/reviewer-result.schema.json"),
            Path("schemas/rapid-review-session.schema.json"),
        ):
            with self.subTest(path=path):
                inspect(json.loads(path.read_text(encoding="utf-8")))

    def command(self) -> list[str]:
        runtime = Path.cwd() / ".synthetic-codex-runtime"
        with patch(
            "codex_governance.reviewer.resolve_reviewer_runtime_read_roots",
            return_value=(runtime,),
        ):
            return build_reviewer_command(
                codex_executable="codex",
                model="gpt-5.6-sol",
                schema_path=Path("schemas/reviewer-result.schema.json"),
                output_path=Path("artifacts/reviewer.json"),
                review_root=Path("review-root"),
                reasoning_effort="xhigh",
            )

    def test_command_is_new_ephemeral_root_denied_schema_bound_process(self) -> None:
        command = self.command()
        self.assertEqual("codex", command[0])
        self.assertIn("exec", command)
        self.assertIn("--ephemeral", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("--ignore-rules", command)
        self.assertIn("--strict-config", command)
        self.assertNotIn("--sandbox", command)
        self.assertEqual("gpt-5.6-sol", command[command.index("--model") + 1])
        self.assertIn("--output-schema", command)
        self.assertIn("--json", command)
        self.assertIn("--output-last-message", command)
        self.assertIn("--cd", command)
        self.assertEqual("-", command[-1])
        self.assertIn('features.hooks=false', " ".join(command))
        self.assertIn('agents.enabled=false', " ".join(command))
        joined = " ".join(command)
        self.assertIn('default_permissions="governed_reviewer"', joined)
        self.assertIn('extends=":read-only"', joined)
        self.assertIn('":root"="deny"', joined)
        self.assertIn('":workspace_roots"={"."="read"}', joined)
        self.assertIn('network={enabled=false}', joined)
        self.assertIn('approval_policy="never"', joined)
        self.assertIn('shell_environment_policy=', joined)
        self.assertIn('HOME=".reviewer-home"', joined)
        self.assertIn('ZDOTDIR=".reviewer-home"', joined)
        self.assertIn('PYTHONDONTWRITEBYTECODE="1"', joined)
        for forbidden in ("CODEX_HOME", "HTTPS_PROXY", "HTTP_PROXY"):
            self.assertNotIn(f'"{forbidden}"', joined)

    def test_execution_surfaces_use_explicit_codex_model_without_api_key(self) -> None:
        paths = (
            Path(".codex/config.toml"),
            Path(".codex/agents/independent-reviewer.toml"),
            Path("examples/effective-policy.json"),
            Path("examples/reviewer-qualification.json"),
            Path("examples/context-receipt.json"),
            Path("examples/reviewer-result.json"),
            Path("examples/github/governed-change.yml"),
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("gpt-5.6-sol", text)
                self.assertNotIn('"gpt-5.6"', text)
                self.assertNotIn("--model gpt-5.6 ", text)
                self.assertNotIn("OPENAI_API_KEY", text)
        workflow = Path("examples/github/governed-change.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("codex login status", workflow)
        self.assertIn("Logged in using ChatGPT", workflow)

    def test_command_never_resumes_or_allows_write(self) -> None:
        command = self.command()
        joined = " ".join(command)
        self.assertNotIn("resume", command)
        self.assertNotIn("workspace-write", joined)
        self.assertNotIn("danger-full-access", joined)
        self.assertNotIn("--yolo", command)

    def test_stdin_accepts_only_permitted_machine_inputs(self) -> None:
        digest = lambda character: "sha256:" + character * 64
        permitted = {
            "task_contract_path": "artifacts/task-contract.json",
            "task_contract_sha256": digest("1"),
            "repository_id": "repo:example/project",
            "candidate_id": digest("a"),
            "candidate_path": "candidate",
            "effective_policy_path": "artifacts/policy.json",
            "effective_policy_sha256": digest("b"),
            "gate_manifest_path": "artifacts/gates.json",
            "gate_manifest_sha256": digest("2"),
            "context_receipt_path": "artifacts/context.json",
            "context_receipt_sha256": digest("3"),
            "context_sources_path": "artifacts/context-sources.json",
            "context_sources_sha256": digest("4"),
            "context_projection_path": "artifacts/projection.json",
            "context_projection_sha256": digest("5"),
            "context_qualification_path": "artifacts/context-qualification.json",
            "context_qualification_sha256": digest("6"),
            "context_qualification_id": digest("7"),
            "reviewer_qualification_path": "artifacts/qualification.json",
            "reviewer_qualification_sha256": digest("5"),
            "reviewer_qualification_id": digest("6"),
            "evidence_root": "artifacts",
            "reviewer_prompt_sha256": digest("7"),
            "review_mode": "conformance",
        }
        payload = build_reviewer_stdin(fixed_prompt="FIXED", permitted_inputs=permitted)
        self.assertTrue(payload.startswith("FIXED"))
        self.assertIn("PERMITTED_INPUTS", payload)
        self.assertIn(permitted["candidate_id"], payload)

        missing_root = dict(permitted)
        missing_root.pop("evidence_root")
        with self.assertRaisesRegex(ValueError, "missing required keys"):
            build_reviewer_stdin(
                fixed_prompt="FIXED", permitted_inputs=missing_root
            )

        rapid_materials = dict(permitted)
        rapid_materials.update(
            risk_assessment_path="artifacts/risk.json",
            risk_assessment_sha256=digest("8"),
            review_charter_path="artifacts/charter.json",
            review_charter_sha256=digest("9"),
        )
        with self.assertRaisesRegex(ValueError, "forbidden keys"):
            build_reviewer_stdin(
                fixed_prompt="FIXED", permitted_inputs=rapid_materials
            )
        rapid_materials["review_mode"] = "rapid_review"
        self.assertIn(
            '"review_mode":"rapid_review"',
            build_reviewer_stdin(
                fixed_prompt="FIXED", permitted_inputs=rapid_materials
            ),
        )

    def test_author_transcript_key_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_reviewer_stdin(
                fixed_prompt="FIXED",
                permitted_inputs={
                    "candidate_id": "sha256:" + "a" * 64,
                    "author_transcript": "private conversation",
                },
            )

    def test_unreconstructable_provenance_input_is_rejected(self) -> None:
        permitted = {
            "task_contract_path": "artifacts/task.json",
            "task_contract_sha256": "sha256:" + "1" * 64,
            "repository_id": "repo:example/project",
            "candidate_id": "sha256:" + "a" * 64,
            "candidate_path": "candidate",
            "effective_policy_path": "artifacts/policy.json",
            "effective_policy_sha256": "sha256:" + "b" * 64,
            "gate_manifest_path": "artifacts/gates.json",
            "gate_manifest_sha256": "sha256:" + "2" * 64,
            "context_receipt_path": "artifacts/context.json",
            "context_receipt_sha256": "sha256:" + "3" * 64,
            "context_sources_path": "artifacts/sources.json",
            "context_sources_sha256": "sha256:" + "4" * 64,
            "context_projection_path": "artifacts/projection.json",
            "context_projection_sha256": "sha256:" + "5" * 64,
            "context_qualification_path": "artifacts/context-qualification.json",
            "context_qualification_sha256": "sha256:" + "6" * 64,
            "context_qualification_id": "sha256:" + "7" * 64,
            "reviewer_qualification_path": "artifacts/qualification.json",
            "reviewer_qualification_sha256": "sha256:" + "8" * 64,
            "reviewer_qualification_id": "sha256:" + "9" * 64,
            "evidence_root": "artifacts",
            "reviewer_prompt_sha256": "sha256:" + "c" * 64,
            "review_mode": "conformance",
            "provenance_manifest_path": "artifacts/candidate.json",
            "provenance_manifest_sha256": "sha256:" + "d" * 64,
        }
        with self.assertRaisesRegex(ValueError, "forbidden keys"):
            build_reviewer_stdin(
                fixed_prompt="FIXED", permitted_inputs=permitted
            )

    def test_any_process_or_binding_uncertainty_is_unknown(self) -> None:
        cases = [
            {"return_code": 1},
            {"timed_out": True},
            {"observation_complete": False},
            {"output_present": False},
            {"output_valid": False},
            {"candidate_matches": False},
            {"output_truncated": True},
        ]
        baseline = {
            "return_code": 0,
            "timed_out": False,
            "observation_complete": True,
            "output_present": True,
            "output_valid": True,
            "candidate_matches": True,
            "output_truncated": False,
            "declared_verdict": "PASS",
        }
        for change in cases:
            values = baseline | change
            with self.subTest(change=change):
                self.assertEqual(ReviewerVerdict.UNKNOWN, classify_reviewer_execution(**values))

    def test_valid_declared_block_is_preserved(self) -> None:
        self.assertEqual(
            ReviewerVerdict.BLOCK,
            classify_reviewer_execution(
                return_code=0,
                timed_out=False,
                observation_complete=True,
                output_present=True,
                output_valid=True,
                candidate_matches=True,
                output_truncated=False,
                declared_verdict="BLOCK",
            ),
        )

    def test_success_is_bounded_no_blocking_finding_observed(self) -> None:
        self.assertEqual(
            ReviewerVerdict.NO_BLOCKING_FINDING_OBSERVED,
            classify_reviewer_execution(
                return_code=0,
                timed_out=False,
                observation_complete=True,
                output_present=True,
                output_valid=True,
                candidate_matches=True,
                output_truncated=False,
                declared_verdict="NO_BLOCKING_FINDING_OBSERVED",
            ),
        )


if __name__ == "__main__":
    unittest.main()
