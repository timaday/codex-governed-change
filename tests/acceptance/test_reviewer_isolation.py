import unittest
from pathlib import Path

from codex_governance.domain.model import ReviewerVerdict
from codex_governance.reviewer import (
    build_reviewer_command,
    build_reviewer_stdin,
    classify_reviewer_execution,
)


class ReviewerIsolationAcceptanceTest(unittest.TestCase):
    def command(self) -> list[str]:
        return build_reviewer_command(
            codex_executable="codex",
            model="gpt-5.6",
            schema_path=Path("schemas/reviewer-result.schema.json"),
            output_path=Path("artifacts/reviewer.json"),
            review_root=Path("/tmp/review-root"),
            reasoning_effort="xhigh",
        )

    def test_command_is_new_ephemeral_read_only_schema_bound_process(self) -> None:
        command = self.command()
        self.assertEqual("codex", command[0])
        self.assertIn("exec", command)
        self.assertIn("--ephemeral", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("--ignore-rules", command)
        self.assertIn("--sandbox", command)
        self.assertEqual("read-only", command[command.index("--sandbox") + 1])
        self.assertEqual("gpt-5.6", command[command.index("--model") + 1])
        self.assertIn("--output-schema", command)
        self.assertIn("--output-last-message", command)
        self.assertIn("--cd", command)
        self.assertEqual("-", command[-1])
        self.assertIn('features.hooks=false', " ".join(command))
        self.assertIn('agents.enabled=false', " ".join(command))

    def test_command_never_resumes_or_allows_write(self) -> None:
        command = self.command()
        joined = " ".join(command)
        self.assertNotIn("resume", command)
        self.assertNotIn("workspace-write", joined)
        self.assertNotIn("danger-full-access", joined)
        self.assertNotIn("--yolo", command)

    def test_stdin_accepts_only_permitted_machine_inputs(self) -> None:
        permitted = {
            "task_contract_path": "artifacts/task-contract.json",
            "candidate_id": "sha256:" + "a" * 64,
            "effective_policy_sha256": "sha256:" + "b" * 64,
            "gate_manifest_path": "artifacts/gates.json",
        }
        payload = build_reviewer_stdin(fixed_prompt="FIXED", permitted_inputs=permitted)
        self.assertTrue(payload.startswith("FIXED"))
        self.assertIn("PERMITTED_INPUTS", payload)
        self.assertIn(permitted["candidate_id"], payload)

    def test_author_transcript_key_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            build_reviewer_stdin(
                fixed_prompt="FIXED",
                permitted_inputs={
                    "candidate_id": "sha256:" + "a" * 64,
                    "author_transcript": "private conversation",
                },
            )

    def test_any_process_or_binding_uncertainty_is_unknown(self) -> None:
        cases = [
            {"return_code": 1},
            {"timed_out": True},
            {"output_present": False},
            {"output_valid": False},
            {"candidate_matches": False},
            {"output_truncated": True},
        ]
        baseline = {
            "return_code": 0,
            "timed_out": False,
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
                output_present=True,
                output_valid=True,
                candidate_matches=True,
                output_truncated=False,
                declared_verdict="BLOCK",
            ),
        )


if __name__ == "__main__":
    unittest.main()
