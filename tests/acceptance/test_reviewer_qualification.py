import unittest
import shutil
import tempfile
from pathlib import Path
from codex_governance.evidence import content_address

from codex_governance.domain.model import DispositionState


class ReviewerQualificationAcceptanceTest(unittest.TestCase):
    def test_launcher_identity_covers_every_material_orchestration_module(self) -> None:
        from codex_governance.reviewer import (
            REVIEWER_LAUNCHER_FILES,
            reviewer_launcher_sha256,
        )

        package = Path("src/codex_governance")
        self.assertEqual(
            sorted(path.relative_to(package).as_posix() for path in package.rglob("*.py")),
            sorted(REVIEWER_LAUNCHER_FILES),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in REVIEWER_LAUNCHER_FILES:
                destination = root.joinpath(*relative.split("/"))
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(package.joinpath(*relative.split("/")), destination)
            baseline = reviewer_launcher_sha256(root)
            for relative in REVIEWER_LAUNCHER_FILES:
                with self.subTest(relative=relative):
                    target = root.joinpath(*relative.split("/"))
                    original = target.read_bytes()
                    target.write_bytes(original + b"\n# qualification drift\n")
                    self.assertNotEqual(baseline, reviewer_launcher_sha256(root))
                    target.write_bytes(original)

    def identity(self) -> dict:
        return {
            "prompt_sha256": "sha256:" + "a" * 64,
            "schema_sha256": "sha256:" + "b" * 64,
            "launcher_sha256": "sha256:" + "c" * 64,
            "codex_cli_version": "codex-cli 0.149.1",
            "model": "gpt-5.6-sol",
            "reasoning_effort": "xhigh",
        }

    def record(self) -> dict:
        return content_address(self.identity() | {
            "human_labelled": True,
            "critical_cases": 4,
            "critical_detected": 4,
            "false_passes": 0,
            "false_blocks": 0,
            "unknowns": 0,
            "latency_ms": 100,
            "cost": "unavailable",
            "qualified": True,
        }, "qualification_id")

    def test_exact_qualified_prompt_schema_model_launcher_is_required(self) -> None:
        from codex_governance.qualification import reviewer_qualification_state

        self.assertEqual(
            DispositionState.READY_FOR_HUMAN,
            reviewer_qualification_state(
                self.identity(), self.record(),
                protected_qualification_id=self.record()["qualification_id"],
            ),
        )
        for field in ("prompt_sha256", "schema_sha256", "launcher_sha256", "codex_cli_version", "model"):
            identity = self.identity()
            identity[field] = (
                "changed"
                if field == "model"
                else "codex-cli 9.9.9"
                if field == "codex_cli_version"
                else "sha256:" + "f" * 64
            )
            with self.subTest(field=field):
                record = self.record()
                self.assertEqual(
                    DispositionState.UNKNOWN,
                    reviewer_qualification_state(
                        identity, record,
                        protected_qualification_id=record["qualification_id"],
                    ),
                )

    def test_false_pass_or_missed_critical_defect_prevents_qualification(self) -> None:
        from codex_governance.qualification import reviewer_qualification_state

        for field, value in (("false_passes", 1), ("critical_detected", 3), ("human_labelled", False)):
            record = content_address(self.record() | {field: value}, "qualification_id")
            with self.subTest(field=field):
                self.assertNotEqual(
                    DispositionState.READY_FOR_HUMAN,
                    reviewer_qualification_state(
                        self.identity(), record,
                        protected_qualification_id=record["qualification_id"],
                    ),
                )

    def test_high_risk_disagreement_is_visible_unknown_not_majority_vote(self) -> None:
        from codex_governance.qualification import reconcile_review_lanes

        self.assertEqual(
            DispositionState.UNKNOWN,
            reconcile_review_lanes(risk="critical", outcomes=["NO_BLOCKING_FINDING_OBSERVED", "BLOCK"], specialist_required=True, specialist_present=True),
        )
        self.assertEqual(
            DispositionState.UNKNOWN,
            reconcile_review_lanes(risk="critical", outcomes=["NO_BLOCKING_FINDING_OBSERVED"], specialist_required=True, specialist_present=False),
        )


if __name__ == "__main__":
    unittest.main()
