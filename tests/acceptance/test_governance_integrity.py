import unittest

from codex_governance.domain.model import DispositionState
from codex_governance.governance import classify_governance_change


class GovernanceIntegrityAcceptanceTest(unittest.TestCase):
    GOVERNANCE_PATHS = [
        "AGENTS.md",
        ".agents/skills/governed-change/SKILL.md",
        ".codex/review/reviewer.prompt.md",
        "schemas/disposition.schema.json",
        ".github/workflows/governed-change.yml",
        ".github/CODEOWNERS",
    ]

    def test_ordinary_candidate_cannot_change_acceptance_authority(self) -> None:
        for path in self.GOVERNANCE_PATHS:
            with self.subTest(path=path):
                self.assertEqual(
                    DispositionState.BLOCK,
                    classify_governance_change(
                        changed_paths=[path],
                        task_profile="code",
                        governance_change_authorized=False,
                    ),
                )

    def test_boolean_governance_assertion_never_authorizes(self) -> None:
        self.assertEqual(
            DispositionState.BLOCK,
            classify_governance_change(
                changed_paths=["schemas/disposition.schema.json"],
                task_profile="governance",
                governance_change_authorized=True,
            )
        )

    def test_ordinary_source_change_is_not_misclassified(self) -> None:
        self.assertIsNone(
            classify_governance_change(
                changed_paths=["src/codex_governance/candidate.py"],
                task_profile="code",
                governance_change_authorized=False,
            )
        )


if __name__ == "__main__":
    unittest.main()
