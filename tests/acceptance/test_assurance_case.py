import tempfile
import unittest
from pathlib import Path

from codex_governance.canonical import sha256_bytes
from codex_governance.domain.model import DispositionState


class AssuranceCaseAcceptanceTest(unittest.TestCase):
    def test_typed_excerpt_locator_resolves_exact_lines_and_digest(self) -> None:
        from codex_governance.locators import resolve_evidence_locator

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            content = b"one\ntwo\nthree\n"
            (repository / "evidence.txt").write_bytes(content)
            excerpt = b"two\nthree\n"
            locator = {
                "kind": "repository_excerpt", "path": "evidence.txt",
                "artifact_sha256": sha256_bytes(content), "start_line": 2, "end_line": 3,
                "excerpt_sha256": sha256_bytes(excerpt),
            }
            self.assertEqual(excerpt, resolve_evidence_locator(repository, locator))
            locator["start_line"] = 20
            with self.assertRaises(ValueError):
                resolve_evidence_locator(repository, locator)

    def test_missing_hallucinated_or_refuting_evidence_is_never_ready(self) -> None:
        from codex_governance.assurance import evaluate_assurance_claim

        complete = {
            "classification": "VERIFIED_WITHIN_SCOPE", "supporting_evidence": ["verified"],
            "refuting_evidence": [], "limitations": [], "unresolved_defeaters": [],
        }
        self.assertEqual(DispositionState.READY_FOR_HUMAN, evaluate_assurance_claim(complete))
        for field, value in (
            ("supporting_evidence", []), ("refuting_evidence", ["failure"]),
            ("unresolved_defeaters", ["locator unresolved"]), ("classification", "UNKNOWN"),
        ):
            claim = complete | {field: value}
            with self.subTest(field=field):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, evaluate_assurance_claim(claim))

    def test_disposition_is_monotonic_under_evidence_degradation(self) -> None:
        from codex_governance.assurance import disposition_cannot_improve

        degradations = [
            "add_failure", "add_unknown", "remove_required_evidence", "make_stale",
            "change_repository", "change_candidate", "change_policy",
            "change_source_identity", "change_execution_identity",
        ]
        for degradation in degradations:
            with self.subTest(degradation=degradation):
                self.assertTrue(disposition_cannot_improve(degradation))


if __name__ == "__main__":
    unittest.main()
