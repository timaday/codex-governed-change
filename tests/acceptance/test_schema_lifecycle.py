import json
import unittest
from datetime import timezone
from pathlib import Path


class SchemaLifecycleAcceptanceTest(unittest.TestCase):
    def test_each_example_declares_the_exact_mapped_schema_version(self) -> None:
        from scripts.validate_blueprint import EXAMPLE_SCHEMAS

        for example_path, schema_path in EXAMPLE_SCHEMAS.items():
            example = json.loads(Path(example_path).read_text(encoding="utf-8"))
            schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
            with self.subTest(example=example_path):
                self.assertEqual(schema["properties"]["schema_version"]["const"], example["schema_version"])

    def test_reviewer_v1_to_v2_is_explicit_not_silent(self) -> None:
        from codex_governance.lifecycle import migration_policy

        self.assertEqual("explicit_required", migration_policy("reviewer-result", "1.0.0", "2.0.0"))
        self.assertEqual("explicit_required", migration_policy("reviewer-execution", "1.0.0", "2.0.0"))
        self.assertEqual("explicit_required", migration_policy("reviewer-execution", "2.0.0", "3.0.0"))
        for kind in (
            "effective-policy",
            "evidence-manifest",
            "reviewer-qualification",
            "reviewer-qualification-cases",
            "reviewer-qualification-corpus",
        ):
            with self.subTest(kind=kind):
                self.assertEqual(
                    "explicit_required", migration_policy(kind, "1.0.0", "2.0.0")
                )
        self.assertEqual("unsupported", migration_policy("reviewer-result", "0.1.0", "2.0.0"))

    def test_complete_rfc3339_and_real_calendar_values_are_required(self) -> None:
        from codex_governance.lifecycle import parse_rfc3339

        parsed = parse_rfc3339("2026-08-26T10:00:00.123+01:00")
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(9, parsed.astimezone(timezone.utc).hour)
        for invalid in (
            "2026-08-26T", "2026-02-30T10:00:00Z", "2026-13-01T10:00:00Z",
            "2026-08-26 10:00:00Z", "2026-08-26T25:00:00Z", "2026-08-26T10:00:00",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_rfc3339(invalid)

    def test_lifecycle_end_and_expiry_must_follow_start_and_issue(self) -> None:
        from codex_governance.lifecycle import validate_time_order

        self.assertTrue(validate_time_order("2026-08-26T10:00:00Z", "2026-08-26T10:00:01Z"))
        self.assertFalse(validate_time_order("2026-08-26T10:00:01Z", "2026-08-26T10:00:00Z"))

    def test_content_addressed_examples_reconstruct_their_own_identity(self) -> None:
        from codex_governance.canonical import verify_content_address

        identities = {
            "authenticated-decision.json": "decision_id",
            "assurance-case.json": "assurance_case_id",
            "context-execution-receipt.json": "execution_receipt_id",
            "context-receipt.json": "receipt_id",
            "coverage-note.json": "coverage_note_id",
            "evidence-locator.json": "locator_id",
            "evidence-manifest.json": "manifest_id",
            "follow-up.json": "follow_up_id",
            "gate-manifest.json": "gate_manifest_id",
            "mutant-record.json": "mutant_record_id",
            "oracle-reference.json": "oracle_id",
            "provenance-statement.json": "statement_id",
            "reviewer-qualification.json": "qualification_id",
            "reviewer-qualification-cases.json": "case_evidence_id",
            "reviewer-qualification-corpus.json": "corpus_id",
            "reviewer-qualification-label-decision.json": "decision_id",
            "reviewer-execution.json": "execution_id",
            "risk-assessment.json": "assessment_id",
            "risk-register.json": "risk_register_id",
            "rollback-evidence.json": "rollback_evidence_id",
            "sandbox-capability.json": "capability_id",
            "waiver.json": "waiver_id",
        }
        for filename, field in identities.items():
            document = json.loads((Path("examples") / filename).read_text(encoding="utf-8"))
            with self.subTest(filename=filename):
                self.assertTrue(verify_content_address(document, field))


if __name__ == "__main__":
    unittest.main()
