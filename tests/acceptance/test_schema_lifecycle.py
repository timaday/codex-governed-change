import json
import unittest
from copy import deepcopy
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
        self.assertEqual(
            "explicit_required",
            migration_policy("reviewer-qualification-cases", "2.0.0", "3.0.0"),
        )
        self.assertEqual(
            "explicit_required",
            migration_policy("evidence-manifest", "2.0.0", "3.0.0"),
        )
        self.assertEqual(
            "explicit_required",
            migration_policy("reviewer-result", "2.0.0", "3.0.0"),
        )
        self.assertEqual(
            "explicit_required",
            migration_policy("rollback-evidence", "1.0.0", "2.0.0"),
        )
        for kind in (
            "effective-policy",
            "evidence-manifest",
            "reviewer-qualification",
            "reviewer-qualification-cases",
            "reviewer-qualification-corpus",
            "context-receipt",
            "sandbox-capability",
            "provenance-statement",
        ):
            with self.subTest(kind=kind):
                self.assertEqual(
                    "explicit_required", migration_policy(kind, "1.0.0", "2.0.0")
                )
        self.assertEqual("unsupported", migration_policy("reviewer-result", "0.1.0", "2.0.0"))

    def test_breaking_v1_evidence_migrates_explicitly_to_current_v2(self) -> None:
        from codex_governance.canonical import content_address
        from codex_governance.lifecycle import (
            migrate_context_receipt_v1_to_v2,
            migrate_provenance_statement_v1_to_v2,
            migrate_sandbox_capability_v1_to_v2,
        )
        from codex_governance.schema import load_json, validate_instance

        cases = []

        receipt = json.loads(Path("examples/context-receipt.json").read_text())
        qualification = receipt.pop("context_qualification_id")
        source_bundle = receipt.pop("source_bundle_sha256")
        receipt["schema_version"] = "1.0.0"
        receipt = content_address(receipt, "receipt_id")
        receipt_schema = load_json(Path("schemas/context-receipt.schema.json"))
        legacy_receipt_schema = deepcopy(receipt_schema)
        legacy_receipt_schema["properties"]["schema_version"]["const"] = "1.0.0"
        for field in ("context_qualification_id", "source_bundle_sha256"):
            legacy_receipt_schema["required"].remove(field)
            legacy_receipt_schema["properties"].pop(field)
        cases.append(
            (
                "context-receipt",
                receipt,
                legacy_receipt_schema,
                migrate_context_receipt_v1_to_v2(
                    receipt,
                    context_qualification_id=qualification,
                    source_bundle_sha256=source_bundle,
                ),
            )
        )

        capability = json.loads(Path("examples/sandbox-capability.json").read_text())
        image = capability.pop("image")
        command = capability.pop("command")
        capability["schema_version"] = "1.0.0"
        capability = content_address(capability, "capability_id")
        capability_schema = load_json(Path("schemas/sandbox-capability.schema.json"))
        legacy_capability_schema = deepcopy(capability_schema)
        legacy_capability_schema["properties"]["schema_version"]["const"] = "1.0.0"
        legacy_capability_schema["properties"]["provider"] = {
            "type": "string",
            "minLength": 1,
        }
        for field in ("image", "command"):
            legacy_capability_schema["required"].remove(field)
            legacy_capability_schema["properties"].pop(field)
        cases.append(
            (
                "sandbox-capability",
                capability,
                legacy_capability_schema,
                migrate_sandbox_capability_v1_to_v2(
                    capability, image=image, command=command
                ),
            )
        )

        statement = json.loads(Path("examples/provenance-statement.json").read_text())
        cpu_seconds = statement["predicate"]["limits"].pop("cpu_seconds")
        statement["schema_version"] = "1.0.0"
        statement = content_address(statement, "statement_id")
        statement_schema = load_json(Path("schemas/provenance-statement.schema.json"))
        legacy_statement_schema = deepcopy(statement_schema)
        legacy_statement_schema["properties"]["schema_version"]["const"] = "1.0.0"
        legacy_limits = legacy_statement_schema["properties"]["predicate"][
            "properties"
        ]["limits"]
        legacy_limits["required"].remove("cpu_seconds")
        legacy_limits["properties"].pop("cpu_seconds")
        cases.append(
            (
                "provenance-statement",
                statement,
                legacy_statement_schema,
                migrate_provenance_statement_v1_to_v2(
                    statement, cpu_seconds=cpu_seconds
                ),
            )
        )

        for kind, legacy, legacy_schema, migrated in cases:
            schema = load_json(Path("schemas") / f"{kind}.schema.json")
            with self.subTest(kind=kind):
                self.assertEqual([], validate_instance(legacy, legacy_schema))
                self.assertNotEqual([], validate_instance(legacy, schema))
                self.assertEqual([], validate_instance(migrated, schema))
                self.assertEqual("2.0.0", migrated["schema_version"])

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
