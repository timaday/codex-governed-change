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
        from codex_governance.lifecycle import (
            EXECUTABLE_MIGRATIONS,
            migration_policy,
        )

        self.assertEqual("explicit_required", migration_policy("reviewer-result", "1.0.0", "2.0.0"))
        self.assertEqual("explicit_required", migration_policy("reviewer-execution", "1.0.0", "2.0.0"))
        self.assertEqual("explicit_required", migration_policy("reviewer-execution", "2.0.0", "3.0.0"))
        self.assertEqual(
            "explicit_required",
            migration_policy("reviewer-qualification-cases", "2.0.0", "3.0.0"),
        )
        self.assertEqual(
            "explicit_required",
            migration_policy("reviewer-qualification-corpus", "2.0.0", "3.0.0"),
        )
        self.assertEqual(
            "explicit_required",
            migration_policy("rapid-review-session", "1.0.0", "2.0.0"),
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
        advertised = {
            (kind, source, target)
            for kind in (
                "effective-policy",
                "evidence-manifest",
                "reviewer-qualification",
                "reviewer-qualification-cases",
                "reviewer-qualification-corpus",
                "rapid-review-session",
                "reviewer-result",
                "reviewer-execution",
                "rollback-evidence",
                "context-receipt",
                "sandbox-capability",
                "provenance-statement",
            )
            for source, target in (
                ("1.0.0", "2.0.0"),
                ("2.0.0", "3.0.0"),
            )
            if migration_policy(kind, source, target) == "explicit_required"
        }
        self.assertEqual(advertised, set(EXECUTABLE_MIGRATIONS))
        self.assertTrue(
            all(callable(item) for item in EXECUTABLE_MIGRATIONS.values())
        )

    def test_every_advertised_migration_reaches_its_exact_current_shape(self) -> None:
        from codex_governance.canonical import content_address
        from codex_governance.context import MANDATORY_REVIEWER_CLAIMS
        from codex_governance.lifecycle import (
            EXECUTABLE_MIGRATIONS,
            migrate_context_receipt_v1_to_v2,
            migrate_effective_policy_v1_to_v2,
            migrate_effective_policy_v2_to_v3,
            migrate_evidence_manifest_v1_to_v2,
            migrate_evidence_manifest_v2_to_v3,
            migrate_provenance_statement_v1_to_v2,
            migrate_rapid_review_session_v1_to_v2,
            migrate_reviewer_execution_v1_to_v2,
            migrate_reviewer_execution_v2_to_v3,
            migrate_reviewer_qualification_cases_v1_to_v2,
            migrate_reviewer_qualification_cases_v2_to_v3,
            migrate_reviewer_qualification_corpus_v1_to_v2,
            migrate_reviewer_qualification_corpus_v2_to_v3,
            migrate_reviewer_qualification_v1_to_v2,
            migrate_reviewer_result_v1_to_v2,
            migrate_reviewer_result_v2_to_v3,
            migrate_rollback_evidence_v1_to_v2,
            migrate_sandbox_capability_v1_to_v2,
        )
        from codex_governance.schema import load_json, validate_instance

        observed: set[tuple[str, str, str]] = set()

        def example(kind: str) -> dict:
            return json.loads(
                (Path("examples") / f"{kind}.json").read_text(encoding="utf-8")
            )

        def addressed(document: dict, version: str, identity: str) -> dict:
            document["schema_version"] = version
            return content_address(document, identity)

        def current(kind: str, migrated: dict) -> None:
            schema = load_json(Path("schemas") / f"{kind}.schema.json")
            self.assertEqual([], validate_instance(migrated, schema), kind)

        def rejected_by_current(kind: str, legacy: dict) -> None:
            schema = load_json(Path("schemas") / f"{kind}.schema.json")
            self.assertNotEqual([], validate_instance(legacy, schema), kind)

        policy_v3 = example("effective-policy")
        mutation_corpus_sha = policy_v3["mutation"]["corpus_sha256"]
        policy_v2 = deepcopy(policy_v3)
        policy_v2["schema_version"] = "2.0.0"
        policy_v2["mutation"].pop("corpus_sha256")
        rejected_by_current("effective-policy", policy_v2)
        policy_v1 = deepcopy(policy_v2)
        policy_v1["schema_version"] = "1.0.0"
        context_qualification_ids = policy_v1["context"].pop("qualification_ids")
        qualification_corpus_sha = policy_v1["reviewer"].pop(
            "qualification_corpus_sha256"
        )
        qualification_label_id = policy_v1["reviewer"].pop(
            "qualification_label_decision_id"
        )
        migrated_policy_v2 = migrate_effective_policy_v1_to_v2(
            policy_v1,
            context_qualification_ids=context_qualification_ids,
            reviewer_qualification_corpus_sha256=qualification_corpus_sha,
            reviewer_qualification_label_decision_id=qualification_label_id,
        )
        self.assertEqual(policy_v2, migrated_policy_v2)
        observed.add(("effective-policy", "1.0.0", "2.0.0"))
        migrated_policy_v3 = migrate_effective_policy_v2_to_v3(
            migrated_policy_v2, mutation_corpus_sha256=mutation_corpus_sha
        )
        self.assertEqual(policy_v3, migrated_policy_v3)
        current("effective-policy", migrated_policy_v3)
        observed.add(("effective-policy", "2.0.0", "3.0.0"))

        manifest_v3 = example("evidence-manifest")
        lkg_policy_decision = manifest_v3["lkg_policy_decision"]
        manifest_v2 = deepcopy(manifest_v3)
        manifest_v2.pop("lkg_policy_decision")
        manifest_v2 = addressed(manifest_v2, "2.0.0", "manifest_id")
        rejected_by_current("evidence-manifest", manifest_v2)
        protected_names = {
            "reviewer_qualification_cases",
            "rapid_review_qualification_cases",
            "reviewer_qualification_corpus",
            "reviewer_qualification_label_decision",
            "context_sources",
            "context_projection",
            "context_qualification",
        }
        protected_references = {
            name: manifest_v2[name] for name in protected_names
        }
        manifest_v1 = deepcopy(manifest_v2)
        for name in protected_names:
            manifest_v1.pop(name)
        manifest_v1 = addressed(manifest_v1, "1.0.0", "manifest_id")
        rebuilt_manifest_v2 = migrate_evidence_manifest_v1_to_v2(
            manifest_v1, protected_references=protected_references
        )
        self.assertEqual(manifest_v2, rebuilt_manifest_v2)
        observed.add(("evidence-manifest", "1.0.0", "2.0.0"))
        rebuilt_manifest_v3 = migrate_evidence_manifest_v2_to_v3(
            rebuilt_manifest_v2, lkg_policy_decision=lkg_policy_decision
        )
        self.assertEqual(manifest_v3, rebuilt_manifest_v3)
        current("evidence-manifest", rebuilt_manifest_v3)
        observed.add(("evidence-manifest", "2.0.0", "3.0.0"))

        qualification_v2 = example("reviewer-qualification")
        label_id = qualification_v2["label_decision_id"]
        case_evidence_sha = qualification_v2["case_evidence_sha256"]
        qualification_v1 = deepcopy(qualification_v2)
        qualification_v1.pop("label_decision_id")
        qualification_v1.pop("case_evidence_sha256")
        qualification_v1 = addressed(
            qualification_v1, "1.0.0", "qualification_id"
        )
        rejected_by_current("reviewer-qualification", qualification_v1)
        rebuilt_qualification = migrate_reviewer_qualification_v1_to_v2(
            qualification_v1,
            label_decision_id=label_id,
            case_evidence_sha256=case_evidence_sha,
        )
        self.assertEqual(qualification_v2, rebuilt_qualification)
        current("reviewer-qualification", rebuilt_qualification)
        observed.add(("reviewer-qualification", "1.0.0", "2.0.0"))

        qualification_cases_v3 = example("reviewer-qualification-cases")
        context_names = {
            "context_sources",
            "context_projection",
            "context_qualification",
            "context_receipt",
            "context_execution_receipt",
        }
        context_references = {
            item["case_id"]: {name: item[name] for name in context_names}
            for item in qualification_cases_v3["observations"]
        }
        qualification_cases_v2 = deepcopy(qualification_cases_v3)
        for item in qualification_cases_v2["observations"]:
            for name in context_names:
                item.pop(name)
        qualification_cases_v2 = addressed(
            qualification_cases_v2, "2.0.0", "case_evidence_id"
        )
        rejected_by_current(
            "reviewer-qualification-cases", qualification_cases_v2
        )
        qualification_cases_v1 = addressed(
            deepcopy(qualification_cases_v2), "1.0.0", "case_evidence_id"
        )
        rebuilt_cases_v2 = migrate_reviewer_qualification_cases_v1_to_v2(
            qualification_cases_v1
        )
        self.assertEqual(qualification_cases_v2, rebuilt_cases_v2)
        observed.add(("reviewer-qualification-cases", "1.0.0", "2.0.0"))
        rebuilt_cases_v3 = migrate_reviewer_qualification_cases_v2_to_v3(
            rebuilt_cases_v2, context_references=context_references
        )
        self.assertEqual(qualification_cases_v3, rebuilt_cases_v3)
        current("reviewer-qualification-cases", rebuilt_cases_v3)
        observed.add(("reviewer-qualification-cases", "2.0.0", "3.0.0"))

        qualification_corpus_v3 = example("reviewer-qualification-corpus")
        expected_findings = {
            item["case_id"]: item["expected_finding"]
            for item in qualification_corpus_v3["cases"]
        }
        qualification_corpus_v2 = deepcopy(qualification_corpus_v3)
        for item in qualification_corpus_v2["cases"]:
            item.pop("expected_finding")
        qualification_corpus_v2 = addressed(
            qualification_corpus_v2, "2.0.0", "corpus_id"
        )
        rejected_by_current(
            "reviewer-qualification-corpus", qualification_corpus_v2
        )
        case_classes = {
            item["case_id"]: item["case_classes"]
            for item in qualification_corpus_v2["cases"]
        }
        qualification_corpus_v1 = deepcopy(qualification_corpus_v2)
        for item in qualification_corpus_v1["cases"]:
            item.pop("case_classes")
        qualification_corpus_v1 = addressed(
            qualification_corpus_v1, "1.0.0", "corpus_id"
        )
        rejected_by_current(
            "reviewer-qualification-corpus", qualification_corpus_v1
        )
        rebuilt_corpus = migrate_reviewer_qualification_corpus_v1_to_v2(
            qualification_corpus_v1, case_classes=case_classes
        )
        self.assertEqual(qualification_corpus_v2, rebuilt_corpus)
        observed.add(("reviewer-qualification-corpus", "1.0.0", "2.0.0"))
        rebuilt_corpus_v3 = migrate_reviewer_qualification_corpus_v2_to_v3(
            rebuilt_corpus, expected_findings=expected_findings
        )
        self.assertEqual(qualification_corpus_v3, rebuilt_corpus_v3)
        current("reviewer-qualification-corpus", rebuilt_corpus_v3)
        observed.add(("reviewer-qualification-corpus", "2.0.0", "3.0.0"))

        rapid_v2 = example("rapid-review-session")
        rapid_v2["findings"] = [
            {
                "finding_id": "QUAL-AUTHORITY-BYPASS",
                "path": "src/example.py",
                "line": 2,
                "claim": "The labelled bypass is present.",
                "impact": "Protected authority can be bypassed.",
                "severity": "high",
                "confidence": "high",
                "oracle": "GOV-055",
                "evidence_refs": ["src/example.py"],
                "threatened_value": "governed authority",
            }
        ]
        rapid_v1 = deepcopy(rapid_v2)
        rapid_v1["schema_version"] = "1.0.0"
        finding_targets = {}
        for finding in rapid_v1["findings"]:
            finding_targets[finding["finding_id"]] = {
                "path": finding.pop("path"),
                "line": finding.pop("line"),
            }
        rejected_by_current("rapid-review-session", rapid_v1)
        with self.assertRaises(ValueError):
            migrate_rapid_review_session_v1_to_v2(
                rapid_v1, finding_targets={}
            )
        duplicate_findings = deepcopy(rapid_v1)
        duplicate_findings["findings"].append(
            deepcopy(duplicate_findings["findings"][0])
        )
        with self.assertRaises(ValueError):
            migrate_rapid_review_session_v1_to_v2(
                duplicate_findings, finding_targets=finding_targets
            )
        rebuilt_rapid = migrate_rapid_review_session_v1_to_v2(
            rapid_v1, finding_targets=finding_targets
        )
        self.assertEqual(rapid_v2, rebuilt_rapid)
        current("rapid-review-session", rebuilt_rapid)
        observed.add(("rapid-review-session", "1.0.0", "2.0.0"))

        reviewer_result_v3 = example("reviewer-result")
        claim_ids = [item["claim_id"] for item in reviewer_result_v3["claims"]]
        self.assertEqual(
            {item["claim_id"] for item in MANDATORY_REVIEWER_CLAIMS},
            set(claim_ids),
        )
        reviewer_result_v2 = deepcopy(reviewer_result_v3)
        reviewer_result_v2["schema_version"] = "2.0.0"
        for item in reviewer_result_v2["claims"]:
            item.pop("claim_id")
        rejected_by_current("reviewer-result", reviewer_result_v2)
        reviewer_result_v1 = deepcopy(reviewer_result_v2)
        reviewer_result_v1["schema_version"] = "1.0.0"
        rebuilt_result_v2 = migrate_reviewer_result_v1_to_v2(reviewer_result_v1)
        self.assertEqual(reviewer_result_v2, rebuilt_result_v2)
        observed.add(("reviewer-result", "1.0.0", "2.0.0"))
        rebuilt_result_v3 = migrate_reviewer_result_v2_to_v3(
            rebuilt_result_v2, claim_ids=claim_ids
        )
        self.assertEqual(reviewer_result_v3, rebuilt_result_v3)
        current("reviewer-result", rebuilt_result_v3)
        observed.add(("reviewer-result", "2.0.0", "3.0.0"))

        execution_v3 = example("reviewer-execution")
        v3_execution_fields = {
            name: execution_v3[name]
            for name in (
                "observation",
                "stdin_delivery_complete",
                "stdout",
                "stderr",
            )
        }
        execution_v2 = deepcopy(execution_v3)
        for name in v3_execution_fields:
            execution_v2.pop(name)
        execution_v2 = addressed(execution_v2, "2.0.0", "execution_id")
        rejected_by_current("reviewer-execution", execution_v2)
        v2_execution_fields = {
            name: execution_v2[name]
            for name in (
                "observation_complete",
                "capture_threads_completed",
                "process_cleanup_complete",
                "execution_valid",
            )
        }
        execution_v1 = deepcopy(execution_v2)
        for name in v2_execution_fields:
            execution_v1.pop(name)
        execution_v1 = addressed(execution_v1, "1.0.0", "execution_id")
        rebuilt_execution_v2 = migrate_reviewer_execution_v1_to_v2(
            execution_v1, **v2_execution_fields
        )
        self.assertEqual(execution_v2, rebuilt_execution_v2)
        observed.add(("reviewer-execution", "1.0.0", "2.0.0"))
        rebuilt_execution_v3 = migrate_reviewer_execution_v2_to_v3(
            rebuilt_execution_v2, **v3_execution_fields
        )
        self.assertEqual(execution_v3, rebuilt_execution_v3)
        current("reviewer-execution", rebuilt_execution_v3)
        observed.add(("reviewer-execution", "2.0.0", "3.0.0"))

        rollback_v2 = example("rollback-evidence")
        rollback_references = {
            name: rollback_v2[name]
            for name in ("gate_result", "sandbox_capability", "provenance_statement")
        }
        rollback_v1 = deepcopy(rollback_v2)
        for name, reference in rollback_references.items():
            rollback_v1.pop(name)
            rollback_v1[f"{name}_sha256"] = reference["sha256"]
        rollback_v1 = addressed(
            rollback_v1, "1.0.0", "rollback_evidence_id"
        )
        rejected_by_current("rollback-evidence", rollback_v1)
        rebuilt_rollback = migrate_rollback_evidence_v1_to_v2(
            rollback_v1, **rollback_references
        )
        self.assertEqual(rollback_v2, rebuilt_rollback)
        current("rollback-evidence", rebuilt_rollback)
        observed.add(("rollback-evidence", "1.0.0", "2.0.0"))

        receipt_v2 = example("context-receipt")
        qualification_id = receipt_v2["context_qualification_id"]
        source_bundle_sha = receipt_v2["source_bundle_sha256"]
        receipt_v1 = deepcopy(receipt_v2)
        receipt_v1.pop("context_qualification_id")
        receipt_v1.pop("source_bundle_sha256")
        receipt_v1 = addressed(receipt_v1, "1.0.0", "receipt_id")
        rejected_by_current("context-receipt", receipt_v1)
        rebuilt_receipt = migrate_context_receipt_v1_to_v2(
            receipt_v1,
            context_qualification_id=qualification_id,
            source_bundle_sha256=source_bundle_sha,
        )
        self.assertEqual(receipt_v2, rebuilt_receipt)
        current("context-receipt", rebuilt_receipt)
        observed.add(("context-receipt", "1.0.0", "2.0.0"))

        capability_v2 = example("sandbox-capability")
        image = capability_v2["image"]
        command = capability_v2["command"]
        capability_v1 = deepcopy(capability_v2)
        capability_v1.pop("image")
        capability_v1.pop("command")
        capability_v1 = addressed(capability_v1, "1.0.0", "capability_id")
        rejected_by_current("sandbox-capability", capability_v1)
        rebuilt_capability = migrate_sandbox_capability_v1_to_v2(
            capability_v1, image=image, command=command
        )
        self.assertEqual(capability_v2, rebuilt_capability)
        current("sandbox-capability", rebuilt_capability)
        observed.add(("sandbox-capability", "1.0.0", "2.0.0"))

        provenance_v2 = example("provenance-statement")
        cpu_seconds = provenance_v2["predicate"]["limits"]["cpu_seconds"]
        provenance_v1 = deepcopy(provenance_v2)
        provenance_v1["predicate"]["limits"].pop("cpu_seconds")
        provenance_v1 = addressed(provenance_v1, "1.0.0", "statement_id")
        rejected_by_current("provenance-statement", provenance_v1)
        rebuilt_provenance = migrate_provenance_statement_v1_to_v2(
            provenance_v1, cpu_seconds=cpu_seconds
        )
        self.assertEqual(provenance_v2, rebuilt_provenance)
        current("provenance-statement", rebuilt_provenance)
        observed.add(("provenance-statement", "1.0.0", "2.0.0"))

        self.assertEqual(set(EXECUTABLE_MIGRATIONS), observed)

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
