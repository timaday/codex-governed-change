import json
import math
import os
import tempfile
import time
import unittest
from copy import deepcopy
from pathlib import Path

from codex_governance.schema import (
    JsonRepresentationAdapter,
    SchemaValidationError,
    authoritative_json_session,
    load_json,
    validate_instance,
    validate_semantics,
)


class SchemaAdapterTest(unittest.TestCase):
    def test_every_example_round_trips_canonically(self) -> None:
        for schema_path in sorted(Path("schemas").glob("*.schema.json")):
            example_path = Path("examples") / schema_path.name.replace(".schema", "")
            adapter = JsonRepresentationAdapter(schema_path)
            original = load_json(example_path)
            encoded = adapter.serialize(original)
            self.assertEqual(original, adapter.parse(encoded), schema_path.name)
            self.assertEqual(encoded, adapter.serialize(adapter.parse(encoded)))

    def test_additional_properties_and_bad_version_fail_closed(self) -> None:
        schema = load_json(Path("schemas/candidate.schema.json"))
        example = load_json(Path("examples/candidate.json"))
        extra = deepcopy(example)
        extra["unexpected"] = True
        self.assertTrue(any("additional" in item for item in validate_instance(extra, schema)))
        old = deepcopy(example)
        old["schema_version"] = "0.0.0"
        self.assertTrue(validate_instance(old, schema))

    def test_nonfinite_values_and_unsupported_schema_keywords_are_rejected(self) -> None:
        adapter = JsonRepresentationAdapter(Path("schemas/candidate.schema.json"))
        with self.assertRaises(SchemaValidationError):
            adapter.parse(b'{"value":NaN}')
        schema = load_json(Path("schemas/candidate.schema.json"))
        schema["format"] = "custom"
        self.assertTrue(any("unsupported keyword" in item for item in validate_instance({}, schema)))
        self.assertFalse(math.isfinite(float("nan")))

    def test_authoritative_json_rejects_symlink_fifo_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = root / "document.json"
            document.write_bytes(b"{}")
            link = root / "link.json"
            link.symlink_to(document)
            with self.assertRaisesRegex(ValueError, "symlink"):
                load_json(link)
            with self.assertRaisesRegex(ValueError, "size bound"):
                load_json(document, max_bytes=1)
            if hasattr(os, "mkfifo"):
                fifo = root / "input.json"
                os.mkfifo(fifo)
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, "regular file"):
                    load_json(fifo)
                self.assertLess(time.monotonic() - started, 0.5)

    def test_authoritative_json_session_reuses_one_byte_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = Path(directory) / "document.json"
            document.write_bytes(b'{"value":"first"}')
            with authoritative_json_session():
                first = load_json(document)
                document.write_bytes(b'{"value":"second"}')
                second = load_json(document)
            self.assertEqual({"value": "first"}, first)
            self.assertEqual(first, second)
            self.assertEqual({"value": "second"}, load_json(document))

    def test_union_types_accept_null_and_still_enforce_each_concrete_type(self) -> None:
        reviewer_schema = load_json(Path("schemas/reviewer-result.schema.json"))
        reviewer = load_json(Path("examples/reviewer-result.json"))
        finding = {
            "severity": "high",
            "category": "correctness",
            "path": "src/codex_governance/schema.py",
            "line": None,
            "claim": "A finding without a concrete line is not admissible.",
            "violated_oracle": "reviewer-result schema",
            "evidence_refs": [{
                "locator_id": "sha256:" + "1" * 64,
                "sha256": "sha256:" + "2" * 64,
            }],
            "remediation": "Preserve JSON Schema union-type semantics.",
        }
        reviewer["findings"] = [finding]
        self.assertTrue(
            any("expected integer" in item for item in validate_instance(reviewer, reviewer_schema))
        )
        reviewer["findings"][0]["line"] = 1
        self.assertEqual([], validate_instance(reviewer, reviewer_schema))

        schema = load_json(Path("schemas/reviewer-qualification-corpus.schema.json"))
        example = load_json(Path("examples/reviewer-qualification-corpus.json"))
        self.assertEqual([], validate_instance(example, schema))
        example["cases"][1]["expected_finding"] = False
        self.assertTrue(any("expected" in item for item in validate_instance(example, schema)))

        invalid_definition = {"$schema": schema["$schema"], "type": ["null", "null"]}
        self.assertTrue(
            any("invalid type declaration" in item for item in validate_instance(None, invalid_definition))
        )

    def test_reviewer_requires_the_exact_five_evidence_backed_claims(self) -> None:
        schema = load_json(Path("schemas/reviewer-result.schema.json"))
        example = load_json(Path("examples/reviewer-result.json"))
        defects = []
        omitted = deepcopy(example)
        omitted["claims"].pop()
        defects.append(omitted)
        duplicate = deepcopy(example)
        duplicate["claims"][-1] = deepcopy(duplicate["claims"][0])
        defects.append(duplicate)
        unknown = deepcopy(example)
        unknown["claims"][0]["claim_id"] = "caller_selected"
        defects.append(unknown)
        unsupported = deepcopy(example)
        unsupported["claims"][0]["evidence_refs"] = []
        defects.append(unsupported)
        for document in defects:
            with self.subTest(document=document):
                self.assertTrue(validate_instance(document, schema))

    def test_semantic_identity_and_lifecycle_validation_fails_closed(self) -> None:
        candidate = load_json(Path("examples/candidate.json"))
        candidate["changed_paths"] = ["schemas/hidden.schema.json"]
        self.assertTrue(validate_semantics(candidate, "candidate"))
        waiver = load_json(Path("examples/waiver.json"))
        waiver["expires_at"] = waiver["created_at"]
        errors = validate_semantics(waiver, "waiver")
        self.assertTrue(any("must follow" in item for item in errors), errors)
        self.assertTrue(any("content address" in item for item in errors), errors)


if __name__ == "__main__":
    unittest.main()
