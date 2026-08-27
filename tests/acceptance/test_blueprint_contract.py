import json
import tomllib
import unittest
from pathlib import Path


class BlueprintContractAcceptanceTest(unittest.TestCase):
    def test_package_and_evidence_producer_versions_are_consistent(self) -> None:
        from codex_governance import __version__
        from codex_governance.evidence import PRODUCER_VERSION

        project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual("0.1.0", project["project"]["version"])
        self.assertEqual(project["project"]["version"], __version__)
        self.assertEqual(__version__, PRODUCER_VERSION)

    def test_all_mapped_examples_match_their_exact_schema_version(self) -> None:
        from scripts.validate_blueprint import EXAMPLE_SCHEMAS

        for example_path, schema_path in EXAMPLE_SCHEMAS.items():
            with self.subTest(path=example_path):
                document = json.loads(Path(example_path).read_text(encoding="utf-8"))
                schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
                self.assertEqual(
                    schema["properties"]["schema_version"]["const"],
                    document.get("schema_version"),
                )

    def test_status_is_fail_closed_for_the_unqualified_candidate(self) -> None:
        status = Path("IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
        self.assertIn("IMPLEMENTED_CANDIDATE", status)
        self.assertIn("FINAL_QUALIFICATION_UNKNOWN", status)
        self.assertIn("RELEASE_BLOCKED", status)
        self.assertIn("release or enforcement claim.", status)
        self.assertNotIn("`READY_FOR_HUMAN`", status.split("## Promotion conditions", 1)[0])

    def test_master_prompt_prohibits_gate_weakening_and_external_authority(self) -> None:
        prompt = Path("IMPLEMENT_WITH_GPT_5_6.md").read_text(encoding="utf-8")
        self.assertIn("weaken, skip, delete", prompt)
        self.assertIn("publish, merge, release", prompt)
        self.assertIn("READY_FOR_HUMAN", prompt)


if __name__ == "__main__":
    unittest.main()
