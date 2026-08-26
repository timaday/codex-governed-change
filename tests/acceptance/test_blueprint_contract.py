import json
import unittest
from pathlib import Path


class BlueprintContractAcceptanceTest(unittest.TestCase):
    def test_all_schema_examples_declare_version_1(self) -> None:
        for path in Path("examples").glob("*.json"):
            with self.subTest(path=path):
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual("1.0.0", document.get("schema_version"))

    def test_status_does_not_claim_implementation_readiness(self) -> None:
        status = Path("IMPLEMENTATION_STATUS.md").read_text(encoding="utf-8")
        self.assertIn("BLOCKED_IMPLEMENTATION_NOT_STARTED", status)
        self.assertIn("Production behavior is not yet proven", status)

    def test_master_prompt_prohibits_gate_weakening_and_external_authority(self) -> None:
        prompt = Path("IMPLEMENT_WITH_GPT_5_6.md").read_text(encoding="utf-8")
        self.assertIn("weaken, skip, delete", prompt)
        self.assertIn("publish, merge, release", prompt)
        self.assertIn("READY_FOR_HUMAN", prompt)


if __name__ == "__main__":
    unittest.main()
