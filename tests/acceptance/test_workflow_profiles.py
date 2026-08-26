import json
import unittest
from copy import deepcopy
from pathlib import Path

from codex_governance.profiles import validate_task_contract


class WorkflowProfilesAcceptanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = json.loads(Path("examples/task-contract.json").read_text(encoding="utf-8"))

    def test_reference_mixed_contract_is_accepted(self) -> None:
        self.assertEqual([], validate_task_contract(self.reference))

    def test_specification_requires_three_amigos_and_rst(self) -> None:
        contract = deepcopy(self.reference)
        contract["profile"] = "specification"
        contract["specialist_reviews"] = ["engineering"]
        violations = validate_task_contract(contract)
        combined = " ".join(violations).lower()
        self.assertIn("business", combined)
        self.assertIn("qa", combined)
        self.assertIn("rst", combined)

    def test_code_profile_requires_executable_gate(self) -> None:
        contract = deepcopy(self.reference)
        contract["profile"] = "code"
        contract["required_gate_ids"] = ["document-inspection"]
        violations = validate_task_contract(contract)
        self.assertTrue(any("executable" in item.lower() for item in violations))

    def test_governance_change_requires_explicit_authorization(self) -> None:
        contract = deepcopy(self.reference)
        contract["profile"] = "governance"
        contract["governance_change_authorized"] = False
        violations = validate_task_contract(contract)
        self.assertTrue(any("authoriz" in item.lower() for item in violations))


if __name__ == "__main__":
    unittest.main()
