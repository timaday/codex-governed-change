import json
import os
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from codex_governance.profiles import validate_task_contract


class WorkflowProfilesAcceptanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = json.loads(Path("examples/task-contract.json").read_text(encoding="utf-8"))

    def test_reference_governance_contract_is_accepted(self) -> None:
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

    def test_governance_profile_requires_an_explicit_request(self) -> None:
        contract = deepcopy(self.reference)
        contract["profile"] = "governance"
        contract["governance_change_requested"] = False
        violations = validate_task_contract(contract)
        self.assertTrue(any("request" in item.lower() for item in violations))

    def test_protected_src_layout_gate_argv_is_self_contained(self) -> None:
        policy = json.loads(
            Path("examples/effective-policy.json").read_text(encoding="utf-8")
        )
        test_gates = {
            gate["gate_id"]: gate["command"]
            for gate in policy["gates"]
            if "unittest" in gate["command"]
        }
        self.assertEqual(
            {"acceptance", "unit", "security-adversarial"}, set(test_gates)
        )
        for gate_id, command in test_gates.items():
            with self.subTest(gate_id=gate_id):
                self.assertEqual(
                    ["env", "PYTHONPATH=src", "python3"], command[:3]
                )

        with tempfile.TemporaryDirectory() as home:
            completed = subprocess.run(
                test_gates["unit"],
                cwd=Path.cwd(),
                env={
                    "HOME": home,
                    "PATH": os.defpath,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                check=False,
            )
        self.assertEqual(0, completed.returncode, completed.stderr.decode("utf-8"))

    def test_protected_reviewer_requires_portable_relative_tool_arguments(self) -> None:
        prompt = Path(".codex/review/reviewer.prompt.md").read_text(encoding="utf-8")
        self.assertIn("Do not invent or emit absolute filesystem paths", prompt)
        self.assertIn("Use repository-relative paths for tool arguments", prompt)


if __name__ == "__main__":
    unittest.main()
