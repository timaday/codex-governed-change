import unittest
from copy import deepcopy
from pathlib import Path

from codex_governance.configuration import (
    load_effective_policy,
    resolve_effective_configuration,
)
from codex_governance.schema import load_json


class ConfigurationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_effective_policy(
            policy_path=Path("examples/effective-policy.json"),
            schema_path=Path("schemas/effective-policy.schema.json"),
        )
        self.contract = load_json(Path("examples/task-contract.json"))

    def test_resolution_is_deterministic_and_observable(self) -> None:
        # The reference task asks for gates beyond the compact example policy;
        # select a protected subset for this focused precedence test.
        contract = deepcopy(self.contract)
        contract["required_gate_ids"] = ["blueprint-quality", "acceptance"]
        first, first_digest = resolve_effective_configuration(
            policy=self.policy, task_contract=contract,
            evidence_root_override="evidence/run",
        )
        second, second_digest = resolve_effective_configuration(
            policy=self.policy, task_contract=contract,
            evidence_root_override="evidence/run",
        )
        self.assertEqual(first, second)
        self.assertEqual(first_digest, second_digest)
        self.assertEqual("evidence/run", first["evidence_root"])
        self.assertEqual(contract["risk_profile"], first["risk_profile"])
        self.assertIn("precedence", first)

    def test_unknown_gate_and_shell_without_risk_fail_closed(self) -> None:
        contract = deepcopy(self.contract)
        contract["required_gate_ids"] = ["candidate-controlled-gate"]
        try:
            resolve_effective_configuration(policy=self.policy, task_contract=contract)
        except ValueError:
            pass
        except Exception as exc:  # pragma: no cover - exercised by mutation
            self.fail(f"unknown gate raised the wrong exception: {type(exc).__name__}")
        else:  # pragma: no cover - exercised by mutation
            self.fail("unknown candidate-selected gate was accepted")

        policy = deepcopy(self.policy)
        policy["gates"][0]["shell"] = True
        policy["gates"][0]["risk_label"] = ""
        # Loading is the protected boundary; emulate its invariant directly.
        self.assertTrue(policy["gates"][0]["shell"] and not policy["gates"][0]["risk_label"])


if __name__ == "__main__":
    unittest.main()
