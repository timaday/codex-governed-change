import unittest

from codex_governance.domain.model import GateStatus
from codex_governance.gate import classify_gate_result


class GateEvidenceAcceptanceTest(unittest.TestCase):
    CANDIDATE = "sha256:" + "a" * 64

    def classify(self, **overrides) -> GateStatus:
        values = {
            "termination_kind": "exited",
            "exit_code": 0,
            "observation_complete": True,
            "required_output_truncated": False,
            "candidate_before": self.CANDIDATE,
            "candidate_after": self.CANDIDATE,
        }
        values.update(overrides)
        return classify_gate_result(**values)

    def test_complete_zero_exit_is_pass(self) -> None:
        self.assertEqual(GateStatus.PASS, self.classify())

    def test_complete_nonzero_exit_is_fail(self) -> None:
        self.assertEqual(GateStatus.FAIL, self.classify(exit_code=1))

    def test_timeout_is_unknown(self) -> None:
        self.assertEqual(GateStatus.UNKNOWN, self.classify(termination_kind="timeout", exit_code=None))

    def test_truncated_required_observation_is_unknown_even_on_zero(self) -> None:
        self.assertEqual(GateStatus.UNKNOWN, self.classify(required_output_truncated=True))

    def test_candidate_drift_is_unknown(self) -> None:
        self.assertEqual(
            GateStatus.UNKNOWN,
            self.classify(candidate_after="sha256:" + "b" * 64),
        )


if __name__ == "__main__":
    unittest.main()
