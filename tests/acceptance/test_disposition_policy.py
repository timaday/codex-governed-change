import unittest

from codex_governance.domain.model import DispositionState
from codex_governance.domain.policy import evaluate_disposition


class DispositionPolicyAcceptanceTest(unittest.TestCase):
    CANDIDATE = "sha256:" + "a" * 64

    def evaluate(self, *, gates=None, reviewer=None, integrity=True):
        if gates is None:
            gates = {
                "unit": {"status": "PASS", "candidate_id": self.CANDIDATE},
                "security": {"status": "PASS", "candidate_id": self.CANDIDATE},
            }
        if reviewer is None:
            reviewer = {"verdict": "PASS", "candidate_id": self.CANDIDATE}
        return evaluate_disposition(
            candidate_id=self.CANDIDATE,
            required_gate_ids=["unit", "security"],
            gate_results=gates,
            reviewer_result=reviewer,
            governance_integrity=integrity,
        )

    def test_all_valid_evidence_is_ready_for_human_not_approval(self) -> None:
        self.assertEqual(DispositionState.READY_FOR_HUMAN, self.evaluate())

    def test_missing_gate_is_unknown(self) -> None:
        self.assertEqual(
            DispositionState.UNKNOWN,
            self.evaluate(gates={"unit": {"status": "PASS", "candidate_id": self.CANDIDATE}}),
        )

    def test_gate_failure_blocks(self) -> None:
        gates = {
            "unit": {"status": "FAIL", "candidate_id": self.CANDIDATE},
            "security": {"status": "PASS", "candidate_id": self.CANDIDATE},
        }
        self.assertEqual(DispositionState.BLOCK, self.evaluate(gates=gates))

    def test_gate_unknown_stays_unknown(self) -> None:
        gates = {
            "unit": {"status": "UNKNOWN", "candidate_id": self.CANDIDATE},
            "security": {"status": "PASS", "candidate_id": self.CANDIDATE},
        }
        self.assertEqual(DispositionState.UNKNOWN, self.evaluate(gates=gates))

    def test_reviewer_pass_without_gates_cannot_certify(self) -> None:
        self.assertEqual(DispositionState.UNKNOWN, self.evaluate(gates={}))

    def test_reviewer_block_blocks(self) -> None:
        self.assertEqual(
            DispositionState.BLOCK,
            self.evaluate(reviewer={"verdict": "BLOCK", "candidate_id": self.CANDIDATE}),
        )

    def test_stale_reviewer_is_unknown(self) -> None:
        self.assertEqual(
            DispositionState.UNKNOWN,
            self.evaluate(reviewer={"verdict": "PASS", "candidate_id": "sha256:" + "b" * 64}),
        )

    def test_unauthorized_governance_change_blocks(self) -> None:
        self.assertEqual(DispositionState.BLOCK, self.evaluate(integrity=False))


if __name__ == "__main__":
    unittest.main()
