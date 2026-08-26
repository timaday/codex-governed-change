import unittest

from codex_governance.hook import decide_stop


class StopHookAcceptanceTest(unittest.TestCase):
    CANDIDATE = "sha256:" + "a" * 64

    def event(self, active: bool) -> dict:
        return {
            "turn_id": "turn-example",
            "stop_hook_active": active,
            "last_assistant_message": "Implementation complete",
        }

    def test_ready_for_human_allows_stop(self) -> None:
        result = decide_stop(
            event=self.event(False),
            current_candidate_id=self.CANDIDATE,
            disposition={"state": "READY_FOR_HUMAN", "candidate_id": self.CANDIDATE},
        )
        self.assertEqual({"continue": True}, result)

    def test_missing_evidence_forces_one_continuation(self) -> None:
        result = decide_stop(
            event=self.event(False),
            current_candidate_id=self.CANDIDATE,
            disposition=None,
        )
        self.assertEqual("block", result.get("decision"))
        self.assertIn("UNKNOWN", result.get("reason", ""))

    def test_second_stop_exposes_blocker_without_loop(self) -> None:
        result = decide_stop(
            event=self.event(True),
            current_candidate_id=self.CANDIDATE,
            disposition=None,
        )
        self.assertFalse(result.get("continue", True))
        self.assertNotEqual("block", result.get("decision"))

    def test_stale_disposition_forces_correction(self) -> None:
        result = decide_stop(
            event=self.event(False),
            current_candidate_id=self.CANDIDATE,
            disposition={"state": "READY_FOR_HUMAN", "candidate_id": "sha256:" + "b" * 64},
        )
        self.assertEqual("block", result.get("decision"))
        self.assertIn("stale", result.get("reason", "").lower())


if __name__ == "__main__":
    unittest.main()
