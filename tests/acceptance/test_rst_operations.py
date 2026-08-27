import unittest

from codex_governance.domain.model import DispositionState


class RstOperationsAcceptanceTest(unittest.TestCase):
    def test_all_operational_artifacts_bind_repository_task_and_candidate(self) -> None:
        from codex_governance.rst_operations import validate_rst_lineage

        repository = "repo:example/project"
        task = "sha256:" + "a" * 64
        candidate = "sha256:" + "b" * 64
        artifacts = [
            {"kind": kind, "repository_id": repository, "task_contract_sha256": task, "candidate_id": candidate}
            for kind in ("risk_register", "oracle_reference", "charter", "session", "coverage_note", "debrief", "follow_up")
        ]
        self.assertEqual(DispositionState.READY_FOR_HUMAN, validate_rst_lineage(repository, task, candidate, artifacts))
        artifacts[-1]["candidate_id"] = "sha256:" + "c" * 64
        self.assertEqual(DispositionState.UNKNOWN, validate_rst_lineage(repository, task, candidate, artifacts))

    def test_observations_mutants_and_findings_create_bidirectional_updates(self) -> None:
        from codex_governance.rst_operations import derive_follow_ups

        follow_ups = derive_follow_ups(
            observations=[{"id": "OBS-1", "surprise": "authorization path differed"}],
            mutants=[{"id": "MUT-1", "outcome": "SURVIVED"}],
            reviewer_findings=[{"id": "FIND-1", "severity": "high"}],
        )
        self.assertEqual({"observation", "mutant", "reviewer_finding"}, {item["source_kind"] for item in follow_ups})
        self.assertTrue(all(item["required"] for item in follow_ups if item["source_kind"] != "observation"))

    def test_completed_paperwork_without_direct_investigation_is_unknown(self) -> None:
        from codex_governance.rst_operations import evaluate_operational_rst

        self.assertEqual(
            DispositionState.UNKNOWN,
            evaluate_operational_rst(
                artifacts_complete=True, direct_observations=[], fallible_oracles=[],
                coverage_notes=["all boxes checked"], unresolved_follow_ups=[],
            ),
        )


if __name__ == "__main__":
    unittest.main()
