import unittest
from copy import deepcopy

from codex_governance.canonical import content_address
from codex_governance.domain.model import DispositionState


class RstOperationsAcceptanceTest(unittest.TestCase):
    def lineage(self) -> dict:
        repository = "repo:example/project"
        task = "sha256:" + "a" * 64
        candidate = "sha256:" + "b" * 64
        locator = "sha256:" + "c" * 64
        artifact = "sha256:" + "d" * 64
        charter_digest = "sha256:" + "e" * 64
        debrief_digest = "sha256:" + "f" * 64
        binding = {
            "repository_id": repository,
            "task_contract_sha256": task,
            "candidate_id": candidate,
        }
        risk_assessment = {**binding, "assessment_id": "sha256:" + "1" * 64}
        charter = {
            **binding,
            "charter_id": "CHARTER-1",
            "risk_assessment_sha256": risk_assessment["assessment_id"],
        }
        session = {
            **binding,
            "session_id": "SESSION-1",
            "charter_id": "CHARTER-1",
            "charter_sha256": charter_digest,
            "experiments": [{"id": "OBS-1", "evidence_refs": [locator]}],
            "findings": [
                {"finding_id": "FINDING-1", "evidence_refs": [locator]}
            ],
            "residual_risks": [
                {"risk_id": "RESIDUAL-1", "evidence_refs": [locator]}
            ],
            "retrieval_expansions": [
                {"reference": locator, "sha256": artifact}
            ],
        }
        oracle = content_address(
            {
                **binding,
                "name": "bounded oracle",
                "source": "evidence/observation.bin",
                "source_sha256": artifact,
            },
            "oracle_id",
        )
        coverage = content_address(
            {
                **binding,
                "session_id": "SESSION-1",
                "oracle_refs": [oracle["oracle_id"]],
            },
            "coverage_note_id",
        )
        story = {"evidence_refs": [locator]}
        debrief = {
            **binding,
            "debrief_id": "DEBRIEF-1",
            "session_refs": ["SESSION-1"],
            "product_story": story,
            "testing_story": story,
            "quality_of_testing_story": story,
            "actionable_findings": ["FINDING-1"],
            "residual_risks": ["RESIDUAL-1"],
        }
        follow_up = content_address(
            {
                **binding,
                "kind": "risk",
                "source_kind": "observation",
                "source_id": "OBS-1",
            },
            "follow_up_id",
        )
        risk_register = content_address(
            {
                **binding,
                "risks": [
                    {
                        "risk_id": "RISK-1",
                        "source_refs": [locator],
                        "charter_refs": ["CHARTER-1"],
                    }
                ],
                "updated_from": ["session:SESSION-1"],
            },
            "risk_register_id",
        )
        risk_disposition = {
            **binding,
            "debrief_sha256": debrief_digest,
            "items": [
                {"item_id": "FINDING-1", "evidence_refs": [locator]},
                {"item_id": "RESIDUAL-1", "evidence_refs": [locator]}
            ],
        }
        return {
            "repository_id": repository,
            "task_contract_sha256": task,
            "candidate_id": candidate,
            "risk_assessment": risk_assessment,
            "risk_register": risk_register,
            "oracle_references": [oracle],
            "charters": [charter],
            "sessions": [session],
            "coverage_notes": [coverage],
            "debrief": debrief,
            "follow_ups": [follow_up],
            "risk_disposition": risk_disposition,
            "evidence_index": {
                locator: artifact,
                "evidence/observation.bin": artifact,
            },
            "charter_digests": {"CHARTER-1": charter_digest},
            "debrief_digest": debrief_digest,
        }

    def test_presence_only_artifact_kinds_are_not_lineage_evidence(self) -> None:
        from codex_governance.rst_operations import validate_rst_lineage

        lineage = self.lineage()
        artifacts = [
            {
                "kind": kind,
                "repository_id": lineage["repository_id"],
                "task_contract_sha256": lineage["task_contract_sha256"],
                "candidate_id": lineage["candidate_id"],
            }
            for kind in (
                "risk_register",
                "oracle_reference",
                "charter",
                "session",
                "coverage_note",
                "debrief",
                "follow_up",
            )
        ]
        self.assertEqual(
            DispositionState.UNKNOWN,
            validate_rst_lineage(
                lineage["repository_id"],
                lineage["task_contract_sha256"],
                lineage["candidate_id"],
                artifacts,
            ),
        )

    def test_complete_operational_relationship_graph_is_required(self) -> None:
        from codex_governance.rst_operations import validate_rst_lineage

        clean = self.lineage()
        self.assertEqual(DispositionState.READY_FOR_HUMAN, validate_rst_lineage(**clean))
        mutations = {
            "risk-source": lambda value: value["risk_register"]["risks"][0].update(source_refs=["sha256:" + "0" * 64]),
            "risk-charter": lambda value: value["risk_register"]["risks"][0].update(charter_refs=["CHARTER-MISSING"]),
            "risk-update": lambda value: value["risk_register"].update(updated_from=["session:SESSION-MISSING"]),
            "charter-risk": lambda value: value["charters"][0].update(risk_assessment_sha256="sha256:" + "0" * 64),
            "session-charter-id": lambda value: value["sessions"][0].update(charter_id="CHARTER-MISSING"),
            "session-charter-digest": lambda value: value["sessions"][0].update(charter_sha256="sha256:" + "0" * 64),
            "experiment-evidence": lambda value: value["sessions"][0]["experiments"][0].update(evidence_refs=["sha256:" + "0" * 64]),
            "finding-evidence": lambda value: value["sessions"][0]["findings"][0].update(evidence_refs=["sha256:" + "0" * 64]),
            "residual-evidence": lambda value: value["sessions"][0]["residual_risks"][0].update(evidence_refs=["sha256:" + "0" * 64]),
            "retrieval-reference": lambda value: value["sessions"][0]["retrieval_expansions"][0].update(reference="sha256:" + "0" * 64),
            "retrieval-digest": lambda value: value["sessions"][0]["retrieval_expansions"][0].update(sha256="sha256:" + "0" * 64),
            "oracle-path": lambda value: value["oracle_references"][0].update(source="evidence/missing.bin"),
            "oracle-source": lambda value: value["oracle_references"][0].update(source_sha256="sha256:" + "0" * 64),
            "coverage-session": lambda value: value["coverage_notes"][0].update(session_id="SESSION-MISSING"),
            "coverage-oracle": lambda value: value["coverage_notes"][0].update(oracle_refs=["sha256:" + "0" * 64]),
            "debrief-session": lambda value: value["debrief"].update(session_refs=["SESSION-MISSING"]),
            "debrief-finding": lambda value: value["debrief"].update(actionable_findings=["FINDING-MISSING"]),
            "debrief-residual": lambda value: value["debrief"].update(residual_risks=["RESIDUAL-MISSING"]),
            "debrief-story": lambda value: value["debrief"]["testing_story"].update(evidence_refs=["sha256:" + "0" * 64]),
            "follow-up-source": lambda value: value["follow_ups"][0].update(source_id="OBS-MISSING"),
            "disposition-debrief": lambda value: value["risk_disposition"].update(debrief_sha256="sha256:" + "0" * 64),
            "disposition-item": lambda value: value["risk_disposition"].update(items=[{"item_id": "RESIDUAL-MISSING", "evidence_refs": ["sha256:" + "c" * 64]}]),
            "disposition-evidence": lambda value: value["risk_disposition"]["items"][0].update(evidence_refs=["sha256:" + "0" * 64]),
            "malformed-evidence": lambda value: value["sessions"][0]["experiments"][0].update(evidence_refs=[{}]),
        }
        for name, mutate in mutations.items():
            variant = deepcopy(clean)
            mutate(variant)
            if name.startswith("risk-"):
                document = variant["risk_register"]
                document.pop("risk_register_id", None)
                variant["risk_register"] = content_address(
                    document, "risk_register_id"
                )
            elif name.startswith("oracle-"):
                oracle = variant["oracle_references"][0]
                oracle.pop("oracle_id", None)
                oracle = content_address(oracle, "oracle_id")
                variant["oracle_references"][0] = oracle
                coverage = variant["coverage_notes"][0]
                coverage["oracle_refs"] = [oracle["oracle_id"]]
                coverage.pop("coverage_note_id", None)
                variant["coverage_notes"][0] = content_address(
                    coverage, "coverage_note_id"
                )
            elif name.startswith("coverage-"):
                coverage = variant["coverage_notes"][0]
                coverage.pop("coverage_note_id", None)
                variant["coverage_notes"][0] = content_address(
                    coverage, "coverage_note_id"
                )
            elif name.startswith("follow-up-"):
                follow_up = variant["follow_ups"][0]
                follow_up.pop("follow_up_id", None)
                variant["follow_ups"][0] = content_address(
                    follow_up, "follow_up_id"
                )
            with self.subTest(name=name):
                self.assertEqual(DispositionState.UNKNOWN, validate_rst_lineage(**variant))

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
                artifacts_complete=True,
                direct_observations=[],
                fallible_oracles=[],
                coverage_notes=["all boxes checked"],
                unresolved_follow_ups=[],
            ),
        )


if __name__ == "__main__":
    unittest.main()
