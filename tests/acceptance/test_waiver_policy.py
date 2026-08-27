import unittest
from datetime import datetime, timezone

from codex_governance.canonical import content_address
from codex_governance.domain.policy import waiver_applies


class WaiverPolicyAcceptanceTest(unittest.TestCase):
    REPOSITORY = "repo:example/project"
    CANDIDATE = "sha256:" + "a" * 64
    TASK = "sha256:" + "b" * 64
    POLICY = "sha256:" + "c" * 64

    def decision(self, kind: str, *, consumption_id: str = "") -> dict:
        return content_address(
            {
                "schema_version": "1.0.0", "repository_id": self.REPOSITORY,
                "decision_type": kind, "task_contract_sha256": self.TASK,
                "candidate_id": self.CANDIDATE, "base_commit": "1" * 40,
                "effective_policy_sha256": self.POLICY, "scope": ["GOV-018"],
                "issuer": {
                    "subject": "protected-maintainer",
                    "authentication_method": "protected-source-assertion",
                    "protected_source": "decisions/waiver.json",
                    "assertion_sha256": "sha256:" + "d" * 64,
                },
                "issued_at": "2026-08-26T10:00:00Z",
                "expires_at": "2026-08-26T11:00:00Z", "single_use": True,
                "consumption_id": consumption_id,
            },
            "decision_id",
        )

    def waiver(self) -> tuple[dict, list[dict]]:
        issuance = self.decision("waiver_issuance")
        consumption = self.decision(
            "waiver_consumption", consumption_id=issuance["decision_id"]
        )
        waiver = content_address({
            "schema_version": "2.0.0", "repository_id": self.REPOSITORY,
            "task_contract_sha256": self.TASK,
            "candidate_id": self.CANDIDATE,
            "effective_policy_sha256": self.POLICY,
            "requirement_ids": ["GOV-018"],
            "issuance_decision_id": issuance["decision_id"],
            "consumption_decision_id": consumption["decision_id"],
            "rationale": "bounded test waiver",
            "compensating_controls": ["protected manual check"],
            "created_at": "2026-08-26T10:00:00Z",
            "expires_at": "2026-08-26T11:00:00Z",
            "single_use": True,
        }, "waiver_id")
        return waiver, [issuance, consumption]

    def test_only_current_exact_waiver_applies(self) -> None:
        current = datetime(2026, 8, 26, 10, 30, tzinfo=timezone.utc)
        waiver, decisions = self.waiver()
        self.assertTrue(waiver_applies(
            waiver=waiver, repository_id=self.REPOSITORY,
            candidate_id=self.CANDIDATE, task_contract_sha256=self.TASK,
            policy_sha256=self.POLICY, requirement_id="GOV-018",
            decisions=decisions,
            verified_decision_ids=frozenset(item["decision_id"] for item in decisions),
            now=current,
        ))
        self.assertFalse(waiver_applies(
            waiver=waiver, repository_id=self.REPOSITORY,
            candidate_id=self.CANDIDATE, task_contract_sha256=self.TASK,
            policy_sha256=self.POLICY, requirement_id="GOV-018", decisions=decisions,
            verified_decision_ids=frozenset(item["decision_id"] for item in decisions),
            now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
        ))
        decision_expired_waiver = dict(waiver)
        decision_expired_waiver["expires_at"] = "2026-08-26T13:00:00Z"
        decision_expired_waiver = content_address(
            decision_expired_waiver, "waiver_id"
        )
        self.assertFalse(waiver_applies(
            waiver=decision_expired_waiver, repository_id=self.REPOSITORY,
            candidate_id=self.CANDIDATE, task_contract_sha256=self.TASK,
            policy_sha256=self.POLICY, requirement_id="GOV-018",
            decisions=decisions,
            verified_decision_ids=frozenset(item["decision_id"] for item in decisions),
            now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc),
        ))
        forged = dict(waiver)
        forged["rationale"] = "forged"
        self.assertFalse(waiver_applies(
            waiver=forged, repository_id=self.REPOSITORY,
            candidate_id=self.CANDIDATE, task_contract_sha256=self.TASK,
            policy_sha256=self.POLICY, requirement_id="GOV-018",
            decisions=decisions,
            verified_decision_ids=frozenset(item["decision_id"] for item in decisions),
            now=current,
        ))
        self.assertFalse(waiver_applies(
            waiver=waiver, repository_id=self.REPOSITORY,
            candidate_id=self.CANDIDATE, task_contract_sha256=self.TASK,
            policy_sha256=self.POLICY, requirement_id="GOV-018",
            decisions=decisions, verified_decision_ids=frozenset(), now=current,
        ))


if __name__ == "__main__":
    unittest.main()
