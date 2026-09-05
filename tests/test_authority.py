from __future__ import annotations

import contextlib
import ast
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import io
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".governance" / "ci"
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(CI))
sys.path.insert(0, str(ROOT / "kernel" / "src"))

from common import (  # noqa: E402
    canonical_bytes,
    content_address,
    copy_json_once,
    load_json,
    reset_authoritative_read_session,
    require_json_within,
    sha256_bytes,
    verify_decision_source_assertion,
    verify_candidate_identity,
)
from bootstrap import validate_initial_bootstrap  # noqa: E402
from qualification_verifier import validate_qualification_bundle  # noqa: E402
from paired_comparison import (  # noqa: E402
    build_comparison_document,
    comparison_document_valid,
    human_effort_record_valid,
    reconstruct_task,
    score_task,
    validate_comparison_inputs,
)
from codex_governance import gate as gate_module  # noqa: E402
from codex_governance import qualification as qualification_module  # noqa: E402
from codex_governance import reviewer as reviewer_module  # noqa: E402
from codex_governance.attestation import build_provenance_statement  # noqa: E402
from codex_governance.evidence import (  # noqa: E402
    assemble_evidence_manifest,
    evaluate_manifest,
)
from codex_governance.context import (  # noqa: E402
    MANDATORY_REVIEWER_CLAIMS,
    REVIEW_RUBRIC,
)
from codex_governance.profiles import validate_task_contract  # noqa: E402
from codex_governance.schema import validate_instance, validate_semantics  # noqa: E402
from codex_governance.sandbox import sandbox_execution_identity  # noqa: E402


def run_script(name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CI / name), *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_bytes(value))


def publication_fixture(
    target: dict[str, object], *, conclusion: str = "failure"
) -> dict[str, object]:
    success = conclusion == "success"
    return {
        "schema_version": "1.0.0",
        "target_id": target["target_id"],
        "target_ref": target["target_ref"],
        "authority_repository": "timaday/codex-governed-change",
        "authority_ref": "refs/heads/governance-authority",
        "authority_sha": "a" * 40,
        "source_repository": "timaday/codex-governed-change-authority",
        "source_head_sha": "b" * 40,
        "repository": target["repository"],
        "repository_id": target["repository_id"],
        "head_sha": target["head_sha"],
        "candidate_id": target["expected_candidate_id"],
        "task_contract_sha256": target["expected_task_contract_sha256"],
        "effective_policy_sha256": target["expected_policy_sha256"],
        "manifest_id": "sha256:" + "1" * 64,
        "manifest_sha256": "sha256:" + "2" * 64,
        "disposition_sha256": "sha256:" + "3" * 64,
        "check_name": "disposition",
        "status": "completed",
        "conclusion": conclusion,
        "title": (
            "Governed admission ready"
            if success
            else "Governed admission blocked"
        ),
        "summary": (
            "Protected evidence reconstructed."
            if success
            else "Protected evidence is incomplete."
        ),
        "details_url": "https://github.com/timaday/codex-governed-change-authority/actions/runs/1",
        "workflow_run": "1-1",
        "external_id": "governed-change:1-1:" + str(target["expected_candidate_id"]),
        "reason_codes": ["READY_FOR_HUMAN" if success else "ADMISSION_EVIDENCE_UNAVAILABLE"],
    }


def bootstrap_fixture(repository: Path) -> dict[str, object]:
    evidence = repository / "artifacts/governance/completion/evidence"
    rollback_root = evidence / "rollback"
    rollback_root.mkdir(parents=True)
    stdout = (
        b"ROLLBACK_REHEARSAL=PASS "
        b"target=a0a0b01a19e87f2591c7e97e892cd040ce9c6e58\n"
    )
    stderr = b""
    (rollback_root / "stdout.bin").write_bytes(stdout)
    (rollback_root / "stderr.bin").write_bytes(stderr)

    candidate = load_json(FIXTURES / "candidate.json")
    policy = load_json(ROOT / ".governance/effective-policy.json")
    lkg_commit = load_json(ROOT / ".governance/targets.json")["targets"][0][
        "lkg_governance_commit"
    ]
    policy_sha = sha256_bytes(canonical_bytes(policy))
    proposed = deepcopy(policy)
    proposed["policy_id"] = "POLICY-T24-PROPOSED-001"
    proposed["lkg_governance_commit"] = candidate["head_commit"]
    proposed_sha = sha256_bytes(canonical_bytes(proposed))
    plan_path = ROOT / ".governance/releases/v0.1.0/rollback-plan.json"
    plan = load_json(plan_path)
    plan_sha = sha256_bytes(plan_path.read_bytes())
    rollback_task_path = (
        ROOT / ".governance/releases/v0.1.0/rollback-task-contract.json"
    )
    rollback_task = load_json(rollback_task_path)
    rollback_task_sha = sha256_bytes(rollback_task_path.read_bytes())
    source_identity = plan["rollback_source_identity"]
    rollback_candidate = {
        "schema_version": "1.0.0",
        "repository_id": candidate["repository_id"],
        "candidate_id": source_identity,
        "mode": "commit",
        "base_commit": lkg_commit,
        "head_commit": lkg_commit,
        "tracked_diff_sha256": sha256_bytes(b""),
        "changed_paths": [],
        "untracked_entries": [],
        "submodules": [],
        "effective_policy_sha256": policy_sha,
        "dirty": False,
    }
    execution_identity = sandbox_execution_identity(
        provider=policy["sandbox"]["provider"],
        provider_version="25.0.0",
        image=policy["sandbox"]["image"],
        command=plan["gate_definition"]["command"],
        process_limit=policy["sandbox"]["process_limit"],
        memory_bytes=policy["sandbox"]["memory_bytes"],
        cpu_seconds=plan["gate_definition"]["timeout_seconds"],
        timeout_seconds=plan["gate_definition"]["timeout_seconds"],
        output_bytes=plan["gate_definition"]["max_output_bytes"],
    )
    capability = content_address(
        {
            "schema_version": "2.0.0",
            "provider": policy["sandbox"]["provider"],
            "provider_version": "25.0.0",
            "image": policy["sandbox"]["image"],
            "command": plan["gate_definition"]["command"],
            "implementation_sha256": plan["implementation_sha256"],
            "source_identity": source_identity,
            "execution_identity": execution_identity,
            "disposable": True,
            "secrets_present": False,
            "network_mode": "none",
            "candidate_copy_writable": True,
            "protected_paths_writable": False,
            "evidence_paths_writable": False,
            "supervisor_paths_writable": False,
            "process_limit": policy["sandbox"]["process_limit"],
            "memory_bytes": policy["sandbox"]["memory_bytes"],
            "cpu_seconds": plan["gate_definition"]["timeout_seconds"],
            "cpu_seconds": plan["gate_definition"]["timeout_seconds"],
            "timeout_seconds": plan["gate_definition"]["timeout_seconds"],
            "output_bytes": plan["gate_definition"]["max_output_bytes"],
            "verified_at": "2026-08-27T10:59:00Z",
            "limitations": [],
        },
        "capability_id",
    )
    capability_sha = sha256_bytes(canonical_bytes(capability))
    artifacts = [
        {"name": "stdout", "sha256": sha256_bytes(stdout)},
        {"name": "stderr", "sha256": sha256_bytes(stderr)},
        {"name": "sandbox-capability", "sha256": capability_sha},
    ]
    provenance = build_provenance_statement(
        repository_id=candidate["repository_id"],
        candidate_id=source_identity,
        repository_digest=source_identity,
        task_contract_sha256=plan["rollback_task_contract_sha256"],
        effective_policy_sha256=policy_sha,
        gate_definition_sha256=plan["gate_definition_sha256"],
        reviewer_prompt_sha256=plan["reviewer_prompt_sha256"],
        producer={
            "builder_id": plan["producer_builder_id"],
            "implementation_sha256": plan["implementation_sha256"],
            "version": plan["producer_version"],
        },
        workflow={"system": "github-actions", "run_id": "github-1-rollback", "attempt": 1},
        tools=[
            {"name": "python", "version": "3.12"},
            {"name": policy["sandbox"]["provider"], "version": "25.0.0"},
        ],
        environment={
            "source_identity": source_identity,
            "execution_identity": execution_identity,
            "sandbox_capability_sha256": capability_sha,
        },
        materials=[
            {"name": "candidate", "sha256": source_identity},
            {
                "name": "task-contract",
                "sha256": plan["rollback_task_contract_sha256"],
            },
            {"name": "effective-policy", "sha256": policy_sha},
        ],
        started_at="2026-08-27T11:00:00Z",
        ended_at="2026-08-27T11:01:00Z",
        result="PASS",
        limits={
            "timeout_seconds": plan["gate_definition"]["timeout_seconds"],
            "max_output_bytes": plan["gate_definition"]["max_output_bytes"],
            "process_limit": policy["sandbox"]["process_limit"],
            "memory_bytes": policy["sandbox"]["memory_bytes"],
            "cpu_seconds": plan["gate_definition"]["timeout_seconds"],
        },
        artifacts=artifacts,
        limitations=[],
    )
    provenance_sha = sha256_bytes(canonical_bytes(provenance))
    gate = {
        "schema_version": "1.0.0",
        "repository_id": candidate["repository_id"],
        "task_contract_sha256": plan["rollback_task_contract_sha256"],
        "gate_id": plan["gate_definition"]["gate_id"],
        "profile": "code",
        "candidate_before": source_identity,
        "candidate_after": source_identity,
        "source_identity": source_identity,
        "execution_identity": execution_identity,
        "sandbox_capability_sha256": capability_sha,
        "command": plan["gate_definition"]["command"],
        "started_at": "2026-08-27T11:00:00Z",
        "ended_at": "2026-08-27T11:01:00Z",
        "duration_ms": 60000,
        "termination": {"kind": "exited", "exit_code": 0},
        "artifacts": [
            {
                "stream": "stdout",
                "path": plan["raw_artifacts"]["stdout"],
                "bytes": len(stdout),
                "sha256": sha256_bytes(stdout),
                "truncated": False,
            },
            {
                "stream": "stderr",
                "path": plan["raw_artifacts"]["stderr"],
                "bytes": len(stderr),
                "sha256": sha256_bytes(stderr),
                "truncated": False,
            },
        ],
        "redactions": [],
        "observation_complete": True,
        "status": "PASS",
        "limitations": [],
        "provenance_statement": {
            "path": "artifacts/governance/completion/evidence/rollback/provenance-statement.json",
            "sha256": provenance_sha,
        },
        "producer_version": plan["producer_version"],
    }
    gate_sha = sha256_bytes(canonical_bytes(gate))
    rollback = content_address(
        {
            "schema_version": "2.0.0",
            "repository_id": candidate["repository_id"],
            "task_contract_sha256": plan["task_contract_sha256"],
            "candidate_id": candidate["candidate_id"],
            "previous_lkg_policy_sha256": policy_sha,
            "proposed_policy_sha256": proposed_sha,
            "rollback_target_commit": lkg_commit,
            "gate_result": {
                "path": "artifacts/governance/completion/evidence/rollback/gate-result.json",
                "sha256": gate_sha,
            },
            "sandbox_capability": {
                "path": "artifacts/governance/completion/evidence/rollback/sandbox-capability.json",
                "sha256": capability_sha,
            },
            "provenance_statement": {
                "path": "artifacts/governance/completion/evidence/rollback/provenance-statement.json",
                "sha256": provenance_sha,
            },
            "status": "PASS",
            "created_at": "2026-08-27T11:02:00Z",
            "limitations": [],
        },
        "rollback_evidence_id",
    )
    authority_commit = "a" * 40
    authority_basis_commit = "b" * 40
    issuer_descriptor = {
        "subject": "github:timaday",
        "authentication_method": "github-actions-workflow-dispatch",
        "protected_source": (
            "timaday/codex-governed-change@refs/heads/governance-authority"
        ),
    }
    issuer = {
        **issuer_descriptor,
        "assertion_sha256": sha256_bytes(canonical_bytes(issuer_descriptor)),
    }

    def decision(
        kind: str,
        scope: list[str],
        consumption_id: str,
        *,
        decision_base: str,
    ) -> dict[str, object]:
        return content_address(
            {
                "schema_version": "1.0.0",
                "repository_id": candidate["repository_id"],
                "decision_type": kind,
                "task_contract_sha256": plan["task_contract_sha256"],
                "candidate_id": candidate["candidate_id"],
                "base_commit": decision_base,
                "effective_policy_sha256": policy_sha,
                "scope": scope,
                "issuer": issuer,
                "issued_at": "2026-08-27T10:00:00Z",
                "expires_at": "2026-08-27T14:00:00Z",
                "single_use": True,
                "consumption_id": consumption_id,
            },
            "decision_id",
        )

    bootstrap_decision = decision(
        "lkg_bootstrap",
        [
            f"initial-lkg:{lkg_commit}",
            f"authority-basis:{authority_basis_commit}",
            f"kernel-source:{candidate['head_commit']}",
            f"bootstrap-policy:{policy_sha}",
        ],
        f"initial-lkg-bootstrap:{candidate['candidate_id']}",
        decision_base=candidate["base_commit"],
    )
    promotion_decision = decision(
        "lkg_promotion",
        [
            f"promote:{proposed_sha}",
            f"rollback:{rollback['rollback_evidence_id']}",
        ],
        f"lkg-promotion:{candidate['candidate_id']}",
        decision_base=lkg_commit,
    )
    decisions = [bootstrap_decision, promotion_decision]
    source_assertion = {
        "event_name": "workflow_dispatch",
        "actor": "github:timaday",
        "authority_repository": "timaday/codex-governed-change",
        "authority_ref": "refs/heads/governance-authority",
        "authority_commit": authority_commit,
        "authority_basis_commit": authority_basis_commit,
        "workflow_run_id": "bootstrap-fixture",
        "approved_decision_ids": [item["decision_id"] for item in decisions],
        "authorization_receipt_id": None,
    }
    authority_manifest_sha = sha256_bytes((ROOT / "MANIFEST.json").read_bytes())
    authority_state = {
        "schema_version": "1.0.0",
        "repository": "timaday/codex-governed-change",
        "ref": "refs/heads/governance-authority",
        "commit": authority_commit,
        "manifest_commit": authority_commit,
        "manifest_sha256": authority_manifest_sha,
        "source_assertion": source_assertion,
        "source_assertion_sha256": sha256_bytes(canonical_bytes(source_assertion)),
        "ruleset": {
            "id": 1,
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["refs/heads/governance-authority"],
                    "exclude": [],
                }
            },
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "allowed_merge_methods": ["squash", "rebase"],
                        "dismiss_stale_reviews_on_push": True,
                        "require_code_owner_review": False,
                        "require_extra_approval_for_unattributed_changes": True,
                        "require_last_push_approval": False,
                        "required_approving_review_count": 0,
                        "required_review_thread_resolution": True,
                        "required_reviewers": [],
                    },
                },
            ],
        },
        "observed_at": "2026-08-27T11:59:00Z",
    }
    observation = {
        "authority_commit": authority_commit,
        "authority_basis_commit": authority_basis_commit,
        "kernel_source_commit": candidate["head_commit"],
        "lkg_governance_commit": lkg_commit,
        "governance_transition": {
            "mode": "initial_lkg_bootstrap",
            "basis_commit": lkg_commit,
            "bootstrap_decision_type": "lkg_bootstrap",
            "promotion_decision_type": "lkg_promotion",
            "reusable": False,
        },
        "rollback_plan_id": plan["rollback_plan_id"],
        "rollback_plan_sha256": plan_sha,
        "decision_source_assertion": source_assertion,
    }
    return {
        "repository": repository,
        "evidence": evidence,
        "candidate": candidate,
        "bootstrap_policy": policy,
        "bootstrap_policy_sha256": policy_sha,
        "task_contract_sha256": plan["task_contract_sha256"],
        "rollback_task": rollback_task,
        "rollback_task_sha256": rollback_task_sha,
        "proposed_policy": proposed,
        "proposed_policy_sha256": proposed_sha,
        "rollback_plan": plan,
        "rollback_plan_sha256": plan_sha,
        "rollback_candidate": rollback_candidate,
        "rollback_candidate_sha256": sha256_bytes(canonical_bytes(rollback_candidate)),
        "rollback": rollback,
        "rollback_gate": gate,
        "rollback_gate_sha256": gate_sha,
        "rollback_capability": capability,
        "rollback_capability_sha256": capability_sha,
        "rollback_provenance": provenance,
        "rollback_provenance_sha256": provenance_sha,
        "authority_state": authority_state,
        "authority_state_sha256": sha256_bytes(canonical_bytes(authority_state)),
        "authority_manifest_sha256": authority_manifest_sha,
        "observation": observation,
        "decisions": decisions,
        "verified_decision_ids": {item["decision_id"] for item in decisions},
        "evaluated_at": datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
    }


def rebind_bootstrap_dispatch(arguments: dict[str, object]) -> None:
    """Re-address a fixture after intentionally replacing a protected decision."""
    decisions = arguments["decisions"]
    assert isinstance(decisions, list)
    state = deepcopy(arguments["authority_state"])
    assertion = deepcopy(state["source_assertion"])
    assertion["approved_decision_ids"] = [item["decision_id"] for item in decisions]
    state["source_assertion"] = assertion
    state["source_assertion_sha256"] = sha256_bytes(canonical_bytes(assertion))
    arguments["authority_state"] = state
    arguments["authority_state_sha256"] = sha256_bytes(canonical_bytes(state))
    observation = deepcopy(arguments["observation"])
    observation["decision_source_assertion"] = assertion
    arguments["observation"] = observation
    arguments["verified_decision_ids"] = {
        item["decision_id"] for item in decisions
    }


class AuthorityContractTests(unittest.TestCase):
    def test_bundle_manifest_reconstructs_every_public_file(self) -> None:
        manifest = load_json(ROOT / "MANIFEST.json")
        declared = {item["path"]: item["sha256"] for item in manifest["files"]}
        observed = {}
        for path in sorted(ROOT.rglob("*")):
            if (
                not path.is_file()
                or ".git" in path.parts
                or path.name == "MANIFEST.json"
            ):
                continue
            self.assertNotIn("__pycache__", path.parts)
            self.assertNotEqual(".pyc", path.suffix)
            observed[path.relative_to(ROOT).as_posix()] = sha256_bytes(path.read_bytes())
        self.assertEqual(observed, declared)

    def test_kernel_source_provenance_is_base_plus_explicit_overrides(self) -> None:
        source = load_json(ROOT / "kernel/SOURCE.json")
        source_manifest_path = ROOT / "kernel" / source["source_manifest"]["path"]
        self.assertEqual(
            source["source_manifest"]["sha256"],
            sha256_bytes(source_manifest_path.read_bytes()),
        )
        source_manifest = load_json(source_manifest_path)
        self.assertEqual(source["source_repository"], source_manifest["source_repository"])
        self.assertEqual(source["source_commit"], source_manifest["source_commit"])
        declared_source = {
            item["path"]: item["sha256"] for item in source_manifest["files"]
        }
        current = {}
        for relative in source["included_roots"]:
            root = ROOT / "kernel" / relative
            paths = [root] if root.is_file() else sorted(root.rglob("*"))
            for path in paths:
                if path.is_file():
                    current[path.relative_to(ROOT / "kernel").as_posix()] = sha256_bytes(
                        path.read_bytes()
                    )
        self.assertEqual(set(declared_source), set(current))
        overrides = {
            item["path"]: item for item in source["authority_owned_overrides"]
        }
        self.assertEqual(len(overrides), len(source["authority_owned_overrides"]))
        for path, source_digest in declared_source.items():
            override = overrides.get(path)
            if override is None:
                self.assertEqual(source_digest, current[path], path)
                continue
            self.assertEqual(source_digest, override["source_sha256"], path)
            self.assertEqual(current[path], override["authority_sha256"], path)
            self.assertNotEqual(source_digest, current[path], path)

    def test_app_has_no_webhook_and_only_minimum_repository_permissions(self) -> None:
        app = load_json(ROOT / ".governance/github-app-registration.json")
        self.assertFalse(app["public"])
        self.assertFalse(app["request_oauth_on_install"])
        self.assertFalse(app["webhook_active"])
        self.assertIsNone(app["webhook_url"])
        self.assertEqual([], app["events"])
        self.assertEqual(
            {
                "checks": "write",
                "contents": "read",
                "metadata": "read",
                "statuses": "write",
            },
            app["repository_permissions"],
        )
        self.assertEqual(
            ["timaday/codex-governed-change"],
            app["installation_scope"]["repositories"],
        )
        self.assertIn("webhook_active=false", app["registration_url"])

    def test_target_is_exact_and_dispatch_cannot_supply_a_commit(self) -> None:
        targets = load_json(ROOT / ".governance/targets.json")
        self.assertEqual(1, len(targets["targets"]))
        target = targets["targets"][0]
        self.assertEqual("release-v0.1.0", target["target_id"])
        self.assertEqual("5393338571f8ed5de5192613dcdd6131044932dc", target["base_sha"])
        self.assertEqual("deebb31ee262712bd46912b2ac5de1d2cb92faf1", target["head_sha"])
        self.assertEqual("refs/heads/main", target["target_ref"])
        self.assertEqual(
            "a0a0b01a19e87f2591c7e97e892cd040ce9c6e58",
            target["lkg_governance_commit"],
        )
        self.assertEqual(
            "deebb31ee262712bd46912b2ac5de1d2cb92faf1",
            target["kernel_source_commit"],
        )
        self.assertEqual(
            target["expected_policy_sha256"],
            sha256_bytes((ROOT / ".governance/effective-policy.json").read_bytes()),
        )
        self.assertEqual(
            target["expected_proposed_policy_sha256"],
            sha256_bytes(
                (
                    ROOT
                    / ".governance/releases/v0.1.0/proposed-policy.json"
                ).read_bytes()
            ),
        )
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(encoding="utf-8")
        input_section = workflow.split("jobs:", 1)[0]
        self.assertNotIn("target_id:", input_section)
        self.assertIn("TARGET_ID: release-v0.1.0", input_section)
        self.assertNotIn("head_sha:", input_section)
        self.assertNotIn("target_repository:", input_section)
        self.assertNotIn("authority_repository:", input_section)
        self.assertIn(
            "AUTHORITY_REF: refs/heads/governance-authority", input_section
        )
        self.assertEqual(4, workflow.count("fetch-depth: 0"))
        deterministic_job = workflow.split(
            "  deterministic_evidence:", 1
        )[1].split("  fresh_context_review:", 1)[0]
        authority_checkout = deterministic_job.split(
            "Check out protected authority", 1
        )[1].split("Verify protected authority tree", 1)[0]
        self.assertIn("fetch-depth: 0", authority_checkout)
        for checkout, next_step in (
            (
                "Check out exact target candidate",
                "Verify actual target checkout identity",
            ),
            (
                "Check out exact target read-only candidate",
                "Verify actual review checkout identity",
            ),
            (
                "Check out exact target candidate",
                "Verify actual admission checkout identity",
            ),
        ):
            if next_step == "Verify actual admission checkout identity":
                section = workflow.rsplit(checkout, 1)[1].split(next_step, 1)[0]
            else:
                section = workflow.split(checkout, 1)[1].split(next_step, 1)[0]
            self.assertIn("fetch-depth: 0", section)

    def test_workflow_is_reusable_only_and_broker_has_bounded_triggers(self) -> None:
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(encoding="utf-8")
        trigger = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_call:", trigger)
        for forbidden in (
            "workflow_dispatch:",
            "schedule:",
            "pull_request:",
            "pull_request_target:",
            "repository_dispatch:",
            "workflow_run:",
        ):
            self.assertNotIn(forbidden, trigger)
        broker = (ROOT / ".governance/broker-templates/disposition.yml").read_text(
            encoding="utf-8"
        )
        broker_trigger = broker.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", broker_trigger)
        self.assertIn("schedule:", broker_trigger)
        self.assertIn(
            "github.event_name != 'schedule' || "
            "vars.GOVERNED_SCHEDULE_ENABLED == 'true'",
            broker,
        )
        self.assertNotIn("pull_request:", broker_trigger)
        self.assertNotIn("push:", broker_trigger)
        self.assertNotIn("OPENAI_API_KEY", workflow)
        self.assertIn("gpt-5.6-sol", workflow)
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, governed-reviewer-jit]",
            workflow,
        )
        self.assertIn("PYTHONPATH: authority/kernel/src", workflow)
        self.assertIn("observe_codex_authentication", workflow)
        self.assertIn('!= "chatgpt"', workflow)
        self.assertNotIn("path: governance", workflow)
        self.assertGreaterEqual(
            workflow.count(
                "--reviewer-prompt authority/kernel/.codex/review/reviewer.prompt.md"
            ),
            3,
        )
        self.assertIn(
            "--qualification-repository candidate/artifacts/governance/completion/evidence/context-qualification-authority",
            workflow,
        )
        self.assertIn(
            "--qualification-prompt authority/kernel/.codex/review/reviewer.prompt.md",
            workflow,
        )
        self.assertIn(
            "--authority-observation live-authority-observation.json",
            workflow,
        )
        self.assertIn("--authority-root authority", workflow)
        self.assertEqual(
            4,
            workflow.count(
                '--verified-decision-id "$VERIFIED_LABEL_DECISION_ID"'
            ),
        )

    def test_qualification_workflow_is_reusable_chatgpt_only_and_read_only(self) -> None:
        workflow = (ROOT / ".github/workflows/qualify-reviewer.yml").read_text(
            encoding="utf-8"
        )
        trigger = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_call:", trigger)
        for forbidden in (
            "workflow_dispatch:",
            "schedule:",
            "pull_request:",
            "pull_request_target:",
            "repository_dispatch:",
            "workflow_run:",
        ):
            self.assertNotIn(forbidden, trigger)
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, governed-reviewer-jit]",
            workflow,
        )
        self.assertIn(
            'test "$(codex login status 2>&1)" = "Logged in using ChatGPT"',
            workflow,
        )
        self.assertNotIn("OPENAI_API_KEY", workflow)
        self.assertNotIn("CODEX_API_KEY", workflow)
        self.assertIn("gpt-5.6-sol", workflow)
        self.assertIn("codex-cli 0.149.1", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("verify-bundle.py", workflow)
        self.assertIn(
            "github.repository == 'timaday/codex-governed-change-authority'",
            workflow,
        )
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.event.repository.private == true", workflow)
        self.assertNotIn("--require-private", workflow)
        self.assertLess(
            workflow.index("Verify live public authority ref"),
            workflow.index("Require exact ChatGPT-authenticated Codex identity"),
        )
        self.assertIn("run-qualification.py", workflow)
        self.assertIn("reviewer and context-profile corpus", workflow)
        self.assertIn('--actor "$GITHUB_ACTOR"', workflow)
        self.assertIn("qualification-results", workflow)
        self.assertIn("run-comparison.py", workflow)
        self.assertIn("paired-comparison-label-decision.schema.json", workflow)
        self.assertIn("--model gpt-5.6-sol", workflow)
        self.assertIn("--reasoning-effort xhigh", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("QUALIFICATION_OUTCOME", workflow)
        self.assertIn("COMPARISON_OUTCOME", workflow)
        self.assertEqual(1, workflow.count('--authority-sha "${{ job.workflow_sha }}"'))
        self.assertLess(workflow.index("Upload content-addressed qualification results"), workflow.index("Preserve fail-closed job result"))

    def test_reviewer_authentication_accepts_exact_combined_status(self) -> None:
        for output in (b"Logged in using ChatGPT\n", b"Logged in using ChatGPT\r\n"):
            with self.subTest(output=output):
                completed = subprocess.CompletedProcess(
                    ["codex", "login", "status"],
                    0,
                    stdout=output,
                    stderr=None,
                )
                with mock.patch.object(
                    reviewer_module.subprocess,
                    "run",
                    return_value=completed,
                ) as observed:
                    self.assertEqual(
                        "chatgpt",
                        reviewer_module.observe_codex_authentication("codex"),
                    )
                self.assertEqual(
                    subprocess.STDOUT,
                    observed.call_args.kwargs["stderr"],
                )

    def test_reviewer_authentication_rejects_nonexact_combined_status(self) -> None:
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "CODEX_HOME": "/portable/auth-root",
            "OPENAI_API_KEY": "must-not-cross",
        }
        invalid = (
            (0, b""),
            (0, b"Logged in using an API key\n"),
            (0, b"Logged in using ChatGPT\nextra\n"),
            (0, b"Logged in using ChatGPT\nLogged in using ChatGPT\n"),
            (1, b"Logged in using ChatGPT\n"),
        )
        for returncode, output in invalid:
            with self.subTest(returncode=returncode, output=output):
                completed = subprocess.CompletedProcess(
                    ["codex", "login", "status"],
                    returncode,
                    stdout=output,
                    stderr=None,
                )
                with mock.patch.object(
                    reviewer_module.subprocess,
                    "run",
                    return_value=completed,
                ) as observed, self.assertRaisesRegex(
                    RuntimeError, "not authenticated through ChatGPT"
                ):
                    reviewer_module.observe_codex_authentication(
                        "codex", environment=environment
                    )
                self.assertEqual(
                    subprocess.STDOUT,
                    observed.call_args.kwargs["stderr"],
                )
        sanitized = observed.call_args.kwargs["env"]
        self.assertNotIn("OPENAI_API_KEY", sanitized)
        self.assertEqual("/portable/auth-root", sanitized["CODEX_HOME"])

    def test_context_adapters_bind_only_the_authority_prompt(self) -> None:
        for name in ("prepare-context-sources.py", "prepare-review-inputs.py"):
            source = (CI / name).read_text(encoding="utf-8")
            self.assertIn('parser.add_argument("--reviewer-prompt"', source)
            self.assertNotIn(
                'repository / ".codex/review/reviewer.prompt.md"', source
            )
        deterministic = (CI / "prepare-deterministic-inputs.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'authority / "kernel/.codex/review/reviewer.prompt.md"',
            deterministic,
        )
        self.assertIn('schema_root=authority / "kernel/schemas"', deterministic)
        self.assertNotIn(
            'candidate / ".codex/review/reviewer.prompt.md"', deterministic
        )

    def test_initial_lkg_bootstrap_is_explicit_and_rollback_is_reconstructed(self) -> None:
        closeout = (CI / "prepare-closeout-inputs.py").read_text(encoding="utf-8")
        source = (CI / "bootstrap.py").read_text(encoding="utf-8")
        for required in (
            "validate_initial_bootstrap(",
            "evaluate_lkg_promotion(",
            '"mode": "initial_lkg_bootstrap"',
            '"lkg_bootstrap"',
            "verify_provenance_statement(",
            "validate_sandbox_capability(",
            "_raw_artifact(",
        ):
            self.assertIn(required, source)
        self.assertIn("validate_initial_bootstrap(", closeout)
        self.assertIn('f"session:{session_id}"', closeout)
        self.assertIn(
            'locator("governance-integrity", evidence / "promotion-verification.json")',
            closeout,
        )
        self.assertIn(
            'copy_json_once(authority_root / "MANIFEST.json", authority_manifest_path)',
            closeout,
        )
        self.assertIn(
            '("authority-manifest", authority_manifest_path)',
            closeout,
        )
        self.assertIn(
            '("authority-state", authority_state_path)',
            closeout,
        )
        self.assertIn("authority_state=authority_state", closeout)
        self.assertIn("authority_state_sha256=", closeout)
        self.assertIn("authority_state_sha256", source)
        self.assertIn(
            '("rollback-task", rollback_task_path)',
            closeout,
        )
        target = load_json(ROOT / ".governance/targets.json")["targets"][0]
        self.assertEqual("initial_lkg_bootstrap", target["governance_transition"]["mode"])
        self.assertFalse(target["governance_transition"]["reusable"])
        self.assertIn("authority-basis:", source)
        self.assertNotIn('f"authority:{authority_commit}"', source)
        rollback_gate = next(
            gate
            for gate in load_json(ROOT / ".governance/effective-policy.json")["gates"]
            if gate["gate_id"] == "initial-lkg-rollback-quality"
        )
        self.assertIn(
            "pycache_prefix=/tmp/rollback-pycache",
            " ".join(rollback_gate["command"]),
        )
        self.assertEqual(target["lkg_governance_commit"], rollback_gate["command"][-1])

    def test_production_manifest_adapter_reaches_assembler_and_evaluator(self) -> None:
        source = (CI / "prepare-manifest-input.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        assignment = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "manifest_input"
                for target in node.targets
            )
        )
        keys = {
            key.value
            for key in assignment.value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        signature = inspect.signature(assemble_evidence_manifest)
        required = {
            name
            for name, parameter in signature.parameters.items()
            if parameter.default is inspect.Parameter.empty
        }
        self.assertLessEqual(required, keys)
        self.assertLessEqual(
            {
                "context_sources",
                "context_projection",
                "context_qualification",
                "proposed_policy",
                "lkg_promotion_decision",
                "rollback_evidence",
                "initial_bootstrap_decision",
                "initial_bootstrap_verification",
            },
            keys,
        )
        digest = "sha256:" + "0" * 64
        reference = {"path": "evidence.json", "sha256": digest}
        sequence_names = {
            "authenticated_decisions",
            "evidence_locators",
            "sandbox_capabilities",
            "provenance_statements",
            "mutant_records",
            "rapid_review_executions",
            "rapid_review_context_execution_receipts",
            "oracle_references",
            "coverage_notes",
            "follow_ups",
            "rapid_review_charters",
            "rapid_review_sessions",
        }
        inputs = {
            name: (
                [reference]
                if name in sequence_names and name != "follow_ups"
                else ([] if name == "follow_ups" else reference)
            )
            for name in keys
            if name in signature.parameters
        }
        inputs.update(
            repository_id="repo:timaday/codex-governed-change",
            candidate_id=digest,
            required_gate_ids=["gate"],
            gate_references={"gate": reference},
            created_at="2026-09-03T00:00:00Z",
        )
        manifest = assemble_evidence_manifest(**inputs)
        schema = load_json(ROOT / "kernel/schemas/evidence-manifest.schema.json")
        self.assertEqual([], validate_instance(manifest, schema))
        self.assertEqual([], validate_semantics(manifest, "evidence-manifest"))
        partial_bootstrap = dict(manifest)
        partial_bootstrap.pop("initial_bootstrap_verification")
        partial_bootstrap = content_address(partial_bootstrap, "manifest_id")
        self.assertTrue(
            validate_semantics(partial_bootstrap, "evidence-manifest")
        )
        conflicting_modes = content_address(
            {**manifest, "lkg_policy_decision": reference}, "manifest_id"
        )
        self.assertIn(
            "$: initial-bootstrap manifests must not contain 'lkg_policy_decision'",
            validate_semantics(conflicting_modes, "evidence-manifest"),
        )
        normal_manifest = dict(manifest)
        normal_manifest["lkg_policy_decision"] = reference
        normal_manifest.pop("initial_bootstrap_decision")
        normal_manifest.pop("initial_bootstrap_verification")
        normal_manifest = content_address(normal_manifest, "manifest_id")
        self.assertEqual(
            [], validate_semantics(normal_manifest, "evidence-manifest")
        )
        state, reasons = evaluate_manifest(
            repository=ROOT,
            manifest=manifest,
            schema_root=ROOT / "kernel/schemas",
            protected_prompt_bytes=b"prompt",
            current_candidate={"candidate_id": digest},
            evaluated_at="2026-09-03T00:00:00Z",
        )
        self.assertEqual("UNKNOWN", state.value)
        self.assertEqual(["CURRENT_CANDIDATE_IDENTITY_INVALID"], reasons)

    def test_dispatch_authenticates_only_explicit_decisions(self) -> None:
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(
            encoding="utf-8"
        )
        trigger = workflow.split("permissions:", 1)[0]
        self.assertIn("approved_decision_ids:", trigger)
        self.assertIn("required: true", trigger)
        self.assertIn('--approved-decision-ids "$APPROVED_DECISION_IDS"', workflow)
        self.assertIn('--actor "$AUTHENTICATED_ACTOR"', workflow)
        self.assertIn('--event-name "$TRIGGER_EVENT"', workflow)
        broker = (ROOT / ".governance/broker-templates/disposition.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('default: "[]"', broker)
        self.assertNotIn("authenticated_actor:", broker)
        self.assertNotIn("trigger_event:", broker)
        self.assertIn("AUTHENTICATED_ACTOR: ${{ github.actor }}", workflow)
        self.assertIn("TRIGGER_EVENT: ${{ github.event_name }}", workflow)
        source = (CI / "prepare-deterministic-inputs.py").read_text(encoding="utf-8")
        self.assertIn('args.event_name == "schedule" and selected_ids', source)
        self.assertIn('release / "authorization-receipt.json"', source)
        self.assertIn('output / "authorization-receipt-proposal.json"', source)
        self.assertNotIn('for source in sorted((release / "decisions").glob("*.json")):\n        destination', source)

    def test_rollback_plan_binds_lkg_not_candidate_comparison_base(self) -> None:
        source = (CI / "prepare-deterministic-inputs.py").read_text(encoding="utf-8")
        self.assertIn(
            'rollback_plan.get("rollback_target_commit")\n        != target.get("lkg_governance_commit")',
            source,
        )
        self.assertIn(
            'rollback_task.get("base_commit") != target.get("lkg_governance_commit")',
            source,
        )

    def test_status_permission_is_not_used_to_publish_commit_statuses(self) -> None:
        python_sources = "\n".join(
            path.read_text(encoding="utf-8") for path in sorted(CI.glob("*.py"))
        )
        self.assertNotIn("/statuses/", python_sources)
        self.assertIn("/check-runs", (CI / "publish-check.py").read_text(encoding="utf-8"))
        self.assertIn("expected-source eligibility", (ROOT / "AGENTS.md").read_text())

    def test_rollback_task_is_profile_validated_before_execution(self) -> None:
        task = load_json(
            ROOT / ".governance/releases/v0.1.0/rollback-task-contract.json"
        )
        self.assertEqual([], validate_task_contract(task))
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(
            encoding="utf-8"
        )
        rollback = workflow.split("  rollback_rehearsal:", 1)[1].split(
            "  deterministic_evidence:", 1
        )[0]
        self.assertLess(
            rollback.index("scope \\"),
            rollback.index("run-gates \\"),
        )
        self.assertIn(
            "--task authority/.governance/releases/v0.1.0/rollback-task-contract.json",
            rollback,
        )

    def test_draft_qualification_records_are_explicitly_non_authorizing(self) -> None:
        policy = load_json(ROOT / ".governance/effective-policy.json")
        for mode, name in (
            ("conformance", "conformance.json"),
            ("rapid_review", "rapid-review.json"),
        ):
            record = load_json(
                ROOT / ".governance/releases/v0.1.0/qualification" / name
            )
            self.assertEqual(
                policy["reviewer"]["qualification_ids"][mode],
                record["qualification_id"],
            )
            self.assertTrue(record["human_labelled"])
            self.assertFalse(record["qualified"])
            self.assertEqual(
                reviewer_module.reviewer_launcher_sha256(),
                record["launcher_sha256"],
            )
            self.assertEqual(content_address(record, "qualification_id"), record)
            self.assertEqual(
                "UNKNOWN",
                qualification_module.reviewer_qualification_state(
                    {
                        field: record[field]
                        for field in qualification_module.REVIEWER_IDENTITY_FIELDS
                    },
                    record,
                    protected_qualification_id=record["qualification_id"],
                    protected_corpus_sha256=policy["reviewer"][
                        "qualification_corpus_sha256"
                    ],
                    protected_label_decision_id=policy["reviewer"][
                        "qualification_label_decision_id"
                    ],
                ).value,
            )

    def test_synthetic_context_records_are_explicitly_non_authorizing(self) -> None:
        policy = load_json(ROOT / ".governance/effective-policy.json")
        schema = load_json(
            ROOT / "kernel/schemas/context-qualification.schema.json"
        )
        for profile in ("COMPACT", "STANDARD", "DEEP"):
            record = load_json(
                ROOT / ".governance/context-qualifications" / f"{profile}.json"
            )
            self.assertEqual([], validate_instance(record, schema), profile)
            self.assertEqual(
                policy["context"]["qualification_ids"][profile],
                record["qualification_id"],
            )
            self.assertEqual("3.0.0", record["schema_version"])
            self.assertEqual("synthetic_bootstrap", record["evidence_class"])
            self.assertFalse(record["qualified"])
            self.assertFalse(record["candidate"]["disposition_correct"])
            self.assertEqual(content_address(record, "qualification_id"), record)

    def test_qualification_corpus_has_exact_human_approved_labels(self) -> None:
        corpus = load_json(
            ROOT / ".governance/releases/v0.1.0/qualification/corpus.json"
        )
        decision = load_json(
            ROOT
            / ".governance/releases/v0.1.0/qualification/human-label-decision.json"
        )
        self.assertTrue(corpus["human_labelled"])
        self.assertEqual(8, len(corpus["cases"]))
        self.assertEqual(
            ["BLOCK"] * 7 + ["NO_BLOCKING_FINDING_OBSERVED"],
            [case["expected_disposition"] for case in corpus["cases"]],
        )
        self.assertEqual(
            [case["case_id"] for case in corpus["cases"]],
            decision["approved_case_ids"],
        )
        self.assertEqual(
            corpus["corpus_id"], decision["approved_corpus_id"]
        )
        self.assertEqual(
            content_address(decision, "decision_id"), decision
        )

    def test_paired_comparison_inputs_are_protected_and_human_approved(self) -> None:
        comparison = ROOT / ".governance/releases/v0.1.0/comparison"
        corpus = load_json(comparison / "corpus.json")
        decision = load_json(comparison / "human-label-decision.json")
        self.assertEqual(
            [],
            validate_instance(
                corpus,
                load_json(
                    ROOT / "kernel/schemas/reviewer-qualification-corpus.schema.json"
                ),
            ),
        )
        self.assertEqual(
            [],
            validate_instance(
                decision,
                load_json(
                    ROOT
                    / ".governance/schemas/paired-comparison-label-decision.schema.json"
                ),
            ),
        )
        actor = str(decision["issuer"]["subject"]).removeprefix("github:")
        validate_comparison_inputs(
            corpus,
            decision,
            actor=actor,
            authority_repository="timaday/codex-governed-change",
            authority_ref="refs/heads/governance-authority",
            evaluated_at=str(decision["issued_at"]),
        )

    def test_qualification_adapter_scores_fail_closed(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "run_qualification", CI / "run-qualification.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            "BLOCK",
            module.classify_observed_disposition(
                "conformance", {"verdict": "BLOCK"}
            ),
        )
        self.assertEqual(
            "UNKNOWN",
            module.classify_observed_disposition(
                "conformance", {"verdict": "NO_BLOCKING_FINDING_OBSERVED"},
                execution_valid=False,
            ),
        )
        self.assertEqual(
            "BLOCK",
            module.classify_observed_disposition(
                "rapid_review",
                {
                    "status": "completed",
                    "findings": [{"severity": "critical"}],
                    "residual_risks": [],
                },
            ),
        )
        self.assertEqual(
            "BLOCK",
            module.classify_observed_disposition(
                "rapid_review",
                {
                    "status": "completed",
                    "findings": [],
                    "residual_risks": [{"material": True}],
                },
            ),
        )
        self.assertEqual(
            "NO_BLOCKING_FINDING_OBSERVED",
            module.classify_observed_disposition(
                "rapid_review",
                {
                    "status": "completed",
                    "findings": [],
                    "residual_risks": [{"material": False}],
                },
            ),
        )
        per_mode = {
            "critical_cases": 7,
            "critical_detected": 7,
            "false_passes": 0,
            "false_blocks": 0,
            "unknowns": 0,
            "traceable_cases": 7,
            "traceability_cases": 7,
            "tokens": 30,
        }
        combined = module._combine_context_metrics(
            {"conformance": per_mode, "rapid_review": per_mode}
        )
        self.assertEqual(1.0, combined["critical_recall"])
        self.assertEqual(1.0, combined["traceability"])
        self.assertTrue(combined["disposition_correct"])
        self.assertEqual(60, combined["tokens"])
        qualified = module._context_qualification_record(
            profile="COMPACT",
            baseline=combined,
            candidate=combined,
            created_at="2026-09-05T00:00:00Z",
            corpus_sha256="sha256:" + "1" * 64,
            label_decision_id="sha256:" + "2" * 64,
            measurement_evidence={"fixture": "typed references"},
        )
        self.assertEqual("empirical", qualified["evidence_class"])
        self.assertTrue(qualified["qualified"])
        self.assertEqual(content_address(qualified, "qualification_id"), qualified)
        degraded = dict(combined)
        degraded["critical_recall"] = 0.5
        blocked = module._context_qualification_record(
            profile="COMPACT",
            baseline=combined,
            candidate=degraded,
            created_at="2026-09-05T00:00:00Z",
            corpus_sha256="sha256:" + "1" * 64,
            label_decision_id="sha256:" + "2" * 64,
            measurement_evidence={"fixture": "typed references"},
        )
        self.assertFalse(blocked["qualified"])

    def test_context_variant_builder_keeps_bootstrap_non_authorizing(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "run_context_variant", CI / "run-qualification.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        corpus = load_json(
            ROOT / ".governance/releases/v0.1.0/qualification/corpus.json"
        )
        decision = load_json(
            ROOT
            / ".governance/releases/v0.1.0/qualification/human-label-decision.json"
        )
        prompt = ROOT / "kernel/.codex/review/reviewer.prompt.md"
        schema = ROOT / "kernel/schemas/reviewer-result.schema.json"
        identity = {
            "prompt_sha256": sha256_bytes(prompt.read_bytes()),
            "schema_sha256": sha256_bytes(schema.read_bytes()),
            "launcher_sha256": module.reviewer_launcher_sha256(),
            "codex_cli_version": "codex-cli 0.149.1",
            "authentication": "chatgpt",
            "model": "gpt-5.6-sol",
            "reasoning_effort": "xhigh",
        }
        bootstrap = qualification_module.bootstrap_qualification_record(
            identity=identity,
            corpus_sha256=sha256_bytes(canonical_bytes(corpus)),
            label_decision_id=decision["decision_id"],
        )
        with tempfile.TemporaryDirectory() as directory:
            prepared = module._prepare_case(
                root=Path(directory),
                case=corpus["cases"][-1],
                mode="conformance",
                prompt_path=prompt,
                schema_path=schema,
                bootstrap=bootstrap,
                requested_profile="COMPACT",
            )
        context = prepared["preliminary_context"]
        self.assertEqual("COMPACT", context["context_projection"]["profile"])
        self.assertEqual(
            "COMPACT", context["context_sources"]["requested_profile"]
        )
        self.assertEqual(
            "synthetic_bootstrap",
            context["context_qualification"]["evidence_class"],
        )
        self.assertFalse(context["context_qualification"]["qualified"])

    def test_every_action_is_full_sha_pinned(self) -> None:
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
        self.assertGreaterEqual(len(uses), 10)
        for reference in uses:
            self.assertRegex(reference, r"^[^@]+@[0-9a-f]{40}$")

    def test_app_secret_is_isolated_to_initializer_and_final_publisher(self) -> None:
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(encoding="utf-8")
        initializer, after_initializer = workflow.split("  resolve_target:", 1)
        before_publisher, publisher = after_initializer.split("  publish_disposition:", 1)
        self.assertIn("secrets.disposition_app_private_key", initializer)
        self.assertNotIn("secrets.disposition_app_private_key", before_publisher)
        self.assertNotIn("GITHUB_APP_TOKEN", initializer)
        self.assertNotIn("GITHUB_APP_TOKEN", before_publisher)
        self.assertIn("secrets.disposition_app_private_key", publisher)
        self.assertEqual(2, workflow.count("secrets.disposition_app_private_key"))
        self.assertIn("permission-checks: write", publisher)
        self.assertIn("permission-statuses: write", publisher)
        self.assertIn("permission-contents: read", publisher)
        self.assertNotIn("permission-pull-requests: write", publisher)
        self.assertNotIn("environment:", publisher)
        self.assertLess(
            publisher.index("Validate publication before credential creation"),
            publisher.index("secrets.disposition_app_private_key"),
        )
        self.assertIn("artifact-ids:", workflow)
        self.assertNotIn("name: disposition-publication\n          path: publication", publisher)

    def test_rulesets_have_no_bypass_and_target_starts_disabled(self) -> None:
        authority = load_json(ROOT / "rulesets/authority-ref.ruleset.json")
        reviewed = load_json(
            ROOT / "rulesets/authority-ref-reviewed.ruleset.json"
        )
        target = load_json(ROOT / "rulesets/target-main.ruleset.template.json")
        self.assertEqual([], authority["bypass_actors"])
        self.assertEqual("active", authority["enforcement"])
        self.assertEqual([], reviewed["bypass_actors"])
        reviewed_pull_request = next(
            rule for rule in reviewed["rules"] if rule["type"] == "pull_request"
        )
        self.assertEqual(
            1,
            reviewed_pull_request["parameters"]["required_approving_review_count"],
        )
        self.assertFalse(
            reviewed_pull_request["parameters"]["require_code_owner_review"]
        )
        self.assertTrue(
            reviewed_pull_request["parameters"]["require_last_push_approval"]
        )
        self.assertEqual([], target["bypass_actors"])
        self.assertEqual("disabled", target["enforcement"])
        checks = [rule for rule in target["rules"] if rule["type"] == "required_status_checks"]
        self.assertEqual(1, len(checks))
        self.assertEqual(
            "__GITHUB_APP_INTEGRATION_ID__",
            checks[0]["parameters"]["required_status_checks"][0]["integration_id"],
        )

    def test_private_broker_scopes_secret_and_publication_inputs(self) -> None:
        broker = load_json(ROOT / ".governance/private-broker.json")
        self.assertEqual("private", broker["required_visibility"])
        self.assertEqual(
            ["DISPOSITION_APP_PRIVATE_KEY"], broker["repository_secrets"]
        )
        self.assertEqual(
            ["DISPOSITION_APP_ID", "GOVERNED_SCHEDULE_ENABLED"],
            broker["repository_variables"],
        )
        self.assertEqual(
            "target_repository_only",
            broker["credential_constraints"]["github_app_installation"],
        )
        self.assertTrue(broker["credential_constraints"]["publisher_only"])
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(encoding="utf-8")
        publisher = workflow.split("  publish_disposition:", 1)[1]
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("publication_artifact_id", workflow)
        self.assertIn("publication_artifact_digest", workflow)
        for expression in (
            "needs.rollback_rehearsal.outputs.artifact_digest",
            "needs.deterministic_evidence.outputs.artifact_digest",
            "needs.fresh_context_review.outputs.artifact_digest",
            "needs.admission.outputs.publication_artifact_digest",
            "needs.resolve_target.outputs.fallback_artifact_digest",
        ):
            self.assertIn(expression, workflow)
        self.assertEqual(4, workflow.count("verify-artifact-metadata.py"))
        self.assertGreaterEqual(workflow.count("verify-live-authority-ref.py"), 2)
        self.assertGreaterEqual(
            workflow.count('--authority-sha "${{ job.workflow_sha }}"'), 4
        )
        self.assertIn("PUBLICATION_ADMISSION_RESULT:", publisher)
        self.assertIn("PUBLICATION_ARTIFACT_ID:", publisher)
        self.assertIn("needs.resolve_target.outputs.fallback_artifact_id", publisher)
        self.assertEqual(2, publisher.count("--admission-result"))
        self.assertEqual(2, publisher.count("--app-id"))
        self.assertEqual(2, publisher.count("--check-run-id"))
        publisher_source = (CI / "publish-check.py").read_text(encoding="utf-8")
        self.assertIn('check.get("conclusion") == "success"', publisher_source)
        self.assertIn('method="PATCH"', publisher_source)
        self.assertIn("GH_API_TOKEN: ${{ github.token }}", publisher)

    def test_failed_skipped_or_cancelled_prerequisites_select_only_failure_payload(self) -> None:
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(
            encoding="utf-8"
        )
        before_publisher, publisher = workflow.split("  publish_disposition:", 1)
        resolve, admission = before_publisher.split("  admission:", 1)
        self.assertIn("if: always() && needs.resolve_target.result == 'success'", admission)
        prerequisite_guard = (
            "needs.rollback_rehearsal.result == 'success' && "
            "needs.deterministic_evidence.result == 'success' && "
            "needs.fresh_context_review.result == 'success'"
        )
        self.assertGreaterEqual(admission.count(prerequisite_guard), 3)
        self.assertIn("--fallback-reason ADMISSION_PREREQUISITE_UNSUCCESSFUL", admission)
        self.assertIn("if: always()", admission.split("Upload publication payload", 1)[1])
        self.assertIn("steps.reconstruct.outcome != 'success'", admission)
        self.assertIn("Initialize downstream fail-closed publication", resolve)
        self.assertIn("Upload downstream fail-closed publication", resolve)
        self.assertIn("fallback_artifact_id:", resolve)
        self.assertIn("fallback_artifact_digest:", resolve)
        self.assertIn("initialize_disposition:", resolve)
        self.assertLess(
            resolve.index("Create immutable-target failure sentinel before checkout"),
            resolve.index("Check out protected authority"),
        )
        self.assertIn("needs.resolve_target.outputs.fallback_artifact_id != ''", publisher)
        self.assertIn("needs.resolve_target.outputs.fallback_artifact_digest != ''", publisher)
        self.assertIn("needs.admission.result == 'success'", publisher)
        self.assertIn("needs.initialize_disposition.outputs.check_run_id", publisher)
        self.assertIn("|| needs.resolve_target.outputs.fallback_artifact_id", publisher)
        self.assertIn("if: env.PUBLICATION_ADMISSION_RESULT != 'success'", publisher)

        finalizer = (ROOT / ".github/workflows/finalize-disposition.yml").read_text(
            encoding="utf-8"
        )
        finalizer_trigger = finalizer.split("permissions:", 1)[0]
        self.assertIn("workflow_call:", finalizer_trigger)
        self.assertNotIn("workflow_run:", finalizer_trigger)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", finalizer)
        self.assertIn("github.event.workflow_run.status == 'completed'", finalizer)
        self.assertNotIn("inputs.source_run_", finalizer)
        self.assertIn("--finalize-completed-success", finalizer)
        self.assertIn("--admission-result success", finalizer)
        self.assertIn("merge-multiple: true", finalizer)
        self.assertNotIn("--check-run-id", finalizer)
        broker_finalizer = (
            ROOT / ".governance/broker-templates/finalize-disposition.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_run:", broker_finalizer)
        self.assertIn('workflows: ["Governed disposition broker"]', broker_finalizer)
        self.assertIn(
            "github.event.workflow_run.conclusion == 'success'", broker_finalizer
        )
        self.assertIn(
            "github.event.workflow_run.status == 'completed'", broker_finalizer
        )

    def test_workflow_authority_inputs_use_descriptor_bound_observations(self) -> None:
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", workflow)
        self.assertNotIn(".read_bytes(", workflow)
        self.assertNotIn(".is_file(", workflow)
        self.assertGreaterEqual(workflow.count("from common import"), 6)

    def test_initializer_is_bound_to_the_only_protected_target(self) -> None:
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(
            encoding="utf-8"
        )
        target = load_json(ROOT / ".governance/targets.json")["targets"][0]
        initializer = workflow.split("  resolve_target:", 1)[0]
        self.assertIn(
            f"INITIAL_TARGET_REPOSITORY: {target['repository']}", initializer
        )
        self.assertIn(f"INITIAL_TARGET_HEAD: {target['head_sha']}", initializer)
        self.assertIn("conclusion: 'failure'", initializer)
        self.assertIn("status: 'completed'", initializer)
        self.assertNotIn("actions/checkout", initializer)

    def test_public_bundle_contains_no_machine_or_secret_material(self) -> None:
        fragments = (
            "".join(("/", "home", "/")),
            "".join(("/", "Users", "/")),
            "".join(("C:", "\\", "Users", "\\")),
            "".join(("local", "host")),
            ".".join(("127", "0", "0", "1")),
            "Idea" + "Projects",
            ".codex/" + "attachments",
            "file" + "://",
        )
        secret_patterns = (
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
            re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
        )
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            value = path.read_text(encoding="utf-8")
            for fragment in fragments:
                self.assertNotIn(fragment, value, path.as_posix())
            for pattern in secret_patterns:
                self.assertIsNone(pattern.search(value), path.as_posix())


class AdapterTests(unittest.TestCase):
    def _comparison_fixture(self) -> tuple[dict[str, object], dict[str, object]]:
        cases: list[dict[str, object]] = []
        labels: dict[str, str] = {}
        for index, (classes, disposition) in enumerate(
            (
                (["seeded_defect"], "BLOCK"),
                (["seeded_defect", "prompt_injection"], "BLOCK"),
                (["clean_control"], "NO_BLOCKING_FINDING_OBSERVED"),
                (["clean_control"], "NO_BLOCKING_FINDING_OBSERVED"),
            ),
            start=1,
        ):
            case_id = f"C-{index}"
            expected = (
                {
                    "defect_id": f"DEFECT-{index}",
                    "path": "src/example.py",
                    "line": index,
                }
                if disposition == "BLOCK"
                else None
            )
            cases.append(
                {
                    "case_id": case_id,
                    "case_classes": classes,
                    "severity": "critical" if expected else "control",
                    "requirement_id": "GOV-001",
                    "expected_finding": expected,
                    "expected_disposition": disposition,
                    "risk": "bounded risk",
                    "charter": "review the bounded candidate",
                    "files": {"src/example.py": "pass\n"},
                }
            )
            labels[case_id] = disposition
        corpus = content_address(
            {
                "schema_version": "3.0.0",
                "corpus_name": "held-out paired comparison",
                "human_labelled": True,
                "cases": cases,
            },
            "corpus_id",
        )
        issuer = {
            "subject": "github:reviewer",
            "authentication_method": "github-actions-workflow-dispatch",
            "protected_source": (
                "timaday/codex-governed-change@refs/heads/governance-authority"
            ),
        }
        decision = content_address(
            {
                "schema_version": "1.0.0",
                "repository_id": "repo:timaday/codex-governed-change",
                "decision_type": "paired_comparison_labels",
                "approved_corpus_id": corpus["corpus_id"],
                "approved_case_ids": [item["case_id"] for item in cases],
                "approved_labels": labels,
                "approved_arms": ["governed", "ordinary"],
                "issuer": issuer
                | {"assertion_sha256": sha256_bytes(canonical_bytes(issuer))},
                "issued_at": "2026-09-05T10:00:00Z",
                "expires_at": "2026-09-06T10:00:00Z",
            },
            "decision_id",
        )
        return corpus, decision

    def _comparison_artifacts(
        self, case: dict[str, object], arm: str
    ) -> tuple[dict[str, dict[str, str]], dict[str, bytes]]:
        disposition = str(case["expected_disposition"])
        expected = case["expected_finding"]
        findings = (
            [
                {
                    "requirement_id": case["requirement_id"],
                    "path": expected["path"],
                    "line": expected["line"],
                }
            ]
            if isinstance(expected, dict)
            else []
        )
        result = {
            "findings": findings,
            "verdict" if arm == "governed" else "disposition": disposition,
        }
        result_bytes = canonical_bytes(result)
        event = canonical_bytes(
            {"type": "thread.started", "thread_id": "comparison-thread"}
        ) + b"\n" + canonical_bytes(
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": result_bytes.decode()},
            }
        ) + b"\n" + canonical_bytes(
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 2,
                    "output_tokens": 3,
                    "reasoning_output_tokens": 1,
                },
            }
        ) + b"\n"
        prefix = f"comparison/{arm}/{case['case_id']}"
        raw = {
            "result": result_bytes,
            "stdout": event,
            "stderr": b"",
        }
        refs = {
            name: {
                "path": f"{prefix}/{name}.bin",
                "sha256": sha256_bytes(data),
            }
            for name, data in raw.items()
        }
        primitive: dict[str, object]
        if arm == "governed":
            source_execution = content_address(
                {
                    "reviewer_output_sha256": refs["result"]["sha256"],
                    "stdout_sha256": refs["stdout"]["sha256"],
                    "stderr_sha256": refs["stderr"]["sha256"],
                    "execution_valid": True,
                    "input_tokens": 10,
                    "cached_input_tokens": 2,
                    "output_tokens": 3,
                    "reasoning_output_tokens": 1,
                    "latency_ms": 25,
                },
                "execution_id",
            )
            primitive = {"reviewer_execution": source_execution}
        else:
            primitive = {
                "return_code": 0,
                "timed_out": False,
                "stdin_complete": True,
                "output_present": True,
                "output_valid": True,
                "stdout_complete": True,
                "stderr_complete": True,
                "process_cleanup_complete": True,
                "output_truncated": False,
                "ambiguous_redaction": False,
                "candidate_unchanged": True,
            }
        execution = content_address(
            {
                "schema_version": "1.0.0",
                "case_id": case["case_id"],
                "case_sha256": sha256_bytes(canonical_bytes(case)),
                "arm": arm,
                "result_sha256": refs["result"]["sha256"],
                "stdout_sha256": refs["stdout"]["sha256"],
                "stderr_sha256": refs["stderr"]["sha256"],
                "execution_valid": True,
                "usage_observed": True,
                "input_tokens": 10,
                "cached_input_tokens": 2,
                "output_tokens": 3,
                "reasoning_output_tokens": 1,
                "elapsed_ms": 25,
                "primitive": primitive,
            },
            "execution_id",
        )
        raw["execution"] = canonical_bytes(execution)
        refs["execution"] = {
            "path": f"{prefix}/execution.json",
            "sha256": sha256_bytes(raw["execution"]),
        }
        return refs, {refs[name]["path"]: data for name, data in raw.items()}

    def test_paired_comparison_reconstructs_metrics_and_is_non_authorizing(self) -> None:
        corpus, decision = self._comparison_fixture()
        validate_comparison_inputs(
            corpus,
            decision,
            actor="reviewer",
            authority_repository="timaday/codex-governed-change",
            authority_ref="refs/heads/governance-authority",
            evaluated_at="2026-09-05T12:00:00Z",
        )
        stored: dict[str, bytes] = {}
        arms: dict[str, list[dict[str, object]]] = {"governed": [], "ordinary": []}
        for arm in arms:
            for case in corpus["cases"]:
                refs, artifacts = self._comparison_artifacts(case, arm)
                stored.update(artifacts)
                arms[arm].append(
                    reconstruct_task(
                        arm=arm,
                        case=case,
                        artifacts=refs,
                        artifact_reader=lambda ref: stored[ref["path"]],
                    )
                )
        document = build_comparison_document(
            corpus=corpus,
            decision=decision,
            identity={
                "model": "gpt-5.6-sol",
                "reasoning_effort": "xhigh",
                "governed_profile": "STANDARD",
                "codex_cli_version": "codex-cli 0.149.1",
                "authentication": "chatgpt",
                "governed_prompt_sha256": "sha256:" + "1" * 64,
                "governed_schema_sha256": "sha256:" + "2" * 64,
                "ordinary_schema_sha256": "sha256:" + "3" * 64,
                "ordinary_prompt_version": "1.0.0",
                "same_case_bytes": True,
                "labels_excluded_from_prompts": True,
                "execution_controls": "matched_sanitized_read_only",
                "authority_repository": "timaday/codex-governed-change",
                "authority_ref": "refs/heads/governance-authority",
                "authority_sha": "a" * 40,
                "workflow_run_id": "123",
                "workflow_attempt": 1,
            },
            governed_tasks=arms["governed"],
            ordinary_tasks=arms["ordinary"],
            created_at="2026-09-05T12:10:00Z",
        )
        self.assertFalse(document["admission_authority"])
        self.assertEqual(4, document["arms"]["governed"]["aggregate"]["correct_completions"])
        self.assertEqual(
            [],
            validate_instance(
                document,
                load_json(ROOT / ".governance/schemas/paired-comparison.schema.json"),
            ),
        )
        self.assertTrue(
            comparison_document_valid(
                document,
                corpus=corpus,
                decision=decision,
                expected_identity=document["identity"],
                artifact_reader=lambda ref: stored[ref["path"]],
            )
        )
        effort = content_address(
            {
                "schema_version": "1.0.0",
                "comparison_id": document["comparison_id"],
                "recorded_by": "github:reviewer",
                "issuer": {
                    "subject": "github:reviewer",
                    "authentication_method": "github-actions-workflow-dispatch",
                    "protected_source": "timaday/codex-governed-change@refs/heads/governance-authority",
                    "assertion_sha256": "sha256:598222f8f154d947dd8bad2dc1f31a595d1dde784223a6490731b6551de7328e",
                },
                "measurement_method": "human_self_report",
                "governed": {"review_minutes": 3.5, "operation_minutes": 2},
                "ordinary": {"review_minutes": 4, "operation_minutes": 1},
                "recorded_at": "2026-09-05T12:15:00Z",
                "limitations": ["single human self-report"],
                "admission_authority": False,
            },
            "effort_id",
        )
        self.assertTrue(
            human_effort_record_valid(effort, comparison=document, actor="reviewer")
        )
        self.assertEqual(
            [],
            validate_instance(
                effort,
                load_json(
                    ROOT
                    / ".governance/schemas/paired-comparison-human-effort.schema.json"
                ),
            ),
        )
        tampered = deepcopy(document)
        tampered["arms"]["ordinary"]["tasks"][0]["correct_completion"] = False
        tampered = content_address(tampered, "comparison_id")
        self.assertFalse(
            comparison_document_valid(
                tampered,
                corpus=corpus,
                decision=decision,
                expected_identity=document["identity"],
                artifact_reader=lambda ref: stored[ref["path"]],
            )
        )

    def test_paired_comparison_wrong_finding_is_not_correct(self) -> None:
        corpus, _decision = self._comparison_fixture()
        case = corpus["cases"][0]
        task = score_task(
            arm="ordinary",
            case=case,
            observed_disposition="BLOCK",
            findings=[
                {
                    "requirement_id": case["requirement_id"],
                    "path": case["expected_finding"]["path"],
                    "line": case["expected_finding"]["line"] + 1,
                }
            ],
            usage={name: 0 for name in (
                "input_tokens", "cached_input_tokens", "output_tokens", "reasoning_output_tokens"
            )},
            usage_complete=True,
            elapsed_ms=0,
            artifacts={
                name: {"path": f"comparison/ordinary/C-1/{name}.bin", "sha256": "sha256:" + "0" * 64}
                for name in ("result", "execution", "stdout", "stderr")
            },
        )
        self.assertFalse(task["correct_completion"])

    def test_paired_comparison_rejects_double_countable_reasoning_usage(self) -> None:
        corpus, _decision = self._comparison_fixture()
        with self.assertRaisesRegex(ValueError, "reasoning output exceeds"):
            score_task(
                arm="ordinary",
                case=corpus["cases"][0],
                observed_disposition="BLOCK",
                findings=[
                    {
                        "requirement_id": "GOV-001",
                        "path": "src/example.py",
                        "line": 1,
                    }
                ],
                usage={
                    "input_tokens": 4,
                    "cached_input_tokens": 1,
                    "output_tokens": 1,
                    "reasoning_output_tokens": 2,
                },
                usage_complete=True,
                elapsed_ms=1,
                artifacts={
                    name: {
                        "path": f"comparison/ordinary/H-TASK-001/{name}.bin",
                        "sha256": "sha256:" + "1" * 64,
                    }
                    for name in ("result", "execution", "stdout", "stderr")
                },
            )

    def test_paired_comparison_rejects_readdressed_primitive_and_machine_value(self) -> None:
        corpus, decision = self._comparison_fixture()
        stored: dict[str, bytes] = {}
        arms: dict[str, list[dict[str, object]]] = {"governed": [], "ordinary": []}
        refs_by_arm: dict[str, list[dict[str, dict[str, str]]]] = {
            "governed": [],
            "ordinary": [],
        }
        for arm in arms:
            for case in corpus["cases"]:
                refs, artifacts = self._comparison_artifacts(case, arm)
                refs_by_arm[arm].append(refs)
                stored.update(artifacts)
                arms[arm].append(
                    reconstruct_task(
                        arm=arm,
                        case=case,
                        artifacts=refs,
                        artifact_reader=lambda ref: stored[ref["path"]],
                    )
                )
        document = build_comparison_document(
            corpus=corpus,
            decision=decision,
            identity={"model": "gpt-5.6-sol"},
            governed_tasks=arms["governed"],
            ordinary_tasks=arms["ordinary"],
            created_at="2026-09-05T12:10:00Z",
        )
        execution_ref = refs_by_arm["ordinary"][0]["execution"]
        execution = json.loads(stored[execution_ref["path"]])
        execution["primitive"]["return_code"] = 9
        execution["execution_id"] = content_address(execution, "execution_id")["execution_id"]
        stored[execution_ref["path"]] = canonical_bytes(execution)
        execution_ref["sha256"] = sha256_bytes(stored[execution_ref["path"]])
        document["arms"]["ordinary"]["tasks"][0]["artifacts"]["execution"] = execution_ref
        document = content_address(document, "comparison_id")
        self.assertFalse(
            comparison_document_valid(
                document,
                corpus=corpus,
                decision=decision,
                expected_identity=document["identity"],
                artifact_reader=lambda ref: stored[ref["path"]],
            )
        )
        fresh_refs, fresh_artifacts = self._comparison_artifacts(
            corpus["cases"][0], "ordinary"
        )
        stored.update(fresh_artifacts)
        document["arms"]["ordinary"]["tasks"][0]["artifacts"] = fresh_refs
        shaped_ref = document["arms"]["ordinary"]["tasks"][1]["artifacts"]["stderr"]
        stored[shaped_ref["path"]] = b"/" + b"home" + b"/specific-user/private\n"
        shaped_ref["sha256"] = sha256_bytes(stored[shaped_ref["path"]])
        document = content_address(document, "comparison_id")
        self.assertFalse(
            comparison_document_valid(
                document,
                corpus=corpus,
                decision=decision,
                expected_identity=document["identity"],
                artifact_reader=lambda ref: stored[ref["path"]],
            )
        )

    def test_ordinary_comparison_prompt_is_label_blind_and_identity_fixed(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "run_comparison", CI / "run-comparison.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        corpus, _decision = self._comparison_fixture()
        case = corpus["cases"][0]
        prompt = module._ordinary_prompt(case)
        self.assertNotIn(str(case["expected_disposition"]), prompt)
        self.assertNotIn(str(case["expected_finding"]["defect_id"]), prompt)
        self.assertIn(str(case["requirement_id"]), prompt)
        command = module._ordinary_command(
            codex="codex",
            candidate=Path("candidate"),
            schema=Path("schema.json"),
            result=Path("result.json"),
            permission_profile="permissions-for-bounded-workspace",
        )
        self.assertIn("gpt-5.6-sol", command)
        self.assertIn('model_reasoning_effort="xhigh"', command)
        self.assertIn("read-only", command)
        self.assertIn('default_permissions="governed_reviewer"', command)
        self.assertIn("permissions-for-bounded-workspace", command)

    def test_ordinary_comparison_adapter_retains_reconstructable_evidence(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "run_comparison_adapter", CI / "run-comparison.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        corpus, _decision = self._comparison_fixture()
        case = corpus["cases"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fake-codex"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import json, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "if args == ['login', 'status']:\n"
                "    print('Logged in using ChatGPT')\n"
                "    raise SystemExit(0)\n"
                "output = pathlib.Path(args[args.index('--output-last-message') + 1])\n"
                "payload = {'disposition': 'BLOCK', 'findings': [{"
                "'requirement_id': 'GOV-001', 'path': 'src/example.py', 'line': 1}]}\n"
                "text = json.dumps(payload, sort_keys=True, separators=(',', ':'))\n"
                "output.write_text(text)\n"
                "events = ["
                "{'type': 'thread.started', 'thread_id': 'ordinary-thread'},"
                "{'type': 'item.completed', 'item': {'type': 'agent_message', 'text': text}},"
                "{'type': 'turn.completed', 'usage': {'input_tokens': 7, "
                "'cached_input_tokens': 1, 'output_tokens': 2, "
                "'reasoning_output_tokens': 1}}]\n"
                "for event in events: print(json.dumps(event, sort_keys=True, separators=(',', ':')))\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            with mock.patch.object(
                module,
                "resolve_reviewer_runtime_read_roots",
                return_value=(Path("/opt/codex-runtime"),),
            ):
                task = module._run_ordinary_case(
                    case=case,
                    codex=str(executable),
                    authentication="chatgpt",
                    schema_path=ROOT / ".governance/schemas/paired-comparison-result.schema.json",
                    timeout_seconds=5,
                    max_output_bytes=100_000,
                    output=root / "evidence",
                )
            self.assertTrue(task["correct_completion"])
            self.assertFalse(task["accepted_defect"])
            self.assertFalse(task["unknown"])
            self.assertEqual(9, task["total_tokens"])

    def test_ordinary_comparison_timeout_is_retained_unknown(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "run_comparison_timeout", CI / "run-comparison.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        corpus, _decision = self._comparison_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "slow-codex"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import sys, time\n"
                "if sys.argv[1:] == ['login', 'status']:\n"
                "    print('Logged in using ChatGPT')\n"
                "    raise SystemExit(0)\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            with mock.patch.object(
                module,
                "resolve_reviewer_runtime_read_roots",
                return_value=(Path("/opt/codex-runtime"),),
            ):
                task = module._run_ordinary_case(
                    case=corpus["cases"][0],
                    codex=str(executable),
                    authentication="chatgpt",
                    schema_path=ROOT / ".governance/schemas/paired-comparison-result.schema.json",
                    timeout_seconds=0.05,
                    max_output_bytes=100_000,
                    output=root / "evidence",
                )
            self.assertEqual("UNKNOWN", task["observed_disposition"])
            self.assertTrue(task["unknown"])
            self.assertFalse(task["correct_completion"])

    def test_ordinary_comparison_bounds_streams_while_the_process_runs(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "run_comparison_bounded", CI / "run-comparison.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertNotIn(".communicate(", inspect.getsource(module._run_ordinary_case))
        corpus, _decision = self._comparison_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "noisy-codex"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import json, pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "if args == ['login', 'status']:\n"
                "    print('Logged in using ChatGPT')\n"
                "    raise SystemExit(0)\n"
                "output = pathlib.Path(args[args.index('--output-last-message') + 1])\n"
                "payload = {'disposition': 'BLOCK', 'findings': [{"
                "'requirement_id': 'GOV-001', 'path': 'src/example.py', 'line': 1}]}\n"
                "text = json.dumps(payload, sort_keys=True, separators=(',', ':'))\n"
                "output.write_text(text)\n"
                "print(json.dumps({'type': 'thread.started', 'thread_id': 'ordinary-thread'}))\n"
                "print(json.dumps({'type': 'item.completed', 'item': {"
                "'type': 'agent_message', 'text': text}}))\n"
                "print(json.dumps({'type': 'turn.completed', 'usage': {"
                "'input_tokens': 7, 'cached_input_tokens': 1, 'output_tokens': 2, "
                "'reasoning_output_tokens': 1}}))\n"
                "sys.stdout.write('x' * 100000)\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            evidence = root / "evidence"
            with mock.patch.object(
                module,
                "resolve_reviewer_runtime_read_roots",
                return_value=(Path("/opt/codex-runtime"),),
            ):
                task = module._run_ordinary_case(
                    case=corpus["cases"][0],
                    codex=str(executable),
                    authentication="chatgpt",
                    schema_path=ROOT / ".governance/schemas/paired-comparison-result.schema.json",
                    timeout_seconds=5,
                    max_output_bytes=1024,
                    output=evidence,
                )
            retained_stdout = evidence.joinpath(
                *task["artifacts"]["stdout"]["path"].split("/")
            ).read_bytes()
            self.assertLessEqual(len(retained_stdout), 1024)
            self.assertEqual("UNKNOWN", task["observed_disposition"])
            self.assertTrue(task["unknown"])

    def _assert_real_lingering_reviewer_stream_is_unknown(self, held: str) -> None:
        candidate_id = "sha256:" + "a" * 64
        digest = "sha256:" + "b" * 64
        payload = {
            "schema_version": "2.0.0",
            "repository_id": "repo:example/project",
            "candidate_id": candidate_id,
            "task_contract_sha256": digest,
            "effective_policy_sha256": digest,
            "gate_manifest_sha256": digest,
            "context_receipt_sha256": digest,
            "reviewer_prompt_sha256": digest,
            "qualification_id": digest,
            "model": "fake-gpt",
            "invocation_id": f"retained-{held}",
            "verdict": "NO_BLOCKING_FINDING_OBSERVED",
            "reviewed_surfaces": ["candidate"],
            "affected_closure": ["candidate"],
            "retrieval_expansions": [],
            "findings": [],
            "missing_evidence": [],
            "claims": [],
            "limitations": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "retained-stream.py"
            output = root / "reviewer-result.json"
            process_info = root / "process.json"
            script.write_text(
                "import json, os, sys, time\n"
                "from pathlib import Path\n"
                f"payload = {payload!r}\n"
                "output, process_info, held = map(Path, sys.argv[1:4])\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    os.close(2 if held.name == 'stdout' else 1)\n"
                "    time.sleep(60)\n"
                "    os._exit(0)\n"
                "process_info.write_text(json.dumps({'pid': child, 'pgid': os.getpgrp()}))\n"
                "output.write_text(json.dumps(payload))\n"
                "print(json.dumps({'type': 'thread.started', 'thread_id': 'retained-pipe'}))\n"
                "print(json.dumps({'type': 'turn.completed', 'usage': {"
                "'input_tokens': 1, 'cached_input_tokens': 0, 'output_tokens': 1, "
                "'reasoning_output_tokens': 0}}))\n",
                encoding="utf-8",
            )
            actual_popen = reviewer_module.subprocess.Popen
            processes: list[tuple[object, tuple[object, ...], dict[str, object]]] = []

            def capture_process(*args: object, **kwargs: object) -> object:
                process = actual_popen(*args, **kwargs)
                processes.append((process, tuple(args), dict(kwargs)))
                return process

            with mock.patch.object(
                reviewer_module.subprocess, "Popen", side_effect=capture_process
            ):
                result = reviewer_module.launch_reviewer(
                    command=[
                        sys.executable,
                        str(script),
                        str(output),
                        str(process_info),
                        held,
                        "-",
                    ],
                    stdin_text="review",
                    schema_path=ROOT / "kernel/schemas/reviewer-result.schema.json",
                    output_path=output,
                    expected_candidate_id=candidate_id,
                    candidate_supplier=lambda _deadline: candidate_id,
                    timeout_seconds=10,
                    environment={},
                )
            review_processes = [
                process
                for process, arguments, _options in processes
                if arguments
                and isinstance(arguments[0], list)
                and any(
                    str(item).endswith("reviewer_supervisor.py")
                    for item in arguments[0]
                )
            ]
            self.assertEqual(1, len(review_processes))
            review_process = review_processes[0]
            self.assertIsNotNone(review_process.stdout)
            self.assertIsNotNone(review_process.stderr)
            self.assertTrue(review_process.stdout.closed)
            self.assertTrue(review_process.stderr.closed)
            self.assertEqual("UNKNOWN", result["verdict"])
            self.assertFalse(result["execution_valid"])
            self.assertFalse(result["observation_complete"])
            self.assertTrue(result["capture_threads_completed"])
            self.assertIn("pid", load_json(process_info))
            group = review_process.pid
            if not gate_module._posix_process_group_exited(
                group, 1.0, allow_zombie_only=True
            ):
                self.fail("retained reviewer process group survived cleanup")
            self.assertFalse(result["process_cleanup_complete"])
            self.assertIn(
                "reviewer process cleanup could not be proven complete",
                result["limitations"],
            )

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "fork"), "Linux only")
    def test_real_descendant_held_stdout_is_unknown_and_cleaned_up(self) -> None:
        self._assert_real_lingering_reviewer_stream_is_unknown("stdout")

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "fork"), "Linux only")
    def test_real_descendant_held_stderr_is_unknown_and_cleaned_up(self) -> None:
        self._assert_real_lingering_reviewer_stream_is_unknown("stderr")

    def test_posix_cleanup_kills_lingering_reviewer_process_group(self) -> None:
        process = mock.MagicMock()
        process.pid = 12345
        process.wait.return_value = 0
        with (
            mock.patch.object(gate_module.os, "name", "posix"),
            mock.patch.object(gate_module.os, "killpg") as kill_group,
            mock.patch.object(gate_module.time, "monotonic", return_value=0.0),
            mock.patch.object(
                gate_module,
                "_posix_process_group_exited",
                side_effect=[False, True],
            ),
        ):
            gate_module._terminate_process_tree(process)
        signal_calls = [
            call
            for call in kill_group.call_args_list
            if call.args[1] in {gate_module.signal.SIGTERM, gate_module.signal.SIGKILL}
        ]
        self.assertEqual(
            [
                mock.call(process.pid, gate_module.signal.SIGTERM),
                mock.call(process.pid, gate_module.signal.SIGKILL),
            ],
            signal_calls,
        )
        self.assertEqual(
            [mock.call(timeout=0.2), mock.call(timeout=1.0)],
            process.wait.call_args_list,
        )

    def test_reviewer_incomplete_stream_observation_forces_unknown(self) -> None:
        stream = {
            "bytes_observed": 1,
            "bytes_captured": 1,
            "bytes_normalized": 1,
            "thread_completed": True,
            "eof": True,
            "read_failed": False,
            "truncated": False,
            "ambiguous_redaction": False,
        }
        observation = {
            "parent_exit_observed": True,
            "return_code": 0,
            "timed_out": False,
            "candidate_unchanged": True,
            "stdin": {"complete": True, "bytes_expected": 1, "bytes_written": 1},
            "stdout": stream | {"thread_completed": False, "eof": False},
            "stderr": stream,
            "supervisor": {
                "boundary_available": True,
                "boundary_kind": "seccomp_signal_guard",
                "descendants_observed": False,
                "cleanup_complete": True,
                "executed_argv_sha256": "sha256:" + "a" * 64,
            },
            "process_cleanup_complete": True,
            "output": {
                "present": True,
                "regular": True,
                "bytes": 2,
                "schema_valid": True,
                "candidate_matches": True,
                "bindings_match": True,
                "truncated": False,
            },
        }
        facts = reviewer_module.reviewer_observation_facts(observation)
        self.assertFalse(facts["capture_threads_completed"])
        self.assertFalse(facts["observation_complete"])
        self.assertFalse(facts["execution_valid"])

    def test_live_authority_ref_rejects_stale_workflow_commit(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_live_authority_ref", CI / "verify-live-authority-ref.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        document = {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": "a" * 40},
        }

        class Response:
            status = 200

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *unused: object) -> None:
                return None

            def read(self, unused_limit: int) -> bytes:
                return json.dumps(document).encode("utf-8")

        with mock.patch.object(module.urllib.request, "urlopen", return_value=Response()):
            observed = module.observe_live_ref(
                repository="timaday/codex-governed-change-authority",
                ref="refs/heads/main",
                expected_sha="a" * 40,
                token="x",
                api_url="https://api.github.com",
            )
            self.assertTrue(observed["current"])
            document["object"]["sha"] = "b" * 40
            with self.assertRaisesRegex(ValueError, "stale"):
                module.observe_live_ref(
                    repository="timaday/codex-governed-change-authority",
                    ref="refs/heads/main",
                    expected_sha="a" * 40,
                    token="x",
                    api_url="https://api.github.com",
                )

    def test_live_authority_state_binds_ruleset_and_commit_manifest(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_live_authority_state", CI / "verify-live-authority-ref.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        ref = "refs/heads/governance-authority"
        commit = "a" * 40
        ruleset = {
            "id": 7,
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {"ref_name": {"include": [ref], "exclude": []}},
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "allowed_merge_methods": ["squash", "rebase"],
                        "dismiss_stale_reviews_on_push": True,
                        "require_code_owner_review": False,
                        "require_extra_approval_for_unattributed_changes": True,
                        "require_last_push_approval": False,
                        "required_approving_review_count": 0,
                        "required_review_thread_resolution": True,
                        "required_reviewers": [],
                    },
                },
            ],
        }
        manifest = (ROOT / "MANIFEST.json").read_bytes()
        completed = subprocess.CompletedProcess(
            [], 0, stdout=manifest, stderr=b""
        )
        with (
            mock.patch.object(
                module,
                "observe_live_ref",
                return_value={"sha": commit, "current": True},
            ),
            mock.patch.object(
                module,
                "_request_json",
                side_effect=[
                    [{"id": 7, "target": "branch", "enforcement": "active"}],
                    ruleset,
                ],
            ) as request_json,
            mock.patch.object(module.subprocess, "run", return_value=completed),
        ):
            observed = module.observe_live_authority(
                repository="timaday/codex-governed-change",
                ref=ref,
                expected_sha=commit,
                token="x",
                api_url="https://api.github.com",
                authority_root=ROOT,
                observed_at="2026-09-05T12:00:00Z",
            )
        self.assertIn("targets=branch", request_json.call_args_list[0].args[0])
        self.assertIn("per_page=100", request_json.call_args_list[0].args[0])

        with (
            mock.patch.object(
                module,
                "observe_live_ref",
                return_value={"sha": commit, "current": True},
            ),
            mock.patch.object(
                module,
                "_request_json",
                return_value=[
                    {"id": 7, "target": "branch", "enforcement": "active"},
                    {"id": 8, "target": "branch", "enforcement": "active"},
                ],
            ),
            self.assertRaisesRegex(ValueError, "exactly one active branch ruleset"),
        ):
            module.observe_live_authority(
                repository="timaday/codex-governed-change",
                ref=ref,
                expected_sha=commit,
                token="x",
                api_url="https://api.github.com",
                authority_root=ROOT,
                observed_at="2026-09-05T12:00:00Z",
            )

        drifted = deepcopy(ruleset)
        drifted["rules"][3]["parameters"]["allowed_merge_methods"] = ["merge"]
        with (
            mock.patch.object(
                module,
                "observe_live_ref",
                return_value={"sha": commit, "current": True},
            ),
            mock.patch.object(
                module,
                "_request_json",
                side_effect=[
                    [{"id": 7, "target": "branch", "enforcement": "active"}],
                    drifted,
                ],
            ),
            self.assertRaisesRegex(ValueError, "pull-request rule"),
        ):
            module.observe_live_authority(
                repository="timaday/codex-governed-change",
                ref=ref,
                expected_sha=commit,
                token="x",
                api_url="https://api.github.com",
                authority_root=ROOT,
                observed_at="2026-09-05T12:00:00Z",
            )
        self.assertEqual(commit, observed["manifest_commit"])
        self.assertEqual(sha256_bytes(manifest), observed["manifest_sha256"])
        self.assertEqual(ruleset, observed["ruleset"])

        weakened = deepcopy(ruleset)
        weakened["bypass_actors"] = [{"actor_id": 1}]
        with (
            mock.patch.object(
                module,
                "observe_live_ref",
                return_value={"sha": commit, "current": True},
            ),
            mock.patch.object(
                module,
                "_request_json",
                side_effect=[
                    [{"id": 7, "target": "branch", "enforcement": "active"}],
                    weakened,
                ],
            ),
            self.assertRaisesRegex(ValueError, "bypass-free"),
        ):
            module.observe_live_authority(
                repository="timaday/codex-governed-change",
                ref=ref,
                expected_sha=commit,
                token="x",
                api_url="https://api.github.com",
                authority_root=ROOT,
                observed_at="2026-09-05T12:00:00Z",
            )

    def test_decision_source_rejects_unselected_and_actor_mismatched_files(self) -> None:
        descriptor = {
            "subject": "github:timaday",
            "authentication_method": "github-actions-workflow-dispatch",
            "protected_source": (
                "timaday/codex-governed-change@refs/heads/governance-authority"
            ),
        }
        regular = content_address(
            {
                "schema_version": "1.0.0",
                "kind": "label",
                "issuer": {
                    **descriptor,
                    "assertion_sha256": sha256_bytes(canonical_bytes(descriptor)),
                },
            },
            "decision_id",
        )
        label = content_address(
            {
                "schema_version": "1.0.0",
                "issuer": {
                    **descriptor,
                    "assertion_sha256": sha256_bytes(canonical_bytes(descriptor)),
                },
            },
            "decision_id",
        )
        assertion = {
            "event_name": "workflow_dispatch",
            "actor": "github:timaday",
            "authority_repository": "timaday/codex-governed-change",
            "authority_ref": "refs/heads/governance-authority",
            "authority_commit": "a" * 40,
            "authority_basis_commit": "b" * 40,
            "workflow_run_id": "123",
            "approved_decision_ids": [
                regular["decision_id"],
                label["decision_id"],
            ],
            "authorization_receipt_id": None,
        }
        observation = {
            "authority_commit": "a" * 40,
            "authority_basis_commit": "b" * 40,
            "decision_source_assertion": assertion,
            "decision_source_assertion_sha256": sha256_bytes(
                canonical_bytes(assertion)
            ),
        }
        self.assertEqual(
            set(assertion["approved_decision_ids"]),
            verify_decision_source_assertion(observation, [regular, label]),
        )
        with self.assertRaisesRegex(ValueError, "differs"):
            verify_decision_source_assertion(observation, [regular])
        forged = deepcopy(label)
        forged_descriptor = descriptor | {"subject": "github:someone-else"}
        forged["issuer"] = forged_descriptor | {
            "assertion_sha256": sha256_bytes(canonical_bytes(forged_descriptor))
        }
        forged = content_address(forged, "decision_id")
        assertion["approved_decision_ids"][1] = forged["decision_id"]
        observation["decision_source_assertion_sha256"] = sha256_bytes(
            canonical_bytes(assertion)
        )
        with self.assertRaisesRegex(ValueError, "issuer"):
            verify_decision_source_assertion(observation, [regular, forged])

        assertion["approved_decision_ids"][1] = label["decision_id"]
        receipt = content_address(
            {
                "schema_version": "1.0.0",
                "repository_id": "repo:timaday/codex-governed-change",
                "target_id": "release-v0.1.0",
                "authority_repository": assertion["authority_repository"],
                "authority_ref": assertion["authority_ref"],
                "authority_decision_commit": assertion["authority_commit"],
                "authority_basis_commit": assertion["authority_basis_commit"],
                "actor": assertion["actor"],
                "approved_decision_ids": assertion["approved_decision_ids"],
                "decision_source_assertion": assertion,
                "decision_source_assertion_sha256": sha256_bytes(
                    canonical_bytes(assertion)
                ),
            },
            "receipt_id",
        )
        scheduled_assertion = {
            **assertion,
            "event_name": "schedule",
            "authority_commit": "c" * 40,
            "workflow_run_id": "124",
            "authorization_receipt_id": receipt["receipt_id"],
        }
        scheduled_observation = {
            "authority_commit": scheduled_assertion["authority_commit"],
            "authority_basis_commit": scheduled_assertion[
                "authority_basis_commit"
            ],
            "authorization_receipt": {"receipt_id": receipt["receipt_id"]},
            "decision_source_assertion": scheduled_assertion,
            "decision_source_assertion_sha256": sha256_bytes(
                canonical_bytes(scheduled_assertion)
            ),
        }
        self.assertEqual(
            set(scheduled_assertion["approved_decision_ids"]),
            verify_decision_source_assertion(
                scheduled_observation,
                [regular, label],
                authorization_receipt=receipt,
            ),
        )
        extended_receipt = content_address(
            {**receipt, "unprotected_extension": True}, "receipt_id"
        )
        extended_assertion = {
            **scheduled_assertion,
            "authorization_receipt_id": extended_receipt["receipt_id"],
        }
        extended_observation = {
            **scheduled_observation,
            "authorization_receipt": {
                "receipt_id": extended_receipt["receipt_id"]
            },
            "decision_source_assertion": extended_assertion,
            "decision_source_assertion_sha256": sha256_bytes(
                canonical_bytes(extended_assertion)
            ),
        }
        with self.assertRaisesRegex(ValueError, "receipt does not reconstruct"):
            verify_decision_source_assertion(
                extended_observation,
                [regular, label],
                authorization_receipt=extended_receipt,
            )

    def test_authority_decision_commit_is_a_non_self_referential_child(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "prepare_deterministic_inputs",
            CI / "prepare-deterministic-inputs.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(repository), *arguments],
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "--quiet", "--initial-branch=main")
            git("config", "user.name", "Authority Test")
            git("config", "user.email", "authority@example.invalid")
            (repository / "MANIFEST.json").write_text("basis\n", encoding="utf-8")
            git("add", "MANIFEST.json")
            git("commit", "--quiet", "-m", "basis")
            basis = git("rev-parse", "HEAD")
            decision = repository / ".governance/releases/v0.1.0/decisions/task.json"
            decision.parent.mkdir(parents=True)
            decision.write_text("{}\n", encoding="utf-8")
            (repository / "MANIFEST.json").write_text("decision\n", encoding="utf-8")
            git("add", ".governance", "MANIFEST.json")
            git("commit", "--quiet", "-m", "decision")
            head, observed_basis, decision_commit = module.verify_authority_decision_commit(
                repository,
                release_directory=".governance/releases/v0.1.0",
            )
            self.assertEqual(git("rev-parse", "HEAD"), head)
            self.assertEqual(basis, observed_basis)
            self.assertEqual(head, decision_commit)
            receipt = repository / ".governance/releases/v0.1.0/authorization-receipt.json"
            receipt.write_text("{}\n", encoding="utf-8")
            (repository / "MANIFEST.json").write_text("receipt\n", encoding="utf-8")
            git("add", ".governance", "MANIFEST.json")
            git("commit", "--quiet", "-m", "receipt")
            receipt_head, receipt_basis, receipt_decision = (
                module.verify_authority_decision_commit(
                    repository,
                    release_directory=".governance/releases/v0.1.0",
                )
            )
            self.assertEqual(git("rev-parse", "HEAD"), receipt_head)
            self.assertEqual(basis, receipt_basis)
            self.assertEqual(head, receipt_decision)
            (repository / "README.md").write_text("unexpected\n", encoding="utf-8")
            decision.write_text('{"changed":true}\n', encoding="utf-8")
            git("add", ".")
            git("commit", "--quiet", "-m", "mixed")
            with self.assertRaisesRegex(ValueError, "decision-only"):
                module.verify_authority_decision_commit(
                    repository,
                    release_directory=".governance/releases/v0.1.0",
                )

    def test_two_parent_decision_and_receipt_merges_fail_closed(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "prepare_deterministic_inputs_merge_rejection",
            CI / "prepare-deterministic-inputs.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for transition in ("decision", "receipt"):
            with self.subTest(transition=transition), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory)

                def git(*arguments: str) -> str:
                    completed = subprocess.run(
                        ["git", "-C", str(repository), *arguments],
                        check=True,
                        stdout=subprocess.PIPE,
                        text=True,
                    )
                    return completed.stdout.strip()

                git("init", "--quiet", "--initial-branch=main")
                git("config", "user.name", "Authority Test")
                git("config", "user.email", "authority@example.invalid")
                (repository / "MANIFEST.json").write_text("basis\n", encoding="utf-8")
                git("add", "MANIFEST.json")
                git("commit", "--quiet", "-m", "basis")
                basis = git("rev-parse", "HEAD")

                decision = repository / ".governance/releases/v0.1.0/decisions/task.json"
                decision.parent.mkdir(parents=True)
                decision.write_text("{}\n", encoding="utf-8")
                (repository / "MANIFEST.json").write_text(
                    "decision\n", encoding="utf-8"
                )
                git("add", ".governance", "MANIFEST.json")
                git("commit", "--quiet", "-m", "decision")
                decision_head = git("rev-parse", "HEAD")

                if transition == "receipt":
                    receipt = (
                        repository
                        / ".governance/releases/v0.1.0/authorization-receipt.json"
                    )
                    receipt.write_text("{}\n", encoding="utf-8")
                    (repository / "MANIFEST.json").write_text(
                        "receipt\n", encoding="utf-8"
                    )
                    git("add", ".governance", "MANIFEST.json")
                    git("commit", "--quiet", "-m", "receipt")

                branch_point = basis if transition == "decision" else decision_head
                git("checkout", "--quiet", "-b", "merge-side", branch_point)
                side = decision.parent / f"{transition}-merge-side.json"
                side.parent.mkdir(parents=True, exist_ok=True)
                side.write_text("{}\n", encoding="utf-8")
                git("add", ".governance")
                git("commit", "--quiet", "-m", "merge side")
                git("checkout", "--quiet", "main")
                git("merge", "--quiet", "--no-ff", "merge-side", "-m", "merge side")
                self.assertEqual(
                    3,
                    len(git("rev-list", "--parents", "-n", "1", "HEAD").split()),
                )
                with self.assertRaisesRegex(ValueError, "exactly one basis parent"):
                    module.verify_authority_decision_commit(
                        repository,
                        release_directory=".governance/releases/v0.1.0",
                    )

    def test_qualification_live_ref_requires_private_repository(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_live_authority_private", CI / "verify-live-authority-ref.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        class Response:
            status = 200

            def __init__(self, document: dict) -> None:
                self.document = document

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *unused: object) -> None:
                return None

            def read(self, unused_limit: int) -> bytes:
                return json.dumps(self.document).encode("utf-8")

        ref = {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": "a" * 40},
        }
        repository = {
            "full_name": "timaday/codex-governed-change-authority",
            "private": True,
        }
        with mock.patch.object(
            module.urllib.request,
            "urlopen",
            side_effect=[Response(ref), Response(repository)],
        ):
            observed = module.observe_live_ref(
                repository="timaday/codex-governed-change-authority",
                ref="refs/heads/main",
                expected_sha="a" * 40,
                token="x",
                api_url="https://api.github.com",
                require_private=True,
            )
        self.assertTrue(observed["private"])
        repository["private"] = False
        with (
            mock.patch.object(
                module.urllib.request,
                "urlopen",
                side_effect=[Response(ref), Response(repository)],
            ),
            self.assertRaisesRegex(ValueError, "not private"),
        ):
            module.observe_live_ref(
                repository="timaday/codex-governed-change-authority",
                ref="refs/heads/main",
                expected_sha="a" * 40,
                token="x",
                api_url="https://api.github.com",
                require_private=True,
            )

    def test_qualification_verifier_recomputes_each_case(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "run_qualification_reconstruction", CI / "run-qualification.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        corpus_path = (
            ROOT / ".governance/releases/v0.1.0/qualification/corpus.json"
        )
        decision_path = (
            ROOT
            / ".governance/releases/v0.1.0/qualification/human-label-decision.json"
        )
        corpus = load_json(corpus_path)
        decision = load_json(decision_path)
        corpus_sha = sha256_bytes(canonical_bytes(corpus))

        expected = {
            case["case_id"]: case["expected_disposition"]
            for case in corpus["cases"]
        }
        cases_by_id = {case["case_id"]: case for case in corpus["cases"]}

        def fake_launch(**arguments: object) -> dict[str, object]:
            command = list(arguments["command"])
            root = Path(command[command.index("--cd") + 1])
            inputs = json.loads(
                str(arguments["stdin_text"]).split("PERMITTED_INPUTS ", 1)[1]
            )
            task = load_json(root / inputs["task_contract_path"])
            label = expected[task["case_id"]]
            case = cases_by_id[task["case_id"]]
            policy = qualification_module.qualification_policy_document(
                repository_id=inputs["repository_id"],
                case=case,
                corpus_sha256=corpus_sha,
                bootstrap_qualification_id=inputs["reviewer_qualification_id"],
                model="gpt-5.6-sol",
                reasoning_effort="xhigh",
            )
            candidate = qualification_module.qualification_candidate_document(
                repository_id=inputs["repository_id"],
                case=case,
                effective_policy_sha256=sha256_bytes(canonical_bytes(policy)),
            )
            locators = qualification_module.qualification_evidence_locators(
                repository_id=inputs["repository_id"],
                task_contract_sha256=inputs["task_contract_sha256"],
                candidate=candidate,
            )
            locator = next(
                item
                for item in locators
                if item["path"]
                == (
                    case["expected_finding"]["path"]
                    if case["expected_finding"] is not None
                    else "docs/requirements.md"
                )
            )
            evidence_reference = {
                "locator_id": locator["locator_id"],
                "sha256": locator["artifact_sha256"],
            }
            mode = str(arguments["review_mode"])
            if mode == "conformance":
                payload = {
                    "schema_version": "3.0.0",
                    "repository_id": inputs["repository_id"],
                    "candidate_id": inputs["candidate_id"],
                    "task_contract_sha256": inputs["task_contract_sha256"],
                    "effective_policy_sha256": inputs["effective_policy_sha256"],
                    "gate_manifest_sha256": inputs["gate_manifest_sha256"],
                    "context_receipt_sha256": inputs["context_receipt_sha256"],
                    "reviewer_prompt_sha256": inputs["reviewer_prompt_sha256"],
                    "qualification_id": inputs["reviewer_qualification_id"],
                    "model": "gpt-5.6-sol",
                    "invocation_id": "qualification-fixture",
                    "verdict": label,
                    "reviewed_surfaces": list(REVIEW_RUBRIC["required_surfaces"]),
                    "affected_closure": candidate["changed_paths"],
                    "retrieval_expansions": [],
                    "findings": (
                        [{
                            "severity": "high",
                            "category": "authority",
                            "path": case["expected_finding"]["path"],
                            "line": case["expected_finding"]["line"],
                            "claim": "The labelled defect is present.",
                            "violated_oracle": case["requirement_id"],
                            "evidence_refs": [evidence_reference],
                            "remediation": "Remove the seeded defect.",
                        }]
                        if label == "BLOCK"
                        else []
                    ),
                    "missing_evidence": [],
                    "claims": [
                        {
                            "claim_id": item["claim_id"],
                            "claim": item["claim"],
                            "classification": "VERIFIED_WITHIN_SCOPE",
                            "evidence_refs": [evidence_reference],
                        }
                        for item in MANDATORY_REVIEWER_CLAIMS
                    ],
                    "limitations": [],
                }
            else:
                charter = load_json(root / inputs["review_charter_path"])
                finding = (
                    {
                        "finding_id": case["expected_finding"]["defect_id"],
                        "path": case["expected_finding"]["path"],
                        "line": case["expected_finding"]["line"],
                        "claim": "seeded critical defect observed",
                        "impact": "the mandatory oracle is violated",
                        "severity": "high",
                        "confidence": "high",
                        "oracle": case["requirement_id"],
                        "evidence_refs": [case["expected_finding"]["path"]],
                        "threatened_value": "governed disposition correctness",
                    }
                    if label == "BLOCK"
                    else None
                )
                payload = {
                    "schema_version": "2.0.0",
                    "repository_id": inputs["repository_id"],
                    "task_contract_sha256": inputs["task_contract_sha256"],
                    "session_id": "QUALIFICATION-SESSION",
                    "candidate_id": inputs["candidate_id"],
                    "charter_id": charter["charter_id"],
                    "charter_sha256": inputs["review_charter_sha256"],
                    "reviewer_prompt_sha256": inputs["reviewer_prompt_sha256"],
                    "qualification_id": inputs["reviewer_qualification_id"],
                    "model": "gpt-5.6-sol",
                    "status": "blocked" if label == "BLOCK" else "completed",
                    "environment": ["sanitized read-only fixture"],
                    "tools": ["protected reviewer adapter"],
                    "experiments": [{
                        "id": "QUALIFICATION-EXPERIMENT",
                        "activity_kind": "investigation",
                        "procedure": "inspect the bounded candidate",
                        "observation": "the mandatory oracle was evaluated",
                        "oracle": "docs/requirements.md",
                        "evidence_refs": ["docs/requirements.md"],
                    }],
                    "retrieval_expansions": [],
                    "findings": [finding] if label == "BLOCK" else [],
                    "counter_hypotheses": ["the seeded behavior may be unreachable"],
                    "coverage_achieved": ["bounded changed surface"],
                    "omitted_areas": ["unrelated behavior"],
                    "obstacles": ["none"],
                    "new_risks": [],
                    "follow_up_charters": [],
                    "residual_risks": [{
                        "risk_id": "QUALIFICATION-RESIDUAL",
                        "description": "the fixture is intentionally bounded",
                        "material": False,
                        "evidence_refs": ["docs/requirements.md"],
                    }],
                    "started_at": "2026-09-02T00:00:00Z",
                    "ended_at": "2026-09-02T00:00:01Z",
                    "producer_version": "test",
                    "provenance": {
                        "produced_by": "authority test fixture",
                        "method": "deterministic adapter simulation",
                        "source_refs": ["protected qualification corpus"],
                    },
                }
            output_path = Path(arguments["output_path"])
            output_bytes = canonical_bytes(payload)
            output_path.write_bytes(output_bytes)
            stdout = (
                json.dumps(
                    {"type": "thread.started", "thread_id": "qualification-thread"},
                    separators=(",", ":"),
                )
                + "\n"
                + json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "agent_message",
                            "text": output_bytes.decode("utf-8"),
                        },
                    },
                    separators=(",", ":"),
                )
                + "\n"
                + json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {
                            "input_tokens": 1,
                            "cached_input_tokens": 0,
                            "output_tokens": 1,
                            "reasoning_output_tokens": 1,
                        },
                    },
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            stderr = b""
            executed_argv_sha256 = "sha256:" + "3" * 64
            stdin_bytes = str(arguments["stdin_text"]).encode("utf-8")
            observation = {
                "parent_exit_observed": True,
                "return_code": 0,
                "timed_out": False,
                "candidate_unchanged": True,
                "stdin": {
                    "complete": True,
                    "bytes_expected": len(stdin_bytes),
                    "bytes_written": len(stdin_bytes),
                },
                "stdout": {
                    "bytes_observed": len(stdout),
                    "bytes_captured": len(stdout),
                    "bytes_normalized": len(stdout),
                    "thread_completed": True,
                    "eof": True,
                    "read_failed": False,
                    "truncated": False,
                    "ambiguous_redaction": False,
                },
                "stderr": {
                    "bytes_observed": 0,
                    "bytes_captured": 0,
                    "bytes_normalized": 0,
                    "thread_completed": True,
                    "eof": True,
                    "read_failed": False,
                    "truncated": False,
                    "ambiguous_redaction": False,
                },
                "supervisor": {
                    "boundary_available": True,
                    "boundary_kind": "seccomp_signal_guard",
                    "descendants_observed": False,
                    "cleanup_complete": True,
                    "executed_argv_sha256": executed_argv_sha256,
                },
                "process_cleanup_complete": True,
                "output": {
                    "present": True,
                    "regular": True,
                    "bytes": len(output_bytes),
                    "schema_valid": True,
                    "candidate_matches": True,
                    "bindings_match": True,
                    "truncated": False,
                },
            }
            output_path.write_bytes(b'{"replacement":true}\n')
            return {
                "verdict": label,
                "result": payload,
                "return_code": 0,
                "started_at": "2026-09-02T00:00:00Z",
                "ended_at": "2026-09-02T00:00:01Z",
                "latency_ms": 1,
                "candidate_before": inputs["candidate_id"],
                "candidate_after": inputs["candidate_id"],
                "environment_keys": ["PATH"],
                "argv_sha256": "sha256:" + "1" * 64,
                "executed_argv_sha256": executed_argv_sha256,
                "stdin_sha256": sha256_bytes(stdin_bytes),
                "output_sha256": sha256_bytes(output_bytes),
                "output_bytes": output_bytes,
                "timed_out": False,
                "observation_complete": True,
                "capture_threads_completed": True,
                "process_cleanup_complete": True,
                "stdin_delivery_complete": True,
                "stdout_sha256": sha256_bytes(stdout),
                "stderr_sha256": sha256_bytes(stderr),
                "stdout_bytes": stdout,
                "stderr_bytes": stderr,
                "output_valid": True,
                "candidate_matches": True,
                "bindings_match": True,
                "execution_valid": True,
                "review_status": payload.get("status"),
                "output_truncated": False,
                "observation": observation,
                "limitations": [],
                "usage_observed": True,
                "thread_id": "qualification-thread",
                "input_tokens": 1,
                "cached_input_tokens": 0,
                "output_tokens": 1,
                "reasoning_output_tokens": 1,
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                mock.patch.object(module, "launch_reviewer", side_effect=fake_launch),
                mock.patch.object(
                    module, "observe_codex_authentication", return_value="chatgpt"
                ),
            ):
                records = {
                    mode: module._run_mode(
                        mode=mode,
                        corpus=corpus,
                        label_decision=decision,
                        prompt_path=ROOT / "kernel/.codex/review/reviewer.prompt.md",
                        schema_path=ROOT / "kernel/schemas" / schema,
                        codex=sys.executable,
                        cli_version="codex-cli 0.149.1",
                        authentication="chatgpt",
                        timeout_seconds=60,
                        max_output_bytes=1_000_000,
                        workflow_run_id="fixture-run",
                        workflow_attempt=1,
                        output=root,
                        requested_profile=None,
                    )[0]
                    for mode, schema in (
                        ("conformance", "reviewer-result.schema.json"),
                        ("rapid_review", "rapid-review-session.schema.json"),
                    )
                }
            policy = load_json(ROOT / ".governance/effective-policy.json")
            policy["reviewer"]["qualification_corpus_sha256"] = corpus_sha
            policy["reviewer"]["qualification_label_decision_id"] = decision[
                "decision_id"
            ]
            policy["reviewer"]["qualification_ids"] = {
                mode: record["qualification_id"] for mode, record in records.items()
            }
            policy_path = root / "policy.json"
            write_json(policy_path, policy)
            arguments = {
                "corpus_path": corpus_path,
                "label_decision_path": decision_path,
                "conformance_record_path": root / "conformance.json",
                "conformance_cases_path": root / "conformance-cases.json",
                "rapid_record_path": root / "rapid-review.json",
                "rapid_cases_path": root / "rapid-review-cases.json",
                "policy_path": policy_path,
                "authenticated_label_decision_id": decision["decision_id"],
                "artifact_root": root / "raw",
            }
            validated = validate_qualification_bundle(**arguments)
            self.assertEqual(corpus_sha, validated["corpus_sha256"])
            raw = next((root / "raw/conformance").glob("*/stdout.bin"))
            raw.write_bytes(raw.read_bytes() + b"tampered")
            reset_authoritative_read_session()
            with self.assertRaisesRegex(ValueError, "per-case"):
                validate_qualification_bundle(**arguments)

    def test_initial_bootstrap_accepts_only_fully_reconstructed_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = bootstrap_fixture(Path(directory))
            verification = validate_initial_bootstrap(**arguments)
            self.assertEqual("initial_lkg_bootstrap", verification["evaluation_mode"])
            self.assertEqual("READY_FOR_HUMAN", verification["state"])

            raw = arguments["evidence"] / "rollback/stdout.bin"
            original = raw.read_bytes()
            raw.write_bytes(original + b"forged")
            reset_authoritative_read_session()
            with self.assertRaisesRegex(ValueError, "raw artifact"):
                validate_initial_bootstrap(**arguments)
            raw.write_bytes(original)
            reset_authoritative_read_session()

            missing_bootstrap = deepcopy(arguments)
            missing_bootstrap["decisions"] = [arguments["decisions"][1]]
            with self.assertRaisesRegex(ValueError, "bootstrap and one promotion"):
                validate_initial_bootstrap(**missing_bootstrap)

            substituted_task = deepcopy(arguments)
            substituted_task["rollback_task_sha256"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(ValueError, "rollback plan"):
                validate_initial_bootstrap(**substituted_task)

            wrong_stdout = deepcopy(arguments)
            raw.write_bytes(b"blueprint validation passed\n")
            wrong_stdout["rollback_gate"] = deepcopy(arguments["rollback_gate"])
            wrong_stdout["rollback_gate"]["artifacts"][0]["bytes"] = len(
                b"blueprint validation passed\n"
            )
            wrong_stdout["rollback_gate"]["artifacts"][0]["sha256"] = sha256_bytes(
                b"blueprint validation passed\n"
            )
            reset_authoritative_read_session()
            with self.assertRaisesRegex(ValueError, "target receipt"):
                validate_initial_bootstrap(**wrong_stdout)

    def test_initial_bootstrap_rejects_limitations_and_manifest_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = bootstrap_fixture(Path(directory))

            limited_plan = deepcopy(arguments)
            plan = content_address(
                {**limited_plan["rollback_plan"], "limitations": ["unverified"]},
                "rollback_plan_id",
            )
            plan_sha = sha256_bytes(canonical_bytes(plan))
            observation = deepcopy(limited_plan["observation"])
            observation["rollback_plan_id"] = plan["rollback_plan_id"]
            observation["rollback_plan_sha256"] = plan_sha
            limited_plan["rollback_plan"] = plan
            limited_plan["rollback_plan_sha256"] = plan_sha
            limited_plan["observation"] = observation
            with self.assertRaisesRegex(ValueError, "rollback plan"):
                validate_initial_bootstrap(**limited_plan)

            substituted_manifest = deepcopy(arguments)
            wrong_manifest_sha = "sha256:" + "9" * 64
            state = deepcopy(substituted_manifest["authority_state"])
            state["manifest_sha256"] = wrong_manifest_sha
            substituted_manifest["authority_state"] = state
            substituted_manifest["authority_state_sha256"] = sha256_bytes(
                canonical_bytes(state)
            )
            substituted_manifest["authority_manifest_sha256"] = wrong_manifest_sha
            with self.assertRaisesRegex(ValueError, "live protected authority"):
                validate_initial_bootstrap(**substituted_manifest)

            weakened_ruleset = deepcopy(arguments)
            state = deepcopy(weakened_ruleset["authority_state"])
            state["ruleset"]["bypass_actors"] = [{"actor_id": 1}]
            weakened_ruleset["authority_state"] = state
            weakened_ruleset["authority_state_sha256"] = sha256_bytes(
                canonical_bytes(state)
            )
            with self.assertRaisesRegex(ValueError, "live protected authority"):
                validate_initial_bootstrap(**weakened_ruleset)

    def test_initial_bootstrap_rejects_fully_readdressed_capability_limitations(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = bootstrap_fixture(Path(directory))
            forged = deepcopy(arguments)

            capability = content_address(
                {
                    **forged["rollback_capability"],
                    "limitations": ["provider guarantee unavailable"],
                },
                "capability_id",
            )
            capability_sha = sha256_bytes(canonical_bytes(capability))

            provenance = deepcopy(forged["rollback_provenance"])
            provenance.pop("statement_id")
            provenance["predicate"]["environment"][
                "sandbox_capability_sha256"
            ] = capability_sha
            provenance["predicate"]["artifacts"][2]["sha256"] = capability_sha
            provenance = content_address(provenance, "statement_id")
            provenance_sha = sha256_bytes(canonical_bytes(provenance))

            gate = deepcopy(forged["rollback_gate"])
            gate["sandbox_capability_sha256"] = capability_sha
            gate["provenance_statement"]["sha256"] = provenance_sha
            gate_sha = sha256_bytes(canonical_bytes(gate))

            rollback = deepcopy(forged["rollback"])
            rollback.pop("rollback_evidence_id")
            rollback["gate_result"]["sha256"] = gate_sha
            rollback["sandbox_capability"]["sha256"] = capability_sha
            rollback["provenance_statement"]["sha256"] = provenance_sha
            rollback = content_address(rollback, "rollback_evidence_id")

            promotion = deepcopy(forged["decisions"][1])
            promotion.pop("decision_id")
            promotion["scope"] = [
                promotion["scope"][0],
                f"rollback:{rollback['rollback_evidence_id']}",
            ]
            promotion = content_address(promotion, "decision_id")
            forged.update(
                {
                    "rollback_capability": capability,
                    "rollback_capability_sha256": capability_sha,
                    "rollback_provenance": provenance,
                    "rollback_provenance_sha256": provenance_sha,
                    "rollback_gate": gate,
                    "rollback_gate_sha256": gate_sha,
                    "rollback": rollback,
                    "decisions": [forged["decisions"][0], promotion],
                }
            )
            rebind_bootstrap_dispatch(forged)
            with self.assertRaisesRegex(ValueError, "sandbox identity or limits"):
                validate_initial_bootstrap(**forged)

    def test_initial_bootstrap_decisions_expire_at_the_exclusive_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = bootstrap_fixture(Path(directory))
            arguments["evaluated_at"] = datetime(
                2026, 8, 27, 14, 0, tzinfo=timezone.utc
            )
            with self.assertRaisesRegex(ValueError, "decision does not reconstruct"):
                validate_initial_bootstrap(**arguments)

    def test_initial_bootstrap_rejects_a_fully_readdressed_wrong_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = bootstrap_fixture(Path(directory))
            forged = deepcopy(arguments)
            wrong_source = "sha256:" + "9" * 64
            capability = dict(forged["rollback_capability"])
            capability["source_identity"] = wrong_source
            capability = content_address(capability, "capability_id")
            capability_sha = sha256_bytes(canonical_bytes(capability))

            prior = forged["rollback_provenance"]["predicate"]
            provenance = build_provenance_statement(
                repository_id=forged["candidate"]["repository_id"],
                candidate_id=wrong_source,
                repository_digest=wrong_source,
                task_contract_sha256=prior["task_contract_sha256"],
                effective_policy_sha256=prior["effective_policy_sha256"],
                gate_definition_sha256=prior["gate_definition_sha256"],
                reviewer_prompt_sha256=prior["reviewer_prompt_sha256"],
                producer=prior["producer"],
                workflow=prior["workflow"],
                tools=prior["tools"],
                environment={
                    **prior["environment"],
                    "source_identity": wrong_source,
                    "sandbox_capability_sha256": capability_sha,
                },
                materials=[
                    {"name": "candidate", "sha256": wrong_source},
                    *prior["materials"][1:],
                ],
                started_at=prior["started_at"],
                ended_at=prior["ended_at"],
                result=prior["result"],
                limits=prior["limits"],
                artifacts=[
                    *prior["artifacts"][:2],
                    {"name": "sandbox-capability", "sha256": capability_sha},
                ],
                limitations=prior["limitations"],
            )
            provenance_sha = sha256_bytes(canonical_bytes(provenance))
            gate = deepcopy(forged["rollback_gate"])
            gate["candidate_before"] = wrong_source
            gate["candidate_after"] = wrong_source
            gate["source_identity"] = wrong_source
            gate["sandbox_capability_sha256"] = capability_sha
            gate["provenance_statement"]["sha256"] = provenance_sha
            gate_sha = sha256_bytes(canonical_bytes(gate))
            rollback = dict(forged["rollback"])
            rollback["gate_result"]["sha256"] = gate_sha
            rollback["sandbox_capability"]["sha256"] = capability_sha
            rollback["provenance_statement"]["sha256"] = provenance_sha
            rollback = content_address(rollback, "rollback_evidence_id")
            promotion = dict(forged["decisions"][1])
            promotion["scope"] = [
                promotion["scope"][0],
                f"rollback:{rollback['rollback_evidence_id']}",
            ]
            promotion = content_address(promotion, "decision_id")
            forged.update(
                {
                    "rollback_capability": capability,
                    "rollback_capability_sha256": capability_sha,
                    "rollback_provenance": provenance,
                    "rollback_provenance_sha256": provenance_sha,
                    "rollback_gate": gate,
                    "rollback_gate_sha256": gate_sha,
                    "rollback": rollback,
                    "decisions": [forged["decisions"][0], promotion],
                    "verified_decision_ids": {
                        forged["decisions"][0]["decision_id"],
                        promotion["decision_id"],
                    },
                }
            )
            rebind_bootstrap_dispatch(forged)
            with self.assertRaisesRegex(ValueError, "sandbox identity"):
                validate_initial_bootstrap(**forged)

    def test_live_rollback_packager_reconstructs_and_rejects_manifest_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            candidate_root = temporary / "candidate"
            arguments = bootstrap_fixture(candidate_root)
            authority = temporary / "authority"
            release = authority / ".governance/releases/v0.1.0"
            release.mkdir(parents=True)
            shutil.copytree(ROOT / "kernel/schemas", authority / "kernel/schemas")
            shutil.copy2(
                ROOT / ".governance/effective-policy.json",
                authority / ".governance/effective-policy.json",
            )
            for name in (
                "task-contract.json",
                "rollback-task-contract.json",
                "rollback-plan.json",
            ):
                shutil.copy2(ROOT / ".governance/releases/v0.1.0" / name, release / name)
            write_json(release / "proposed-policy.json", arguments["proposed_policy"])
            target = load_json(ROOT / ".governance/targets.json")["targets"][0]
            target_path = temporary / "target.json"
            write_json(target_path, target)
            candidate_path = temporary / "rollback-candidate.json"
            write_json(candidate_path, arguments["rollback_candidate"])

            source_root = (
                arguments["evidence"]
                / (
                    "sha256-rollback/runs/github-1-rollback-1/gates/"
                    + str(arguments["rollback_plan"]["gate_definition"]["gate_id"])
                )
            )
            source_root.mkdir(parents=True)
            source_paths = {
                "stdout": source_root / "stdout.bin",
                "stderr": source_root / "stderr.bin",
            }
            source_paths["stdout"].write_bytes(
                b"ROLLBACK_REHEARSAL=PASS "
                b"target=a0a0b01a19e87f2591c7e97e892cd040ce9c6e58\n"
            )
            source_paths["stderr"].write_bytes(b"")
            write_json(
                source_root / "sandbox-capability.json",
                arguments["rollback_capability"],
            )
            write_json(
                source_root / "provenance.json", arguments["rollback_provenance"]
            )
            source_result = deepcopy(arguments["rollback_gate"])
            gate_id = str(arguments["rollback_plan"]["gate_definition"]["gate_id"])
            for artifact in source_result["artifacts"]:
                artifact["path"] = artifact["path"].replace(
                    "rollback/",
                    f"sha256-rollback/runs/github-1-rollback-1/gates/{gate_id}/",
                )
            source_result["provenance_statement"]["path"] = (
                "artifacts/governance/completion/evidence/sha256-rollback/"
                f"runs/github-1-rollback-1/gates/{gate_id}/provenance.json"
            )
            result_path = source_root / "result.json"
            write_json(result_path, source_result)
            result_sha = sha256_bytes(result_path.read_bytes())
            manifest = content_address(
                {
                    "schema_version": "1.0.0",
                    "repository_id": arguments["candidate"]["repository_id"],
                    "task_contract_sha256": arguments["rollback_plan"][
                        "rollback_task_contract_sha256"
                    ],
                    "candidate_id": arguments["rollback_candidate"]["candidate_id"],
                    "required_gate_ids": [gate_id],
                    "gate_results": [
                        {
                            "gate_id": gate_id,
                            "reference": {
                                "path": result_path.relative_to(candidate_root).as_posix(),
                                "sha256": result_sha,
                            },
                        }
                    ],
                    "created_at": "2026-08-27T11:00:00Z",
                    "producer_version": "0.1.0",
                },
                "gate_manifest_id",
            )
            manifest_path = source_root.parent.parent / "gate-manifest.json"
            write_json(manifest_path, manifest)
            summary = {
                "repository_id": arguments["candidate"]["repository_id"],
                "candidate_id": arguments["rollback_candidate"]["candidate_id"],
                "gate_manifest": {
                    "path": manifest_path.relative_to(candidate_root).as_posix(),
                    "sha256": sha256_bytes(manifest_path.read_bytes()),
                },
                "results": [{"gate_id": gate_id, "status": "PASS"}],
            }
            summary_path = temporary / "gate-summary.json"
            write_json(summary_path, summary)

            rollback_task = load_json(release / "rollback-task-contract.json")
            for source in rollback_task["authoritative_sources"]:
                fixture = FIXTURES / "rollback-source" / source["path"]
                fixture_bytes = fixture.read_bytes()
                self.assertEqual(source["sha256"], sha256_bytes(fixture_bytes))
                destination = candidate_root / source["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(fixture_bytes)

            spec = importlib.util.spec_from_file_location(
                "prepare_rollback_package", CI / "prepare-rollback-package.py"
            )
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            class Adapter:
                def __init__(self, unused_repository: Path) -> None:
                    pass

                def identify(self, **unused: object) -> dict[str, object]:
                    return deepcopy(arguments["rollback_candidate"])

                def resolve_commit(self, revision: str) -> str:
                    if revision != "HEAD":
                        raise ValueError("unexpected revision")
                    return str(target["lkg_governance_commit"])

            command = [
                "prepare-rollback-package.py",
                "--authority",
                str(authority),
                "--candidate",
                str(candidate_root),
                "--target",
                str(target_path),
                "--candidate-identity",
                str(candidate_path),
                "--gate-summary",
                str(summary_path),
                "--created-at",
                "2026-08-27T11:02:00Z",
                "--output",
                str(arguments["evidence"]),
            ]
            with (
                mock.patch.object(module, "GitCliRepositoryAdapter", Adapter),
                mock.patch.object(sys, "argv", command),
            ):
                module.main()

            package = arguments["evidence"] / "rollback"
            reconstructed = deepcopy(arguments)
            reconstructed.update(
                {
                    "rollback_candidate": load_json(package / "candidate.json"),
                    "rollback_candidate_sha256": sha256_bytes(
                        (package / "candidate.json").read_bytes()
                    ),
                    "rollback": load_json(package / "rollback-evidence.json"),
                    "rollback_gate": load_json(package / "gate-result.json"),
                    "rollback_gate_sha256": sha256_bytes(
                        (package / "gate-result.json").read_bytes()
                    ),
                    "rollback_capability": load_json(
                        package / "sandbox-capability.json"
                    ),
                    "rollback_capability_sha256": sha256_bytes(
                        (package / "sandbox-capability.json").read_bytes()
                    ),
                    "rollback_provenance": load_json(
                        package / "provenance-statement.json"
                    ),
                    "rollback_provenance_sha256": sha256_bytes(
                        (package / "provenance-statement.json").read_bytes()
                    ),
                }
            )
            promotion = dict(reconstructed["decisions"][1])
            promotion["scope"] = [
                promotion["scope"][0],
                f"rollback:{reconstructed['rollback']['rollback_evidence_id']}",
            ]
            promotion = content_address(promotion, "decision_id")
            reconstructed["decisions"] = [reconstructed["decisions"][0], promotion]
            rebind_bootstrap_dispatch(reconstructed)
            self.assertEqual(
                "READY_FOR_HUMAN",
                validate_initial_bootstrap(**reconstructed)["state"],
            )

            substituted = deepcopy(summary)
            substituted["gate_manifest"]["sha256"] = "sha256:" + "0" * 64
            substituted_path = temporary / "substituted-summary.json"
            write_json(substituted_path, substituted)
            rejected = command.copy()
            rejected[rejected.index(str(summary_path))] = str(substituted_path)
            rejected[-1] = str(temporary / "rejected-output")
            with (
                mock.patch.object(module, "GitCliRepositoryAdapter", Adapter),
                mock.patch.object(sys, "argv", rejected),
                self.assertRaisesRegex(ValueError, "gate manifest"),
            ):
                module.main()

    def test_manifest_references_cannot_escape_the_effective_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            evidence = repository / "artifacts/governance/completion/evidence"
            evidence.mkdir(parents=True)
            inside = evidence / "inside.json"
            outside = repository / "artifacts/governance/stale.json"
            outside.parent.mkdir(parents=True, exist_ok=True)
            write_json(inside, {"inside": True})
            write_json(outside, {"stale": True})
            self.assertEqual(
                inside,
                require_json_within(
                    repository,
                    evidence,
                    "artifacts/governance/completion/evidence/inside.json",
                ),
            )
            with self.assertRaises(ValueError):
                require_json_within(
                    repository, evidence, "artifacts/governance/stale.json"
                )

    def test_artifact_metadata_must_match_id_digest_name_and_run(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_artifact_metadata", CI / "verify-artifact-metadata.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        digest = "a" * 64
        metadata = {
            "id": 123,
            "name": "reviewed-evidence",
            "expired": False,
            "digest": "sha256:" + digest,
            "workflow_run": {"id": 456},
        }

        class Response:
            status = 200

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *unused: object) -> None:
                return None

            def read(self, unused_limit: int) -> bytes:
                return json.dumps(metadata).encode("utf-8")

        arguments = [
            "verify-artifact-metadata.py",
            "--repository",
            "timaday/codex-governed-change-authority",
            "--artifact-id",
            "123",
            "--artifact-digest",
            digest,
            "--artifact-name",
            "reviewed-evidence",
            "--workflow-run-id",
            "456",
        ]
        with (
            mock.patch.dict(os.environ, {"GH_API_TOKEN": "x"}, clear=False),
            mock.patch.object(sys, "argv", arguments),
            mock.patch.object(module.urllib.request, "urlopen", return_value=Response()),
        ):
            module.main()
        metadata["workflow_run"] = {"id": 999}
        with (
            mock.patch.dict(os.environ, {"GH_API_TOKEN": "x"}, clear=False),
            mock.patch.object(sys, "argv", arguments),
            mock.patch.object(module.urllib.request, "urlopen", return_value=Response()),
            self.assertRaises(ValueError),
        ):
            module.main()

    def test_target_resolution_accepts_only_registered_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "target.json"
            result = run_script(
                "resolve-target.py",
                "--targets",
                str(ROOT / ".governance/targets.json"),
                "--target-id",
                "release-v0.1.0",
                "--output",
                str(output),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("release-v0.1.0", load_json(output)["target_id"])
            rejected = run_script(
                "resolve-target.py",
                "--targets",
                str(ROOT / ".governance/targets.json"),
                "--target-id",
                "unregistered",
                "--output",
                str(Path(directory) / "rejected.json"),
            )
            self.assertNotEqual(0, rejected.returncode)

            reused = load_json(ROOT / ".governance/targets.json")
            reused["targets"].append(
                {**reused["targets"][0], "target_id": "release-v0.1.1"}
            )
            reused_path = Path(directory) / "reused-targets.json"
            write_json(reused_path, reused)
            rejected = run_script(
                "resolve-target.py",
                "--targets",
                str(reused_path),
                "--target-id",
                "release-v0.1.0",
                "--output",
                str(Path(directory) / "reused.json"),
            )
            self.assertNotEqual(0, rejected.returncode)

    def test_protected_json_copy_preserves_exact_validated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            destination = root / "destination.json"
            source.write_bytes(b'{\n  "value": 1\n}\n')
            self.assertEqual({"value": 1}, copy_json_once(source, destination))
            self.assertEqual(source.read_bytes(), destination.read_bytes())

    def test_protected_json_copy_reuses_one_descriptor_bound_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            destination = root / "destination.json"
            original = b'{"value":1}\n'
            source.write_bytes(original)
            reset_authoritative_read_session()
            self.assertEqual({"value": 1}, load_json(source))
            source.write_bytes(b'{"value":2}\n')
            self.assertEqual({"value": 1}, copy_json_once(source, destination))
            self.assertEqual(original, destination.read_bytes())

    def test_protected_json_copy_rejects_ambiguous_json(self) -> None:
        for body in (b'{"value":1,"value":2}\n', b'{"value":NaN}\n'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source.json"
                destination = root / "destination.json"
                source.write_bytes(body)
                reset_authoritative_read_session()
                with self.assertRaises(ValueError):
                    copy_json_once(source, destination)
                self.assertFalse(destination.exists())

    def test_authority_reads_reject_symlinked_ancestors_and_nonregular_leaves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            write_json(real / "input.json", {"value": 1})
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            reset_authoritative_read_session()
            with self.assertRaisesRegex(ValueError, "unsafe authoritative input"):
                load_json(linked / "input.json")

            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            reset_authoritative_read_session()
            with self.assertRaisesRegex(ValueError, "leaf is unsafe"):
                load_json(fifo)

            duplicate = root / "duplicate.json"
            duplicate.write_bytes(b'{"value":1,"value":2}')
            reset_authoritative_read_session()
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                load_json(duplicate)

    def test_bundle_verifier_rejects_undeclared_directory_symlinks(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_bundle", CI / "verify-bundle.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / "MANIFEST.json", {"files": []})
            target = root / "real-directory"
            target.mkdir()
            (root / "undeclared-directory-link").symlink_to(
                target,
                target_is_directory=True,
            )
            with (
                mock.patch.object(module, "ROOT", root),
                self.assertRaisesRegex(ValueError, "symlink"),
            ):
                module.main()

    def test_kernel_and_authority_share_exact_canonical_task_digests(self) -> None:
        release = ROOT / ".governance/releases/v0.1.0"
        task_path = release / "task-contract.json"
        rollback_task_path = release / "rollback-task-contract.json"
        task_sha = sha256_bytes(task_path.read_bytes())
        rollback_task_sha = sha256_bytes(rollback_task_path.read_bytes())
        self.assertEqual(canonical_bytes(load_json(task_path)), task_path.read_bytes())
        self.assertEqual(
            canonical_bytes(load_json(rollback_task_path)),
            rollback_task_path.read_bytes(),
        )
        target = load_json(ROOT / ".governance/targets.json")["targets"][0]
        plan = load_json(release / "rollback-plan.json")
        self.assertEqual(task_sha, target["expected_task_contract_sha256"])
        self.assertEqual(task_sha, plan["task_contract_sha256"])
        self.assertEqual(
            rollback_task_sha,
            plan["rollback_task_contract_sha256"],
        )
        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(
            encoding="utf-8"
        )
        rollback_lane = workflow.split(
            "Execute exact rollback plan in protected sandbox", 1
        )[1].split("Upload protected rollback rehearsal", 1)[0]
        self.assertIn("run-gates \\", rollback_lane)
        self.assertIn("--repository rollback-candidate", rollback_lane)
        self.assertIn(
            "--task authority/.governance/releases/v0.1.0/rollback-task-contract.json",
            workflow,
        )
        self.assertIn("prepare-rollback-package.py", workflow)
        self.assertIn("prepare-closeout-inputs.py", workflow)

    def test_checkout_verifier_rejects_wrong_head_and_unexpected_untracked_files(
        self,
    ) -> None:
        spec = importlib.util.spec_from_file_location(
            "verify_checkout", CI / "verify-checkout.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Authority Test"],
                cwd=repository,
                check=True,
            )
            tracked = repository / "tracked.txt"
            tracked.write_text("one\n", encoding="utf-8")
            (repository / ".gitignore").write_text(
                "ignored-outside/\n"
                "artifacts/governance/completion/evidence/\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "add", "tracked.txt", ".gitignore"],
                cwd=repository,
                check=True,
            )
            subprocess.run(["git", "commit", "-qm", "one"], cwd=repository, check=True)
            first = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            tracked.write_text("two\n", encoding="utf-8")
            subprocess.run(["git", "commit", "-qam", "two"], cwd=repository, check=True)
            second = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            self.assertTrue(module.verify_checkout(repository, second)["verified"])
            with self.assertRaisesRegex(ValueError, "exact clean commit"):
                module.verify_checkout(repository, first)

            unexpected = repository / "unexpected.txt"
            unexpected.write_text("not evidence\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact clean commit"):
                module.verify_checkout(repository, second)
            unexpected.unlink()

            ignored_outside = repository / "ignored-outside/cache.bin"
            ignored_outside.parent.mkdir()
            ignored_outside.write_bytes(b"machine cache\n")
            with self.assertRaisesRegex(ValueError, "exact clean commit"):
                module.verify_checkout(repository, second)
            ignored_outside.unlink()
            ignored_outside.parent.rmdir()

            evidence = repository / "artifacts/governance/completion/evidence"
            evidence.mkdir(parents=True)
            (evidence / "result.json").write_text("{}\n", encoding="utf-8")
            verified = module.verify_checkout(
                repository,
                second,
                ["artifacts/governance/completion/evidence"],
            )
            self.assertEqual(1, verified["allowed_untracked_count"])
            self.assertEqual(1, verified["allowed_ignored_count"])

            outside = repository / "artifacts/governance/not-evidence.json"
            outside.parent.mkdir(parents=True, exist_ok=True)
            outside.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact clean commit"):
                module.verify_checkout(
                    repository,
                    second,
                    ["artifacts/governance/completion/evidence"],
                )

        workflow = (ROOT / ".github/workflows/disposition.yml").read_text(
            encoding="utf-8"
        )
        allowance = (
            "--allow-untracked-prefix "
            "artifacts/governance/completion/evidence"
        )
        self.assertEqual(4, workflow.count(allowance))
        for step, next_step in (
            (
                "Verify actual rollback checkout identity",
                "Set up Python",
            ),
            (
                "Verify actual target checkout identity",
                "Set up Python",
            ),
            (
                "Verify actual review checkout identity",
                "Download deterministic evidence",
            ),
            (
                "Verify actual admission checkout identity",
                "Resolve target and initialize fail-closed publication",
            ),
        ):
            section = workflow.split(step, 1)[1].split(next_step, 1)[0]
            self.assertNotIn(allowance, section)

    def test_ruleset_renderer_binds_one_positive_integration_and_stays_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ruleset.json"
            result = run_script(
                "render-ruleset.py",
                "--template",
                str(ROOT / "rulesets/target-main.ruleset.template.json"),
                "--integration-id",
                "12345",
                "--output",
                str(output),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            ruleset = load_json(output)
            self.assertEqual("disabled", ruleset["enforcement"])
            encoded = json.dumps(ruleset)
            self.assertNotIn("__GITHUB_APP_INTEGRATION_ID__", encoded)
            self.assertIn('"integration_id": 12345', encoded)
            rejected = run_script(
                "render-ruleset.py",
                "--template",
                str(ROOT / "rulesets/target-main.ruleset.template.json"),
                "--integration-id",
                "0",
                "--output",
                str(Path(directory) / "invalid.json"),
            )
            self.assertNotEqual(0, rejected.returncode)

    def test_publication_is_fail_closed_and_success_requires_exact_ready_artifacts(self) -> None:
        target_path = ROOT / ".governance/targets.json"
        target = load_json(target_path)["targets"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / "target.json"
            write_json(selected, target)
            fallback = root / "fallback.json"
            result = run_script(
                "make-publication.py",
                "--target",
                str(selected),
                "--details-url",
                "https://github.com/timaday/codex-governed-change-authority/actions/runs/1",
                "--workflow-run",
                "1-1",
                "--authority-repository",
                "timaday/codex-governed-change",
                "--authority-sha",
                "a" * 40,
                "--source-repository",
                "timaday/codex-governed-change-authority",
                "--source-head-sha",
                "b" * 40,
                "--output",
                str(fallback),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("failure", load_json(fallback)["conclusion"])

            candidate = load_json(FIXTURES / "candidate.json")
            self.assertTrue(verify_candidate_identity(candidate))
            self.assertNotEqual(content_address(candidate, "candidate_id"), candidate)
            target["expected_candidate_id"] = candidate["candidate_id"]
            write_json(selected, target)
            manifest = content_address(
                {"repository_id": target["repository_id"], "candidate_id": candidate["candidate_id"]},
                "manifest_id",
            )
            candidate_path = root / "candidate.json"
            manifest_path = root / "manifest.json"
            disposition_path = root / "disposition.json"
            write_json(candidate_path, candidate)
            write_json(manifest_path, manifest)
            write_json(
                disposition_path,
                {
                    "schema_version": "1.0.0",
                    "repository_id": target["repository_id"],
                    "task_contract_sha256": target["expected_task_contract_sha256"],
                    "effective_policy_sha256": target["expected_policy_sha256"],
                    "candidate_id": candidate["candidate_id"],
                    "manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
                    "state": "READY_FOR_HUMAN",
                    "human_action_required": True,
                    "approved": False,
                    "reasons": [
                        {
                            "code": "READY_FOR_HUMAN",
                            "message": "All protected claims reconstructed.",
                            "evidence_refs": ["evidence-manifest.json"],
                        }
                    ],
                    "evaluated_at": "2026-08-27T12:00:00Z",
                    "producer_version": "0.1.0",
                },
            )
            ready = root / "ready.json"
            result = run_script(
                "make-publication.py",
                "--target",
                str(selected),
                "--candidate",
                str(candidate_path),
                "--manifest",
                str(manifest_path),
                "--disposition",
                str(disposition_path),
                "--details-url",
                "https://github.com/timaday/codex-governed-change-authority/actions/runs/1",
                "--workflow-run",
                "1-1",
                "--authority-repository",
                "timaday/codex-governed-change",
                "--authority-sha",
                "a" * 40,
                "--source-repository",
                "timaday/codex-governed-change-authority",
                "--source-head-sha",
                "b" * 40,
                "--output",
                str(ready),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            publication = load_json(ready)
            self.assertEqual("success", publication["conclusion"])
            self.assertEqual(["READY_FOR_HUMAN"], publication["reason_codes"])

            malformed_disposition = load_json(disposition_path)
            malformed_disposition.pop("producer_version")
            malformed_path = root / "malformed-disposition.json"
            write_json(malformed_path, malformed_disposition)
            malformed_output = root / "malformed-publication.json"
            result = run_script(
                "make-publication.py",
                "--target",
                str(selected),
                "--candidate",
                str(candidate_path),
                "--manifest",
                str(manifest_path),
                "--disposition",
                str(malformed_path),
                "--details-url",
                "https://github.com/timaday/codex-governed-change-authority/actions/runs/1",
                "--workflow-run",
                "1-1",
                "--authority-repository",
                "timaday/codex-governed-change",
                "--authority-sha",
                "a" * 40,
                "--source-repository",
                "timaday/codex-governed-change-authority",
                "--source-head-sha",
                "b" * 40,
                "--output",
                str(malformed_output),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("failure", load_json(malformed_output)["conclusion"])

            candidate["candidate_id"] = "sha256:" + "f" * 64
            write_json(candidate_path, candidate)
            rejected = root / "rejected.json"
            result = run_script(
                "make-publication.py",
                "--target",
                str(selected),
                "--candidate",
                str(candidate_path),
                "--manifest",
                str(manifest_path),
                "--disposition",
                str(disposition_path),
                "--details-url",
                "https://github.com/timaday/codex-governed-change-authority/actions/runs/1",
                "--workflow-run",
                "1-1",
                "--authority-repository",
                "timaday/codex-governed-change",
                "--authority-sha",
                "a" * 40,
                "--source-repository",
                "timaday/codex-governed-change-authority",
                "--source-head-sha",
                "b" * 40,
                "--output",
                str(rejected),
            )
            self.assertEqual(0, result.returncode, result.stderr)
            rejected_publication = load_json(rejected)
            self.assertEqual("failure", rejected_publication["conclusion"])
            self.assertEqual(target["expected_candidate_id"], rejected_publication["candidate_id"])

    def test_publisher_posts_only_the_fixed_check_contract(self) -> None:
        spec = importlib.util.spec_from_file_location("publish_check", CI / "publish-check.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = load_json(ROOT / ".governance/targets.json")["targets"][0]
        publication = publication_fixture(target)

        class Response:
            def __init__(self, status: int, body: bytes) -> None:
                self.status = status
                self.body = body

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *unused: object) -> None:
                return None

            def read(self, unused_limit: int) -> bytes:
                return self.body

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "publication.json"
            selected = Path(directory) / "target.json"
            write_json(source, publication)
            write_json(selected, target)
            captured = []

            def fake_open(request: object, timeout: int) -> Response:
                captured.append((request, timeout))
                if getattr(request, "method", None) == "GET":
                    if "/commits/" in request.full_url:
                        return Response(
                            200,
                            json.dumps(
                                {
                                    "total_count": 1,
                                    "check_suites": [
                                        {
                                            "id": 5,
                                            "app": {"id": 77},
                                        }
                                    ]
                                }
                            ).encode("utf-8"),
                        )
                    if "/check-suites/5/check-runs" in request.full_url:
                        return Response(
                            200,
                            json.dumps(
                                {
                                    "total_count": 1,
                                    "check_runs": [
                                        {
                                            "id": 99,
                                            "name": "disposition",
                                            "head_sha": target["head_sha"],
                                            "conclusion": "success",
                                            "external_id": "governed-change:0-1:old",
                                            "app": {"id": 77},
                                            "check_suite": {"id": 5},
                                        }
                                    ],
                                }
                            ).encode("utf-8"),
                        )
                    if "/git/ref/heads/governance-authority" in request.full_url:
                        return Response(
                            200,
                            json.dumps(
                                {
                                    "ref": "refs/heads/governance-authority",
                                    "object": {"type": "commit", "sha": "a" * 40},
                                }
                            ).encode("utf-8"),
                        )
                    return Response(
                        200,
                        json.dumps(
                            {
                                "ref": target["target_ref"],
                                "object": {"type": "commit", "sha": target["head_sha"]},
                            }
                        ).encode("utf-8"),
                    )
                if getattr(request, "method", None) == "PATCH":
                    if request.full_url.endswith("/123"):
                        return Response(
                            200,
                            json.dumps(
                                {
                                    "id": 123,
                                    "name": "disposition",
                                    "head_sha": target["head_sha"],
                                    "conclusion": "failure",
                                    "app": {"id": 77},
                                }
                            ).encode("utf-8"),
                        )
                    return Response(200, b'{"id":99,"conclusion":"failure"}')
                raise AssertionError("unexpected request")

            with (
                mock.patch.dict(
                    os.environ,
                    {"GITHUB_APP_TOKEN": "x", "GH_API_TOKEN": "y"},
                    clear=False,
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "publish-check.py",
                        "--publication",
                        str(source),
                        "--target",
                        str(selected),
                        "--workflow-run",
                        "1-1",
                        "--authority-repository",
                        "timaday/codex-governed-change",
                        "--authority-sha",
                        "a" * 40,
                        "--source-repository",
                        "timaday/codex-governed-change-authority",
                        "--source-head-sha",
                        "b" * 40,
                        "--app-id",
                        "77",
                        "--check-run-id",
                        "123",
                        "--admission-result",
                        "failure",
                    ],
                ),
                mock.patch.object(module.urllib.request, "urlopen", side_effect=fake_open),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                module.main()
            self.assertEqual(6, len(captured))
            self.assertEqual("GET", captured[0][0].method)
            self.assertEqual("GET", captured[1][0].method)
            request, timeout = captured[2]
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(30, timeout)
            self.assertEqual("PATCH", request.method)
            self.assertEqual("disposition", body["name"])
            self.assertEqual("failure", body["conclusion"])
            self.assertNotIn("merge", body)
            self.assertNotIn("release", body)
            self.assertEqual("GET", captured[3][0].method)
            self.assertIn("/check-suites", captured[3][0].full_url)
            self.assertEqual("GET", captured[4][0].method)
            revoke = json.loads(captured[5][0].data.decode("utf-8"))
            self.assertEqual("PATCH", captured[5][0].method)
            self.assertEqual("failure", revoke["conclusion"])
            module.validate_publication(
                publication,
                target,
                workflow_run="1-1",
                authority_repository="timaday/codex-governed-change",
                authority_sha="a" * 40,
                source_repository="timaday/codex-governed-change-authority",
                source_head_sha="b" * 40,
                admission_result="failure",
            )
            with self.assertRaisesRegex(ValueError, "contradicts"):
                module.validate_publication(
                    publication,
                    target,
                    workflow_run="1-1",
                    authority_repository="timaday/codex-governed-change",
                    authority_sha="a" * 40,
                    source_repository="timaday/codex-governed-change-authority",
                    source_head_sha="b" * 40,
                    admission_result="success",
                )

    def test_success_is_created_only_after_completed_source_workflow(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "publish_check_finalizer", CI / "publish-check.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = load_json(ROOT / ".governance/targets.json")["targets"][0]
        publication = publication_fixture(target, conclusion="success")

        class Response:
            def __init__(self, status: int, body: object) -> None:
                self.status = status
                self.body = json.dumps(body).encode("utf-8")

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *unused: object) -> None:
                return None

            def read(self, unused_limit: int) -> bytes:
                return self.body

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "publication.json"
            selected = Path(directory) / "target.json"
            write_json(source, publication)
            write_json(selected, target)
            captured: list[object] = []
            source_run = {
                "id": 1,
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": "b" * 40,
                "name": "Governed disposition broker",
                "path": ".github/workflows/broker-disposition.yml",
                "repository": {
                    "full_name": "timaday/codex-governed-change-authority"
                },
                "referenced_workflows": [
                    {
                        "path": (
                            "timaday/codex-governed-change/.github/workflows/"
                            "disposition.yml@" + "a" * 40
                        ),
                        "sha": "a" * 40,
                    }
                ],
            }
            sentinel = {
                "id": 123,
                "name": "disposition",
                "head_sha": target["head_sha"],
                "status": "completed",
                "conclusion": "failure",
                "external_id": "governed-change:1-1:initialized",
                "details_url": publication["details_url"],
                "app": {"id": 77},
                "check_suite": {"id": 5},
            }

            def fake_open(request: object, timeout: int) -> Response:
                captured.append(request)
                if getattr(request, "method", None) == "PATCH":
                    return Response(
                        200,
                        {
                            "id": 123,
                            "name": "disposition",
                            "head_sha": target["head_sha"],
                            "conclusion": "success",
                            "app": {"id": 77},
                        },
                    )
                if "/actions/runs/1/attempts/1" in request.full_url:
                    return Response(200, source_run)
                if "/commits/" in request.full_url:
                    return Response(
                        200,
                        {"total_count": 1, "check_suites": [{"id": 5, "app": {"id": 77}}]},
                    )
                if "/check-suites/5/check-runs" in request.full_url:
                    return Response(200, {"total_count": 1, "check_runs": [sentinel]})
                if "/git/ref/heads/governance-authority" in request.full_url:
                    return Response(
                        200,
                        {
                            "ref": "refs/heads/governance-authority",
                            "object": {"type": "commit", "sha": "a" * 40},
                        },
                    )
                return Response(
                    200,
                    {
                        "ref": target["target_ref"],
                        "object": {"type": "commit", "sha": target["head_sha"]},
                    },
                )

            with (
                mock.patch.dict(
                    os.environ,
                    {"GITHUB_APP_TOKEN": "x", "GH_API_TOKEN": "y"},
                    clear=False,
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "publish-check.py",
                        "--publication",
                        str(source),
                        "--target",
                        str(selected),
                        "--workflow-run",
                        "1-1",
                        "--authority-repository",
                        "timaday/codex-governed-change",
                        "--authority-sha",
                        "a" * 40,
                        "--source-repository",
                        "timaday/codex-governed-change-authority",
                        "--source-head-sha",
                        "b" * 40,
                        "--app-id",
                        "77",
                        "--admission-result",
                        "success",
                        "--finalize-completed-success",
                    ],
                ),
                mock.patch.object(
                    module.urllib.request, "urlopen", side_effect=fake_open
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                module.main()
            self.assertEqual(
                ["GET", "GET", "GET", "GET", "GET", "PATCH", "GET", "GET"],
                [item.method for item in captured],
            )
            posted = json.loads(captured[5].data.decode("utf-8"))
            self.assertEqual("success", posted["conclusion"])
            self.assertNotIn("head_sha", posted)
            self.assertTrue(captured[5].full_url.endswith("/check-runs/123"))

            with self.assertRaisesRegex(ValueError, "newer governed reevaluation"):
                module.resolve_generation_sentinel(
                    [sentinel, {**sentinel, "id": 124, "external_id": "governed-change:2-1:initialized"}],
                    publication,
                )

            source_run["conclusion"] = "cancelled"
            captured.clear()
            with (
                mock.patch.dict(
                    os.environ,
                    {"GITHUB_APP_TOKEN": "x", "GH_API_TOKEN": "y"},
                    clear=False,
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "publish-check.py",
                        "--publication",
                        str(source),
                        "--target",
                        str(selected),
                        "--workflow-run",
                        "1-1",
                        "--authority-repository",
                        "timaday/codex-governed-change",
                        "--authority-sha",
                        "a" * 40,
                        "--source-repository",
                        "timaday/codex-governed-change-authority",
                        "--source-head-sha",
                        "b" * 40,
                        "--app-id",
                        "77",
                        "--admission-result",
                        "success",
                        "--finalize-completed-success",
                    ],
                ),
                mock.patch.object(
                    module.urllib.request, "urlopen", side_effect=fake_open
                ),
                self.assertRaisesRegex(ValueError, "did not complete"),
            ):
                module.main()
            self.assertEqual(
                ["GET", "GET", "GET"], [item.method for item in captured]
            )

            source_run["conclusion"] = "success"
            source_run["referenced_workflows"][0]["sha"] = "c" * 40
            with (
                mock.patch.object(
                    module.urllib.request, "urlopen", side_effect=fake_open
                ),
                self.assertRaisesRegex(ValueError, "exact protected authority"),
            ):
                module.verify_completed_source_run(
                    api_url="https://api.github.com",
                    source_repository="timaday/codex-governed-change-authority",
                    source_head_sha="b" * 40,
                    authority_repository="timaday/codex-governed-change",
                    authority_sha="a" * 40,
                    workflow_run="1-1",
                    headers={},
                )

            with (
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "publish-check.py",
                        "--publication",
                        str(source),
                        "--target",
                        str(selected),
                        "--workflow-run",
                        "1-1",
                        "--authority-repository",
                        "timaday/codex-governed-change",
                        "--authority-sha",
                        "a" * 40,
                        "--source-repository",
                        "timaday/codex-governed-change-authority",
                        "--source-head-sha",
                        "b" * 40,
                        "--app-id",
                        "77",
                        "--check-run-id",
                        "123",
                        "--admission-result",
                        "success",
                    ],
                ),
                mock.patch.object(
                    module.urllib.request, "urlopen", side_effect=fake_open
                ),
            ):
                with self.assertRaisesRegex(ValueError, "deferred"):
                    module.main()

    def test_failed_reevaluation_revokes_beyond_suite_ceiling(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "publish_check_missing_ref", CI / "publish-check.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = load_json(ROOT / ".governance/targets.json")["targets"][0]
        publication = publication_fixture(target, conclusion="failure")

        class Response:
            def __init__(self, status: int, body: object) -> None:
                self.status = status
                self.body = json.dumps(body).encode("utf-8")

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *unused: object) -> None:
                return None

            def read(self, unused_limit: int) -> bytes:
                return self.body

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "publication.json"
            selected = Path(directory) / "target.json"
            write_json(source, publication)
            write_json(selected, target)
            captured: list[object] = []

            def fake_open(request: object, timeout: int) -> Response:
                captured.append(request)
                if getattr(request, "method", None) == "GET":
                    if "/commits/" in request.full_url:
                        page = int(urllib.parse.parse_qs(
                            urllib.parse.urlparse(request.full_url).query
                        )["page"][0])
                        start = (page - 1) * 100 + 1
                        end = min(page * 100, 1001)
                        return Response(
                            200,
                            {
                                "total_count": 1001,
                                "check_suites": [
                                    {"id": value, "app": {"id": 77}}
                                    for value in range(start, end + 1)
                                ],
                            },
                        )
                    if "/check-suites/" in request.full_url:
                        suite_id = int(
                            request.full_url.split("/check-suites/", 1)[1].split("/", 1)[0]
                        )
                        runs = []
                        if suite_id == 1001:
                            runs = [
                                {
                                    "id": 9001,
                                    "name": "disposition",
                                    "head_sha": target["head_sha"],
                                    "conclusion": "success",
                                    "external_id": "governed-change:0-1:old",
                                    "app": {"id": 77},
                                    "check_suite": {"id": suite_id},
                                }
                            ]
                        return Response(
                            200, {"total_count": len(runs), "check_runs": runs}
                        )
                    if "/git/ref/heads/governance-authority" in request.full_url:
                        return Response(
                            200,
                            {
                                "ref": "refs/heads/governance-authority",
                                "object": {"type": "commit", "sha": "a" * 40},
                            },
                        )
                    raise module.urllib.error.HTTPError(
                        request.full_url, 404, "Not Found", {}, None
                    )
                if getattr(request, "method", None) == "PATCH":
                    check_id = int(request.full_url.rsplit("/", 1)[1])
                    if check_id == 123:
                        return Response(
                            200,
                            {
                                "id": 123,
                                "name": "disposition",
                                "head_sha": target["head_sha"],
                                "conclusion": "failure",
                                "app": {"id": 77},
                            },
                        )
                    return Response(200, {"id": check_id, "conclusion": "failure"})
                raise AssertionError("unexpected request")

            with (
                mock.patch.dict(
                    os.environ,
                    {"GITHUB_APP_TOKEN": "x", "GH_API_TOKEN": "y"},
                    clear=False,
                ),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "publish-check.py",
                        "--publication",
                        str(source),
                        "--target",
                        str(selected),
                        "--workflow-run",
                        "1-1",
                        "--authority-repository",
                        "timaday/codex-governed-change",
                        "--authority-sha",
                        "a" * 40,
                        "--source-repository",
                        "timaday/codex-governed-change-authority",
                        "--source-head-sha",
                        "b" * 40,
                        "--app-id",
                        "77",
                        "--check-run-id",
                        "123",
                        "--admission-result",
                        "failure",
                    ],
                ),
                mock.patch.object(
                    module.urllib.request, "urlopen", side_effect=fake_open
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                module.main()
            posted = json.loads(captured[2].data.decode("utf-8"))
            self.assertEqual("failure", posted["conclusion"])
            self.assertIn("page=1", captured[3].full_url)
            self.assertIn("page=11", captured[13].full_url)
            self.assertIn("/check-suites/1001/check-runs", captured[-2].full_url)
            self.assertEqual("PATCH", captured[-1].method)


if __name__ == "__main__":
    unittest.main()
