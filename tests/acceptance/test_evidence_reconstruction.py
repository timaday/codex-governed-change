import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from codex_governance.attestation import (
    build_provenance_statement,
    gate_implementation_sha256,
    mutation_implementation_sha256,
)
from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    sha256_bytes,
    sha256_canonical,
)
from codex_governance.context import compile_context, finalize_context_receipt
from codex_governance.candidate import candidate_id_from_components
from codex_governance.domain.model import DispositionState
from codex_governance.evidence import (
    PRODUCER_VERSION,
    assemble_gate_manifest,
    evaluate_manifest,
)
from codex_governance.mutation import (
    REQUIRED_CURATED_MUTANTS,
    build_mutation_probe_command,
    mutated_source_identity,
)
from codex_governance.schema import load_json, validate_instance
from codex_governance.reviewer import build_reviewer_execution_statement


class EvidenceReconstructionAcceptanceTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]
    REPOSITORY_ID = "repo:example/project"
    CANDIDATE_ID = "sha256:" + "a" * 64
    AT = "2026-08-26T10:00:00Z"
    ENDED = "2026-08-26T10:00:01Z"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        (self.repository / "evidence").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, document: dict, schema_name: str) -> dict[str, str]:
        schema = load_json(self.ROOT / "schemas" / f"{schema_name}.schema.json")
        errors = validate_instance(document, schema)
        self.assertEqual([], errors, f"{name}: {errors}")
        data = canonical_json_bytes(document)
        path = self.repository / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {"path": f"evidence/{name}", "sha256": sha256_bytes(data)}

    def raw(self, name: str, data: bytes) -> dict[str, str]:
        path = self.repository / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {"path": f"evidence/{name}", "sha256": sha256_bytes(data)}

    def verified_decision_ids(self, manifest: dict) -> frozenset[str]:
        return frozenset(
            {
                json.loads(
                    (self.repository / manifest["authenticated_decisions"][0]["path"]).read_text()
                )["decision_id"]
            }
        )

    def complete_manifest(
        self,
        *,
        candidate_changed_paths: list[str] | None = None,
        usage_mismatch: str | None = None,
        gate_defect: str | None = None,
        risk_downgrade: bool = False,
    ) -> dict:
        qualification = content_address(
            {
                "schema_version": "1.0.0", "prompt_sha256": "sha256:" + "f" * 64,
                "schema_sha256": "sha256:" + "4" * 64, "launcher_sha256": "sha256:" + "5" * 64,
                "codex_cli_version": "codex-cli 0.149.1",
                "model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "corpus_sha256": "sha256:" + "6" * 64,
                "human_labelled": True, "cases": 4, "critical_cases": 4, "critical_detected": 4,
                "critical_defect_recall": "100%", "false_passes": 0, "false_blocks": 0,
                "unknowns": 0, "latency_ms": 1, "cost": "unavailable", "qualified": True,
                "created_at": self.AT, "limitations": ["fixture qualification"],
            },
            "qualification_id",
        )
        qualification_ref = self.write(
            "qualification.json", qualification, "reviewer-qualification"
        )
        rapid_qualification = content_address(
            qualification | {"schema_sha256": "sha256:" + "8" * 64},
            "qualification_id",
        )
        rapid_qualification_ref = self.write(
            "rapid-qualification.json",
            rapid_qualification,
            "reviewer-qualification",
        )
        policy = deepcopy(json.loads((self.ROOT / "examples/effective-policy.json").read_text()))
        policy["repository_id"] = self.REPOSITORY_ID
        policy["reviewer"]["qualification_ids"] = {
            "conformance": qualification["qualification_id"],
            "rapid_review": rapid_qualification["qualification_id"],
        }
        policy["protected_minimums"] = [
            {"path_prefix": "src/", "risk_profile": "standard", "gate_ids": ["unit"]}
        ]
        policy["gates"] = [
            {
                "gate_id": "unit", "profiles": ["code"],
                "command": ["python3", "-m", "unittest"],
                "timeout_seconds": 60, "max_output_bytes": 1000,
                "shell": False, "risk_label": "",
            }
        ]
        policy_ref = self.write("policy.json", policy, "effective-policy")
        policy_sha = policy_ref["sha256"]
        task = deepcopy(json.loads((self.ROOT / "examples/task-contract.json").read_text()))
        task.update(
            repository_id=self.REPOSITORY_ID,
            task_id="FIXTURE-READY",
            profile="code",
            scope=["implement the bounded service change"],
            affected_surfaces=[{"path": "src/service.py", "reason": "fixture"}],
            required_gate_ids=["unit"],
            specialist_reviews=[],
            risk_profile="standard",
            rapid_review={"required": True, "minimum_charters": 1, "skip_rationale": "required"},
            governance_change_requested=False,
        )
        task_ref = self.write("task.json", task, "task-contract")
        task_sha = task_ref["sha256"]
        candidate_components = {
            "repository_id": self.REPOSITORY_ID,
            "mode": "working_tree",
            "base_commit": task["base_commit"],
            "head_commit": task["base_commit"],
            "tracked_diff_sha256": "sha256:" + "7" * 64,
            "changed_paths": candidate_changed_paths or ["src/service.py"],
            "untracked_entries": [],
            "submodules": [],
            "effective_policy_sha256": policy_sha,
        }
        self.CANDIDATE_ID = candidate_id_from_components(**candidate_components)
        self.candidate = {
            "schema_version": "1.0.0",
            **candidate_components,
            "candidate_id": self.CANDIDATE_ID,
            "dirty": True,
        }

        decision = content_address(
            {
                "schema_version": "1.0.0",
                "repository_id": self.REPOSITORY_ID,
                "decision_type": "task_approval",
                "task_contract_sha256": task_sha,
                "candidate_id": self.CANDIDATE_ID,
                "base_commit": task["base_commit"],
                "effective_policy_sha256": policy_sha,
                "scope": task["scope"],
                "issuer": {
                    "subject": "fixture-maintainer",
                    "authentication_method": "protected-source-assertion",
                    "protected_source": "decisions/task.json",
                    "assertion_sha256": "sha256:" + "b" * 64,
                },
                "issued_at": "2026-08-26T09:00:00Z",
                "expires_at": "2026-08-27T09:00:00Z",
                "single_use": False,
                "consumption_id": "",
            },
            "decision_id",
        )
        decision_ref = self.write("decision.json", decision, "authenticated-decision")

        observation = self.raw("observation.txt", b"verified observation\n")
        locator = content_address(
            {
                "schema_version": "1.0.0",
                "repository_id": self.REPOSITORY_ID,
                "task_contract_sha256": task_sha,
                "candidate_id": self.CANDIDATE_ID,
                "kind": "artifact",
                "path": observation["path"],
                "artifact_sha256": observation["sha256"],
                "media_type": "text/plain",
            },
            "locator_id",
        )
        locator_ref = self.write("locator.json", locator, "evidence-locator")
        locator_refs = [locator_ref]
        typed_reference = {"locator_id": locator["locator_id"], "sha256": observation["sha256"]}

        capability = content_address(
            {
                "schema_version": "1.0.0", "provider": "docker",
                "provider_version": "fixture", "implementation_sha256": gate_implementation_sha256(),
                "source_identity": self.CANDIDATE_ID, "execution_identity": "sha256:" + "d" * 64,
                "disposable": True, "secrets_present": False, "network_mode": "none",
                "candidate_copy_writable": True, "protected_paths_writable": False,
                "evidence_paths_writable": False, "supervisor_paths_writable": False,
                "process_limit": 16, "memory_bytes": 1000000, "cpu_seconds": 60,
                "timeout_seconds": 60, "output_bytes": 1000,
                "verified_at": self.ENDED if gate_defect == "future-gate-capability" else self.AT,
                "limitations": ["fixture capability"],
            },
            "capability_id",
        )
        capability_ref = self.write("capability.json", capability, "sandbox-capability")
        capability_refs = [capability_ref]
        stdout_ref = self.raw("stdout.bin", b"ok\n")
        stderr_ref = self.raw("stderr.bin", b"")
        provenance = build_provenance_statement(
            repository_id=self.REPOSITORY_ID, candidate_id=self.CANDIDATE_ID,
            repository_digest=self.CANDIDATE_ID, task_contract_sha256=task_sha,
            effective_policy_sha256=policy_sha,
            gate_definition_sha256=sha256_canonical(policy["gates"][0]),
            reviewer_prompt_sha256="sha256:" + "f" * 64,
            producer={"builder_id": "codex-governed-change", "implementation_sha256": gate_implementation_sha256(), "version": PRODUCER_VERSION},
            workflow={"system": "unit", "run_id": "gate-fixture", "attempt": 1},
            tools=[{"name": "python", "version": "fixture"}],
            environment={
                "source_identity": self.CANDIDATE_ID,
                "execution_identity": capability["execution_identity"],
                "sandbox_capability_sha256": capability_ref["sha256"],
            },
            materials=[{"name": "candidate", "sha256": self.CANDIDATE_ID}],
            started_at=(
                "2026-08-26T09:59:59Z"
                if gate_defect == "provenance-time-mismatch"
                else self.AT
            ),
            ended_at=self.ENDED, result="PASS",
            limits={"timeout_seconds": 60, "max_output_bytes": 1000, "process_limit": 16, "memory_bytes": 1000000},
            artifacts=[
                {"name": "stdout", "sha256": stdout_ref["sha256"]},
                {"name": "stderr", "sha256": stderr_ref["sha256"]},
                {"name": "sandbox-capability", "sha256": capability_ref["sha256"]},
            ],
            limitations=["fixture provenance"],
        )
        provenance_ref = self.write("provenance.json", provenance, "provenance-statement")
        provenance_refs = [provenance_ref]
        gate_result = {
            "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
            "task_contract_sha256": task_sha, "gate_id": "unit", "profile": "code",
            "candidate_before": self.CANDIDATE_ID, "candidate_after": self.CANDIDATE_ID,
            "source_identity": self.CANDIDATE_ID,
            "execution_identity": capability["execution_identity"],
            "sandbox_capability_sha256": capability_ref["sha256"],
            "command": ["python3", "-m", "unittest"], "started_at": self.AT,
            "ended_at": self.ENDED, "duration_ms": 1000,
            "termination": {"kind": "exited", "exit_code": 0},
            "artifacts": [
                {"stream": "stdout", "path": stdout_ref["path"], "bytes": 3, "sha256": stdout_ref["sha256"], "truncated": False},
                {"stream": "stderr", "path": stderr_ref["path"], "bytes": 0, "sha256": stderr_ref["sha256"], "truncated": False},
            ],
            "redactions": [], "observation_complete": True, "status": "PASS",
            "limitations": [], "provenance_statement": provenance_ref,
            "producer_version": PRODUCER_VERSION,
        }
        if gate_defect == "nonzero-pass":
            gate_result["termination"] = {"kind": "exited", "exit_code": 9}
        elif gate_defect == "incomplete-pass":
            gate_result["observation_complete"] = False
        elif gate_defect == "truncated-pass":
            gate_result["artifacts"][0]["truncated"] = True
        elif gate_defect == "timeout-pass":
            gate_result["termination"] = {"kind": "timeout"}
        gate_ref = self.write("gate-result.json", gate_result, "gate-result")
        gate_items = [{"gate_id": "unit", "reference": gate_ref}]
        gate_manifest = assemble_gate_manifest(
            repository_id=self.REPOSITORY_ID, task_contract_sha256=task_sha,
            candidate_id=self.CANDIDATE_ID, required_gate_ids=["unit"],
            gate_references={"unit": gate_ref}, created_at=self.ENDED,
        )
        gate_manifest_ref = self.write("gate-manifest.json", gate_manifest, "gate-manifest")

        corpus_bytes = (self.ROOT / "tests/mutation/corpus.json").read_bytes()
        corpus_path = self.repository / "tests/mutation/corpus.json"
        corpus_path.parent.mkdir(parents=True, exist_ok=True)
        corpus_path.write_bytes(corpus_bytes)
        corpus = json.loads(corpus_bytes)
        corpus_ref = {
            "path": "tests/mutation/corpus.json",
            "sha256": sha256_bytes(corpus_bytes),
        }

        def mutation_execution(
            name: str, source_identity: str, command: list[str], status: str,
            exit_code: int,
        ) -> tuple[dict, dict[str, str], dict[str, str], dict[str, str]]:
            execution_identity = sha256_canonical(
                {"source_identity": source_identity, "command": command}
            )
            mutation_capability = content_address(
                {
                    "schema_version": "1.0.0", "provider": "docker",
                    "provider_version": "fixture", "implementation_sha256": mutation_implementation_sha256(),
                    "source_identity": source_identity, "execution_identity": execution_identity,
                    "disposable": True, "secrets_present": False, "network_mode": "none",
                    "candidate_copy_writable": True, "protected_paths_writable": False,
                    "evidence_paths_writable": False, "supervisor_paths_writable": False,
                    "process_limit": 16, "memory_bytes": 1000000, "cpu_seconds": 60,
                    "timeout_seconds": 60, "output_bytes": 1000,
                    "verified_at": (
                        self.ENDED
                        if gate_defect == "future-mutation-capability"
                        and name == "mutation-baseline"
                        else self.AT
                    ),
                    "limitations": ["fixture mutation capability"],
                },
                "capability_id",
            )
            mutation_capability_ref = self.write(
                f"mutation/{name}/capability.json", mutation_capability,
                "sandbox-capability",
            )
            capability_refs.append(mutation_capability_ref)
            mutation_provenance = build_provenance_statement(
                repository_id=self.REPOSITORY_ID, candidate_id=self.CANDIDATE_ID,
                repository_digest=self.CANDIDATE_ID, task_contract_sha256=task_sha,
                effective_policy_sha256=policy_sha,
                gate_definition_sha256=sha256_canonical(
                    {"gate_id": name, "command": command}
                ),
                reviewer_prompt_sha256="sha256:" + "f" * 64,
                producer={"builder_id": "codex-governed-change", "implementation_sha256": mutation_implementation_sha256(), "version": PRODUCER_VERSION},
                workflow={"system": "unit", "run_id": "mutation-fixture", "attempt": 1},
                tools=[{"name": "curated-governance-corpus", "version": "1.0.0"}],
                environment={
                    "source_identity": source_identity,
                    "execution_identity": execution_identity,
                    "sandbox_capability_sha256": mutation_capability_ref["sha256"],
                },
                materials=[
                    {"name": "candidate", "sha256": self.CANDIDATE_ID},
                    {"name": "mutation-corpus", "sha256": corpus["corpus_id"]},
                ],
                started_at=self.AT, ended_at=self.ENDED, result=status,
                limits={"timeout_seconds": 60, "max_output_bytes": 1000, "process_limit": 16, "memory_bytes": 1000000},
                artifacts=[
                    {"name": "stdout", "sha256": stdout_ref["sha256"]},
                    {"name": "stderr", "sha256": stderr_ref["sha256"]},
                    {"name": "sandbox-capability", "sha256": mutation_capability_ref["sha256"]},
                ],
                limitations=["fixture mutation provenance"],
            )
            mutation_provenance_ref = self.write(
                f"mutation/{name}/provenance.json", mutation_provenance,
                "provenance-statement",
            )
            provenance_refs.append(mutation_provenance_ref)
            result = {
                "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
                "task_contract_sha256": task_sha, "gate_id": name, "profile": "code",
                "candidate_before": self.CANDIDATE_ID, "candidate_after": self.CANDIDATE_ID,
                "source_identity": source_identity, "execution_identity": execution_identity,
                "sandbox_capability_sha256": mutation_capability_ref["sha256"],
                "command": command, "started_at": self.AT, "ended_at": self.ENDED,
                "duration_ms": 1000, "termination": {"kind": "exited", "exit_code": exit_code},
                "artifacts": [
                    {"stream": "stdout", "path": stdout_ref["path"], "bytes": 3, "sha256": stdout_ref["sha256"], "truncated": False},
                    {"stream": "stderr", "path": stderr_ref["path"], "bytes": 0, "sha256": stderr_ref["sha256"], "truncated": False},
                ],
                "redactions": [], "observation_complete": True, "status": status,
                "limitations": [], "provenance_statement": mutation_provenance_ref,
                "producer_version": PRODUCER_VERSION,
            }
            result_ref = self.write(
                f"mutation/{name}/result.json", result, "gate-result"
            )
            return result, result_ref, mutation_capability_ref, mutation_provenance_ref

        baseline_command = ["/usr/bin/env", "PYTHONPATH=src", *corpus["baseline_command"]]
        _, mutation_baseline_ref, _, _ = mutation_execution(
            "mutation-baseline", self.CANDIDATE_ID, baseline_command, "PASS", 0
        )

        mutant_refs = []
        for index, definition in enumerate(corpus["mutants"], 1):
            mutant = definition["mutant_id"]
            patch_sha = sha256_canonical(
                {
                    "path": definition["path"], "old": definition["old"],
                    "new": definition["new"], "operator": definition["operator"],
                }
            )
            source_identity = mutated_source_identity(
                candidate_id=self.CANDIDATE_ID, corpus_id=corpus["corpus_id"],
                mutant_id=mutant, patch_sha256=patch_sha,
            )
            selected_command = list(definition["selected_command"])
            command = build_mutation_probe_command(definition["path"], selected_command)
            gate_name = f"mutant-{mutant}"
            mutation_result, execution_ref, mutation_capability_ref, mutation_provenance_ref = mutation_execution(
                gate_name, source_identity, command, "FAIL", 1
            )
            execution_locator = content_address(
                {
                    "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
                    "task_contract_sha256": task_sha, "candidate_id": self.CANDIDATE_ID,
                    "kind": "artifact", "path": execution_ref["path"],
                    "artifact_sha256": execution_ref["sha256"],
                    "media_type": "application/json",
                },
                "locator_id",
            )
            execution_locator_ref = self.write(
                f"mutation/{gate_name}/locator.json", execution_locator,
                "evidence-locator",
            )
            locator_refs.append(execution_locator_ref)
            record = content_address(
                {
                    "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
                    "task_contract_sha256": task_sha,
                    "effective_policy_sha256": policy_sha,
                    "candidate_id": self.CANDIDATE_ID,
                    "corpus_id": corpus["corpus_id"],
                    "mutant_id": "MUTANT-" + mutant.upper(),
                    "patch_sha256": patch_sha,
                    "mutated_source_identity": source_identity,
                    "execution_identity": mutation_result["execution_identity"],
                    "sandbox_capability": mutation_capability_ref,
                    "provenance_statement": mutation_provenance_ref,
                    "execution_result": execution_ref,
                    "operator": definition["operator"],
                    "tool": "curated-governance-corpus", "tool_version": "1.0.0",
                    "location": {"path": definition["path"], "line": 1},
                    "requirement_id": definition["requirement_id"],
                    "selected_command": selected_command,
                    "selected_tests": sorted(set(item for item in selected_command if item.startswith("tests"))) or ["selected mutation oracle"],
                    "outcome": "KILLED",
                    "causal_evidence": [{"locator_id": execution_locator["locator_id"], "sha256": execution_ref["sha256"]}],
                    "triage": {"identity": "", "rationale": "causal fixture", "human_reviewed": False},
                    "started_at": self.AT, "ended_at": self.ENDED,
                    "limitations": ["fixture mutant"],
                },
                "mutant_record_id",
            )
            mutant_refs.append(self.write(f"mutants/{index}.json", record, "mutant-record"))

        sources = {
            "repository_id": self.REPOSITORY_ID, "candidate_id": self.CANDIDATE_ID,
            "created_at": self.AT, "task_authority": {"sha256": decision_ref["sha256"]},
            "policy": {"sha256": policy_sha}, "repository_inventory": {"sha256": "sha256:" + "2" * 64},
            "changed_files": self.candidate["changed_paths"],
            "affected_closure": sorted(
                {"src/service.py", "tests/test_service.py", *self.candidate["changed_paths"]}
            ),
            "gate_results": [{"status": "PASS", "sha256": gate_ref["sha256"]}],
            "risks": [], "failures": [], "conflicts": [], "survivors": [],
            "limitations": [], "unknowns": [], "rubric": {"sha256": "sha256:" + "3" * 64},
            "disposition_contract": "all fixed claims are mandatory", "artifacts": [],
        }
        context_receipt = compile_context(
            sources=sources, candidate=self.candidate,
            requested_profile="STANDARD", token_budget=24000,
            changed_paths=self.candidate["changed_paths"],
            affected_closure=sources["affected_closure"],
            model="gpt-5.6-sol", reasoning_effort="xhigh",
        )["receipt"]
        context_ref = self.write("context.json", context_receipt, "context-receipt")

        reviewer = {
            "schema_version": "2.0.0", "repository_id": self.REPOSITORY_ID,
            "candidate_id": self.CANDIDATE_ID, "task_contract_sha256": task_sha,
            "effective_policy_sha256": policy_sha,
            "gate_manifest_sha256": gate_manifest_ref["sha256"],
            "context_receipt_sha256": context_ref["sha256"],
            "reviewer_prompt_sha256": qualification["prompt_sha256"],
            "qualification_id": qualification["qualification_id"], "model": "gpt-5.6-sol",
            "invocation_id": "fixture-review", "verdict": "NO_BLOCKING_FINDING_OBSERVED",
            "reviewed_surfaces": ["change"], "affected_closure": ["src/service.py"],
            "retrieval_expansions": [], "findings": [], "missing_evidence": [],
            "claims": [{"claim": "bounded review", "classification": "VERIFIED_WITHIN_SCOPE", "evidence_refs": [typed_reference]}],
            "limitations": ["fresh context is not independence"],
        }
        reviewer_ref = self.write("reviewer.json", reviewer, "reviewer-result")
        context_execution = finalize_context_receipt(
            context_receipt,
            review_mode="conformance",
            reviewer_output_sha256=reviewer_ref["sha256"],
            retrieval_expansions=[],
            usage_observed=True,
            actual_input_tokens=100,
            actual_output_tokens=20,
            cached_input_tokens=10,
            reasoning_output_tokens=5,
            latency_ms=1000,
            cost="unavailable",
            created_at=self.ENDED,
            limitations=["fixture"],
        )
        context_execution_ref = self.write(
            "context-execution.json",
            context_execution,
            "context-execution-receipt",
        )
        execution_facts = {
            "reviewer_prompt_sha256": qualification["prompt_sha256"],
            "output_sha256": reviewer_ref["sha256"],
            "candidate_before": self.CANDIDATE_ID,
            "candidate_after": self.CANDIDATE_ID,
            "environment_keys": ["CODEX_HOME", "PATH"],
            "argv_sha256": "sha256:" + "7" * 64,
            "stdin_sha256": "sha256:" + "8" * 64,
            "thread_id": "fixture-thread-conformance",
            "started_at": self.AT,
            "ended_at": self.ENDED,
            "latency_ms": 1000,
            "return_code": 0,
            "timed_out": False,
            "observation_complete": True,
            "capture_threads_completed": True,
            "process_cleanup_complete": True,
            "execution_valid": True,
            "output_valid": True,
            "bindings_match": True,
            "output_truncated": False,
            "stdout_sha256": "sha256:" + "9" * 64,
            "stderr_sha256": "sha256:" + "0" * 64,
            "usage_observed": True,
            "input_tokens": 101 if usage_mismatch == "conformance" else 100,
            "cached_input_tokens": 10,
            "output_tokens": 20,
            "reasoning_output_tokens": 5,
            "limitations": ["fixture"],
        }
        reviewer_execution = build_reviewer_execution_statement(
            repository_id=self.REPOSITORY_ID,
            task_contract_sha256=task_sha,
            effective_policy_sha256=policy_sha,
            candidate_id=self.CANDIDATE_ID,
            review_mode="conformance",
            output_schema_sha256=qualification["schema_sha256"],
            launcher_sha256=qualification["launcher_sha256"],
            qualification_id=qualification["qualification_id"],
            model=qualification["model"],
            reasoning_effort=qualification["reasoning_effort"],
            input_context_receipt_sha256=context_ref["sha256"],
            context_execution_receipt_sha256=context_execution_ref["sha256"],
            workflow_system="unit",
            run_id="review-fixture",
            attempt=1,
            timeout_seconds=policy["reviewer"]["timeout_seconds"],
            max_output_bytes=policy["reviewer"]["max_output_bytes"],
            codex_cli_version="codex-cli 0.149.1",
            execution=execution_facts,
        )
        reviewer_execution_ref = self.write(
            "reviewer-execution.json", reviewer_execution, "reviewer-execution"
        )

        risk_document = {
            "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
            "task_contract_sha256": task_sha, "candidate_id": self.CANDIDATE_ID,
            "change_kind": "code", "risk_profile": "standard", "hazard_classes": [],
            "assessed_surfaces": ["src/service.py"], "stakeholders": ["users"],
            "value_at_risk": ["correctness"], "risk_hypotheses": ["regression"],
            "mandatory_charter_count": 1, "rapid_review_required": True,
            "skip_rationale": "required", "created_at": self.AT, "producer_version": "test",
            "provenance": {"produced_by": "fixture", "method": "bounded", "source_refs": ["GOV-031"]},
        }
        if risk_downgrade:
            risk_document.update(
                risk_profile="low",
                mandatory_charter_count=0,
                rapid_review_required=False,
                skip_rationale="candidate claims low risk",
            )
        risk = content_address(risk_document, "assessment_id")
        risk_ref = self.write("risk.json", risk, "risk-assessment")
        charter = {
            "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
            "task_contract_sha256": task_sha, "charter_id": "CHARTER-FIXTURE",
            "candidate_id": self.CANDIDATE_ID, "risk_assessment_sha256": risk["assessment_id"],
            "mission": "investigate regression", "target": "service", "affected_surfaces": ["src/service.py"],
            "stakeholders": ["users"], "value_at_risk": ["correctness"],
            "risk_hypotheses": ["regression"], "quality_criteria": ["correctness"],
            "coverage_areas": ["behavior"], "techniques": ["scenario"], "oracle_heuristics": ["requirements"],
            "resources": ["tests"], "constraints": ["bounded"], "timebox_minutes": 10,
            "required_evidence": ["observation"], "stopping_heuristic": "risk exercised",
            "created_at": self.AT, "producer_version": "test",
            "provenance": {"produced_by": "fixture", "method": "bounded", "source_refs": ["RISK"]},
        }
        charter_ref = self.write("charter.json", charter, "review-charter")
        session = {
            "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
            "task_contract_sha256": task_sha, "session_id": "SESSION-FIXTURE",
            "candidate_id": self.CANDIDATE_ID, "charter_id": charter["charter_id"],
            "charter_sha256": charter_ref["sha256"],
            "reviewer_prompt_sha256": rapid_qualification["prompt_sha256"],
            "qualification_id": rapid_qualification["qualification_id"],
            "model": rapid_qualification["model"], "status": "completed",
            "environment": ["disposable fixture"], "tools": ["unittest"],
            "experiments": [{"id": "EXPERIMENT-1", "activity_kind": "investigation", "procedure": "exercise scenario", "observation": "no regression observed", "oracle": "requirement", "evidence_refs": [locator["locator_id"]]}],
            "retrieval_expansions": [],
            "findings": [], "counter_hypotheses": ["latent regression"], "coverage_achieved": ["scenario"],
            "omitted_areas": ["production"], "obstacles": ["production unavailable"],
            "new_risks": [], "follow_up_charters": [],
            "residual_risks": [{"risk_id": "RESIDUAL-1", "description": "finite coverage", "material": False, "evidence_refs": [locator["locator_id"]]}],
            "started_at": self.AT, "ended_at": self.ENDED, "producer_version": "test",
            "provenance": {"produced_by": "fixture", "method": "investigation", "source_refs": ["CHARTER-FIXTURE"]},
        }
        session_ref = self.write("session.json", session, "rapid-review-session")
        rapid_context_execution = finalize_context_receipt(
            context_receipt,
            review_mode="rapid_review",
            reviewer_output_sha256=session_ref["sha256"],
            retrieval_expansions=[],
            usage_observed=True,
            actual_input_tokens=120,
            actual_output_tokens=30,
            cached_input_tokens=10,
            reasoning_output_tokens=7,
            latency_ms=1200,
            cost="unavailable",
            created_at=self.ENDED,
            limitations=["fixture"],
        )
        rapid_context_execution_ref = self.write(
            "rapid-context-execution.json",
            rapid_context_execution,
            "context-execution-receipt",
        )
        rapid_execution_facts = dict(
            execution_facts,
            reviewer_prompt_sha256=rapid_qualification["prompt_sha256"],
            output_sha256=session_ref["sha256"],
            thread_id="fixture-thread-rapid-review",
            input_tokens=121 if usage_mismatch == "rapid_review" else 120,
            output_tokens=30,
            reasoning_output_tokens=7,
            latency_ms=1200,
        )
        rapid_execution = build_reviewer_execution_statement(
            repository_id=self.REPOSITORY_ID,
            task_contract_sha256=task_sha,
            effective_policy_sha256=policy_sha,
            candidate_id=self.CANDIDATE_ID,
            review_mode="rapid_review",
            output_schema_sha256=rapid_qualification["schema_sha256"],
            launcher_sha256=rapid_qualification["launcher_sha256"],
            qualification_id=rapid_qualification["qualification_id"],
            model=rapid_qualification["model"],
            reasoning_effort=rapid_qualification["reasoning_effort"],
            input_context_receipt_sha256=context_ref["sha256"],
            context_execution_receipt_sha256=rapid_context_execution_ref["sha256"],
            workflow_system="unit",
            run_id="rapid-fixture",
            attempt=1,
            timeout_seconds=policy["reviewer"]["timeout_seconds"],
            max_output_bytes=policy["reviewer"]["max_output_bytes"],
            codex_cli_version="codex-cli 0.149.1",
            execution=rapid_execution_facts,
        )
        rapid_execution_ref = self.write(
            "rapid-execution.json", rapid_execution, "reviewer-execution"
        )
        story = {"summary": "bounded story", "evidence_refs": [locator["locator_id"]], "limitations": ["finite"]}
        debrief = {
            "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
            "task_contract_sha256": task_sha, "debrief_id": "DEBRIEF-FIXTURE",
            "candidate_id": self.CANDIDATE_ID, "session_refs": [session["session_id"]],
            "product_story": story, "testing_story": story, "quality_of_testing_story": story,
            "actionable_findings": [], "residual_risks": ["RESIDUAL-1"],
            "created_at": self.AT, "producer_version": "test",
            "provenance": {"produced_by": "fixture", "method": "debrief", "source_refs": ["SESSION-FIXTURE"]},
        }
        debrief_ref = self.write("debrief.json", debrief, "rapid-review-debrief")
        risk_disposition = {
            "schema_version": "1.0.0", "risk_disposition_id": "RISK-DISPOSITION-FIXTURE",
            "repository_id": self.REPOSITORY_ID, "task_contract_sha256": task_sha,
            "candidate_id": self.CANDIDATE_ID, "debrief_sha256": debrief_ref["sha256"],
            "items": [{"item_id": "RESIDUAL-1", "kind": "residual_risk", "severity": "low", "disposition": "remediated", "rationale": "bounded evidence", "evidence_refs": [locator["locator_id"]], "decision_ref": ""}],
            "state": "READY_FOR_HUMAN", "human_owned": True, "approved": False,
            "created_at": self.AT, "producer_version": "test",
            "provenance": {"produced_by": "fixture", "method": "deterministic", "source_refs": ["DEBRIEF-FIXTURE"]},
        }
        risk_disposition_ref = self.write("risk-disposition.json", risk_disposition, "risk-disposition")
        risk_register = content_address(
            {
                "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
                "task_contract_sha256": task_sha, "candidate_id": self.CANDIDATE_ID,
                "risks": [{"risk_id": "RISK-1", "description": "regression", "threatened_value": "correctness", "impact": "high", "status": "mitigated", "source_refs": ["GOV-031"], "charter_refs": ["CHARTER-FIXTURE"]}],
                "updated_from": ["session:SESSION-FIXTURE"], "created_at": self.AT, "producer_version": "test",
            },
            "risk_register_id",
        )
        risk_register_ref = self.write("risk-register.json", risk_register, "risk-register")
        oracle = content_address(
            {"schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID, "task_contract_sha256": task_sha,
             "candidate_id": self.CANDIDATE_ID, "name": "requirement", "source": observation["path"],
             "source_sha256": observation["sha256"], "heuristic": "claims", "known_fallibility": ["finite"],
             "applicability": "service", "created_at": self.AT}, "oracle_id",
        )
        oracle_ref = self.write("oracle.json", oracle, "oracle-reference")
        coverage = content_address(
            {"schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID, "task_contract_sha256": task_sha,
             "candidate_id": self.CANDIDATE_ID, "session_id": session["session_id"], "covered": ["scenario"],
             "omitted": ["production"], "oracle_refs": [oracle["oracle_id"]], "limitations": ["finite"],
             "created_at": self.AT}, "coverage_note_id",
        )
        coverage_ref = self.write("coverage.json", coverage, "coverage-note")

        claim_ids = (
            "scope_authorized", "candidate_current", "gates_complete", "governance_integrity",
            "rst_complete", "mutation_complete", "fresh_review_complete", "residual_risk_visible",
            "context_complete",
        )
        assurance = content_address(
            {
                "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
                "candidate_id": self.CANDIDATE_ID, "task_contract_sha256": task_sha,
                "effective_policy_sha256": policy_sha,
                "claims": [
                    {"claim_id": claim_id, "argument_rule": "RULE_" + claim_id.upper(),
                     "supporting_evidence": [typed_reference], "refuting_evidence": [],
                     "limitations": ["bounded claim"], "unresolved_defeaters": [],
                     "classification": "VERIFIED_WITHIN_SCOPE"}
                    for claim_id in claim_ids
                ],
                "unresolved_defeaters": [], "state": "READY_FOR_HUMAN",
                "created_at": self.AT, "producer_version": "test",
            },
            "assurance_case_id",
        )
        assurance_ref = self.write("assurance.json", assurance, "assurance-case")
        manifest = content_address(
            {
                "schema_version": "1.0.0", "repository_id": self.REPOSITORY_ID,
                "candidate_id": self.CANDIDATE_ID, "task_contract": task_ref,
                "effective_policy": policy_ref, "authenticated_decisions": [decision_ref],
                "evidence_locators": locator_refs, "sandbox_capabilities": capability_refs,
                "provenance_statements": provenance_refs, "gate_manifest": gate_manifest_ref,
                "required_gate_ids": ["unit"], "gate_results": gate_items,
                "mutation_corpus": corpus_ref, "mutation_baseline": mutation_baseline_ref,
                "mutant_records": mutant_refs, "reviewer_qualification": qualification_ref,
                "rapid_review_qualification": rapid_qualification_ref,
                "context_receipt": context_ref,
                "context_execution_receipt": context_execution_ref,
                "reviewer_result": reviewer_ref,
                "reviewer_execution": reviewer_execution_ref,
                "rapid_review_executions": [rapid_execution_ref],
                "rapid_review_context_execution_receipts": [rapid_context_execution_ref],
                "risk_register": risk_register_ref, "oracle_references": [oracle_ref],
                "coverage_notes": [coverage_ref], "follow_ups": [], "assurance_case": assurance_ref,
                "risk_assessment": risk_ref, "rapid_review_charters": [charter_ref],
                "rapid_review_sessions": [session_ref], "rapid_review_debrief": debrief_ref,
                "risk_disposition": risk_disposition_ref, "created_at": self.AT,
                "producer_version": "test",
            },
            "manifest_id",
        )
        schema = load_json(self.ROOT / "schemas/evidence-manifest.schema.json")
        self.assertEqual([], validate_instance(manifest, schema))
        return manifest

    def test_only_reconstructable_exact_candidate_manifest_is_ready(self) -> None:
        manifest = self.complete_manifest()
        state, reasons = evaluate_manifest(
            repository=self.repository, manifest=manifest, schema_root=self.ROOT / "schemas",
            current_candidate=self.candidate, evaluated_at="2026-08-26T12:00:00Z",
            verified_decision_ids=frozenset({
                json.loads(
                    (self.repository / manifest["authenticated_decisions"][0]["path"]).read_text()
                )["decision_id"]
            }),
        )
        self.assertEqual(DispositionState.READY_FOR_HUMAN, state, reasons)

    def test_gate_manifest_cannot_predate_referenced_gate_completion(self) -> None:
        manifest = self.complete_manifest()
        path = self.repository / manifest["gate_manifest"]["path"]
        gate_manifest = json.loads(path.read_text(encoding="utf-8"))
        gate_manifest["created_at"] = self.AT
        gate_manifest = content_address(gate_manifest, "gate_manifest_id")
        data = canonical_json_bytes(gate_manifest)
        path.write_bytes(data)
        manifest["gate_manifest"]["sha256"] = sha256_bytes(data)
        state, _ = evaluate_manifest(
            repository=self.repository,
            manifest=manifest,
            schema_root=self.ROOT / "schemas",
            current_candidate=self.candidate,
            evaluated_at="2026-08-26T12:00:00Z",
            verified_decision_ids=self.verified_decision_ids(manifest),
        )
        self.assertNotEqual(DispositionState.READY_FOR_HUMAN, state)

    def test_distinct_producer_workflows_reconstruct_through_causal_links(self) -> None:
        manifest = self.complete_manifest()
        provenance = [
            json.loads((self.repository / reference["path"]).read_text())
            for reference in manifest["provenance_statements"]
        ]
        reviewer_execution = json.loads(
            (self.repository / manifest["reviewer_execution"]["path"]).read_text()
        )
        rapid_execution = json.loads(
            (self.repository / manifest["rapid_review_executions"][0]["path"]).read_text()
        )
        run_ids = {
            *(item["predicate"]["workflow"]["run_id"] for item in provenance),
            reviewer_execution["workflow"]["run_id"],
            rapid_execution["workflow"]["run_id"],
        }
        self.assertEqual(
            {"gate-fixture", "mutation-fixture", "review-fixture", "rapid-fixture"},
            run_ids,
        )
        state, reasons = evaluate_manifest(
            repository=self.repository,
            manifest=manifest,
            schema_root=self.ROOT / "schemas",
            current_candidate=self.candidate,
            evaluated_at="2026-08-26T12:00:00Z",
            verified_decision_ids=self.verified_decision_ids(manifest),
        )
        self.assertEqual(DispositionState.READY_FOR_HUMAN, state, reasons)

    def test_missing_or_tampered_raw_gate_stream_never_reconstructs_ready(self) -> None:
        for defect in ("missing", "tampered"):
            manifest = self.complete_manifest()
            gate_result = json.loads(
                (self.repository / manifest["gate_results"][0]["reference"]["path"]).read_text()
            )
            raw_path = self.repository / gate_result["artifacts"][0]["path"]
            if defect == "missing":
                raw_path.unlink()
            else:
                raw_path.write_bytes(b"altered\n")
            state, _ = evaluate_manifest(
                repository=self.repository,
                manifest=manifest,
                schema_root=self.ROOT / "schemas",
                current_candidate=self.candidate,
                evaluated_at="2026-08-26T12:00:00Z",
                verified_decision_ids=self.verified_decision_ids(manifest),
            )
            with self.subTest(defect=defect):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, state)

    def test_schema_valid_pass_cannot_override_invalid_observation_semantics(self) -> None:
        for defect in (
            "nonzero-pass",
            "incomplete-pass",
            "truncated-pass",
            "timeout-pass",
            "future-gate-capability",
            "future-mutation-capability",
            "provenance-time-mismatch",
        ):
            manifest = self.complete_manifest(gate_defect=defect)
            state, _ = evaluate_manifest(
                repository=self.repository,
                manifest=manifest,
                schema_root=self.ROOT / "schemas",
                current_candidate=self.candidate,
                evaluated_at="2026-08-26T12:00:00Z",
                verified_decision_ids=self.verified_decision_ids(manifest),
            )
            with self.subTest(defect=defect):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, state)

    def test_candidate_risk_assessment_cannot_downgrade_protected_floor(self) -> None:
        manifest = self.complete_manifest(risk_downgrade=True)
        state, reasons = evaluate_manifest(
            repository=self.repository,
            manifest=manifest,
            schema_root=self.ROOT / "schemas",
            current_candidate=self.candidate,
            evaluated_at="2026-08-26T12:00:00Z",
            verified_decision_ids=self.verified_decision_ids(manifest),
        )
        self.assertEqual(DispositionState.BLOCK, state, reasons)
        self.assertTrue(any("rapid review" in reason for reason in reasons), reasons)

    def test_missing_provenance_or_locator_never_preserves_readiness(self) -> None:
        for field in ("provenance_statements", "evidence_locators"):
            manifest = self.complete_manifest()
            manifest[field] = []
            manifest = content_address(manifest, "manifest_id")
            state, _ = evaluate_manifest(
                repository=self.repository, manifest=manifest, schema_root=self.ROOT / "schemas",
                current_candidate=self.candidate, evaluated_at="2026-08-26T12:00:00Z",
                verified_decision_ids=self.verified_decision_ids(manifest),
            )
            with self.subTest(field=field):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, state)

    def test_missing_process_receipts_or_mode_specific_qualification_never_preserve_readiness(self) -> None:
        cases = (
            ("reviewer_execution", None),
            ("rapid_review_executions", []),
            ("rapid_review_context_execution_receipts", []),
            ("rapid_review_qualification", "reuse-conformance"),
        )
        for field, replacement in cases:
            manifest = self.complete_manifest()
            if replacement == "reuse-conformance":
                manifest[field] = manifest["reviewer_qualification"]
            elif replacement is None:
                manifest[field] = {
                    "path": "evidence/missing-execution.json",
                    "sha256": "sha256:" + "0" * 64,
                }
            else:
                manifest[field] = replacement
            manifest = content_address(manifest, "manifest_id")
            state, _ = evaluate_manifest(
                repository=self.repository,
                manifest=manifest,
                schema_root=self.ROOT / "schemas",
                current_candidate=self.candidate,
                evaluated_at="2026-08-26T12:00:00Z",
                verified_decision_ids=self.verified_decision_ids(manifest),
            )
            with self.subTest(field=field):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, state)

    def test_model_usage_must_reconcile_between_process_and_context_receipts(self) -> None:
        for mode in ("conformance", "rapid_review"):
            manifest = self.complete_manifest(usage_mismatch=mode)
            state, _ = evaluate_manifest(
                repository=self.repository,
                manifest=manifest,
                schema_root=self.ROOT / "schemas",
                current_candidate=self.candidate,
                evaluated_at="2026-08-26T12:00:00Z",
                verified_decision_ids=self.verified_decision_ids(manifest),
            )
            with self.subTest(mode=mode):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, state)

    def test_candidate_bound_governance_path_cannot_be_hidden_by_task_scope(self) -> None:
        manifest = self.complete_manifest(
            candidate_changed_paths=["schemas/disposition.schema.json"]
        )
        state, reasons = evaluate_manifest(
            repository=self.repository,
            manifest=manifest,
            schema_root=self.ROOT / "schemas",
            current_candidate=self.candidate,
            evaluated_at="2026-08-26T12:00:00Z",
        )
        self.assertEqual(DispositionState.BLOCK, state)
        self.assertTrue(any("governance" in reason.lower() for reason in reasons), reasons)


if __name__ == "__main__":
    unittest.main()
