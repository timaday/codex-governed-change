"""Trusted orchestration for the protected curated mutation corpus."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from codex_governance.artifacts import FilesystemArtifactStore
from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    normalize_repo_path,
    sha256_bytes,
    sha256_canonical,
)
from codex_governance.evidence import candidate_prefix, repository_reference
from codex_governance.gate import run_gate
from codex_governance.mutation import (
    apply_curated_mutant,
    build_mutation_probe_command,
    expected_mutated_tree_sha256,
    git_visible_tree_sha256,
    mutated_source_identity,
    mutation_record_id,
    parse_curated_corpus,
)
from codex_governance.sandbox import (
    build_container_invocation,
    observe_container_provider,
    prepare_candidate_copy,
)


def _reference(evidence_root: str, relative: str, digest: str) -> dict[str, str]:
    return repository_reference(
        evidence_root=evidence_root, relative_path=relative, sha256=digest
    )


def _result_reference(
    evidence_root: str, prefix: str, result: Mapping[str, Any]
) -> dict[str, str]:
    return _reference(
        evidence_root,
        f"{prefix}/result.json",
        sha256_bytes(canonical_json_bytes(result)),
    )


def parse_protected_corpus(
    data: bytes, *, expected_sha256: str
) -> dict[str, Any]:
    """Validate exact previous-LKG corpus bytes before parsing their semantics."""
    if sha256_bytes(data) != expected_sha256:
        raise ValueError("protected mutation corpus digest mismatch")
    return parse_curated_corpus(data)


def run_governed_mutation_corpus(
    *,
    repository: Path,
    policy: Mapping[str, Any],
    task: Mapping[str, Any],
    candidate: Mapping[str, Any],
    task_contract_sha256: str,
    effective_policy_sha256: str,
    reviewer_prompt_sha256: str,
    run_id: str,
    attempt: int,
    workflow_system: str,
    observed_at: str,
    implementation_sha256: str,
    corpus_bytes: bytes,
    artifact_store: FilesystemArtifactStore | None = None,
) -> dict[str, Any]:
    """Run baseline and each mutant only through the declared container boundary."""
    repository = repository.resolve(strict=True)
    evidence_root = normalize_repo_path(policy["evidence_root"])
    corpus = parse_protected_corpus(
        corpus_bytes,
        expected_sha256=policy["mutation"]["corpus_sha256"],
    )
    limits = {
        "timeout_seconds": max(int(gate["timeout_seconds"]) for gate in policy["gates"]),
        "output_bytes": max(int(gate["max_output_bytes"]) for gate in policy["gates"]),
    }
    store = artifact_store or FilesystemArtifactStore(
        repository=repository,
        root=Path(evidence_root),
        max_bytes=max(limits["output_bytes"] * 2, 8_000_000),
    )
    try:
        provider_version = observe_container_provider(policy["sandbox"]["provider"])
    except RuntimeError:
        provider_version = None
    run_prefix = (
        f"{candidate_prefix(candidate['candidate_id'])}/runs/"
        f"{run_id}-{attempt}/mutation"
    )
    corpus_relative = f"{run_prefix}/curated-corpus.json"
    corpus_sha256 = store.write_bytes(corpus_relative, corpus_bytes)
    corpus_reference = _reference(
        evidence_root, corpus_relative, corpus_sha256
    )
    capabilities: list[dict[str, str]] = []
    provenance: list[dict[str, str]] = []
    locators: list[dict[str, str]] = []
    records: list[dict[str, str]] = []

    def invoke(
        *, candidate_copy: Path, source_identity: str, command: list[str],
        candidate_supplier: Callable[[], str], gate_id: str, prefix: str,
        materials: list[dict[str, str]],
    ) -> tuple[dict[str, Any], dict[str, str], dict[str, str], dict[str, str]]:
        invocation = None
        if provider_version is not None:
            invocation = build_container_invocation(
                executable=policy["sandbox"]["provider"],
                provider_version=provider_version,
                image=policy["sandbox"]["image"],
                candidate_copy=candidate_copy,
                candidate_id=source_identity,
                command=command,
                process_limit=policy["sandbox"]["process_limit"],
                memory_bytes=policy["sandbox"]["memory_bytes"],
                cpu_seconds=limits["timeout_seconds"],
                timeout_seconds=limits["timeout_seconds"],
                output_bytes=limits["output_bytes"],
                implementation_sha256=implementation_sha256,
                verified_at=observed_at,
                supervisor_cwd=candidate_copy.parent,
            )
        result = run_gate(
            gate_id=gate_id,
            profile=task["profile"],
            command=command,
            cwd=candidate_copy,
            sandbox_invocation=invocation,
            repository_id=policy["repository_id"],
            task_contract_sha256=task_contract_sha256,
            effective_policy_sha256=effective_policy_sha256,
            provenance_context={
                "repository_digest": candidate["candidate_id"],
                "gate_definition_sha256": sha256_canonical(
                    {"gate_id": gate_id, "command": command}
                ),
                "reviewer_prompt_sha256": reviewer_prompt_sha256,
                "producer": {
                    "builder_id": "codex-governed-change",
                    "implementation_sha256": implementation_sha256,
                    "version": "0.1.0",
                },
                "workflow": {
                    "system": workflow_system,
                    "run_id": run_id,
                    "attempt": attempt,
                },
                "tools": [
                    {"name": policy["sandbox"]["provider"], "version": provider_version or "unavailable"},
                    {"name": "curated-governance-corpus", "version": "1.0.0"},
                ],
                "materials": materials,
            },
            candidate_supplier=candidate_supplier,
            artifact_store=store,
            artifact_prefix=prefix,
            timeout_seconds=limits["timeout_seconds"],
            max_output_bytes=limits["output_bytes"],
        )
        result_ref = _result_reference(evidence_root, prefix, result)
        capability_ref = _reference(
            evidence_root,
            f"{prefix}/sandbox-capability.json",
            result["sandbox_capability_sha256"],
        )
        provenance_ref = dict(result["provenance_statement"])
        capabilities.append(capability_ref)
        provenance.append(provenance_ref)
        return result, result_ref, capability_ref, provenance_ref

    with tempfile.TemporaryDirectory(prefix="codex-governance-mutation-") as temporary:
        supervisor = Path(temporary).resolve()
        baseline_copy = prepare_candidate_copy(
            repository=repository,
            destination=supervisor / "baseline",
            evidence_root=evidence_root,
        )
        baseline_adapter = GitCliRepositoryAdapter(baseline_copy)

        def baseline_candidate() -> str:
            return baseline_adapter.identify(
                repository_id=policy["repository_id"],
                mode=candidate["mode"],
                base_commit=candidate["base_commit"],
                head_commit=candidate.get("head_commit"),
                effective_policy_sha256=effective_policy_sha256,
                evidence_root=evidence_root,
            )["candidate_id"]

        if baseline_candidate() != candidate["candidate_id"]:
            raise RuntimeError("mutation baseline copy identity mismatch")
        baseline_command = [
            "/usr/bin/env", "PYTHONPATH=src", *corpus["baseline_command"]
        ]
        baseline_prefix = f"{run_prefix}/baseline"
        baseline, baseline_ref, _, _ = invoke(
            candidate_copy=baseline_copy,
            source_identity=candidate["candidate_id"],
            command=baseline_command,
            candidate_supplier=baseline_candidate,
            gate_id="mutation-baseline",
            prefix=baseline_prefix,
            materials=[
                {"name": "candidate", "sha256": candidate["candidate_id"]},
                {"name": "mutation-corpus", "sha256": corpus["corpus_id"]},
            ],
        )
        if baseline["status"] != "PASS":
            return {
                "state": "BLOCK" if baseline["status"] == "FAIL" else "UNKNOWN",
                "corpus": corpus_reference,
                "baseline": baseline_ref,
                "mutant_records": records,
                "evidence_locators": locators,
                "sandbox_capabilities": capabilities,
                "provenance_statements": provenance,
            }

        for index, mutant in enumerate(corpus["mutants"], 1):
            mutant_copy = prepare_candidate_copy(
                repository=repository,
                destination=supervisor / f"mutant-{index}",
                evidence_root=evidence_root,
            )
            relative = normalize_repo_path(mutant["path"])
            original = mutant_copy.joinpath(*relative.split("/")).read_text(
                encoding="utf-8"
            )
            line = original[: original.index(mutant["old"])].count("\n") + 1
            patch_sha = apply_curated_mutant(mutant_copy, mutant)
            expected_tree_sha256 = expected_mutated_tree_sha256(
                repository=repository,
                evidence_root=evidence_root,
                mutant=mutant,
            )
            actual_tree_sha256 = git_visible_tree_sha256(
                mutant_copy, evidence_root=evidence_root
            )
            if actual_tree_sha256 != expected_tree_sha256:
                raise RuntimeError("mutated candidate copy identity mismatch")
            source_identity = mutated_source_identity(
                candidate_id=candidate["candidate_id"],
                corpus_id=corpus["corpus_id"],
                mutant_id=mutant["mutant_id"],
                patch_sha256=patch_sha,
                tree_sha256=actual_tree_sha256,
            )

            def current_mutant_source(
                *,
                copy: Path = mutant_copy,
                mutant_id: str = mutant["mutant_id"],
                patch: str = patch_sha,
            ) -> str:
                return mutated_source_identity(
                    candidate_id=candidate["candidate_id"],
                    corpus_id=corpus["corpus_id"],
                    mutant_id=mutant_id,
                    patch_sha256=patch,
                    tree_sha256=git_visible_tree_sha256(
                        copy, evidence_root=evidence_root
                    ),
                )
            selected = list(mutant["selected_command"])
            command = build_mutation_probe_command(relative, selected)
            prefix = f"{run_prefix}/mutants/{mutant['mutant_id']}"
            result, result_ref, capability_ref, provenance_ref = invoke(
                candidate_copy=mutant_copy,
                source_identity=source_identity,
                command=command,
                candidate_supplier=current_mutant_source,
                gate_id=f"mutant-{mutant['mutant_id']}",
                prefix=prefix,
                materials=[
                    {"name": "candidate", "sha256": candidate["candidate_id"]},
                    {"name": "mutation-corpus", "sha256": corpus["corpus_id"]},
                    {"name": "mutation-patch", "sha256": patch_sha},
                ],
            )
            termination = result["termination"]
            exit_code = termination.get("exit_code")
            if result["status"] == "PASS":
                outcome = "SURVIVED"
            elif result["status"] == "FAIL" and exit_code == 120:
                outcome = "INVALID"
            elif result["status"] == "FAIL":
                outcome = "KILLED"
            elif termination.get("kind") == "timeout":
                outcome = "TIMEOUT"
            else:
                outcome = "UNKNOWN"
            locator = content_address(
                {
                    "schema_version": "1.0.0",
                    "repository_id": policy["repository_id"],
                    "task_contract_sha256": task_contract_sha256,
                    "candidate_id": candidate["candidate_id"],
                    "kind": "artifact",
                    "path": result_ref["path"],
                    "artifact_sha256": result_ref["sha256"],
                    "media_type": "application/json",
                },
                "locator_id",
            )
            locator_relative = f"{prefix}/execution-locator.json"
            locator_sha = store.write_bytes(
                locator_relative, canonical_json_bytes(locator)
            )
            locator_reference = _reference(
                evidence_root, locator_relative, locator_sha
            )
            locators.append(locator_reference)
            selected_tests = sorted(
                set(item for item in selected if item.startswith("tests"))
            ) or [" ".join(selected)]
            record = mutation_record_id(
                {
                    "schema_version": "1.0.0",
                    "repository_id": policy["repository_id"],
                    "task_contract_sha256": task_contract_sha256,
                    "effective_policy_sha256": effective_policy_sha256,
                    "candidate_id": candidate["candidate_id"],
                    "corpus_id": corpus["corpus_id"],
                    "mutant_id": "MUTANT-" + mutant["mutant_id"].upper(),
                    "patch_sha256": patch_sha,
                    "mutated_source_identity": source_identity,
                    "execution_identity": result["execution_identity"],
                    "sandbox_capability": capability_ref,
                    "provenance_statement": provenance_ref,
                    "execution_result": result_ref,
                    "operator": mutant["operator"],
                    "tool": "curated-governance-corpus",
                    "tool_version": "1.0.0",
                    "location": {"path": relative, "line": line},
                    "requirement_id": mutant["requirement_id"],
                    "selected_command": selected,
                    "selected_tests": selected_tests,
                    "outcome": outcome,
                    "causal_evidence": (
                        [{"locator_id": locator["locator_id"], "sha256": result_ref["sha256"]}]
                        if outcome == "KILLED"
                        else []
                    ),
                    "triage": {
                        "identity": "",
                        "rationale": "protected selected command outcome",
                        "human_reviewed": False,
                    },
                    "started_at": result["started_at"],
                    "ended_at": result["ended_at"],
                    "limitations": ["curated semantic mutation"],
                }
            )
            record_relative = f"{prefix}/mutant-record.json"
            record_sha = store.write_bytes(
                record_relative, canonical_json_bytes(record)
            )
            records.append(_reference(evidence_root, record_relative, record_sha))

    outcomes = [
        json.loads(
            store.read_bytes(
                reference["path"].removeprefix(evidence_root + "/"),
                expected_sha256=reference["sha256"],
            ).decode("utf-8")
        )["outcome"]
        for reference in records
    ]
    state = "PASS" if outcomes and all(item == "KILLED" for item in outcomes) else (
        "BLOCK" if "SURVIVED" in outcomes else "UNKNOWN"
    )
    return {
        "state": state,
        "corpus": corpus_reference,
        "baseline": baseline_ref,
        "mutant_records": records,
        "evidence_locators": locators,
        "sandbox_capabilities": capabilities,
        "provenance_statements": provenance,
    }
